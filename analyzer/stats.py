"""Traffic statistics: one pass over the capture, many useful numbers.

The whole module is a single loop over the packet list. Each packet is
classified once, which keeps the tool fast even on large captures.

Every value produced here is a *plain* Python type (int / str / list), so
the results can be printed, written to CSV or tested without Scapy.

Returned dictionary (grouped by topic)
--------------------------------------
Overview
    ``total_packets``      number of frames in the capture
    ``total_bytes``        sum of the frame lengths
    ``avg_packet_size``    mean frame length in bytes
    ``first_seen``         timestamp of the first packet
    ``last_seen``          timestamp of the last packet
    ``duration_seconds``   ``last_seen - first_seen``
Protocols
    ``protocol_counts``    TCP / UDP / ICMP / Other
    ``icmp_total``         number of ICMP packets
Talkers
    ``top_src_ips``        ``[(ip, count), ...]`` - top ``config.TOP_N``
    ``top_dst_ips``        ``[(ip, count), ...]``
    ``top_src_ports``      ``[(port, count), ...]``
    ``top_dst_ports``      ``[(port, count), ...]``
    ``unique_src_ips``     how many distinct sources sent traffic
    ``unique_dst_ips``     how many distinct destinations were contacted
Application layer
    ``dns_total``          DNS *queries* (not answers)
    ``top_dns_domains``    ``[(domain, count), ...]``
    ``http_total``         HTTP requests seen in clear text
    ``top_http_hosts``     ``[(host, count), ...]``
TCP behaviour
    ``tcp_flag_counts``    SYN / ACK / SYN-ACK / RST / FIN / PSH counts
    ``unanswered_syns``    SYNs per source IP that never got a SYN-ACK
Full counters (used by the anomaly engine, not printed as tables)
    ``all_src_counts``         ``{ip: packets_sent}``
    ``all_dst_port_counts``    ``{port: packets_received}``
    ``dports_by_src``          ``{ip: {port, ...}}`` - scan detection
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List, Set, Tuple

import config


def _safe_int(value: Any) -> int:
    """Convert a Scapy field to ``int``, returning ``-1`` if impossible.

    Scapy can return ``None`` for a missing port or flag field, and
    ``int(None)`` raises ``TypeError``. Instead of crashing on a single
    odd packet we fall back to ``-1`` and let the caller skip it.

    Args:
        value: The raw field value taken from the packet.

    Returns:
        The value as an int, or ``-1`` when it cannot be converted.
    """
    try:
        return int(value)
    except (TypeError, ValueError, IndexError, AttributeError):
        return -1


def _safe_float(value: Any) -> float:
    """Convert a Scapy timestamp to ``float``, returning ``0.0`` on failure.

    Packet times are seconds since the epoch and may carry a fraction.
    Keeping the fraction matters: a capture that only lasts 200 ms still
    shows a non-zero duration.

    Args:
        value: The raw ``pkt.time`` value.

    Returns:
        The value as a float, or ``0.0`` when it cannot be converted.
    """
    try:
        return float(value)
    except (TypeError, ValueError, IndexError, AttributeError):
        return 0.0


def _clean_text(value: Any) -> str:
    """Turn a Scapy string field such as ``b"example.com."`` into plain text.

    Args:
        value: Raw field value (bytes or str).

    Returns:
        Cleaned string without the ``b''`` wrapper or a trailing dot.
    """
    text = value.decode("utf-8", "ignore") if isinstance(value, bytes) else str(value)
    return text.strip().strip("'\"").rstrip(".")


def service_for_domain(domain: str) -> str:
    """Map a DNS name to a friendly service (``""`` when unknown).

    Suffix match against ``config.SERVICE_DOMAINS`` so any subdomain works:
    ``rr1---sn-abcd.googlevideo.com`` → ``"YouTube"``.

    Args:
        domain: Already-cleaned, lower-cased DNS name.

    Returns:
        Service name or ``""``.
    """
    name = (domain or "").lower().strip().rstrip(".")
    if not name:
        return ""
    for service, suffixes in config.SERVICE_DOMAINS.items():
        for suffix in suffixes:
            if name == suffix or name.endswith("." + suffix):
                return service
    return ""


def base_domain(domain: str) -> str:
    """Return the registrable base (last two labels) for grouping.

    ``rr1---sn-xyz.googlevideo.com`` → ``googlevideo.com``. Keeps the
    DNS table readable when CDNs rotate subdomains per connection.
    """
    parts = (domain or "").lower().strip().rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return (domain or "").lower()


def compute_stats(packets: List[Any]) -> Dict[str, Any]:
    """Calculate statistics for a list of Scapy packets.

    Args:
        packets: Packets as returned by :func:`analyzer.utils.load_pcap`.

    Returns:
        A dictionary of statistics (see the module docstring for the full
        list of keys).
    """
    # Lazy import keeps this module importable even without Scapy present.
    from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
    from scapy.layers.dns import DNS, DNSQR  # noqa: E402
    try:
        from scapy.layers.inet6 import IPv6  # noqa: E402
    except ImportError:  # pragma: no cover - very old Scapy builds
        IPv6 = None  # type: ignore[assignment]

    # HTTP lives in an optional Scapy layer, so import it defensively.
    try:
        from scapy.layers.http import HTTP, HTTPRequest  # noqa: E402
    except ImportError:  # pragma: no cover - depends on the Scapy build
        HTTP = HTTPRequest = None  # type: ignore[assignment]

    # ── Counters for everything we want to report ──────────────────
    protocol_counts: Counter[str] = Counter({"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0})
    src_counter: Counter[str] = Counter()
    dst_counter: Counter[str] = Counter()
    sport_counter: Counter[int] = Counter()
    dport_counter: Counter[int] = Counter()
    dns_domain_counter: Counter[str] = Counter()
    http_host_counter: Counter[str] = Counter()
    flag_counts: Counter[str] = Counter({"SYN": 0, "ACK": 0, "SYN-ACK": 0,
                                         "RST": 0, "FIN": 0, "PSH": 0})
    icmp_total = 0
    dns_total = 0
    http_total = 0
    total_bytes = 0

    # Which (source IP -> destination port) pairs were seen. Used later to
    # recognise a port scan: many different ports from one host.
    dports_by_src: Dict[str, Set[int]] = defaultdict(set)

    # Sources that sent a SYN and the destinations that received a SYN-ACK.
    # NOTE: a SYN-ACK's *source* is the responder, so attributing it to the
    # source would never cancel the original SYN. We therefore count SYN-ACKs
    # by *destination* (the original SYN sender) to compute unanswered SYNs.
    syn_by_src: Counter[str] = Counter()
    synack_by_dst: Counter[str] = Counter()

    first_seen: float | None = None
    last_seen: float | None = None

    # ── The main loop: one pass, no packets read twice ─────────────
    for pkt in packets:
        # --- Size ---
        # len(pkt) is the captured frame length, which is what Wireshark
        # shows as "Frame size".
        total_bytes += len(pkt)

        # --- Capture window (used to show the duration) ---
        stamp = _safe_float(getattr(pkt, "time", None))
        if stamp > 0:
            if first_seen is None or stamp < first_seen:
                first_seen = stamp
            if last_seen is None or stamp > last_seen:
                last_seen = stamp

        # --- Protocol classification ---
        # Order matters: TCP/UDP are checked before ICMP so a packet that
        # carries several layers is counted under the most specific one.
        if pkt.haslayer(TCP):
            protocol_counts["TCP"] += 1
        elif pkt.haslayer(UDP):
            protocol_counts["UDP"] += 1
        elif pkt.haslayer(ICMP):
            protocol_counts["ICMP"] += 1
            icmp_total += 1
        else:
            protocol_counts["Other"] += 1

        # --- Addresses and ports (IPv4 *and* IPv6; skip ARP etc.) ---
        # BUGFIX: the old code used `if not pkt.haslayer(IP): continue`,
        # which silently dropped ALL IPv6 traffic (YouTube/Google/Instagram
        # are heavily IPv6). Protocol counts still went up (they run before
        # this check) so users saw "193 TCP packets" but zero TCP flags.
        src = dst = None
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
        elif IPv6 is not None and pkt.haslayer(IPv6):
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
        if src is None:
            continue
        src_counter[src] += 1
        dst_counter[dst] += 1

        # --- TCP details ---
        if pkt.haslayer(TCP):
            dport = _safe_int(pkt[TCP].dport)
            sport = _safe_int(pkt[TCP].sport)
            if dport > 0:
                dport_counter[dport] += 1
                dports_by_src[src].add(dport)
            if sport > 0:
                sport_counter[sport] += 1

            # BUGFIX: count every flag independently. The old
            # if-SYN/else-ACK structure undercounted ACK (SYN-ACKs were
            # never counted as ACK) and dropped RST/FIN/PSH whenever SYN
            # was set. Independent bit tests match Wireshark semantics.
            flags = _safe_int(pkt[TCP].flags)
            if flags < 0:
                # Scapy may expose flags as a FlagValue/str on odd packets;
                # fall back to string inspection instead of losing the pkt.
                raw_flags = str(pkt[TCP].flags).upper()
                is_syn = "S" in raw_flags
                is_ack = "A" in raw_flags
                has_rst = "R" in raw_flags
                has_fin = "F" in raw_flags
                has_psh = "P" in raw_flags
            else:
                is_syn = bool(flags & 0x02)   # SYN
                is_ack = bool(flags & 0x10)   # ACK
                has_rst = bool(flags & 0x04)  # RST
                has_fin = bool(flags & 0x01)  # FIN
                has_psh = bool(flags & 0x08)  # PSH
            if is_syn:
                flag_counts["SYN"] += 1
                syn_by_src[src] += 1
            if is_ack:
                flag_counts["ACK"] += 1
            if is_syn and is_ack:
                flag_counts["SYN-ACK"] += 1
                # SYN-ACK goes responder -> originator, so credit the
                # *destination* (the host being answered).
                if dst is not None:
                    synack_by_dst[dst] += 1
            if has_rst:
                flag_counts["RST"] += 1
            if has_fin:
                flag_counts["FIN"] += 1
            if has_psh:
                flag_counts["PSH"] += 1

        # --- UDP details ---
        elif pkt.haslayer(UDP):
            dport = _safe_int(pkt[UDP].dport)
            sport = _safe_int(pkt[UDP].sport)
            if dport > 0:
                dport_counter[dport] += 1
                dports_by_src[src].add(dport)
            if sport > 0:
                sport_counter[sport] += 1

        # --- DNS: only count real questions (qr == 0) ---
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            reply_bit = _safe_int(pkt[DNS].qr)
            if reply_bit == 0:
                dns_total += 1
                # qname is bytes like b"example.com." - decode it safely.
                # Lower-case so `YouTube.com` and `youtube.com` group together.
                qname = _clean_text(pkt[DNSQR].qname or b"").lower()
                if qname:
                    dns_domain_counter[qname] += 1

        # --- HTTP: counts clear-text web requests (a privacy concern) ---
        if HTTP is not None and HTTPRequest is not None and pkt.haslayer(HTTPRequest):
            http_total += 1
            host = pkt[HTTPRequest].Host
            if host:
                # Scapy hands us bytes (b"example.com"), so normalise to text.
                http_host_counter[_clean_text(host)] += 1

    # ── Derived values ─────────────────────────────────────────────
    duration = (last_seen - first_seen) if (first_seen and last_seen) else 0.0

    # A SYN that was never answered with a SYN-ACK is a strong hint of a
    # half-open connection: exactly what a SYN flood looks like.
    # Fixed: compare SYNs sent by IP vs SYN-ACKs *received* by that IP.
    unanswered_syns = {
        ip: count - synack_by_dst.get(ip, 0)
        for ip, count in syn_by_src.items()
        if count - synack_by_dst.get(ip, 0) > 0
    }

    top = config.TOP_N
    dns_limit = getattr(config, "DNS_DISPLAY_LIMIT", 10)
    ephemeral_start = getattr(config, "EPHEMERAL_PORT_START", 32768)

    # ── DNS insights: tagged top list, base-domain grouping, services ──
    all_dns = dict(dns_domain_counter)
    top_dns_extended = dns_domain_counter.most_common(dns_limit)
    # (domain, count, service) for display - service "" means "other/unknown".
    dns_tagged = [(dom, cnt, service_for_domain(dom))
                  for dom, cnt in top_dns_extended]
    # Group rotating CDN subdomains: googlevideo.com: 12 instead of
    # 12× one-off `rr1---sn-*.googlevideo.com` rows.
    base_counter: Counter[str] = Counter()
    for dom, cnt in dns_domain_counter.items():
        base_counter[base_domain(dom)] += cnt
    top_dns_base = base_counter.most_common(dns_limit)
    service_dns_counter: Counter[str] = Counter()
    for dom, cnt in dns_domain_counter.items():
        svc = service_for_domain(dom)
        if svc:
            service_dns_counter[svc] += cnt
    # Detected services: ranked by DNS evidence, with example domain.
    # e.g. [{"service": "YouTube", "dns_queries": 12, "example": "..."}]
    _example: Dict[str, str] = {}
    for dom, _ in dns_domain_counter.most_common():
        svc = service_for_domain(dom)
        if svc and svc not in _example:
            _example[svc] = dom
    detected_services = [
        {"service": svc, "dns_queries": cnt, "example": _example.get(svc, "")}
        for svc, cnt in service_dns_counter.most_common()
    ]

    # ── Port insights: split service ports from ephemeral return traffic ──
    all_dports = dict(dport_counter)
    service_port_counts = {p: c for p, c in dport_counter.items()
                           if p < ephemeral_start}
    ephemeral_port_total = sum(c for p, c in dport_counter.items()
                               if p >= ephemeral_start)
    service_port_total = sum(service_port_counts.values())
    top_service_ports = sorted(service_port_counts.items(),
                               key=lambda kv: kv[1], reverse=True)[:top]
    # Per-port share of *all* packets carrying a dst port (for the % column).
    _dport_pkts = sum(dport_counter.values()) or 1

    return {
        # Overview
        "total_packets": len(packets),
        "total_bytes": total_bytes,
        "avg_packet_size": round(total_bytes / len(packets), 2) if packets else 0.0,
        "first_seen": first_seen or 0.0,
        "last_seen": last_seen or 0.0,
        "duration_seconds": duration,
        # Protocols
        "protocol_counts": dict(protocol_counts),
        "icmp_total": icmp_total,
        # Talkers
        "top_src_ips": src_counter.most_common(top),
        "top_dst_ips": dst_counter.most_common(top),
        "top_src_ports": sport_counter.most_common(top),
        "top_dst_ports": dport_counter.most_common(top),
        "unique_src_ips": len(src_counter),
        "unique_dst_ips": len(dst_counter),
        # Application layer (legacy keys kept for compat)
        "dns_total": dns_total,
        "top_dns_domains": dns_domain_counter.most_common(top),
        "http_total": http_total,
        "top_http_hosts": http_host_counter.most_common(top),
        # Application layer - enriched DNS insights
        "dns_unique": len(dns_domain_counter),
        "all_dns_domains": all_dns,
        "top_dns_extended": top_dns_extended,
        "dns_tagged": dns_tagged,
        "top_dns_base": top_dns_base,
        "service_dns_counts": dict(service_dns_counter),
        "detected_services": detected_services,
        # Port insights - clean service view + ephemeral accounting
        "all_dst_port_counts": all_dports,
        "top_service_ports": top_service_ports,
        "service_port_total": service_port_total,
        "ephemeral_port_total": ephemeral_port_total,
        "ephemeral_port_start": ephemeral_start,
        # TCP behaviour
        "tcp_flag_counts": dict(flag_counts),
        "unanswered_syns": unanswered_syns,
        # Full counters - the anomaly engine needs every value, not only
        # the top N rows that are printed on screen.
        "all_src_counts": dict(src_counter),
        "all_src_port_counts": dict(sport_counter),
        "all_sport_counts": dict(sport_counter),
        "dports_by_src": {ip: set(ports) for ip, ports in dports_by_src.items()},
    }


def summarize_stats(stats: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Flatten the main numbers into ``(label, value)`` pairs.

    Handy for reports and for a quick one-line summary.

    Args:
        stats: Dictionary returned by :func:`compute_stats`.

    Returns:
        List of ``(label, value)`` tuples, already formatted as strings.
    """
    from analyzer.utils import human_bytes, human_duration

    protocols = stats.get("protocol_counts", {})
    return [
        ("Total packets", str(stats.get("total_packets", 0))),
        ("Total size", human_bytes(stats.get("total_bytes", 0))),
        ("Avg packet size", f"{stats.get('avg_packet_size', 0)} B"),
        ("Duration", human_duration(stats.get("duration_seconds", 0))),
        ("TCP packets", str(protocols.get("TCP", 0))),
        ("UDP packets", str(protocols.get("UDP", 0))),
        ("ICMP packets", str(protocols.get("ICMP", 0))),
        ("Unique sources", str(stats.get("unique_src_ips", 0))),
        ("Unique destinations", str(stats.get("unique_dst_ips", 0))),
        ("DNS queries", str(stats.get("dns_total", 0))),
        ("HTTP requests", str(stats.get("http_total", 0))),
    ]
