"""Rule-based anomaly detection - simple enough to read in one sitting.

Each rule compares the numbers produced by :func:`analyzer.stats.compute_stats`
against the thresholds defined in ``config.py`` and returns
:class:`Finding` objects with a severity level.

Why rules instead of machine learning?
-------------------------------------
Because rules are explainable: every warning tells you *which* threshold
was crossed and *why* it matters. That is exactly what you want while
learning, and it is fast enough for millions of packets.

Adding a new rule is three steps:

1. Write a function ``_rule_xxx(stats) -> list[Finding]``.
2. Call it from :func:`detect_anomalies`.
3. Add the matching thresholds to ``config.py``.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

import config
from analyzer.utils import format_port

# Maximum findings a single rule may contribute. Anything above that is
# counted and reported as one extra "(+N more)" line, so nothing is hidden.
_LIMIT = config.MAX_FINDINGS_PER_RULE


@dataclass(frozen=True)
class Finding:
    """One suspicious observation about a capture.

    Attributes:
        rule: Short machine-friendly id, e.g. ``"PORT_SCAN"``.
        severity: One of ``config.SEVERITY_ORDER``.
        message: Full, human-readable explanation shown to the user.
    """

    rule: str
    severity: str
    message: str

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return f"[{self.severity:<8}] {self.message}"


# ═══════════════════════════════════════════════════════════════════
#  Individual rules
# ═══════════════════════════════════════════════════════════════════

def _rule_empty_capture(stats: Dict[str, Any]) -> List[Finding]:
    """Flag a capture that contains no packets at all.

    An empty capture almost always means the *capture* failed, not that the
    network was silent. The message therefore points at the two usual
    culprits: capturing on the wrong (or down) interface, and forgetting to
    generate traffic while tcpdump was running.
    """
    if stats.get("total_packets", 0) == 0:
        return [Finding(
            rule="EMPTY_CAPTURE",
            severity="INFO",
            message=("The capture contains 0 packets, so there is nothing to "
                     "analyse. Usual causes: captured on the wrong interface "
                     "(run 'ip -br link' and 'ip route get 1.1.1.1', then "
                     "repeat with -i on a real interface - never -i any), or "
                     "no traffic was generated while tcpdump was running."),
        )]
    return []


def _rule_high_volume(stats: Dict[str, Any]) -> List[Finding]:
    """One source IP sending an unusual number of packets."""
    threshold = config.MAX_PACKETS_FROM_SINGLE_IP
    # Sort by volume so the worst offender is reported first.
    offenders = sorted(stats.get("all_src_counts", {}).items(),
                       key=lambda pair: pair[1], reverse=True)
    hits = [Finding(
        rule="HIGH_VOLUME",
        severity="HIGH",
        message=(f"High packet volume: {ip} sent {count} packets "
                 f"(threshold: {threshold}). Possible port scan, flood or "
                 f"simply a very busy host."),
    ) for ip, count in offenders if count > threshold]
    return hits[:_LIMIT]


def _rule_unusual_port(stats: Dict[str, Any]) -> List[Finding]:
    """Traffic aimed at ports outside ``config.ALLOWED_PORTS``.

    Real-capture tuning (fixes false-positive storm on eth0 browsing):
    1. Ports >= ``EPHEMERAL_PORT_START`` are return traffic (server -> client
       ephemeral port such as 39432, 57243), not services - skip them.
    2. A port also seen as a *source* port elsewhere in the same capture is
       almost certainly a local client port - skip it.
    3. Ports with fewer than ``UNUSUAL_PORT_MIN_PACKETS`` packets are stray
       retransmits/probes - skip them to cut noise.
    Remaining offenders are real services on unexpected ports and stay MEDIUM.
    All offenders are returned; :func:`detect_anomalies` trims for display.
    """
    allowed = set(config.ALLOWED_PORTS)
    ephemeral_start = getattr(config, "EPHEMERAL_PORT_START", 32768)
    min_packets = getattr(config, "UNUSUAL_PORT_MIN_PACKETS", 3)
    src_ports = set(stats.get("all_src_port_counts",
                              stats.get("all_sport_counts", {})).keys())
    # Back-compat: older stats dicts used "all_sport_counts".
    if not src_ports and "all_sport_counts" in stats:
        src_ports = set(stats["all_sport_counts"].keys())
    findings: List[Finding] = []
    for port, count in sorted(stats.get("all_dst_port_counts", {}).items(),
                              key=lambda pair: pair[1], reverse=True):
        try:
            port_num = int(port)
        except (TypeError, ValueError):
            continue
        if port_num in allowed:
            continue
        if port_num >= ephemeral_start:
            # Normal return traffic: e.g. YouTube server -> client:39432.
            continue
        if port_num in src_ports:
            # We also sent *from* this port: it is a local ephemeral port
            # reused across flows, not a remote service.
            continue
        if count < min_packets:
            continue
        hint = _port_hint(port_num)
        findings.append(Finding(
            rule="UNUSUAL_PORT",
            severity="MEDIUM",
            message=(f"Unusual port: {count} packet(s) to {format_port(port_num)}. "
                     f"Not in the allowed list. {hint}"),
        ))
    return findings


def _rule_excessive_dns(stats: Dict[str, Any]) -> List[Finding]:
    """An unusual number of DNS questions in one capture."""
    dns_total = int(stats.get("dns_total", 0))
    if dns_total <= config.MAX_DNS_QUERIES:
        return []

    top_domains = ", ".join(domain for domain, _ in
                            stats.get("top_dns_domains", [])[:3]) or "n/a"
    return [Finding(
        rule="EXCESSIVE_DNS",
        severity="HIGH",
        message=(f"Excessive DNS queries: {dns_total} questions "
                 f"(threshold: {config.MAX_DNS_QUERIES}). Possible DNS "
                 f"tunnelling or DGA malware. Most asked: {top_domains}"),
    )]


def _rule_port_scan(stats: Dict[str, Any]) -> List[Finding]:
    """One host contacting many *different* ports - classic scanning.

    Real-capture tuning: ephemeral return ports (>= EPHEMERAL_PORT_START)
    are excluded before counting. Without this, a busy server (YouTube,
    Instagram) that answers many client ephemeral ports looks like a
    scanner. Only service-like ports count toward the threshold.
    All scan candidates are returned; :func:`detect_anomalies` trims.
    """
    threshold = config.MAX_DISTINCT_PORTS_PER_IP
    ephemeral_start = getattr(config, "EPHEMERAL_PORT_START", 32768)
    findings: List[Finding] = []
    for ip, ports in stats.get("dports_by_src", {}).items():
        service_ports = {p for p in ports
                         if _safe_port(p) < ephemeral_start}
        if len(service_ports) <= threshold:
            continue
        sample = ", ".join(format_port(p) for p in sorted(service_ports)[:5])
        findings.append(Finding(
            rule="PORT_SCAN",
            severity="CRITICAL",
            message=(f"Possible port scan: {ip} contacted {len(service_ports)} "
                     f"different service ports (threshold: {threshold}) - {sample}"),
        ))
    return findings


def _safe_port(port: Any) -> int:
    """Return port as int, or a large sentinel so it is treated as ephemeral."""
    try:
        return int(port)
    except (TypeError, ValueError):
        return 10 ** 9


def _rule_syn_flood(stats: Dict[str, Any]) -> List[Finding]:
    """Many SYNs that were never answered - half-open connection flood."""
    threshold = config.SYN_FLOOD_THRESHOLD
    unanswered: Dict[str, int] = stats.get("unanswered_syns", {})
    findings: List[Finding] = []
    for ip, count in sorted(unanswered.items(), key=lambda pair: pair[1],
                            reverse=True):
        if count <= threshold:
            continue
        findings.append(Finding(
            rule="SYN_FLOOD",
            severity="CRITICAL",
            message=(f"SYN flood pattern: {ip} sent {count} SYN packet(s) "
                     f"with no matching SYN-ACK (threshold: {threshold})."),
        ))
    return findings


def _rule_icmp_flood(stats: Dict[str, Any]) -> List[Finding]:
    """A lot of ICMP in one capture - ping sweep or flood."""
    icmp_total = int(stats.get("icmp_total", 0))
    if icmp_total <= config.ICMP_FLOOD_THRESHOLD:
        return []
    return [Finding(
        rule="ICMP_FLOOD",
        severity="MEDIUM",
        message=(f"High ICMP volume: {icmp_total} ICMP packets "
                 f"(threshold: {config.ICMP_FLOOD_THRESHOLD}). Possible "
                 f"ping sweep, DoS attempt or a reachability check."),
    )]


def _rule_plaintext_http(stats: Dict[str, Any]) -> List[Finding]:
    """HTTP requests are unencrypted - worth knowing, not necessarily bad."""
    http_total = int(stats.get("http_total", 0))
    if http_total == 0:
        return []
    hosts = ", ".join(host for host, _ in
                      stats.get("top_http_hosts", [])[:3]) or "unknown host"
    return [Finding(
        rule="PLAINTEXT_HTTP",
        severity="LOW",
        message=(f"Clear-text HTTP: {http_total} request(s) visible in the "
                 f"capture (hosts: {hosts}). Traffic can be read by anyone "
                 f"on the path - prefer HTTPS."),
    )]


# ═══════════════════════════════════════════════════════════════════
#  Engine
# ═══════════════════════════════════════════════════════════════════

def _rule_browsing_profile(stats: Dict[str, Any]) -> List[Finding]:
    """Summarise recognised browsing services as INFO (not a threat).

    Turns a real eth0 capture into a meaningful sentence: "YouTube (12 DNS),
    Google (8 DNS), WhatsApp..." instead of silence. INFO severity, so it
    never changes the verdict - it just makes clean reports useful.
    """
    services = stats.get("detected_services", [])
    if not services:
        return []
    summary = ", ".join(
        f"{entry['service']} ({entry['dns_queries']} DNS)"
        for entry in services[:5]
    )
    return [Finding(
        rule="BROWSING_PROFILE",
        severity="INFO",
        message=(f"Browsing profile: {summary}. "
                 f"This matches normal user activity, not an attack."),
    )]


# All rules, in the order they run. ``detect_anomalies`` simply loops.
RULES: Dict[str, Callable[[Dict[str, Any]], List[Finding]]] = {
    "EMPTY_CAPTURE": _rule_empty_capture,
    "HIGH_VOLUME": _rule_high_volume,
    "UNUSUAL_PORT": _rule_unusual_port,
    "EXCESSIVE_DNS": _rule_excessive_dns,
    "PORT_SCAN": _rule_port_scan,
    "SYN_FLOOD": _rule_syn_flood,
    "ICMP_FLOOD": _rule_icmp_flood,
    "PLAINTEXT_HTTP": _rule_plaintext_http,
    "BROWSING_PROFILE": _rule_browsing_profile,
}


def _port_hint(port: int) -> str:
    """Return a short 'what is this usually?' hint for an unknown port."""
    known_well_known = {
        4444: "4444 is the default Metasploit handler port - check for a "
              "backdoor if you do not run pentest tooling.",
        6667: "6667 is IRC - often seen with botnets and command-and-control.",
        8080: "8080 is a common alternative HTTP proxy port.",
        8443: "8443 is a common alternative HTTPS port.",
        5222: "5222 is XMPP / WhatsApp messaging - normal if you use chat apps.",
        5228: "5228 is Google push / Firebase Cloud Messaging - normal on Android.",
        3478: "3478 is STUN (NAT traversal for calls/video) - normal for meets.",
        5349: "5349 is TURN over TLS (relay for calls) - normal for meets.",
        5353: "5353 is mDNS - normal LAN service discovery.",
        1900: "1900 is SSDP/UPnP discovery - normal LAN chatter.",
        19302: "19302 is Google voice/video (STUN) - normal for Meet/YouTube calls.",
    }
    if port in known_well_known:
        return known_well_known[port]
    ephemeral_start = getattr(config, "EPHEMERAL_PORT_START", 32768)
    if port >= ephemeral_start:
        return "Ephemeral client port - usually normal return traffic."
    if 1024 < port < ephemeral_start:
        return "Registered port - could be a custom application."
    return "Well-known port - verify the service is expected."


def detect_anomalies(stats: Dict[str, Any]) -> List[Finding]:
    """Run every rule against the statistics of one capture.

    Args:
        stats: Dictionary returned by
            :func:`analyzer.stats.compute_stats`.

    Returns:
        Findings sorted from most to least severe. An empty list means
        "nothing crossed a threshold", which is the healthy result.

        If one rule produced more than ``config.MAX_FINDINGS_PER_RULE``
        findings, an extra ``INFO`` finding reports how many were left out,
        so a truncated list is never confused with "all is well".
    """
    findings: List[Finding] = []
    hidden: Dict[str, int] = {}

    for rule_name, rule in RULES.items():
        produced = rule(stats)
        if len(produced) > _LIMIT:
            hidden[rule_name] = len(produced) - _LIMIT
        findings.extend(produced[:_LIMIT])

    # Tell the user what was cut, and where to change the limit.
    for rule_name, count in hidden.items():
        findings.append(Finding(
            rule=f"{rule_name}_TRUNCATED",
            severity="INFO",
            message=(f"{count} more {rule_name} finding(s) were not listed. "
                     f"Raise MAX_FINDINGS_PER_RULE in config.py to see them."),
        ))

    # Most severe first; stable within the same severity.
    order = {level: index for index, level in enumerate(config.SEVERITY_ORDER)}
    findings.sort(key=lambda f: order.get(f.severity, len(order)))
    return findings


def severity_counts(findings: List[Finding]) -> Dict[str, int]:
    """Count how many findings there are per severity level.

    Args:
        findings: List returned by :func:`detect_anomalies`.

    Returns:
        Dict such as ``{"CRITICAL": 1, "LOW": 2}`` (zero levels omitted).
    """
    counter: Counter[str] = Counter(f.severity for f in findings)
    return dict(counter)


def highest_severity(findings: List[Finding]) -> str:
    """Return the most serious level present, or ``"NONE"`` when clean.

    Args:
        findings: List returned by :func:`detect_anomalies`.

    Returns:
        One of ``config.SEVERITY_ORDER`` or ``"NONE"``.
    """
    if not findings:
        return "NONE"
    order = {level: index for index, level in enumerate(config.SEVERITY_ORDER)}
    return min((f.severity for f in findings),
               key=lambda level: order.get(level, len(order)))


def verdict_for(findings: List[Finding]) -> str:
    """Turn a list of findings into the one-line verdict used in reports.

    Args:
        findings: List returned by :func:`detect_anomalies`.

    Returns:
        A short verdict string, e.g. ``"CRITICAL - immediate review"``.
    """
    level = highest_severity(findings)
    total = len(findings)
    if level == "NONE":
        return "CLEAN - no anomalies detected"
    label = {
        "CRITICAL": "CRITICAL - review immediately",
        "HIGH": "SUSPICIOUS - strong indicators found",
        "MEDIUM": "SUSPICIOUS - needs a closer look",
        "LOW": "LOW RISK - informational only",
        "INFO": "INFO - nothing to act on",
    }.get(level, "REVIEW - see findings")
    return f"{label} ({total} finding{'s' if total != 1 else ''})"
