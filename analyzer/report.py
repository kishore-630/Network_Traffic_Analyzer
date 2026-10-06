"""Report writers: a professional text report and a machine-friendly CSV.

Both writers use the *same* statistics dictionary, so the numbers in the
report always match what you saw on screen.

Why no colors here?
-------------------
A saved file should stay readable in a text editor, in a mail or in a ticketing
system. All styling is therefore done with plain ASCII/Unicode characters, and
the tables are aligned with ``tabulate`` (which is perfect here because no ANSI
escape codes are involved).

Output files
------------
* ``reports/report_<timestamp>.txt``  - human readable, boxed, with a verdict
* ``output/summary_<timestamp>.csv``  - one ``section,metric,value`` row per fact
"""

from __future__ import annotations

import csv
import os
from typing import Any, Dict, List, Sequence

from tabulate import tabulate

import config
from analyzer.anomalies import (
    Finding,
    severity_counts,
    verdict_for,
)
from analyzer.stats import summarize_stats
from analyzer.utils import (
    format_port,
    get_timestamp,
    human_bytes,
    truncate,
    wrap_text,
)

# Box drawing characters used in the report (files are always UTF-8, so these
# are safe even on a machine with an old console code page).
BOX = {
    "tl": "╔", "tr": "╗", "bl": "╚", "br": "╝",
    "hline": "═", "tline": "─", "vline": "│",
    "tjoin": "╦", "bjoin": "╩", "hjoin": "╪",
    "sep_l": "╠", "sep_r": "╣",
}

WIDTH = 100  # inside characters of the report box / divider lines
FINDING_WRAP = 63  # column width of the "Finding" cell in the report


# ═══════════════════════════════════════════════════════════════════
#  Small formatting helpers
# ═══════════════════════════════════════════════════════════════════

def _title_box(title: str) -> List[str]:
    """Return the boxed report title as a list of lines.

    Args:
        title: Text placed in the middle of the box.

    Returns:
        Lines that can be written straight to a file.
    """
    line = BOX["hline"] * WIDTH
    inner = f"  {title}".ljust(WIDTH - 2)
    return [
        BOX["tl"] + line + BOX["tr"],
        BOX["vline"] + inner + BOX["vline"],
        BOX["bl"] + line + BOX["br"],
    ]


def _section(number: str, title: str) -> List[str]:
    """Return the heading of a numbered report section."""
    return ["", f"{number} {title}", BOX["tline"] * WIDTH]


def _kv_table(rows: Sequence[Sequence[Any]]) -> str:
    """Render ``label / value`` rows as a clean two-column list.

    ``tablefmt="plain"`` means no separator lines, which looks tidier inside
    a bordered report than the default ``simple`` style.
    """
    return tabulate(rows, tablefmt="plain",
                    colalign=("left", "right"),
                    disable_numparse=True)


def _grid_table(rows: Sequence[Sequence[Any]], headers: Sequence[str]) -> str:
    """Render a bordered table for the report."""
    return tabulate(rows, headers=list(headers), tablefmt="grid")


# ═══════════════════════════════════════════════════════════════════
#  Text report
# ═══════════════════════════════════════════════════════════════════

def build_text_report(pcap_path: str, stats: Dict[str, Any],
                      findings: List[Finding], timestamp: str) -> str:
    """Build the full text report as a single string.

    Args:
        pcap_path: Capture file that was analysed.
        stats: Result of :func:`analyzer.stats.compute_stats`.
        findings: Result of :func:`analyzer.anomalies.detect_anomalies`.
        timestamp: Timestamp used in the file name (see
            :func:`analyzer.utils.get_timestamp`).

    Returns:
        The report content, ready to be written to disk.
    """
    out: List[str] = []
    out.extend(_title_box(f"{config.TOOL_NAME.upper()} - ANALYSIS REPORT"))
    out.append("")
    out.append(f"  File analysed : {pcap_path}")
    if os.path.isfile(pcap_path):
        size = human_bytes(os.path.getsize(pcap_path))
        out.append(f"  File size     : {size}")
    out.append(f"  Generated at  : {timestamp}")
    out.append(f"  Tool version  : {config.TOOL_NAME} v{config.TOOL_VERSION}")
    out.append(f"  Verdict       : {verdict_for(findings)}")
    out.append("")

    # ── 01 · Overview ────────────────────────────────────────────
    out.extend(_section("01", "TRAFFIC OVERVIEW"))
    overview = summarize_stats(stats)
    out.append(_kv_table(overview))
    out.append("")

    # ── 02 · Protocols ───────────────────────────────────────────
    out.extend(_section("02", "PROTOCOL BREAKDOWN"))
    out.append(_grid_table(
        [[proto, count, _percent(count, stats["total_packets"])]
         for proto, count in stats["protocol_counts"].items()],
        ["Protocol", "Packets", "Share"],
    ))
    out.append("")

    # ── 03 · Talkers ─────────────────────────────────────────────
    out.extend(_section("03", "TOP TALKERS"))
    talker_rows: List[List[Any]] = []
    for rank, (ip, count) in enumerate(stats["top_src_ips"], start=1):
        talker_rows.append([rank, "source", ip, count])
    for rank, (ip, count) in enumerate(stats["top_dst_ips"], start=1):
        talker_rows.append([rank, "destination", ip, count])
    out.append(_grid_table(talker_rows or [["-", "-", "-", 0]],
                           ["#", "Direction", "IP address", "Packets"]))
    out.append("")

    # ── 04 · Ports ───────────────────────────────────────────────
    out.extend(_section("04", "TOP SERVICE PORTS (EPHEMERAL FILTERED)"))
    svc_ports = stats.get("top_service_ports", stats.get("top_dst_ports", []))
    total_dport = sum(stats.get("all_dst_port_counts", {}).values()) or 1
    port_rows = [[rank, format_port(port), count,
                  f"{count / total_dport * 100:.1f}%"]
                 for rank, (port, count) in enumerate(svc_ports, start=1)]
    out.append(_grid_table(port_rows or [["-", "-", 0, "-"]],
                           ["#", "Port / service", "Packets", "Share"]))
    eph_total = stats.get("ephemeral_port_total", 0)
    eph_start = stats.get("ephemeral_port_start",
                          getattr(config, "EPHEMERAL_PORT_START", 32768))
    if eph_total:
        out.append(f"  Ephemeral return traffic: {eph_total} packet(s) to "
                   f"client ports >= {eph_start} (excluded above).")
    out.append("")

    # ── 05 · Applications ────────────────────────────────────────
    out.extend(_section("05", "APPLICATION LAYER"))
    app_rows: List[List[Any]] = [
        ["DNS queries", stats["dns_total"]],
        ["DNS unique domains", stats.get("dns_unique",
                                         len(stats.get("all_dns_domains", {})))],
        ["Clear-text HTTP requests", stats["http_total"]],
        ["TCP SYN packets", stats["tcp_flag_counts"].get("SYN", 0)],
        ["TCP RST packets", stats["tcp_flag_counts"].get("RST", 0)],
        ["Service-port packets", stats.get("service_port_total", "n/a")],
        ["Ephemeral-port packets", stats.get("ephemeral_port_total", "n/a")],
    ]
    out.append(_kv_table(app_rows))
    tagged = stats.get("dns_tagged") or [
        (d, c, "") for d, c in stats.get("top_dns_domains", [])]
    if tagged:
        out.append("")
        out.append("  Most queried domains (with service):")
        for domain, count, svc in tagged:
            label = svc if svc else "other"
            out.append(f"    - {truncate(domain, 50):<50} {count:<5} [{label}]")
    if stats.get("top_dns_base"):
        out.append("")
        out.append("  Grouped by base domain:")
        for domain, count in stats["top_dns_base"][:10]:
            out.append(f"    - {truncate(domain, 50):<50} {count}")
    services = stats.get("detected_services", [])
    if services:
        out.append("")
        out.append("  Detected browsing services (from DNS):")
        for entry in services:
            out.append(f"    - {entry['service']:<15} "
                       f"{entry['dns_queries']} queries "
                       f"(e.g. {truncate(entry.get('example', ''), 45)})")
    else:
        out.append("")
        out.append("  Detected services: none recognised "
                   "(generic traffic, direct IPs or DoH).")
    out.append("")

    # ── 06 · Findings ────────────────────────────────────────────
    out.extend(_section("06", "ANOMALY FINDINGS"))
    if not findings:
        out.append("  No anomalies detected - nothing crossed the configured")
        out.append("  thresholds.")
    else:
        finding_rows = [[index, f.severity, f.rule, wrap_text(f.message,
                                                              FINDING_WRAP)]
                        for index, f in enumerate(findings, start=1)]
        out.append(_grid_table(finding_rows,
                               ["#", "Severity", "Rule", "Finding"]))
        counts = severity_counts(findings)
        out.append("")
        out.append("  Severity breakdown: " + ", ".join(
            f"{level}={count}" for level, count in counts.items()))

    # ── Footer ───────────────────────────────────────────────────
    out.append("")
    out.append(BOX["tline"] * WIDTH)
    out.append("  Thresholds used for this run:")
    for name, value in config.describe_threshold_settings().items():
        out.append(f"    {name:<28} = {value}")
    out.append("")
    out.append("  Reminder: these rules are heuristics, not proof of an attack.")
    out.append("  Always correlate the findings with a known-good baseline and")
    out.append("  only analyse traffic you own or are authorised to analyse.")
    return "\n".join(out) + "\n"


def _percent(value: int, total: int) -> str:
    """Return ``value`` as a percentage string of ``total``."""
    if not total:
        return "0.0%"
    return f"{value / total * 100:.1f}%"


# ═══════════════════════════════════════════════════════════════════
#  CSV summary
# ═══════════════════════════════════════════════════════════════════

def build_csv_rows(stats: Dict[str, Any],
                   findings: List[Finding]) -> List[List[Any]]:
    """Build the rows of the CSV summary (header included).

    Every row is ``section, metric, value``. This "long" shape is easy to
    load into Excel, pandas or a SQL database and to filter afterwards.

    Args:
        stats: Result of :func:`analyzer.stats.compute_stats`.
        findings: Result of :func:`analyzer.anomalies.detect_anomalies`.

    Returns:
        List of rows, the first one being the header.
    """
    rows: List[List[Any]] = [["section", "metric", "value"]]

    for label, value in summarize_stats(stats):
        rows.append(["overview", label, value])

    for proto, count in stats["protocol_counts"].items():
        rows.append(["protocols", proto, count])

    for ip, count in stats["top_src_ips"]:
        rows.append(["top_src_ips", ip, count])

    for ip, count in stats["top_dst_ips"]:
        rows.append(["top_dst_ips", ip, count])

    for port, count in stats["top_dst_ports"]:
        rows.append(["top_dst_ports", f"port_{port}", count])

    for port, count in stats.get("top_service_ports", []):
        rows.append(["top_service_ports", f"port_{port}", count])
    rows.append(["ports", "service_port_packets",
                 stats.get("service_port_total", 0)])
    rows.append(["ports", "ephemeral_port_packets",
                 stats.get("ephemeral_port_total", 0)])

    for domain, count in stats["top_dns_domains"]:
        rows.append(["top_dns_domains", domain, count])

    for item in stats.get("dns_tagged", []):
        domain, count, svc = item[0], item[1], (item[2] if len(item) > 2 else "")
        rows.append(["dns_tagged", domain, f"{count} [{svc or 'other'}]"])

    for entry in stats.get("detected_services", []):
        rows.append(["services", entry.get("service", "unknown"),
                     f"{entry.get('dns_queries', 0)} queries "
                     f"(e.g. {entry.get('example', '')})"])

    rows.append(["anomalies", "anomaly_count", len(findings)])
    rows.append(["anomalies", "verdict", verdict_for(findings)])
    for level, count in severity_counts(findings).items():
        rows.append(["anomalies", f"severity_{level.lower()}", count])
    for index, finding in enumerate(findings, start=1):
        rows.append(["anomalies", f"finding_{index}",
                     f"{finding.severity} | {finding.rule} | {finding.message}"])
    return rows


# ═══════════════════════════════════════════════════════════════════
#  Writing to disk
# ═══════════════════════════════════════════════════════════════════

def save_text_report(pcap_path: str, stats: Dict[str, Any],
                     findings: List[Finding], timestamp: str) -> str:
    """Write the text report into ``config.REPORTS_FOLDER``.

    Args:
        pcap_path: Capture file that was analysed.
        stats: Result of :func:`analyzer.stats.compute_stats`.
        findings: Result of :func:`analyzer.anomalies.detect_anomalies`.
        timestamp: Timestamp used in the file name.

    Returns:
        Full path of the written file.

    Raises:
        OSError: The file could not be written (permissions, disk full...).
    """
    os.makedirs(config.REPORTS_FOLDER, exist_ok=True)
    report_path = os.path.join(config.REPORTS_FOLDER,
                               f"report_{timestamp}.txt")
    content = build_text_report(pcap_path, stats, findings, timestamp)
    with open(report_path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return report_path


def save_csv_summary(stats: Dict[str, Any],
                     findings: List[Finding], timestamp: str) -> str:
    """Write the CSV summary into ``config.OUTPUT_FOLDER``.

    Args:
        stats: Result of :func:`analyzer.stats.compute_stats`.
        findings: Result of :func:`analyzer.anomalies.detect_anomalies`.
        timestamp: Timestamp used in the file name.

    Returns:
        Full path of the written file.

    Raises:
        OSError: The file could not be written.
    """
    os.makedirs(config.OUTPUT_FOLDER, exist_ok=True)
    csv_path = os.path.join(config.OUTPUT_FOLDER, f"summary_{timestamp}.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        csv.writer(handle).writerows(build_csv_rows(stats, findings))
    return csv_path


def save_all(pcap_path: str, stats: Dict[str, Any],
             findings: List[Finding]) -> List[str]:
    """Write both the text report and the CSV summary.

    Args:
        pcap_path: Capture file that was analysed.
        stats: Result of :func:`analyzer.stats.compute_stats`.
        findings: Result of :func:`analyzer.anomalies.detect_anomalies`.

    Returns:
        ``[report_path, csv_path]`` in that order.

    Raises:
        OSError: One of the files could not be written.
    """
    timestamp = get_timestamp()
    return [
        save_text_report(pcap_path, stats, findings, timestamp),
        save_csv_summary(stats, findings, timestamp),
    ]
