"""Central configuration for the Network Traffic Analyzer.

EVERY tunable value lives in this file on purpose: a beginner only has to
open one place to change how the tool behaves, without touching the logic.

Nothing in this module imports Scapy, so it stays safe to import from tests
or any other tool.
"""

from __future__ import annotations

from typing import Dict, List

# ═══════════════════════════════════════════════════════════════════
#  1. Tool metadata (used in the banner and in every report header)
# ═══════════════════════════════════════════════════════════════════

TOOL_NAME: str = "Network Traffic Analyzer"
TOOL_VERSION: str = "2.1.0"
# Shown in the splash header, under the product name.
AUTHOR: str = "GURRALA KISHORE KUMAR"

MIN_PYTHON: str = "3.9"


# ═══════════════════════════════════════════════════════════════════
#  2. Folders (relative to the project root)
# ═══════════════════════════════════════════════════════════════════

OUTPUT_FOLDER: str = "output"
REPORTS_FOLDER: str = "reports"
PCAPS_FOLDER: str = "pcaps"


# ═══════════════════════════════════════════════════════════════════
#  3. Display options
# ═══════════════════════════════════════════════════════════════════

# How many rows to show in each "Top N" table.
TOP_N: int = 5

# Set to False if you want plain text with no colors (handy when piping
# the output into a file or a log collector).
USE_COLOR: bool = True


# ═══════════════════════════════════════════════════════════════════
#  4. Anomaly detection thresholds
# ═══════════════════════════════════════════════════════════════════

# A single source IP sending more than this many packets is suspicious.
# Typical value: 100 on a small LAN, 1000 on a busy gateway.
MAX_PACKETS_FROM_SINGLE_IP: int = 100

# More DNS lookups than this can mean DNS tunnelling or DGA malware.
MAX_DNS_QUERIES: int = 50

# A source IP that touches more than this many DIFFERENT destination ports
# in one capture is probably port-scanning.
MAX_DISTINCT_PORTS_PER_IP: int = 15

# More unanswered SYNs than this from one IP looks like a SYN flood.
SYN_FLOOD_THRESHOLD: int = 50

# More ICMP packets than this looks like a ping flood / reachability sweep.
ICMP_FLOOD_THRESHOLD: int = 30

# Ports considered "normal" for a typical workstation or web server.
# Anything else raises an UNUSUAL PORT warning (subject to the ephemeral
# and minimum-packet filters below, so normal return traffic stays quiet).
#   20 = FTP-DATA      22 = SSH        25 = SMTP
#   53 = DNS          80 = HTTP      123 = NTP
#  443 = HTTPS       993 = IMAPS    3306 = MySQL   3389 = RDP
# Plus real-world browsing essentials: DHCP, alt-web, push, STUN, mDNS...
ALLOWED_PORTS: List[int] = [
    20, 22, 25, 53, 67, 68, 80, 110, 123, 143, 161, 389, 443, 445,
    587, 993, 995, 1433, 3306, 3389, 5222, 5228, 3478, 5349, 5353,
    1900, 8080, 8443, 8883, 8000, 19302,
]

# Destination ports at/above this are treated as ephemeral client ports
# (return traffic), not services. Linux uses 32768-60999, Windows/macOS use
# 49152-65535 - so 32768 covers all of them. UNUSUAL_PORT skips these and
# PORT_SCAN excludes them from the distinct-port count.
EPHEMERAL_PORT_START: int = 32768

# Ignore a non-allowed port seen fewer times than this. A single stray
# packet (retransmit, probe, QUIC retry) is not worth a MEDIUM finding;
# real concerns (backdoor, tunnel) send sustained traffic.
UNUSUAL_PORT_MIN_PACKETS: int = 3

# How many individual findings of the same kind to print before summarizing.
# Keeps the output readable when a capture contains thousands of odd ports.
MAX_FINDINGS_PER_RULE: int = 5

# ── Real-browsing service map (DNS suffix → friendly service) ──
# Used for DNS tagging + "Detected services" insights. Suffix match, so
# `rr1---sn-xyz.googlevideo.com` maps to YouTube, `scontent.cdninstagram.com`
# maps to Instagram, etc. Order matters only for display, not matching.
SERVICE_DOMAINS: Dict[str, List[str]] = {
    "YouTube": ["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com"],
    "Google": ["google.com", "googleapis.com", "gstatic.com", "gmail.com",
               "googleusercontent.com", "gvt1.com", "gvt2.com"],
    "Instagram": ["instagram.com", "cdninstagram.com"],
    "Facebook/Meta": ["facebook.com", "fbcdn.net", "fb.com", "messenger.com",
                      "fbsbx.com"],
    "WhatsApp": ["whatsapp.com", "whatsapp.net"],
    "Cloudflare": ["cloudflare.com", "cloudflare-dns.com", "cloudflarestream.com"],
    "Microsoft": ["microsoft.com", "windowsupdate.com", "office.com",
                  "live.com", "msedge.net"],
    "Apple": ["apple.com", "icloud.com", "mzstatic.com"],
    "Netflix": ["netflix.com", "nflxvideo.net", "nflximg.net"],
    "Amazon/AWS": ["amazon.com", "amazonaws.com", "cloudfront.net"],
    "Akamai CDN": ["akamaihd.net", "akamaized.net", "edgesuite.net"],
}

# How many DNS rows to show in UI/report (TOP_N stays for talkers/ports).
DNS_DISPLAY_LIMIT: int = 10

# Friendly names shown next to ports in reports.
PORT_LABELS: Dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    137: "NetBIOS-NS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP-SUB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit-default",
    5900: "VNC",
    6667: "IRC",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}


# ═══════════════════════════════════════════════════════════════════
#  5. Severity levels
# ═══════════════════════════════════════════════════════════════════
#  Findings are sorted from most to least serious. Add your own level
#  here if you invent a new rule, then map it in analyzer/ui.py.

SEVERITY_ORDER: List[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def describe_threshold_settings() -> Dict[str, str]:
    """Return the active thresholds as strings (used in report footers).

    Returns:
        Mapping of setting name -> printable value.
    """
    return {
        "MAX_PACKETS_FROM_SINGLE_IP": str(MAX_PACKETS_FROM_SINGLE_IP),
        "MAX_DNS_QUERIES": str(MAX_DNS_QUERIES),
        "MAX_DISTINCT_PORTS_PER_IP": str(MAX_DISTINCT_PORTS_PER_IP),
        "SYN_FLOOD_THRESHOLD": str(SYN_FLOOD_THRESHOLD),
        "ICMP_FLOOD_THRESHOLD": str(ICMP_FLOOD_THRESHOLD),
        "ALLOWED_PORTS": ", ".join(str(p) for p in ALLOWED_PORTS),
        "EPHEMERAL_PORT_START": str(EPHEMERAL_PORT_START),
        "UNUSUAL_PORT_MIN_PACKETS": str(UNUSUAL_PORT_MIN_PACKETS),
    }
