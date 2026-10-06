"""Live (online) packet capture - the second half of the tool.

The analyzer has two modes:

* **offline** - read a ``.pcap`` that already exists on disk
  (:func:`analyzer.utils.load_pcap`),
* **online**  - record traffic straight from a network interface and analyze
  the packets in memory (:func:`capture_live`).

Both modes feed the *same* :func:`analyzer.stats.compute_stats` and
:func:`analyzer.anomalies.detect_anomalies`, so a live capture produces
exactly the same statistics, findings and reports as a saved file.

Recording is wrapped in :class:`LiveCaptureError` because Scapy signals
every kind of failure (missing Npcap/libpcap, no permission, unknown
interface, a broken BPF filter) with its own exception types. This module
turns all of them into one short message a beginner can act on.
"""

from __future__ import annotations

import os
from typing import Any, Callable, List, Optional, Tuple

import config

# Interfaces that exist on Linux but are not a real network card. Recording
# on them is the classic source of an empty capture, so the tool warns.
VIRTUAL_INTERFACES = {"any", "lo", "loopback"}


class LiveCaptureError(Exception):
    """Raised when a live capture cannot start or cannot finish.

    Same reasoning as :class:`analyzer.utils.PcapError`: the module raises,
    and ``main.py`` decides how the message looks on screen.
    """


# ═══════════════════════════════════════════════════════════════════
#  Finding an interface
# ═══════════════════════════════════════════════════════════════════

def list_interfaces() -> List[Tuple[str, str]]:
    """List the network interfaces Scapy can see on this machine.

    Returns:
        A list of ``(name, description)`` pairs, sorted by name. Empty when
        Scapy is not installed.
    """
    try:
        from scapy.all import conf
    except ImportError:
        return []

    try:
        names = sorted(conf.ifaces.keys())
    except Exception:  # noqa: BLE001 - platform specific failures
        return []

    found: List[Tuple[str, str]] = []
    for name in names:
        try:
            description = conf.ifaces[name].description or ""
        except Exception:  # noqa: BLE001 - some interfaces have no desc
            description = ""
        found.append((name, description))
    return found


def format_interface_list(interfaces: List[Tuple[str, str]]) -> str:
    """Render the interface list as aligned ``name  description`` lines.

    Args:
        interfaces: Pairs as returned by :func:`list_interfaces`.

    Returns:
        One line per interface, ready to print.
    """
    if not interfaces:
        return "    (none reported by the operating system)"

    width = max(len(name) for name, _ in interfaces)
    return "\n".join(f"    {name.ljust(width)}  {desc}".rstrip()
                     for name, desc in interfaces)


def resolve_interface(interface: str) -> str:
    """Check that ``interface`` exists before Scapy tries to open it.

    Args:
        interface: Interface name typed by the user, e.g. ``eth0``.

    Returns:
        The same interface name.

    Raises:
        LiveCaptureError: The interface does not exist, or no interfaces
            were reported at all.
    """
    interfaces = list_interfaces()
    names = [name for name, _ in interfaces]

    if not interfaces:
        raise LiveCaptureError(
            "The operating system reported no network interface. Scapy needs "
            "Npcap (Windows) or libpcap (Linux/macOS) to capture live traffic."
        )
    if interface not in names:
        listed = ", ".join(names)
        raise LiveCaptureError(
            f"No such interface: '{interface}'.\n"
            f"    Interfaces available: {listed}"
        )
    return interface


# ═══════════════════════════════════════════════════════════════════
#  Recording
# ═══════════════════════════════════════════════════════════════════

def capture_live(
    interface: str,
    count: int = config.LIVE_DEFAULT_COUNT,
    timeout: int = config.LIVE_DEFAULT_TIMEOUT,
    bpf_filter: Optional[str] = None,
    on_packet: Optional[Callable[[int, int], None]] = None,
) -> List[Any]:
    """Record packets from ``interface`` and return them as a list.

    Recording stops on whichever comes first: ``count`` packets, ``timeout``
    seconds of silence, or ``Ctrl+C``.

    Args:
        interface: Real interface name, e.g. ``eth0`` or ``en0``.
        count: Stop after this many packets (``0`` = no limit).
        timeout: Stop after this many seconds without traffic
            (``0`` = no time limit).
        bpf_filter: Optional tcpdump-style filter, e.g. ``"port 443"``.
        on_packet: Called as ``on_packet(seen, total)`` for every packet,
            so the terminal can show a live progress counter.

    Returns:
        The captured packets, in the order they arrived. May be empty - a
        quiet interface legitimately produces nothing.

    Raises:
        LiveCaptureError: Scapy is missing, the interface cannot be
            opened (usually a permissions problem), or the BPF filter is
            invalid.
    """
    try:
        from scapy.all import sniff
    except ImportError as exc:
        raise LiveCaptureError(
            "Scapy is not installed. Run: pip install -r requirements.txt"
        ) from exc

    def _progress(_pkt: Any) -> None:
        seen += 1
        if on_packet is not None:
            on_packet(seen, count)

    seen = 0
    try:
        packets = sniff(
            iface=interface,
            count=count or None,
            timeout=timeout or None,
            filter=bpf_filter or None,
            store=True,
            prn=_progress,
        )
    except KeyboardInterrupt:
        # Ctrl+C is the documented way to stop a capture, so whatever was
        # recorded so far is still worth analyzing.
        raise
    except Exception as exc:  # noqa: BLE001 - Scapy error types vary a lot
        raise LiveCaptureError(_explain(exc, interface)) from exc

    return list(packets)


def _explain(exc: Exception, interface: str) -> str:
    """Turn a Scapy exception into a message the user can act on.

    Args:
        exc: The exception Scapy raised.
        interface: The interface that was being recorded.

    Returns:
        A multi-line explanation, ending with what to try next.
    """
    raw = str(exc).strip() or exc.__class__.__name__
    lowered = raw.lower()

    if "permission" in lowered or "denied" in lowered:
        return (
            f"Not allowed to capture on '{interface}': {raw}\n"
            "    Capturing live traffic needs root/administrator rights.\n"
            "    Linux/macOS:  sudo python main.py --live -i "
            f"{interface}\n"
            "    Windows:      run PowerShell as Administrator, and "
            "install Npcap in WinPcap-compatible mode."
        )
    if "can't get hardware address" in lowered or "no such device" in lowered:
        return (
            f"Could not open '{interface}': {raw}\n"
            "    The interface may be DOWN. Run 'ip -br link' (Linux) or "
            "'Get-NetAdapter' (Windows) and pick one that is Up."
        )
    if "bpf" in lowered or "filter" in lowered:
        return (
            f"Invalid BPF filter: {raw}\n"
            "    Use tcpdump syntax, for example: "
            "--filter 'port 443' or --filter 'tcp and host 10.0.0.5'"
        )
    if "pcap" in lowered or "npcap" in lowered or "libpcap" in lowered:
        return (
            f"Capture backend unavailable: {raw}\n"
            "    Linux/macOS:  'sudo apt install libpcap0.8'\n"
            "    Windows:      install Npcap with 'WinPcap API support'."
        )
    return f"Could not capture on '{interface}': {raw}"


def save_live_capture(packets: List[Any],
                     folder: str = config.PCAPS_FOLDER) -> Optional[str]:
    """Write a live capture to ``folder`` so it can be analyzed again later.

    Saving is what makes the online mode as useful as the offline one: the
    file shows up in ``pcaps/``, in the interactive menu, and can be opened
    in Wireshark.

    Args:
        packets: The packets returned by :func:`capture_live`.
        folder: Destination folder, created when missing.

    Returns:
        The path that was written, or ``None`` when the file could not be
        saved (the analysis still runs - only the archive is lost).
    """
    if not packets:
        return None

    from analyzer.utils import get_timestamp

    path = os.path.join(
        folder, f"{config.LIVE_CAPTURE_PREFIX}_{get_timestamp()}.pcap"
    )
    try:
        from scapy.all import wrpcap
        wrpcap(path, packets)
    except Exception:  # noqa: BLE001 - a failed save must not kill the run
        return None
    return path
