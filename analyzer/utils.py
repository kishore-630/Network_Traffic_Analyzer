"""Small helper functions used across the project.

Every function here is deliberately tiny so a beginner can read this file
top-to-bottom and understand exactly what happens before the analysis runs.

Contents
--------
* :class:`PcapError`          - friendly error type raised by the loader
* :func:`ensure_output_folders`
* :func:`get_timestamp`
* :func:`load_pcap`           - read a .pcap into a list of Scapy packets
* :func:`describe_pcap_file`  - metadata about a capture file
* :func:`list_available_pcaps`- handy tab-completion for the menu
* :func:`strip_ansi`          - drop color codes (needed to measure width)
* :func:`visible_len`         - real on-screen length of a colored string
* :func:`human_bytes`         - 1536 -> "1.5 KB"
* :func:`human_duration`      - 93.2 -> "1m 33s"
* :func:`format_port`         - 443 -> "443 (HTTPS)"
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Any, List, Optional

import config

# Matches ANSI escape sequences such as the ones colorama emits.
_ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")

# Human-readable byte units, ordered from smallest to largest.
_BYTE_UNITS = ["B", "KB", "MB", "GB", "TB"]


class PcapError(Exception):
    """Raised when a capture file cannot be read.

    Using a real exception (instead of printing inside the function) keeps
    the loading code free of print statements, which means the pretty
    terminal output is decided in exactly one place: ``main.py``.
    """


# ═══════════════════════════════════════════════════════════════════
#  Filesystem helpers
# ═══════════════════════════════════════════════════════════════════

def ensure_output_folders(*folders: str) -> None:
    """Create the given folders if they do not exist yet.

    Args:
        *folders: One or more folder paths, e.g. "output", "reports".

    Note:
        ``exist_ok=True`` means "do not crash if it is already there".
    """
    for folder in folders:
        os.makedirs(folder, exist_ok=True)


def list_available_pcaps(folder: str = config.PCAPS_FOLDER) -> List[str]:
    """Return capture files found in ``folder`` (sorted, newest last).

    The interactive menu uses this to help you pick a file without
    having to remember its exact name.

    Args:
        folder: Directory to search. Defaults to ``config.PCAPS_FOLDER``.

    Returns:
        List of file paths. Empty list if the folder is missing.
    """
    if not os.path.isdir(folder):
        return []

    found: List[str] = []
    for name in sorted(os.listdir(folder)):
        if name.lower().endswith((".pcap", ".pcapng", ".cap")):
            found.append(os.path.join(folder, name))
    return found


def describe_pcap_file(pcap_path: str) -> dict:
    """Return simple metadata (size on disk) about a capture file.

    Args:
        pcap_path: Path to the capture file.

    Returns:
        Dict with ``path``, ``size_bytes``, ``size_human`` and ``exists``.
    """
    exists = os.path.isfile(pcap_path)
    size = os.path.getsize(pcap_path) if exists else 0
    return {
        "path": pcap_path,
        "exists": exists,
        "size_bytes": size,
        "size_human": human_bytes(size),
    }


# ═══════════════════════════════════════════════════════════════════
#  Loading captures
# ═══════════════════════════════════════════════════════════════════

def ensure_scapy_layers() -> None:
    """Register the Scapy dissectors this project needs.

    Why this is important
    ----------------------
    Scapy only decodes a layer if the matching module was imported
    **before** the capture is read. Reading a pcap first and importing
    ``scapy.layers.http`` afterwards does not help: the HTTP information is
    already lost and cannot be recovered from the parsed packets.

    So every capture is loaded through :func:`load_pcap`, which calls this
    function first.

    Note:
        A missing module is ignored here on purpose; :func:`load_pcap`
        raises the friendly "Scapy is not installed" error afterwards.
    """
    for module in ("scapy.layers.inet", "scapy.layers.dns", "scapy.layers.http"):
        try:
            __import__(module)
        except ImportError:
            continue


def load_pcap(pcap_path: str) -> List[Any]:
    """Read a ``.pcap`` / ``.pcapng`` file and return its packets.

    Args:
        pcap_path: Path to the capture file.

    Returns:
        A list of Scapy packets. The list may be empty (that is not an
        error - it just means the capture has no frames in it).

    Raises:
        PcapError: The file is missing, Scapy is not installed, or the
            file is corrupt / not a valid capture.
    """
    # 1. Check the file exists *before* handing anything to Scapy, so the
    #    message stays short and readable.
    if not os.path.isfile(pcap_path):
        raise PcapError(f"File not found: {pcap_path}")

    # 2. Import Scapy here (not at the top of the file) so this module can
    #    still be imported on a machine where Scapy is not installed.
    try:
        from scapy.all import rdpcap
    except ImportError as exc:  # pragma: no cover - depends on the machine
        raise PcapError(
            "Scapy is not installed. Run: pip install -r requirements.txt"
        ) from exc

    # 3. Load the dissectors (inet / dns / http) BEFORE reading the file,
    #    otherwise those layers would not be decoded at all.
    ensure_scapy_layers()

    # 4. Actually read the file. Scapy raises many different exception types
    #    for broken captures, so we catch broadly and re-raise a PcapError.
    try:
        packets = rdpcap(pcap_path)
    except Exception as exc:  # noqa: BLE001 - Scapy's error types vary
        raise PcapError(f"Could not read '{pcap_path}': {exc}") from exc

    return list(packets)


def get_timestamp() -> str:
    """Return the current local time as a filename-safe string.

    Example:
        >>> get_timestamp()
        '2026-09-28_1230'

    Returns:
        Formatted timestamp like ``YYYY-MM-DD_HHMM``.
    """
    return datetime.now().strftime("%Y-%m-%d_%H%M")


# ═══════════════════════════════════════════════════════════════════
#  Formatting helpers (used by the terminal UI and the reports)
# ═══════════════════════════════════════════════════════════════════

def strip_ansi(text: str) -> str:
    """Remove ANSI color codes from a string.

    Why this matters: a colored string such as ``"\\x1b[32mok\\x1b[0m"`` is 11
    characters long in Python but only 2 characters wide on screen. Every
    width calculation has to use the *visible* length, otherwise columns
    drift apart.

    Args:
        text: Possibly colored string.

    Returns:
        The same text without any escape sequences.
    """
    return _ANSI_PATTERN.sub("", text)


def visible_len(text: str) -> int:
    """Return how many columns ``text`` occupies on screen (colors ignored)."""
    return len(strip_ansi(text))


def human_bytes(num_bytes: float) -> str:
    """Convert a byte count into a short human-readable string.

    Args:
        num_bytes: Number of bytes.

    Returns:
        For example ``"0 B"``, ``"1.5 KB"`` or ``"12.3 MB"``.

    Example:
        >>> human_bytes(1536)
        '1.5 KB'
    """
    value = float(num_bytes)
    for unit in _BYTE_UNITS:
        if value < 1024 or unit == _BYTE_UNITS[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} {_BYTE_UNITS[-1]}"  # pragma: no cover - unreachable


def human_duration(seconds: Optional[float]) -> str:
    """Convert a number of seconds into a short human-readable duration.

    Args:
        seconds: Length of the capture in seconds, or ``None``/``0``.

    Returns:
        For example ``"0.0s"``, ``"1m 33s"`` or ``"2h 05m"``.

    Example:
        >>> human_duration(93.2)
        '1m 33s'
    """
    if not seconds or seconds <= 0:
        return "0.0s"
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60):02d}s"
    return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60):02d}m"


def format_port(port: Any) -> str:
    """Return ``"443 (HTTPS)"`` for a known port, or just ``"4444"``.

    Args:
        port: Port number (int or str).

    Returns:
        A port string with a friendly service name when we know one.
    """
    try:
        number = int(port)
    except (TypeError, ValueError):
        return str(port)

    label = config.PORT_LABELS.get(number)
    return f"{number} ({label})" if label else str(number)


def truncate(text: str, limit: int = 46) -> str:
    """Shorten ``text`` to ``limit`` characters with an ellipsis.

    Long DNS names would otherwise stretch the tables far beyond the
    terminal width.

    Args:
        text: The string to shorten.
        limit: Maximum number of characters to keep.

    Returns:
        The original string, or a shortened version ending in ``"..."``.
    """
    text = str(text)
    if len(text) <= limit:
        return text
    return text[: max(1, limit - 3)] + "..."


def wrap_text(text: str, width: int = 50) -> str:
    """Wrap ``text`` into several short lines.

    Newlines already present in ``text`` are respected. The result can be
    printed directly or placed inside a table cell - the renderer in
    ``analyzer/ui.py`` understands the ``\\n`` separators.

    Args:
        text: The text to wrap.
        width: Maximum number of characters per line.

    Returns:
        Wrapped text, lines joined by ``"\\n"``.

    Example:
        >>> print(wrap_text("one two three four", 9))
        one two
        three
        four
    """
    import textwrap

    text = str(text)
    lines: List[str] = []
    for paragraph in text.split("\n"):
        lines.extend(textwrap.wrap(paragraph, width=width) or [""])
    return "\n".join(lines)
