"""Premium terminal user interface - every color, glyph and table lives here.

Why a separate module?
----------------------
``main.py`` should only orchestrate the analysis, and the report writers
should produce *plain* text. Keeping the look and feel in one file makes
both easy: one module to tweak when you want a different color scheme, and
zero color codes leaking into saved reports.

A note on tables
----------------
Colored text contains invisible escape codes, so a normal ``len()`` is
wrong for measuring column width. ``render_table`` therefore measures
with :func:`analyzer.utils.visible_len` and pads by *visible* length.
(``tabulate`` does not do this, which is why the report writers can use it
but this renderer does not.)

If your terminal cannot print box-drawing characters (for example a legacy
Windows console using code page 1252) every glyph automatically falls back
to plain ASCII, so the tool never crashes.
"""

from __future__ import annotations

import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from colorama import Fore, Style, init as colorama_init

import config
from analyzer.anomalies import Finding, severity_counts, verdict_for
from analyzer.stats import summarize_stats
from analyzer.utils import (
    format_port,
    human_bytes,
    human_duration,
    strip_ansi,
    truncate,
    visible_len,
    wrap_text,
)

# Turn ANSI support on for Windows terminals as well, and make sure a
# color never "leaks" into the next print call.
colorama_init(autoreset=True)


# ═══════════════════════════════════════════════════════════════════
#  Unicode / ASCII detection
# ═══════════════════════════════════════════════════════════════════

def _supports_unicode() -> bool:
    """Return True when the terminal can draw box-drawing glyphs.

    Kali Linux and Windows Terminal handle Unicode perfectly. Legacy
    Windows consoles (cp1252) do not, so we switch to ASCII decorations
    instead of raising ``UnicodeEncodeError`` at the worst moment.
    """
    try:
        "╔═║▸●⚠✔✘·─".encode(sys.stdout.encoding or "utf-8")
        return True
    except (UnicodeEncodeError, LookupError, TypeError):
        return False


UNI = _supports_unicode()

# Glyph set: rich Unicode where possible, clean ASCII otherwise.
GLYPH = {
    "hline": "═" if UNI else "=",
    "tline": "─" if UNI else "-",
    "bullet": "●" if UNI else "*",
    "marker": "▸" if UNI else ">",
    "ok": "✔" if UNI else "+",
    "warn": "⚠" if UNI else "!",
    "err": "✘" if UNI else "x",
    "dot": "·" if UNI else "-",
    "dash": "—" if UNI else "-",
    "arrow": "→" if UNI else "->",
    # Box-drawing pieces used by render_table().
    "vline": "│" if UNI else "|",
    "tl": "╔" if UNI else "+",
    "tr": "╗" if UNI else "+",
    "bl": "╚" if UNI else "+",
    "br": "╝" if UNI else "+",
    "tjoin": "╦" if UNI else "+",
    "bjoin": "╩" if UNI else "+",
    "hjoin": "╪" if UNI else "+",
    "sep_l": "╞" if UNI else "+",
    "sep_r": "╣" if UNI else "+",
    # Used by the banner only: a *double*-line frame, so the splash reads
    # like a plate around the wordmark instead of a plain ASCII box.
    "dvline": "║" if UNI else "|",
}

# Total width of a section divider - roughly a standard 80-column terminal.
WIDTH = 66

# How wide the "Finding" column of the anomaly table may grow before the
# message is wrapped onto the next line. Keeps the table inside ~110 columns.
FINDING_WRAP = 58


# ═══════════════════════════════════════════════════════════════════
#  Color palette (tuned for dark terminal themes)
# ═══════════════════════════════════════════════════════════════════

def _c(text: str, color: str) -> str:
    """Wrap ``text`` in a color, honouring ``config.USE_COLOR``.

    Args:
        text: Text to colorize.
        color: A colorama constant such as ``Fore.CYAN``.

    Returns:
        Colored text, or the plain text when colors are disabled.
    """
    if not config.USE_COLOR:
        return text
    return f"{color}{text}{Style.RESET_ALL}"


C_TITLE = Fore.MAGENTA + Style.BRIGHT   # banner + menu prompt
C_HEAD = Fore.WHITE + Style.BRIGHT      # section headers / table headers
C_INFO = Fore.CYAN                      # neutral information
C_ACCENT = Fore.CYAN + Style.BRIGHT     # dividers and accents
C_OK = Fore.GREEN + Style.BRIGHT        # success / healthy numbers
C_WARN = Fore.YELLOW + Style.BRIGHT     # medium findings
C_BAD = Fore.RED + Style.BRIGHT         # critical findings / errors
C_DIM = Fore.WHITE                      # body text
C_NUM = Fore.CYAN + Style.BRIGHT        # numbers inside tables

# One color per severity level so findings stand out at a glance.
SEVERITY_COLORS: Dict[str, str] = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH": Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.CYAN,
    "INFO": Fore.WHITE,
}


# ═══════════════════════════════════════════════════════════════════
#  Banner design tokens — TOP HEADER / BRANDING ONLY
# ═══════════════════════════════════════════════════════════════════
#  Retro cybersecurity-terminal header. Dark background (the terminal
#  itself), thin purple frame, three-line hierarchy:
#    1. NETWORK TRAFFIC ANALYZER (dominant ASCII wordmark, bright purple)
#    2. TOOL BUILDER: GURRALA KISHORE KUMAR (light purple, subordinate)
#    3. PCAP INSIGHTS • TRAFFIC ANALYSIS • ANOMALY DETECTION (muted, small)
#  Nothing below this block affects sidebar/dashboard/cards/charts/tables.

# Printable width *inside* the splash frame. 70 columns of content plus the
# frame characters on each side gives 72 visible columns: the widest word
# ("ANALYZER") is 61 columns, so it still breathes inside the frame.
# On narrow terminals print_banner() shrinks this automatically and falls
# back to plain text below ~52 columns, so the header never overflows.
BANNER_INNER: int = 70
# Minimum inner width before switching to compact (no-ASCII-art) mode.
BANNER_MIN_FULL: int = 52

# Purple-first palette (dark-theme terminal). No unrelated hues.
BANNER_BORDER: Tuple[int, int, int] = (147, 51, 234)   # thin frame purple
BANNER_TITLE: Tuple[int, int, int] = (192, 132, 252)   # main title, bright
BANNER_BUILDER: Tuple[int, int, int] = (216, 180, 254)  # builder, lighter
BANNER_SUB: Tuple[int, int, int] = (167, 139, 250)      # tagline, muted
BANNER_DIM: Tuple[int, int, int] = (109, 88, 150)       # decorative lines

# Thin single-line frame (square corners, no rounded SaaS hero look).
BANNER_TL: str = "┌" if UNI else "+"
BANNER_TR: str = "┐" if UNI else "+"
BANNER_BL: str = "└" if UNI else "+"
BANNER_BR: str = "┘" if UNI else "+"
BANNER_H: str = "─" if UNI else "-"
BANNER_V: str = "│" if UNI else "|"

# The product name, split into the three stacked words that get drawn as
# art. Keeping it as words (not one string) is what makes the stack fit the
# available width: 24 characters on one line would need ~96 columns.
BANNER_WORDS: Tuple[str, ...] = ("NETWORK", "TRAFFIC", "ANALYZER")
BANNER_BUILDER_PREFIX: str = "TOOL BUILDER:"
BANNER_TAGLINE: str = "PCAP INSIGHTS {sep} TRAFFIC ANALYSIS {sep} ANOMALY DETECTION"

# ── The wordmark font ──────────────────────────────────────────────
# A squeezed figlet face - the same family `figlet -f standard` produces,
# compressed to five rows so three stacked words stay compact. Pure ASCII,
# so it renders identically on Kali, on Windows Terminal and on a legacy
# cp1252 console.
#
# Each glyph is padded to its own widest row on import, which is what keeps
# the vertical strokes of neighbouring letters in the same column.
FONT_ROWS: int = 5

# Blank columns between two letters. A squeezed figlet face carries almost no
# side bearing, so without this the strokes of neighbouring letters merge
# into an unreadable blob ("|_| \_||_   _|" instead of "|_| \_| |_   _|").
FONT_GAP: int = 1

FONT_GLYPHS: Dict[str, Tuple[str, ...]] = {
    "A": ("  __  ", " /  \\ ", "/    \\", "\\____/", "      "),
    "C": ("  ____ ", " / ___|", "|     ", "| |___ ", " \\____|"),
    "E": (" _____ ", "| ____|", "|  _|  ", "| |___ ", "|_____|"),
    "F": (" _____ ", "| ____|", "|  _|  ", "| |    ", "| |    "),
    "I": (" ___ ", "|_ _|", " | | ", " | | ", "|___|"),
    "K": (" _  __", "| |/ /", "| ' / ", "| . \\ ", "|_|\\_\\"),
    "L": (" _     ", "| |    ", "| |    ", "| |    ", "|_____ "),
    "N": (" _   _ ", "| \\ | |", "|  \\| |", "| |\\  |", "|_| \\_|"),
    "O": ("  ___  ", " / _ \\ ", "| | | |", "| |_| |", " \\___/ "),
    "R": (" ____  ", "| __) ", "|  _ \\ ", "| | | |", "|_| \\_|"),
    "T": (" _____ ", "|_   _|", "  | |  ", "  | |  ", "  |_|  "),
    "W": ("__     __", "| |    |  |", "| |    |  |", "| |    |  |",
          "|__   __|__|"),
    "Y": ("__   __", "\\ \\ / /", " \\ V / ", "  | |  ", "  |_|  "),
    "Z": (" _____ ", "|__  / ", "  / /  ", " / /_  ", "/____| "),
}

# Safety net, applied once at import: force every glyph to exactly
# FONT_ROWS x (its own widest row). figlet faces are not perfectly
# rectangular, so without this a single short row would shear the art.
FONT_GLYPHS = {
    letter: tuple(row.ljust(width) for row in rows)
    for letter, rows in FONT_GLYPHS.items()
    for width in (max(len(row) for row in rows),)
}

# Widest row of any glyph, used only for the unknown-character fallback.
FONT_WIDE: int = max(len(rows[0]) for rows in FONT_GLYPHS.values())


def _lerp(start: Tuple[int, int, int], end: Tuple[int, int, int],
          ratio: float) -> Tuple[int, int, int]:
    """Blend two RGB colors.

    Args:
        start: Color at ``ratio == 0``.
        end: Color at ``ratio == 1``.
        ratio: Position between both colors, clamped to ``0.0 - 1.0``.

    Returns:
        The interpolated ``(r, g, b)`` triple.
    """
    ratio = max(0.0, min(1.0, ratio))
    return tuple(round(a + (b - a) * ratio) for a, b in zip(start, end))


def _ansi256(rgb: Tuple[int, int, int]) -> str:
    """Convert an RGB color to the closest xterm-256 palette index.

    Grays get the dedicated 24-step grayscale ramp, which is far smoother
    than the 6x6x6 color cube.

    Args:
        rgb: The ``(r, g, b)`` color to convert.

    Returns:
        The palette index as a string.
    """
    red, green, blue = rgb
    if red == green == blue:
        if red < 8:
            return "16"
        if red > 248:
            return "231"
        return str(232 + round((red - 8) / 247 * 23))
    index = (16 + 36 * round(red / 255 * 5)
             + 6 * round(green / 255 * 5) + round(blue / 255 * 5))
    return str(index)


def _fade_solid(rgb: Tuple[int, int, int], bright: bool = False) -> str:
    """Return the escape prefix painting following text in ``rgb``.

    Args:
        rgb: The color to emit.
        bright: Also switch the font to bold. 256-color terminals usually
            render the bright variants more cleanly, which matters for the
            large block letters of the wordmark.

    Returns:
        An ANSI prefix, or an empty string when colors are disabled.
    """
    if not config.USE_COLOR:
        return ""
    weight = Style.BRIGHT if bright else ""
    return f"{weight}\033[38;5;{_ansi256(rgb)}m"


def _fade_text(text: str, start: Tuple[int, int, int],
               end: Tuple[int, int, int], bright: bool = False) -> str:
    """Paint one line with a horizontal gradient.

    Each character gets the color it deserves at its position, so a rule
    drawn with this fades smoothly from one side to the other. Spaces are
    left unpainted, which keeps the escape sequence count down.

    Args:
        text: Line to paint (must not contain ANSI codes).
        start: Color of the first visible character.
        end: Color of the last visible character.
        bright: Paint in bold as well.

    Returns:
        The colorized line, or the plain line when colors are disabled.
    """
    if not config.USE_COLOR:
        return text
    span = max(len(text) - 1, 1)
    painted = [
        char if char == " " else
        f"{_fade_solid(_lerp(start, end, index / span), bright)}{char}"
        for index, char in enumerate(text)
    ]
    return "".join(painted) + Style.RESET_ALL


def _centered(text: str, width: int) -> str:
    """Horizontally center ``text`` inside ``width`` visible columns.

    Args:
        text: Text to center. May contain ANSI codes.
        width: Target width in visible characters.

    Returns:
        The centered text.
    """
    padding = max(width - visible_len(strip_ansi(text)), 0)
    left = padding // 2
    return " " * left + text + " " * (padding - left)


def _centered_row(segments: Sequence[Tuple[str, Optional[str]]], width: int,
                  separator: str = "   ") -> str:
    """Center one line built from several separately colored segments.

    Centering is done on the *visible* text and the colors are injected
    afterwards, so the ANSI codes never disturb the alignment.

    Args:
        segments: ``(text, color)`` pairs. ``color`` may be ``None`` to
            leave that piece uncolored.
        width: Target width in visible characters.
        separator: Text inserted between two segments. It counts towards
            the width, so it must also be uncolored.

    Returns:
        The centered, colored line.
    """
    plain = separator.join(text for text, _ in segments)
    padding = max(width - visible_len(plain), 0)
    left = padding // 2
    body = separator.join(
        text if color is None else _c(text, color)
        for text, color in segments
    )
    return " " * left + body + " " * (padding - left)


def render_wordmark(word: str) -> Tuple[str, ...]:
    """Draw a word with the logo font.

    Args:
        word: Uppercase word to draw, e.g. ``"NTA"``.

    Returns:
        The ``FONT_ROWS`` lines of the word. Every line has exactly the
        same width, so a mark can be placed in a layout with plain
        arithmetic instead of measurement guesswork.

    Note:
        Unknown characters fall back to a blank glyph instead of raising,
        so an unexpected letter can never crash the splash screen.
    """
    glyphs = [
        FONT_GLYPHS.get(character, tuple(" " * FONT_WIDE for _ in range(FONT_ROWS)))
        for character in word.upper()
    ]
    separator = " " * FONT_GAP
    return tuple(
        separator.join(glyph[row] for glyph in glyphs)
        for row in range(FONT_ROWS)
    )


# ═══════════════════════════════════════════════════════════════════
#  One-line printers
# ═══════════════════════════════════════════════════════════════════

def info(msg: str) -> None:
    """Print a cyan informational line with a marker."""
    print(f"{C_INFO}{GLYPH['marker']} {msg}{Style.RESET_ALL}")


def success(msg: str) -> None:
    """Print a bright-green success line."""
    print(f"{C_OK}{GLYPH['ok']} {msg}{Style.RESET_ALL}")


def warning(msg: str) -> None:
    """Print a bright-yellow warning line."""
    print(f"{C_WARN}{GLYPH['warn']} {msg}{Style.RESET_ALL}")


def error(msg: str) -> None:
    """Print a bright-red error line."""
    print(f"{C_BAD}{GLYPH['err']} {msg}{Style.RESET_ALL}")


def divider(char: Optional[str] = None, length: int = WIDTH) -> None:
    """Print a decorative divider line."""
    print(_c((char or GLYPH["hline"]) * length, C_ACCENT))


def section_header(number: str, title: str) -> None:
    """Print a numbered section header.

    Example:
        ━━━━━━━━━━
          ● 01 · TRAFFIC OVERVIEW
        ━━━━━━━━━━
    """
    print()
    divider()
    print(f"{C_HEAD}  {GLYPH['bullet']} {number} {GLYPH['dot']} {title}")
    divider()


def sub_header(title: str) -> None:
    """Print a smaller header used inside a section."""
    print()
    print(f"{C_HEAD}{GLYPH['tline'] * 3} {GLYPH['marker']} {title} "
          f"{GLYPH['tline'] * 3}")


def rule_of_activity(message: str, seconds: float = 0.5) -> None:
    """Show a tiny animated "working..." line so big pcaps do not look frozen.

    Args:
        message: Text to animate after.
        seconds: Total animation time. Keep it small - this runs per action.
    """
    print(f"{C_INFO}{message}", end="", flush=True)
    steps = 3
    for _ in range(steps):
        time.sleep(seconds / steps)
        print(f"{C_INFO}.", end="", flush=True)
    print()


# ═══════════════════════════════════════════════════════════════════
#  ANSI-aware table renderer
# ═══════════════════════════════════════════════════════════════════

def render_table(
    headers: Sequence[str],
    rows: Iterable[Sequence[Any]],
    aligns: Optional[Sequence[str]] = None,
    colors: Optional[Sequence[Optional[str]]] = None,
) -> str:
    """Render a bordered table whose columns stay aligned *with colors*.

    A cell may contain newlines (see :func:`analyzer.utils.wrap_text`); the
    row then grows taller and every other cell is padded with blank lines.

    Args:
        headers: Column titles (may already contain color codes).
        rows: Iterable of rows; every cell is converted with ``str()``.
        aligns: ``"l"`` or ``"r"`` per column. Defaults to all left.
        colors: Optional color constant per column, applied to the body
            cells. ``None`` leaves the column uncolored.

    Returns:
        The finished table as a single string (without a trailing newline).
    """
    ncols = len(headers)
    aligns = list(aligns or ["l"] * ncols)
    colors = list(colors or [None] * ncols)

    # Split every cell into its display lines ("a\nb" becomes two lines).
    parsed: List[List[List[str]]] = []
    for row in rows:
        cells = []
        for index in range(ncols):
            cell = row[index] if index < len(row) else ""
            cells.append(str("" if cell is None else cell).split("\n"))
        parsed.append(cells)

    # 1. Column width = longest *visible* line (color codes do not count).
    widths = [visible_len(header) for header in headers]
    for cells in parsed:
        for index, lines in enumerate(cells):
            for line in lines:
                widths[index] = max(widths[index], visible_len(line))

    # 2. Pad each line to the column width using its visible length.
    def pad(text: str, index: int) -> str:
        gap = " " * max(0, widths[index] - visible_len(text))
        return f"{gap}{text}" if aligns[index] == "r" else f"{text}{gap}"

    def border(left: str, fill: str, mid: str, right: str) -> str:
        return _c(left + mid.join(fill * width for width in widths) + right,
                  C_ACCENT)

    def line_of(cells: List[str]) -> str:
        return GLYPH["vline"] + GLYPH["vline"].join(cells) + GLYPH["vline"]

    lines = [
        border(GLYPH["tl"], GLYPH["hline"], GLYPH["tjoin"], GLYPH["tr"]),
        line_of([pad(f"{C_HEAD}{headers[index]}", index)
                 for index in range(ncols)]),
        border(GLYPH["sep_l"], GLYPH["hline"], GLYPH["hjoin"], GLYPH["sep_r"]),
    ]

    for cells in parsed:
        height = max(len(cell_lines) for cell_lines in cells)
        for row_line in range(height):
            rendered = []
            for index in range(ncols):
                cell_lines = cells[index]
                text = cell_lines[row_line] if row_line < len(cell_lines) else ""
                if text and colors[index]:
                    text = _c(text, colors[index])
                rendered.append(pad(text, index))
            lines.append(line_of(rendered))

    lines.append(border(GLYPH["bl"], GLYPH["hline"], GLYPH["bjoin"], GLYPH["br"]))
    return "\n".join(lines)


def print_stats(stats: Dict[str, Any]) -> None:
    """Print the full statistics view with colored, aligned tables."""
    section_header("01", "TRAFFIC OVERVIEW")

    # ── Key figures ──────────────────────────────────────────────
    overview = [
        ["Total packets", f"{stats['total_packets']}"],
        ["Total size on wire", human_bytes(stats["total_bytes"])],
        ["Average packet size", f"{stats['avg_packet_size']} B"],
        ["Capture duration", human_duration(stats["duration_seconds"])],
        ["Unique source IPs", f"{stats['unique_src_ips']}"],
        ["Unique destination IPs", f"{stats['unique_dst_ips']}"],
    ]
    print(render_table(
        ["Metric", "Value"],
        overview,
        aligns=["l", "r"],
        colors=[None, C_NUM],
    ))

    # ── Protocols ────────────────────────────────────────────────
    sub_header("Protocols")
    proto_rows = [[proto, f"{count}"]
                  for proto, count in stats["protocol_counts"].items()]
    print(render_table(["Protocol", "Packets"], proto_rows,
                       aligns=["l", "r"], colors=[None, C_OK]))

    # ── Talkers ──────────────────────────────────────────────────
    sub_header(f"Top {config.TOP_N} Source IPs")
    print(render_table(
        ["#", "Source IP", "Packets"],
        _ranked_rows(stats["top_src_ips"], fmt=str),
        aligns=["r", "l", "r"],
        colors=[C_DIM, None, C_NUM],
    ))

    sub_header(f"Top {config.TOP_N} Destination IPs")
    print(render_table(
        ["#", "Destination IP", "Packets"],
        _ranked_rows(stats["top_dst_ips"], fmt=str),
        aligns=["r", "l", "r"],
        colors=[C_DIM, None, C_NUM],
    ))

    sub_header(f"Top {config.TOP_N} Service Ports (ephemeral filtered)")
    service_ports = stats.get("top_service_ports", stats.get("top_dst_ports", []))
    if service_ports:
        total_dport = sum(stats.get("all_dst_port_counts", {}).values()) or 1
        port_rows = [
            [str(i), truncate(format_port(p)),
             f"{c}", f"{c / total_dport * 100:.1f}%"]
            for i, (p, c) in enumerate(service_ports, start=1)
        ]
        print(render_table(
            ["#", "Port / Service", "Packets", "Share"],
            port_rows,
            aligns=["r", "l", "r", "r"],
            colors=[C_DIM, None, C_NUM, C_NUM],
        ))
    else:
        info("No destination ports found in this capture.")
    eph_total = stats.get("ephemeral_port_total", 0)
    eph_start = stats.get("ephemeral_port_start",
                          getattr(config, "EPHEMERAL_PORT_START", 32768))
    if eph_total:
        info(f"{eph_total} packet(s) went to ephemeral client ports "
             f"(>= {eph_start}) - normal return traffic, excluded above.")

    # ── Application layer ────────────────────────────────────────
    sub_header(f"DNS Queries (top {getattr(config, 'DNS_DISPLAY_LIMIT', 10)})")
    if stats["dns_total"]:
        dns_total = stats["dns_total"]
        dns_unique = stats.get("dns_unique",
                               len(stats.get("all_dns_domains", {})))
        info(f"{dns_total} queries for {dns_unique} unique domain(s).")
        tagged = stats.get("dns_tagged") or [
            (d, c, "") for d, c in stats.get("top_dns_domains", [])]
        dns_rows = [
            [str(i), truncate(dom), f"{cnt}",
             (svc if svc else "other")]
            for i, (dom, cnt, svc) in enumerate(tagged, start=1)
        ]
        print(render_table(["#", "Queried Domain", "Times", "Service"],
                           dns_rows, aligns=["r", "l", "r", "l"],
                           colors=[C_DIM, None, C_NUM, C_OK]))
        base_top = stats.get("top_dns_base", [])
        if base_top and len(base_top) > 1:
            grouped = ", ".join(f"{dom} ({cnt})"
                                for dom, cnt in base_top[:5])
            info(f"Grouped by base domain: {grouped}")
    else:
        info("No DNS queries found in this capture.")

    # ── Detected services (DNS-based browsing profile) ───────────
    sub_header("Detected Services (from DNS)")
    services = stats.get("detected_services", [])
    if services:
        svc_rows = [[svc["service"], f"{svc['dns_queries']}",
                     truncate(svc.get("example", ""))]
                    for svc in services]
        print(render_table(["Service", "DNS queries", "Example domain"],
                           svc_rows, aligns=["l", "r", "l"],
                           colors=[None, C_NUM, C_DIM]))
    else:
        info("No known browsing services recognised - "
             "traffic looks generic or uses direct IPs / DoH.")

    # ── TCP behaviour ────────────────────────────────────────────
    sub_header("TCP Flags")
    flag_rows = [[flag, f"{count}"]
                 for flag, count in stats["tcp_flag_counts"].items() if count]
    if flag_rows:
        print(render_table(["Flag", "Count"], flag_rows,
                           aligns=["l", "r"], colors=[None, C_OK]))
    else:
        info("No TCP packets, so there are no flags to show.")

    # ── Clear-text web traffic ───────────────────────────────────
    if stats["http_total"]:
        sub_header("Clear-text HTTP Requests")
        print(render_table(
            ["#", "Host", "Requests"],
            _ranked_rows(stats["top_http_hosts"], fmt=str),
            aligns=["r", "l", "r"],
            colors=[C_DIM, None, C_WARN],
        ))


def _ranked_rows(pairs: Sequence[Tuple[Any, int]], fmt=str) -> List[List[str]]:
    """Turn ``[(value, count), ...]`` into ranked table rows.

    Args:
        pairs: The "most common" pairs produced by ``collections.Counter``.
        fmt: How to render the value (e.g. :func:`format_port`).

    Returns:
        Rows shaped ``[[rank, value, count], ...]``.
    """
    return [[str(index), truncate(fmt(value)), f"{count}"]
            for index, (value, count) in enumerate(pairs, start=1)]


def print_anomalies(findings: List[Finding]) -> None:
    """Print anomaly findings, or a reassuring all-clear message."""
    section_header("02", "ANOMALY FINDINGS")

    if not findings:
        success("No anomalies detected - this traffic looks normal.")
        print()
        info("Reminder: \"no findings\" only means nothing crossed the "
             "thresholds in config.py.")
        return

    rows = []
    for index, finding in enumerate(findings, start=1):
        color = SEVERITY_COLORS.get(finding.severity, C_WARN)
        rows.append([
            str(index),
            _c(finding.severity, color),
            _c(finding.rule, C_DIM),
            # Wrap instead of cut: a full sentence is much easier to read.
            wrap_text(finding.message, width=FINDING_WRAP),
        ])

    print(render_table(
        ["#", "Severity", "Rule", "Finding"],
        rows,
        aligns=["r", "l", "l", "l"],
    ))

    print()
    counts = severity_counts(findings)
    breakdown = "  ".join(
        _c(f"{level}: {counts[level]}", SEVERITY_COLORS.get(level, C_WARN))
        for level in config.SEVERITY_ORDER if counts.get(level)
    )
    warning(f"{verdict_for(findings)}")
    info(breakdown)


# ═══════════════════════════════════════════════════════════════════
#  Banner + menu
# ═══════════════════════════════════════════════════════════════════

def print_banner() -> None:
    r"""Print the TOP HEADER / BRANDING banner (header component only).

    Retro cybersecurity-terminal header, 72 columns max::

        ┌──────────────────────────────────────────────────────────────────────┐
        │  _   _  _____  _____ __     __     ___   ____   _  __              │
        │ | \\ | || ____||_   _|| |    |  |  / _ \\ | __)  | |/ /              │
        │ ... (NETWORK / TRAFFIC / ANALYZER stacked ASCII wordmark) ...        │
        │              TOOL BUILDER: GURRALA KISHORE KUMAR                     │
        │     PCAP INSIGHTS • TRAFFIC ANALYSIS • ANOMALY DETECTION              │
        └──────────────────────────────────────────────────────────────────────┘

    Hierarchy (top to bottom):
      1. ``NETWORK TRAFFIC ANALYZER`` — large ASCII wordmark, bright purple,
         bold, monospace, dominant element.
      2. ``TOOL BUILDER: GURRALA KISHORE KUMAR`` — smaller, light purple.
      3. ``PCAP INSIGHTS • TRAFFIC ANALYSIS • ANOMALY DETECTION`` — small
         muted-purple technical tagline.

    Terminal details are deliberately subtle: thin purple frame, one dim
    status line, one dim divider, one blinking block cursor. No images,
    no rounded SaaS hero, no layout changes elsewhere.

    Responsive: the inner width shrinks with the terminal
    (``shutil.get_terminal_size``). Below ``BANNER_MIN_FULL`` columns the
    ASCII art is replaced by plain centered text so the three-line
    hierarchy survives on mobile/narrow consoles without overflow.
    """
    import shutil

    name = config.AUTHOR.strip().upper() or "GURRALA KISHORE KUMAR"
    builder_line = f"{BANNER_BUILDER_PREFIX} {name}"
    sep = "•" if UNI else "-"
    tagline = BANNER_TAGLINE.format(sep=sep)

    try:
        term_width = shutil.get_terminal_size().columns
    except (OSError, ValueError):
        term_width = 80
    inner = max(30, min(BANNER_INNER, term_width - 4))
    width = inner - 2  # printable columns between the bars

    edge = _fade_solid(BANNER_BORDER, bright=True)
    dim_edge = _fade_solid(BANNER_DIM)
    title_paint = _fade_solid(BANNER_TITLE, bright=True)
    builder_paint = _fade_solid(BANNER_BUILDER, bright=True)
    sub_paint = _fade_solid(BANNER_SUB)

    def frame(left: str, right: str) -> str:
        """Thin solid-purple top/bottom border."""
        if not config.USE_COLOR:
            return left + BANNER_H * inner + right
        return f"{edge}{left}{BANNER_H * inner}{right}{Style.RESET_ALL}"

    def framed(body: str) -> str:
        """Wrap one already-styled line between thin vertical bars."""
        gap = max(width - visible_len(strip_ansi(body)), 0)
        if not config.USE_COLOR:
            return f"{BANNER_V} {body}{' ' * gap} {BANNER_V}"
        return f"{edge}{BANNER_V} {body}{' ' * gap} {edge}{BANNER_V}"

    def dim_centered(text: str) -> str:
        plain = truncate(text, width)
        centered = _centered(plain, width)
        if not config.USE_COLOR:
            return centered
        return f"{dim_edge}{centered}{Style.RESET_ALL}"

    # Blinking block cursor (ANSI blink + reset). Stripped correctly by
    # strip_ansi, so centering math stays exact. Falls back to "_" ASCII.
    block = "█" if UNI else "_"
    cursor = (f"\033[5m{block}\033[0m" if config.USE_COLOR
              else block)
    prompt_tail = f"root@kali:~# {cursor}"

    if width < BANNER_MIN_FULL:
        # ── Compact mode: no ASCII art, same 3-line hierarchy, no overflow.
        title_plain = truncate("NETWORK TRAFFIC ANALYZER", width)
        body: List[str] = [
            _centered(f"{title_paint}{title_plain}{Style.RESET_ALL}"
                      if config.USE_COLOR else title_plain, width),
            _centered(f"{builder_paint}{truncate(builder_line, width)}"
                      f"{Style.RESET_ALL}" if config.USE_COLOR
                      else truncate(builder_line, width), width),
            dim_centered(tagline),
            dim_centered(prompt_tail),
        ]
        lines = [frame(BANNER_TL, BANNER_TR)]
        lines += [framed(line) for line in body]
        lines.append(frame(BANNER_BL, BANNER_BR))
        print("\n" + "\n".join(lines))
        return

    # ── Full mode: stacked ASCII wordmark, one flat bright-purple hue so
    #    the title reads as a single deliberate brand, not gradient noise.
    #    FONT_GAP (=1) already gives the slight retro letter spacing.
    wordmark: List[str] = []
    for index, word in enumerate(BANNER_WORDS):
        if index:
            wordmark.append("")
        wordmark.extend(
            _centered(title_paint + line + Style.RESET_ALL, width)
            for line in render_wordmark(word)
        )

    divider_dots = dim_centered("-" * min(width, 46))
    builder_centered = _centered(
        f"{builder_paint}{truncate(builder_line, width)}{Style.RESET_ALL}"
        if config.USE_COLOR else truncate(builder_line, width), width)
    tagline_centered = _centered(
        f"{sub_paint}{truncate(tagline, width)}{Style.RESET_ALL}"
        if config.USE_COLOR else truncate(tagline, width), width)
    prompt_centered = dim_centered(prompt_tail)

    full_body: List[str] = (
        wordmark
        + ["", builder_centered, divider_dots,
           tagline_centered, "", prompt_centered]
    )

    lines = [frame(BANNER_TL, BANNER_TR)]
    lines += [framed(line) for line in full_body]
    lines.append(frame(BANNER_BL, BANNER_BR))

    print("\n" + "\n".join(lines))


def print_menu(pcap_path: str, packet_count: int, files: Sequence[str]) -> None:
    """Print the interactive action menu.

    Args:
        pcap_path: Capture currently loaded.
        packet_count: Number of packets it contains.
        files: Capture files found in ``pcaps/`` (for quick switching).
    """
    print()
    divider(GLYPH["tline"])
    info(f"Loaded: {pcap_path} {C_INFO}({packet_count} packets)")
    print(f"{C_HEAD}  Choose an action:")
    menu = [
        [_c("1", C_OK), "Full analysis       statistics + anomalies"],
        [_c("2", C_OK), "Traffic statistics  tables only"],
        [_c("3", C_OK), "Anomaly findings    verdict only"],
        [_c("4", C_OK), "Save report + CSV   reports/ + output/"],
        [_c("5", C_OK), "Analyze another file"],
        [_c("0", C_BAD), "Exit"],
    ]
    print(render_table(["Key", "Action"], menu, aligns=["r", "l"]))

    if files:
        print()
        print(f"{C_HEAD}  Captures found in {config.PCAPS_FOLDER}/:")
        for file_path in files:
            print(f"    {C_DIM}{file_path}")

    # Flat "key figures" reminder, so the menu screen is useful on its own.
    print()
    print(f"{C_DIM}  Tip: press {C_ACCENT}h{C_DIM} for the README quick start."
          f"{Style.RESET_ALL}")


def ask(prompt: str) -> Optional[str]:
    """Ask the user for a line of input in the tool's accent color.

    Args:
        prompt: Question shown to the user.

    Returns:
        The stripped answer, or ``None`` when the user pressed Ctrl+C or the
        input stream ended (for example ``echo 0 | python main.py ...``).
        Callers must treat ``None`` as "the user wants to leave", otherwise
        an empty answer would be retried forever.
    """
    try:
        return input(f"{C_TITLE}{GLYPH['marker']} {prompt}{Style.RESET_ALL} ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def print_goodbye() -> None:
    """Print the farewell message."""
    info(f"Goodbye {GLYPH['dash']} stay ethical, analyze only your own traffic.")


def print_summary_line(stats: Dict[str, Any]) -> None:
    """Print a one-line summary, e.g. after an analysis finishes.

    Args:
        stats: The statistics dictionary that was just computed.
    """
    overview = dict(summarize_stats(stats))
    print(f"{C_DIM}  {_c(overview['Total packets'], C_OK)} packets {GLYPH['dot']} "
          f"{overview['Total size']} {GLYPH['dot']} {overview['Duration']} "
          f"{GLYPH['dot']} {overview['DNS queries']} DNS queries")
