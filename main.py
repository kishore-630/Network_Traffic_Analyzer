"""Network Traffic Analyzer - command-line entry point.

This file only *orchestrates* the work:

1. parse the command line,
2. load the capture,
3. compute statistics and anomalies,
4. show them, or save a report.

All the interesting logic lives in the ``analyzer`` package:

============================  =========================================
``analyzer/utils.py``         loading captures, formatting helpers
``analyzer/stats.py``         one pass over the packets, many metrics
``analyzer/anomalies.py``     rule-based detection with severities
``analyzer/ui.py``            all colors, glyphs and tables
``analyzer/report.py``        text report + CSV writer
============================  =========================================

Usage
-----
Interactive menu (the default)::

    python main.py pcaps/sample.pcap

Ask for the path, then show the menu::

    python main.py

One-shot modes, perfect for scripts (no menu, always saves a report)::

    python main.py pcaps/sample.pcap --full
    python main.py pcaps/sample.pcap --stats-only
    python main.py pcaps/sample.pcap --anomalies-only
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Dict, List, Optional, Tuple

import config
from analyzer import ui
from analyzer.anomalies import Finding, detect_anomalies
from analyzer.report import save_all
from analyzer.stats import compute_stats
from analyzer.utils import (
    PcapError,
    ensure_output_folders,
    list_available_pcaps,
    load_pcap,
)

# Menu options as constants - avoids "magic numbers" spread around the file.
MENU_FULL = "1"
MENU_STATS = "2"
MENU_ANOMALIES = "3"
MENU_SAVE = "4"
MENU_OTHER = "5"
MENU_EXIT = "0"
# Shown in the prompt, e.g. "Enter choice [0-5]".
MENU_RANGE = "0-5"


# ═══════════════════════════════════════════════════════════════════
#  Command line
# ═══════════════════════════════════════════════════════════════════

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Define and read the command-line arguments.

    Args:
        argv: Arguments to parse. ``None`` means "use sys.argv", which is
            what you want when running the script normally.

    Returns:
        The parsed namespace.
    """
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(f"{config.TOOL_NAME} v{config.TOOL_VERSION} - "
                     "pcap insights and anomaly detection."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python main.py pcaps/sample.pcap              interactive menu\n"
                "  python main.py pcaps/sample.pcap --full        stats + anomalies\n"
                "  python main.py pcaps/sample.pcap --no-save     look, write nothing\n"
                "  python main.py --version\n"),
    )
    parser.add_argument("pcap", nargs="?",
                        help="path to the .pcap / .pcapng file to analyze")
    parser.add_argument("-v", "--version", action="version",
                        version=f"{config.TOOL_NAME} {config.TOOL_VERSION}")

    # These three are mutually exclusive: exactly one mode can be requested.
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--full", action="store_true",
                       help="one-shot: statistics + anomalies, then save")
    group.add_argument("--stats-only", action="store_true",
                       help="one-shot: statistics only, then save")
    group.add_argument("--anomalies-only", action="store_true",
                       help="one-shot: anomalies only, then save")

    parser.add_argument("--no-save", action="store_true",
                        help="do not write any report (useful for a quick look)")
    return parser.parse_args(argv)


# ═══════════════════════════════════════════════════════════════════
#  Loading + analysing
# ═══════════════════════════════════════════════════════════════════

def ask_for_path(suggested: str = "") -> str:
    """Ask the user for a capture path.

    If the folder already contains captures, they are listed so the user
    does not have to remember file names.

    Args:
        suggested: Pre-filled answer (used when re-asking for another file).

    Returns:
        The path typed by the user. An empty string means "no path given"
        (``None`` from the prompt means the user cancelled, which is also
        treated as "no path given").
    """
    files = list_available_pcaps()
    if files and not suggested:
        ui.info(f"{len(files)} capture(s) available in {config.PCAPS_FOLDER}/:")
        for file_path in files:
            ui.info(f"  {file_path}")

    if suggested:
        answer = ui.ask(f"Path to the new .pcap [{suggested}]:")
        return (answer or suggested) if answer is not None else ""
    return ui.ask(f"Enter path to the .pcap "
                  f"(e.g. {config.PCAPS_FOLDER}/sample.pcap): ") or ""


def load_capture(path: str) -> Optional[List[Any]]:
    """Load a capture and print friendly progress or errors.

    Args:
        path: Path to the capture file.

    Returns:
        The packet list, or ``None`` when loading failed.
    """
    ui.info(f"Loading capture: {path} "
            f"{ui.GLYPH['dot']} large files take a moment")
    try:
        packets = load_pcap(path)
    except PcapError as exc:
        ui.error(str(exc))
        return None

    if not packets:
        ui.warning("The capture loaded fine but contains 0 packets.")
        ui.info("Check the capture, not the analyzer: run "
                "'ip -br link' and 'ip route get 1.1.1.1', then record again "
                "with tcpdump -i <interface> -s 0 -U -c 500 -w <file>. "
                "Avoid -i any, and generate traffic while capturing.")
    else:
        ui.success(f"Loaded {len(packets)} packets.")
    return packets


def analyse(packets: List[Any]) -> Tuple[Dict[str, Any], List[Finding]]:
    """Compute statistics and run the anomaly rules.

    Args:
        packets: Packets loaded from a capture file.

    Returns:
        ``(stats, findings)`` - both ready to display or save.
    """
    ui.rule_of_activity(f"{ui.GLYPH['marker']} Crunching packets")
    stats = compute_stats(packets)
    findings = detect_anomalies(stats)
    return stats, findings


def save_results(pcap_path: str, stats: Dict[str, Any],
                 findings: List[Finding]) -> int:
    """Save both reports, printing where they went.

    Args:
        pcap_path: Capture that was analysed.
        stats: Statistics dictionary.
        findings: Findings from the anomaly engine.

    Returns:
        ``0`` on success, ``1`` if the files could not be written.
    """
    ui.rule_of_activity(f"{ui.GLYPH['marker']} Generating reports")
    try:
        report_path, csv_path = save_all(pcap_path, stats, findings)
    except OSError as exc:
        ui.error(f"Could not save the reports: {exc}")
        return 1

    ui.success(f"Text report saved  {ui.GLYPH['arrow']} {report_path}")
    ui.success(f"CSV summary saved  {ui.GLYPH['arrow']} {csv_path}")
    return 0


# ═══════════════════════════════════════════════════════════════════
#  Modes
# ═══════════════════════════════════════════════════════════════════

def run_one_shot(pcap_path: str, packets: List[Any], mode: str,
                 do_save: bool = True) -> int:
    """Display the requested sections once, then optionally save.

    Args:
        pcap_path: Capture that was loaded.
        packets: Its packets.
        mode: ``"full"``, ``"stats"`` or ``"anomalies"``.
        do_save: Write the reports afterwards.

    Returns:
        Process exit code (``0`` = fine, ``1`` = a save failed).
    """
    stats, findings = analyse(packets)

    if mode in ("full", "stats"):
        ui.print_stats(stats)
    if mode in ("full", "anomalies"):
        ui.print_anomalies(findings)
    if mode == "full":
        print()
        ui.print_summary_line(stats)

    if not do_save:
        ui.info("Reports skipped (--no-save).")
        return 0
    return save_results(pcap_path, stats, findings)


def run_interactive(pcap_path: str, packets: List[Any],
                    do_save: bool = True) -> int:
    """Show the menu and repeat until the user exits or switches files.

    A ``while`` loop (instead of recursion) keeps the stack flat no matter
    how many files are analyzed in one session.

    Args:
        pcap_path: Capture that was loaded.
        packets: Its packets.
        do_save: Allow option `4` to write reports. Set from ``--no-save``.

    Returns:
        Process exit code (``0`` = the user closed the tool normally).
    """
    exit_code = 0

    while True:
        stats, findings = analyse(packets)

        while True:  # inner loop: re-display the menu for the same capture
            ui.print_menu(pcap_path, len(packets), list_available_pcaps())
            choice = ui.ask(f"Enter choice [{MENU_RANGE}] (or h for help): ")
            if choice is None:
                # Ctrl+C or end of input stream: leave instead of looping.
                ui.print_goodbye()
                return exit_code
            choice = choice.lower()

            if choice == "h":
                ui.info("1 = full analysis, 2 = statistics only, "
                        "3 = anomalies only, 4 = save report + CSV, "
                        "5 = analyze another file, 0 = exit.")
                continue

            if choice == MENU_FULL:
                ui.print_stats(stats)
                ui.print_anomalies(findings)
            elif choice == MENU_STATS:
                ui.print_stats(stats)
            elif choice == MENU_ANOMALIES:
                ui.print_anomalies(findings)
            elif choice == MENU_SAVE:
                if do_save:
                    exit_code = save_results(pcap_path, stats, findings)
                else:
                    ui.warning("Saving is disabled (--no-save was used).")
            elif choice == MENU_OTHER:
                new_path = ask_for_path(suggested=pcap_path)
                if not new_path:
                    ui.warning("No path given - staying on the current capture.")
                    continue
                new_packets = load_capture(new_path)
                if new_packets is None:
                    ui.warning("Could not read that file - keeping the "
                               "current capture.")
                    continue
                pcap_path, packets = new_path, new_packets
                break  # leave the inner loop: the capture changed
            elif choice == MENU_EXIT:
                ui.print_goodbye()
                return exit_code
            else:
                ui.warning(f"Invalid choice {choice!r} - please enter a number "
                           f"from {MENU_RANGE}.")
                continue

            ui.info(f"{ui.GLYPH['dash']} press Enter to return to the menu")
            try:
                input()
            except (KeyboardInterrupt, EOFError):
                print()
                ui.print_goodbye()
                return exit_code


# ═══════════════════════════════════════════════════════════════════
#  Program start
# ═══════════════════════════════════════════════════════════════════

def main(argv: Optional[List[str]] = None) -> int:
    """Start the tool: banner, load a capture, then run the chosen mode.

    Args:
        argv: Arguments to parse (defaults to ``sys.argv``).

    Returns:
        Process exit code.
    """
    args = parse_args(argv)
    ui.print_banner()

    # 1. Which capture? From the command line, or by asking.
    pcap_path = args.pcap
    if not pcap_path:
        pcap_path = ask_for_path()
        if not pcap_path:
            ui.error("No capture file given - nothing to analyze.")
            return 1

    # 2. Make sure output/, reports/ and pcaps/ exist.
    ensure_output_folders(config.OUTPUT_FOLDER, config.REPORTS_FOLDER,
                          config.PCAPS_FOLDER)

    # 3. Load the packets (friendly errors, no traceback for beginners).
    packets = load_capture(pcap_path)
    if packets is None:
        # load_capture already printed exactly what went wrong.
        return 1
    if not packets:
        return 0  # an empty capture was already reported

    # 4. One-shot modes, or the interactive menu (the default).
    if args.anomalies_only:
        return run_one_shot(pcap_path, packets, "anomalies", not args.no_save)
    if args.stats_only:
        return run_one_shot(pcap_path, packets, "stats", not args.no_save)
    if args.full:
        return run_one_shot(pcap_path, packets, "full", not args.no_save)
    return run_interactive(pcap_path, packets, do_save=not args.no_save)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        # Ctrl+C anywhere in the program ends it politely.
        print()
        ui.print_goodbye()
        sys.exit(130)
