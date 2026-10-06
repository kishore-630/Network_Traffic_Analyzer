"""Network Traffic Analyzer - command line entry point.

This file only *orchestrates* the work:

1. parse the command line,
2. load the capture (from a file, or live from an interface),
3. compute statistics and anomalies,
4. show them, or save a report.

The tool works in two modes:

* **offline** - analyze a ``.pcap`` / ``.pcapng`` file that already exists,
* **online**  - record live traffic from a network interface with
  ``--live``, then analyze exactly the same way.

All the interesting logic lives in the ``analyzer`` package:

============================  =========================================
``analyzer/utils.py``         loading captures, formatting helpers
``analyzer/live.py``          live capture from a network interface
``analyzer/stats.py``         one pass over the packets, many metrics
``analyzer/anomalies.py``     rule-based detection with severities
``analyzer/ui.py``            all colors, glyphs and tables
``analyzer/report.py``        text report + CSV writer
============================  =========================================

Usage
-----
Offline, interactive menu (the default)::

    python main.py pcaps/sample.pcap

Online, record then analyze::

    python main.py --live -i eth0 -c 200 --full

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
from analyzer.live import (
    LiveCaptureError,
    capture_live,
    format_interface_list,
    list_interfaces,
    resolve_interface,
    save_live_capture,
)
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
                     "offline pcap analysis, live capture and anomaly "
                     "detection."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  # offline - analyze a capture that already exists\n"
                "  python main.py pcaps/sample.pcap              interactive menu\n"
                "  python main.py pcaps/sample.pcap --full        stats + anomalies\n"
                "  python main.py pcaps/sample.pcap --no-save     look, write nothing\n"
                "  python main.py --list-interfaces               show capture interfaces\n"
                "\n"
                "  # online - record live traffic, then analyze it\n"
                "  python main.py --live                          pick the interface by number\n"
                "  python main.py --live -i eth0 -c 200 --full    record 200 packets\n"
                "  python main.py --live -i eth0 --filter 'port 443'\n"
                "\n"
                "  python main.py --version\n"),
    )
    parser.add_argument("pcap", nargs="?",
                        help="path to the .pcap / .pcapng file to analyze")
    parser.add_argument("-v", "--version", action="version",
                        version=f"{config.TOOL_NAME} {config.TOOL_VERSION}")

    # ── Online / live capture ─────────────────────────────────────
    live = parser.add_argument_group(
        "online (live) capture",
        "record packets straight from a network interface",
    )
    live.add_argument("--live", action="store_true",
                      help="record from an interface instead of reading a file")
    live.add_argument("-i", "--interface", metavar="NAME",
                      help="interface to record from (e.g. eth0, wlan0, en0)")
    live.add_argument("-c", "--count", type=int,
                      default=config.LIVE_DEFAULT_COUNT, metavar="N",
                      help=("stop after N packets "
                            f"(default: {config.LIVE_DEFAULT_COUNT}, "
                            "0 = no limit)"))
    live.add_argument("--timeout", type=int,
                      default=config.LIVE_DEFAULT_TIMEOUT, metavar="SEC",
                      help=("stop after SEC seconds without traffic "
                            f"(default: {config.LIVE_DEFAULT_TIMEOUT}, "
                            "0 = no limit)"))
    live.add_argument("--filter", dest="bpf_filter", metavar="EXPR",
                      help="tcpdump-style filter, e.g. \"port 443\"")
    live.add_argument("--list-interfaces", action="store_true",
                      help="list the interfaces available for live capture "
                           "and exit")

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
#  Online (live) capture
# ═══════════════════════════════════════════════════════════════════

def list_interfaces_and_exit() -> int:
    """Print every interface available for a live capture.

    Returns:
        Process exit code.
    """
    interfaces = list_interfaces()
    print()
    ui.info(f"Interfaces available for live capture "
            f"({len(interfaces)} found):")
    print(ui.C_DIM + format_interface_list(interfaces) + ui.Style.RESET_ALL)
    print()
    ui.info(f"Record with:  python main.py --live -i "
            f"<name> -c {config.LIVE_DEFAULT_COUNT}")
    ui.warning("Capture needs root/administrator rights, and an interface "
               "that is Up.")
    return 0


def choose_interface() -> Optional[str]:
    """Show the interface list and let the user pick one by number.

    Returns:
        The chosen interface name, or ``None`` if nothing was chosen.
    """
    interfaces = list_interfaces()
    print()
    ui.info(f"Which interface should I record from? "
            f"({len(interfaces)} found)")
    print(ui.C_DIM + format_interface_list(interfaces) + ui.Style.RESET_ALL)
    print()

    if not interfaces:
        ui.error("The operating system reported no network interface.")
        return None

    answer = ui.ask(f"Interface number [1-{len(interfaces)}] "
                    f"(0 = cancel): ")
    if not answer:
        return None

    try:
        index = int(answer)
    except ValueError:
        ui.warning(f"'{answer}' is not a number.")
        return None

    if not 1 <= index <= len(interfaces):
        ui.warning(f"Pick a number between 1 and {len(interfaces)}.")
        return None
    return interfaces[index - 1][0]


def _progress_printer(count: int):
    """Build a callback that draws a one-line live packet counter.

    Args:
        count: The packet target, used to scale the progress bar.

    Returns:
        A callable ``(seen, total) -> None`` that redraws in place.
    """
    bar_width = 28
    # The block glyphs are not part of the ASCII fallback set, so pick them
    # only when the console can actually print them.
    full_glyph, empty_glyph = ("█", "░") if ui.UNI else ("#", ".")

    def report(seen: int, total: int) -> None:
        if total > 0:
            filled = min(bar_width, int(bar_width * seen / total))
            bar = full_glyph * filled + empty_glyph * (bar_width - filled)
            text = f"  recording {bar} {seen}/{total} packets"
        else:
            text = f"  recording {seen} packets"
        # \r + pad-to-width redraws in place without spamming new lines.
        sys.stdout.write("\r" + text.ljust(ui.WIDTH))
        sys.stdout.flush()

    return report


def run_live(args: argparse.Namespace) -> int:
    """Record live traffic, then analyze it exactly like a saved file.

    Args:
        args: The parsed command-line namespace.

    Returns:
        Process exit code (``0`` = fine, ``1`` = the capture could not
        start).
    """
    # 1. Which interface?
    interface = args.interface
    if not interface:
        interface = choose_interface()
        if not interface:
            ui.warning("No interface chosen - leaving.")
            return 1

    try:
        resolve_interface(interface)
    except LiveCaptureError as exc:
        ui.error(str(exc))
        return 1

    if interface in ("any", "lo", "loopback"):
        ui.warning("'{interface}' is a virtual interface. A capture there "
                   "often records nothing - pick a real interface such as "
                   "eth0 or wlan0.".format(interface=interface))

    # 2. Record.
    target = "endless" if not args.count else str(args.count)
    print()
    ui.info(f"Recording from {ui.C_ACCENT}{interface}"
            f"{ui.Style.RESET_ALL} {ui.GLYPH['dot']} target {target} packets "
            f"{ui.GLYPH['dot']} stop after {args.timeout}s of silence")
    if args.bpf_filter:
        ui.info(f"Filter: {args.bpf_filter}")
    ui.info("Generate traffic now (open a page, ping something). "
            f"Press {ui.GLYPH['dot']} Ctrl+C to stop early.")
    print()

    try:
        packets = capture_live(
            interface=interface,
            count=args.count,
            timeout=args.timeout,
            bpf_filter=args.bpf_filter,
            on_packet=_progress_printer(args.count),
        )
    except KeyboardInterrupt:
        # capture_live re-raises this; nothing was returned, so treat the
        # capture as empty and let the shared "0 packets" path report it.
        sys.stdout.write("\r" + " " * ui.WIDTH + "\r")
        sys.stdout.flush()
        ui.warning("Stopped by Ctrl+C.")
        packets = []
    except LiveCaptureError as exc:
        sys.stdout.write("\r" + " " * ui.WIDTH + "\r")
        sys.stdout.flush()
        ui.error(str(exc))
        return 1

    sys.stdout.write("\r" + " " * ui.WIDTH + "\r")
    sys.stdout.flush()

    if not packets:
        ui.warning("The capture recorded 0 packets.")
        ui.info(f"Nothing is wrong with the analyzer. Check the interface is "
                f"Up, that you have permission to capture, and that traffic "
                f"was actually flowing while it recorded.")
        return 0

    ui.success(f"Recorded {len(packets)} packets from {interface}.")

    # 3. Archive the capture so it can be re-analyzed offline later.
    ensure_output_folders(config.OUTPUT_FOLDER, config.REPORTS_FOLDER,
                          config.PCAPS_FOLDER)
    saved_path = save_live_capture(packets)
    if saved_path:
        ui.success(f"Live capture saved {ui.GLYPH['arrow']} {saved_path}")
    else:
        ui.warning("Could not write the capture to disk - "
                   "the analysis below still runs.")

    label = saved_path or f"live capture on {interface}"

    # 4. Analyze it with the exact same pipeline as an offline file.
    if args.anomalies_only:
        return run_one_shot(label, packets, "anomalies", not args.no_save)
    if args.stats_only:
        return run_one_shot(label, packets, "stats", not args.no_save)
    if args.full:
        return run_one_shot(label, packets, "full", not args.no_save)
    return run_interactive(label, packets, do_save=not args.no_save)


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

    # 0. "Which interface can I even record from?" - answer and exit.
    if args.list_interfaces:
        return list_interfaces_and_exit()

    # 1. Online mode: record from an interface, then analyze it in memory.
    if args.live:
        if args.pcap:
            ui.warning("A capture file was also given; --live takes precedence "
                       "and the file argument is ignored.")
        return run_live(args)

    # 2. Offline mode: which capture file? From the command line, or by asking.
    pcap_path = args.pcap
    if not pcap_path:
        pcap_path = ask_for_path()
        if not pcap_path:
            ui.error("No capture file given - nothing to analyze.")
            return 1

    # 3. Make sure output/, reports/ and pcaps/ exist.
    ensure_output_folders(config.OUTPUT_FOLDER, config.REPORTS_FOLDER,
                          config.PCAPS_FOLDER)

    # 4. Load the packets (friendly errors, no traceback for beginners).
    packets = load_capture(pcap_path)
    if packets is None:
        # load_capture already printed exactly what went wrong.
        return 1
    if not packets:
        return 0  # an empty capture was already reported

    # 5. One-shot modes, or the interactive menu (the default).
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
