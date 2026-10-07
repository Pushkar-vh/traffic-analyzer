"""traffic-analyzer: offline pcap analysis CLI.

Usage examples::

    python analyzer.py analyze samples/traffic.pcap report.csv
    python analyzer.py analyze samples/eth_test.pcap report.csv --no-html
    python analyzer.py batch

Only local capture files are read; the tool never sniffs a live network.
"""

import argparse
import importlib.util
import logging
import sys
from pathlib import Path

import config


def _load_local_module(name):
    """Import a module from this project's directory by file path.

    Python 3.9 ships a (deprecated) built-in ``parser`` module that, on
    some platforms, shadows our local ``parser.py``. Loading it explicitly
    by path guarantees the project module is used.
    """
    path = config.BASE_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


pcap_parser = _load_local_module("parser")

import detectors  # noqa: E402
import report  # noqa: E402
import stats  # noqa: E402

LOGGER = logging.getLogger("traffic-analyzer")


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------
def build_arg_parser():
    """Create the ``traffic-analyzer`` argument parser."""
    arg_parser = argparse.ArgumentParser(
        prog="traffic-analyzer",
        description="Static analysis of local .pcap/.pcapng capture files.",
    )
    arg_parser.add_argument("-v", "--verbose", action="store_true",
                            help="Print debug logging to the console.")
    commands = arg_parser.add_subparsers(dest="command", required=True)

    analyze = commands.add_parser("analyze", help="Analyze one capture file.")
    analyze.add_argument("input", type=Path, help="Input .pcap/.pcapng file.")
    analyze.add_argument(
        "report", type=Path,
        help="Summary CSV path. A bare file name is written into the "
             "output directory.")
    analyze.add_argument("--html", type=Path, default=None,
                         help="HTML report path (default: next to the CSV).")
    _add_common_options(analyze)

    batch = commands.add_parser(
        "batch", help="Analyze every capture in a directory.")
    batch.add_argument("--samples-dir", type=Path, default=config.SAMPLES_DIR,
                       help="Directory with captures (default: samples/).")
    _add_common_options(batch)
    return arg_parser


def _add_common_options(sub_parser):
    sub_parser.add_argument("--output-dir", type=Path,
                            default=config.OUTPUT_DIR,
                            help="Directory for charts, CSVs and logs.")
    sub_parser.add_argument("--no-html", action="store_true",
                            help="Skip charts and the HTML report.")
    sub_parser.add_argument("--max-packets", type=int, default=None,
                            help="Only read the first N packets.")
    sub_parser.add_argument("--top", type=int, default=config.TOP_N,
                            help="Entries in top-talker tables.")
    sub_parser.add_argument("--scan-ports", type=int,
                            default=config.PORT_SCAN_UNIQUE_PORTS,
                            help="Distinct ports that flag a port scan.")
    sub_parser.add_argument("--scan-window", type=float,
                            default=config.PORT_SCAN_WINDOW_SECONDS,
                            help="Port-scan sliding window in seconds.")
    sub_parser.add_argument("--spike-multiplier", type=float,
                            default=config.RATE_SPIKE_MULTIPLIER,
                            help="Bucket > average x this = rate spike.")
    sub_parser.add_argument("--bucket", type=float,
                            default=config.RATE_BUCKET_SECONDS,
                            help="Timeline bucket size in seconds.")


def settings_from_args(args):
    """Build detector settings from CLI arguments."""
    return detectors.DetectorSettings(
        port_scan_unique_ports=args.scan_ports,
        port_scan_window_seconds=args.scan_window,
        rate_bucket_seconds=args.bucket,
        rate_spike_multiplier=args.spike_multiplier,
    )


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
def configure_logging(output_dir, verbose):
    """Log to ``output/analyzer.log`` and to the console."""
    output_dir.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(output_dir / config.LOG_FILE_NAME,
                                       encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.WARNING)
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        handlers=[file_handler, console],
    )
    # Keep third-party chatter out of the log.
    for noisy in ("matplotlib", "PIL", "scapy"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


# --------------------------------------------------------------------------
# Analysis pipeline
# --------------------------------------------------------------------------
def resolve_report_paths(report_arg, html_arg, output_dir, no_html):
    """Return (csv_path, html_path or None)."""
    csv_path = report_arg
    if csv_path.parent == Path("."):
        csv_path = output_dir / csv_path.name
    if csv_path.suffix.lower() != ".csv":
        csv_path = csv_path.with_suffix(".csv")
    if no_html:
        return csv_path, None
    return csv_path, html_arg or csv_path.with_suffix(".html")


def analyze_file(input_path, csv_path, html_path, args):
    """Run the full pipeline on one capture. Returns the list of alerts."""
    output_dir = args.output_dir
    frame = pcap_parser.parse_pcap(input_path, max_packets=args.max_packets)

    if frame.empty:
        report.write_empty_report(csv_path, html_path, input_path)
        print(f"{input_path}: {config.NO_TRAFFIC_MESSAGE}")
        return []

    settings = settings_from_args(args)
    size_classes = pcap_parser.aggregate_size_classes(frame)
    metrics = stats.compute_all(frame, size_classes, args.top,
                                settings.rate_bucket_seconds)
    alerts = detectors.run_all_detectors(frame, metrics["timeline"], settings)

    prefix = Path(input_path).stem
    report.write_summary_csv(csv_path, metrics, alerts)
    report.write_detail_csvs(output_dir, prefix, metrics, alerts)
    if html_path:
        charts = report.generate_charts(output_dir, prefix, metrics)
        report.write_html_report(html_path, input_path, metrics, alerts,
                                 charts)

    print_summary(input_path, metrics, alerts, csv_path, html_path)
    return alerts


def print_summary(input_path, metrics, alerts, csv_path, html_path):
    """Short human-readable console summary."""
    overview = metrics["overview"]
    print(f"\n=== {input_path} ===")
    print(f"Packets: {overview['packets']:,}   Bytes: {overview['bytes']:,}"
          f"   Duration: {overview['duration_seconds']} s")
    protocols = ", ".join(
        f"{row.protocol} {row.percent}%"
        for row in metrics["protocols"].itertuples(index=False))
    print(f"Protocols: {protocols}")
    print(f"Alerts: {len(alerts)}")
    for alert in alerts:
        print(f"  [{alert.severity}] {alert.category}: {alert.description}")
    print(f"CSV report : {csv_path.resolve()}")
    if html_path:
        print(f"HTML report: {Path(html_path).resolve()}")


def run_analyze(args):
    csv_path, html_path = resolve_report_paths(
        args.report, args.html, args.output_dir, args.no_html)
    analyze_file(args.input, csv_path, html_path, args)
    return 0


def run_batch(args):
    captures = sorted(
        path for path in args.samples_dir.glob("*")
        if path.suffix.lower() in config.CAPTURE_EXTENSIONS
    )
    if not captures:
        print(f"{args.samples_dir}: {config.NO_TRAFFIC_MESSAGE} "
              "(no capture files)")
        return 1
    failures = 0
    for capture in captures:
        csv_path = args.output_dir / f"{capture.stem}_report.csv"
        html_path = None if args.no_html else csv_path.with_suffix(".html")
        try:
            analyze_file(capture, csv_path, html_path, args)
        except pcap_parser.PcapParseError as exc:
            failures += 1
            LOGGER.error("%s", exc)
    return 1 if failures else 0


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    configure_logging(args.output_dir, args.verbose)
    handlers = {"analyze": run_analyze, "batch": run_batch}
    try:
        return handlers[args.command](args)
    except (FileNotFoundError, pcap_parser.PcapParseError) as exc:
        LOGGER.error("%s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
