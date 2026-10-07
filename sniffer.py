"""Live packet reading with Scapy's ``sniff``.

Prints a one-line summary of every packet as it arrives and (by default)
saves the packets to a ``.pcap`` file in ``output/`` so the capture can be
analyzed afterwards with the normal pipeline (CLI, HTML report or the
Streamlit dashboard).

Usage examples::

    python sniffer.py --list-interfaces
    python sniffer.py                                   # until Ctrl+C
    python sniffer.py --iface "Wi-Fi" --count 500
    python sniffer.py --timeout 60 --filter "tcp or udp" --analyze

Requirements:
    * Windows: Npcap (https://npcap.com). Run the terminal as Administrator
      if Npcap was installed with "restrict to administrators".
    * Linux/macOS: run with ``sudo`` (or grant CAP_NET_RAW to Python).

Only capture traffic on networks and devices you own or are explicitly
authorized to monitor.
"""

import argparse
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

from scapy.all import PcapWriter, get_working_ifaces, sniff
from scapy.error import Scapy_Exception

import config

LOGGER = logging.getLogger(__name__)

PERMISSION_HINT = (
    "Live capture needs raw-socket access. On Windows install Npcap and run "
    "the terminal as Administrator; on Linux/macOS run with sudo."
)


def packet_callback(packet):
    """Print a one-line summary of a captured packet."""
    print(packet.summary())


class LiveCapture:
    """Callback object: prints packets, counts them and optionally saves."""

    def __init__(self, output_file=None, quiet=False):
        self.output_file = Path(output_file) if output_file else None
        self.quiet = quiet
        self.packets = 0
        self.bytes = 0
        self.started = time.time()
        self._writer = None
        if self.output_file:
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            # sync=True flushes every packet, so Ctrl+C never loses data.
            self._writer = PcapWriter(str(self.output_file), sync=True)

    def __call__(self, packet):
        self.packets += 1
        self.bytes += len(packet)
        if not self.quiet:
            packet_callback(packet)
        if self._writer:
            self._writer.write(packet)

    def close(self):
        if self._writer:
            self._writer.close()

    def summary(self):
        duration = time.time() - self.started
        return {
            "packets": self.packets,
            "bytes": self.bytes,
            "duration_seconds": round(duration, 1),
            "output_file": self.output_file if self.packets else None,
        }


def default_output_file():
    """``output/live_YYYYmmdd_HHMMSS.pcap``."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return config.OUTPUT_DIR / f"live_{stamp}.pcap"


def start_capture(iface=None, bpf_filter=None, count=0, timeout=None,
                  output_file=None, quiet=False):
    """Read live packets until ``count``/``timeout`` is reached or Ctrl+C.

    Args:
        iface: Interface name (see ``--list-interfaces``); None = default.
        bpf_filter: Optional BPF filter, e.g. ``"tcp port 443"``.
        count: Stop after this many packets (0 = no limit).
        timeout: Stop after this many seconds (None = no limit).
        output_file: Save packets to this .pcap (None = don't save).
        quiet: Do not print per-packet summaries.

    Returns:
        Dict with packets, bytes, duration_seconds and output_file
        (None when nothing was captured or saving was disabled).

    Raises:
        PermissionError: Raw capture is not allowed for this user.
    """
    capture = LiveCapture(output_file, quiet)
    target = iface or "default interface"
    print(f"Starting live packet capture on {target}... (Ctrl+C to stop)")
    LOGGER.info("Live capture started on %s filter=%s", target, bpf_filter)
    try:
        sniff(prn=capture, store=False, iface=iface, filter=bpf_filter,
              count=count, timeout=timeout)
    except KeyboardInterrupt:
        pass
    except (PermissionError, OSError, RuntimeError, Scapy_Exception) as exc:
        raise PermissionError(f"{exc}\n{PERMISSION_HINT}") from exc
    finally:
        capture.close()

    result = capture.summary()
    _remove_empty_file(output_file, result["packets"])
    LOGGER.info("Live capture stopped: %s", result)
    return result


def _remove_empty_file(output_file, packets):
    if output_file and packets == 0 and Path(output_file).exists():
        Path(output_file).unlink()


def list_interfaces():
    """Print interfaces usable for capture."""
    print(f"{'Name':35} {'IPv4':16} Description")
    for iface in get_working_ifaces():
        print(f"{iface.name[:35]:35} {(iface.ip or '-'):16} "
              f"{iface.description}")


def print_result(result):
    print(f"\nCapture stopped: {result['packets']:,} packets, "
          f"{result['bytes']:,} bytes in {result['duration_seconds']} s")
    if result["output_file"]:
        print(f"Saved to: {Path(result['output_file']).resolve()}")
    elif result["packets"] == 0:
        print(config.NO_TRAFFIC_MESSAGE)


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------
def add_capture_arguments(arg_parser):
    """Capture options shared with ``analyzer.py live``."""
    arg_parser.add_argument("-i", "--iface", default=None,
                            help="Interface to read from (default: system "
                                 "default). See --list-interfaces.")
    arg_parser.add_argument("-f", "--filter", dest="bpf_filter",
                            default=None,
                            help='BPF filter, e.g. "tcp port 443".')
    arg_parser.add_argument("-c", "--count", type=int, default=0,
                            help="Stop after N packets (0 = unlimited).")
    arg_parser.add_argument("-t", "--timeout", type=float, default=None,
                            help="Stop after N seconds.")
    arg_parser.add_argument("-w", "--write", type=Path, default=None,
                            help="Save packets to this .pcap "
                                 "(default: output/live_<time>.pcap).")
    arg_parser.add_argument("--no-save", action="store_true",
                            help="Only print packets; do not save a .pcap.")
    arg_parser.add_argument("-q", "--quiet", action="store_true",
                            help="Do not print per-packet summaries.")


def capture_from_args(args):
    """Run :func:`start_capture` with parsed CLI arguments."""
    output_file = None if args.no_save else (args.write
                                             or default_output_file())
    return start_capture(iface=args.iface, bpf_filter=args.bpf_filter,
                         count=args.count, timeout=args.timeout,
                         output_file=output_file, quiet=args.quiet)


def build_arg_parser():
    arg_parser = argparse.ArgumentParser(
        prog="sniffer", description="Live packet reading with Scapy.")
    arg_parser.add_argument("--list-interfaces", action="store_true",
                            help="Show capture interfaces and exit.")
    arg_parser.add_argument("--analyze", action="store_true",
                            help="Run the full analysis on the saved "
                                 "capture when it stops.")
    add_capture_arguments(arg_parser)
    return arg_parser


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    if args.list_interfaces:
        list_interfaces()
        return 0
    try:
        result = capture_from_args(args)
    except PermissionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print_result(result)

    if args.analyze and result["output_file"]:
        import analyzer  # imported lazily: only needed for --analyze
        report_name = f"{Path(result['output_file']).stem}_report.csv"
        return analyzer.main(["analyze", str(result["output_file"]),
                              report_name])
    return 0


if __name__ == "__main__":
    sys.exit(main())
