"""pcap -> DataFrame conversion engine.

The parser streams packets from a local capture file with Scapy's
``PcapReader`` (pcap and pcapng are both supported) and turns every packet
into one flat record. No live capture is ever performed.

Resulting DataFrame columns
---------------------------
timestamp   float   Epoch seconds of the packet.
datetime    ts      Same as ``timestamp`` as a UTC pandas Timestamp.
src_ip      str     Source IPv4/IPv6 address (None for non-IP frames).
dst_ip      str     Destination IPv4/IPv6 address (None for non-IP frames).
ip_version  Int64   4, 6 or <NA>.
transport   str     TCP, UDP, ICMP or None.
protocol    str     TCP, UDP, ICMP, DNS, ARP, OTHER-IP or OTHER.
src_port    Int64   Source port (<NA> when not TCP/UDP).
dst_port    Int64   Destination port (<NA> when not TCP/UDP).
tcp_flags   str     Scapy flag string such as "S", "SA", "PA" (TCP only).
length      int     Original packet length on the wire in bytes.
size_class  cat     Size bucket defined in ``config.SIZE_CLASSES``.
"""

import logging
import math
import struct
from pathlib import Path

import pandas as pd
from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, IPv6, PcapReader
from scapy.error import Scapy_Exception

import config

LOGGER = logging.getLogger(__name__)

ICMPV6_NEXT_HEADER = 58

COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "ip_version",
    "transport",
    "protocol",
    "src_port",
    "dst_port",
    "tcp_flags",
    "length",
]


class PcapParseError(Exception):
    """Raised when a capture file cannot be read as pcap/pcapng."""


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def parse_pcap(file_path, max_packets=None):
    """Parse a local capture file into a pandas DataFrame.

    Args:
        file_path: Path to a ``.pcap``/``.pcapng`` file.
        max_packets: Optional cap on the number of packets read.

    Returns:
        DataFrame with the columns documented in the module docstring.
        The frame is empty (but has all columns) if the file has no packets.

    Raises:
        FileNotFoundError: The file does not exist.
        PcapParseError: The file is not a readable capture.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Capture file not found: {path}")

    LOGGER.info("Parsing %s", path)
    records = _read_records(path, max_packets)
    frame = _build_frame(records)
    LOGGER.info("Parsed %d packets from %s", len(frame), path.name)
    return frame


def aggregate_size_classes(frame):
    """Aggregate packets and bytes per size class.

    Returns a DataFrame with columns ``size_class``, ``packets``,
    ``bytes`` and ``percent`` (share of packets). Every configured size
    class is present, even when its count is zero.
    """
    labels = [label for label, _, _ in config.SIZE_CLASSES]
    if frame.empty:
        return pd.DataFrame(
            {"size_class": labels, "packets": 0, "bytes": 0, "percent": 0.0}
        )

    grouped = frame.groupby("size_class", observed=False)["length"]
    table = pd.DataFrame(
        {"packets": grouped.count(), "bytes": grouped.sum()}
    ).reindex(labels, fill_value=0)
    table["percent"] = (table["packets"] / len(frame) * 100).round(2)
    table.index.name = "size_class"
    return table.reset_index()


def group_by_protocol(frame):
    """Return packets and bytes per protocol, largest first."""
    if frame.empty:
        return pd.DataFrame(columns=["protocol", "packets", "bytes"])
    grouped = frame.groupby("protocol")["length"]
    table = pd.DataFrame({"packets": grouped.count(), "bytes": grouped.sum()})
    table = table.sort_values("packets", ascending=False)
    return table.reset_index()


def classify_size(lengths):
    """Map a Series of packet lengths onto the configured size classes."""
    edges = [lower for _, lower, _ in config.SIZE_CLASSES]
    last_upper = config.SIZE_CLASSES[-1][2]
    edges.append(math.inf if last_upper is None else last_upper)
    labels = [label for label, _, _ in config.SIZE_CLASSES]
    return pd.cut(lengths, bins=edges, labels=labels, right=False)


# --------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------
def _read_records(path, max_packets):
    """Read packets from ``path`` and convert each one into a dict."""
    records = []
    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                if max_packets is not None and len(records) >= max_packets:
                    break
                records.append(_packet_to_record(packet))
    except (Scapy_Exception, struct.error, EOFError, ValueError) as exc:
        if not records:
            raise PcapParseError(
                f"{path.name} is not a readable pcap/pcapng file: {exc}"
            ) from exc
        # A truncated tail is common in real captures: keep what we have.
        LOGGER.warning(
            "Stopped reading %s after %d packets: %s",
            path.name, len(records), exc,
        )
    return records


def _packet_to_record(packet):
    """Flatten a single Scapy packet into a record dict."""
    src_ip, dst_ip, ip_version = _extract_ips(packet)
    transport, src_port, dst_port, flags = _extract_transport(packet)
    protocol = _classify_protocol(packet, transport, src_port, dst_port)
    length = getattr(packet, "wirelen", None) or len(packet)
    return {
        "timestamp": float(packet.time),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "ip_version": ip_version,
        "transport": transport,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_flags": flags,
        "length": int(length),
    }


def _extract_ips(packet):
    """Return (src, dst, version) for IPv4/IPv6 packets."""
    if packet.haslayer(IP):
        layer = packet[IP]
        return layer.src, layer.dst, 4
    if packet.haslayer(IPv6):
        layer = packet[IPv6]
        return layer.src, layer.dst, 6
    return None, None, None


def _extract_transport(packet):
    """Return (transport, src_port, dst_port, tcp_flags)."""
    # ICMP is checked first: ICMP error messages quote the original
    # TCP/UDP header, which must not be counted as real TCP/UDP traffic.
    if packet.haslayer(ICMP) or _is_icmpv6(packet):
        return "ICMP", None, None, None
    if packet.haslayer(TCP):
        layer = packet[TCP]
        return "TCP", int(layer.sport), int(layer.dport), str(layer.flags)
    if packet.haslayer(UDP):
        layer = packet[UDP]
        return "UDP", int(layer.sport), int(layer.dport), None
    return None, None, None, None


def _is_icmpv6(packet):
    return packet.haslayer(IPv6) and packet[IPv6].nh == ICMPV6_NEXT_HEADER


def _classify_protocol(packet, transport, src_port, dst_port):
    """Pick the protocol label used for grouping."""
    if transport == "ICMP":
        return "ICMP"
    is_dns_port = src_port in config.DNS_PORTS or dst_port in config.DNS_PORTS
    if transport and (packet.haslayer(DNS) or is_dns_port):
        return "DNS"
    if transport:
        return transport
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(IP) or packet.haslayer(IPv6):
        return "OTHER-IP"
    return "OTHER"


# --------------------------------------------------------------------------
# DataFrame construction
# --------------------------------------------------------------------------
def _build_frame(records):
    """Create a typed DataFrame from the list of packet records."""
    frame = pd.DataFrame.from_records(records, columns=COLUMNS)
    frame["timestamp"] = frame["timestamp"].astype("float64")
    frame["length"] = frame["length"].astype("int64")
    for column in ("ip_version", "src_port", "dst_port"):
        frame[column] = frame[column].astype("Int64")
    frame["datetime"] = pd.to_datetime(frame["timestamp"], unit="s", utc=True)
    frame["size_class"] = classify_size(frame["length"])
    return frame.sort_values("timestamp", kind="stable").reset_index(drop=True)
