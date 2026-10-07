"""Traffic metrics: protocol mix, top talkers, IP pairs, sizes and volume.

All functions take the DataFrame produced by ``parser.parse_pcap`` and
return plain pandas objects or dicts, so they are easy to test and reuse.
"""

import pandas as pd

import config


def total_bytes(frame):
    """Total bytes transferred (sum of on-the-wire packet lengths)."""
    return int(frame["length"].sum()) if not frame.empty else 0


def protocol_distribution(frame):
    """Packets, bytes and percentage of packets per protocol."""
    columns = ["protocol", "packets", "bytes", "percent"]
    if frame.empty:
        return pd.DataFrame(columns=columns)
    grouped = frame.groupby("protocol")["length"]
    table = pd.DataFrame({"packets": grouped.count(), "bytes": grouped.sum()})
    table["percent"] = (table["packets"] / len(frame) * 100).round(2)
    table = table.sort_values("packets", ascending=False).reset_index()
    return table[columns]


def top_sources(frame, top_n=config.TOP_N):
    """Top ``top_n`` source IPs by packet count."""
    return _top_ips(frame, "src_ip", top_n)


def top_destinations(frame, top_n=config.TOP_N):
    """Top ``top_n`` destination IPs by packet count."""
    return _top_ips(frame, "dst_ip", top_n)


def ip_pair_counts(frame, top_n=None):
    """Packets and bytes per (source, destination) IP pair."""
    columns = ["src_ip", "dst_ip", "packets", "bytes"]
    ip_frame = frame.dropna(subset=["src_ip", "dst_ip"])
    if ip_frame.empty:
        return pd.DataFrame(columns=columns)
    grouped = ip_frame.groupby(["src_ip", "dst_ip"])["length"]
    table = pd.DataFrame({"packets": grouped.count(), "bytes": grouped.sum()})
    table = table.sort_values(["packets", "bytes"], ascending=False)
    table = table.reset_index()[columns]
    return table.head(top_n) if top_n else table


def size_statistics(frame):
    """Descriptive statistics of packet sizes in bytes."""
    if frame.empty:
        return {key: 0 for key in ("min", "max", "mean", "median", "std")}
    lengths = frame["length"]
    return {
        "min": int(lengths.min()),
        "max": int(lengths.max()),
        "mean": round(float(lengths.mean()), 2),
        "median": round(float(lengths.median()), 2),
        "std": round(float(lengths.std(ddof=0)), 2),
    }


def capture_overview(frame):
    """High-level numbers describing the whole capture."""
    if frame.empty:
        return {
            "packets": 0, "bytes": 0, "start": None, "end": None,
            "duration_seconds": 0.0, "avg_packets_per_second": 0.0,
            "avg_bytes_per_second": 0.0, "unique_sources": 0,
            "unique_destinations": 0,
        }
    duration = float(frame["timestamp"].max() - frame["timestamp"].min())
    divisor = duration if duration > 0 else 1.0
    byte_total = total_bytes(frame)
    return {
        "packets": int(len(frame)),
        "bytes": byte_total,
        "start": frame["datetime"].min(),
        "end": frame["datetime"].max(),
        "duration_seconds": round(duration, 3),
        "avg_packets_per_second": round(len(frame) / divisor, 2),
        "avg_bytes_per_second": round(byte_total / divisor, 2),
        "unique_sources": int(frame["src_ip"].nunique()),
        "unique_destinations": int(frame["dst_ip"].nunique()),
    }


def traffic_timeline(frame, bucket_seconds=config.RATE_BUCKET_SECONDS):
    """Packets per time bucket, including empty buckets (filled with 0).

    The index is the bucket offset in seconds from the first packet.
    """
    if frame.empty:
        return pd.Series(dtype="int64", name="packets")
    offsets = frame["timestamp"] - frame["timestamp"].min()
    buckets = (offsets // bucket_seconds).astype("int64")
    counts = buckets.value_counts().sort_index()
    full_range = range(int(buckets.max()) + 1)
    counts = counts.reindex(full_range, fill_value=0)
    counts.index = [index * bucket_seconds for index in counts.index]
    counts.name = "packets"
    return counts


def compute_all(frame, size_classes, top_n=config.TOP_N,
                bucket_seconds=config.RATE_BUCKET_SECONDS):
    """Bundle every metric used by the report into one dict.

    Args:
        frame: Parsed packet DataFrame.
        size_classes: Output of ``parser.aggregate_size_classes``.
        top_n: Number of entries in the top-talker tables.
        bucket_seconds: Bucket width of the traffic timeline.
    """
    return {
        "overview": capture_overview(frame),
        "protocols": protocol_distribution(frame),
        "top_sources": top_sources(frame, top_n),
        "top_destinations": top_destinations(frame, top_n),
        "ip_pairs": ip_pair_counts(frame, top_n),
        "size_classes": size_classes,
        "size_stats": size_statistics(frame),
        "timeline": traffic_timeline(frame, bucket_seconds),
        "bucket_seconds": bucket_seconds,
    }


def _top_ips(frame, column, top_n):
    """Shared implementation for top source/destination tables."""
    columns = ["ip", "packets", "bytes", "percent"]
    ip_frame = frame.dropna(subset=[column])
    if ip_frame.empty:
        return pd.DataFrame(columns=columns)
    grouped = ip_frame.groupby(column)["length"]
    table = pd.DataFrame({"packets": grouped.count(), "bytes": grouped.sum()})
    table["percent"] = (table["packets"] / len(frame) * 100).round(2)
    table = table.sort_values(["packets", "bytes"], ascending=False)
    table = table.head(top_n).reset_index()
    table = table.rename(columns={column: "ip"})
    return table[columns]
