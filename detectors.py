"""Anomaly detection: port scans, rate spikes and heavy talkers.

Detectors work on the parsed DataFrame only (static, offline analysis) and
return a list of :class:`Alert` objects. Thresholds come from ``config.py``
and can be overridden through :class:`DetectorSettings`.
"""

from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Tuple

import pandas as pd

import config

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@dataclass(frozen=True)
class Alert:
    """A single security finding."""

    severity: str
    category: str
    source: str
    description: str
    value: float
    timestamp: Optional[float] = None

    def to_dict(self):
        record = asdict(self)
        record["time_utc"] = _format_ts(self.timestamp)
        return record


@dataclass
class DetectorSettings:
    """Tunable thresholds (defaults come from ``config.py``)."""

    port_scan_unique_ports: int = config.PORT_SCAN_UNIQUE_PORTS
    port_scan_window_seconds: float = config.PORT_SCAN_WINDOW_SECONDS
    rate_bucket_seconds: float = config.RATE_BUCKET_SECONDS
    rate_spike_multiplier: float = config.RATE_SPIKE_MULTIPLIER
    rate_spike_min_packets: int = config.RATE_SPIKE_MIN_PACKETS
    heavy_talker_share: float = config.HEAVY_TALKER_SHARE
    heavy_talker_min_packets: int = config.HEAVY_TALKER_MIN_PACKETS


# --------------------------------------------------------------------------
# Port scan
# --------------------------------------------------------------------------
def detect_port_scan(
    ip: str,
    ports: Iterable[Tuple[float, int]],
    threshold: int = config.PORT_SCAN_UNIQUE_PORTS,
    window_seconds: float = config.PORT_SCAN_WINDOW_SECONDS,
) -> Optional[Alert]:
    """Detect a port scan from one source using a sliding time window.

    Args:
        ip: Source IP address being evaluated.
        ports: Iterable of ``(timestamp, destination_port)`` connection
            attempts made by ``ip``.
        threshold: Distinct destination ports inside one window that
            trigger an alert.
        window_seconds: Width of the sliding window.

    Returns:
        An :class:`Alert` when the peak number of distinct ports inside any
        window reaches ``threshold``, otherwise ``None``.
    """
    events = sorted((float(ts), int(port)) for ts, port in ports)
    peak_ports, peak_ts = _peak_unique_ports(events, window_seconds)
    if peak_ports < threshold:
        return None

    severity = "HIGH" if peak_ports >= 2 * threshold else "MEDIUM"
    total_ports = len({port for _, port in events})
    description = (
        f"{ip} probed {peak_ports} distinct ports within "
        f"{window_seconds:g}s ({total_ports} distinct ports, "
        f"{len(events)} attempts in total)."
    )
    return Alert(severity, "Port scan", ip, description,
                 float(peak_ports), peak_ts)


def _peak_unique_ports(events, window_seconds):
    """Return (max distinct ports in any window, time of that peak)."""
    window = deque()
    port_counts = Counter()
    peak_ports, peak_ts = 0, None
    for ts, port in events:
        window.append((ts, port))
        port_counts[port] += 1
        while ts - window[0][0] > window_seconds:
            _, old_port = window.popleft()
            port_counts[old_port] -= 1
            if port_counts[old_port] == 0:
                del port_counts[old_port]
        if len(port_counts) > peak_ports:
            peak_ports, peak_ts = len(port_counts), ts
    return peak_ports, peak_ts


def scan_all_sources(frame, settings: DetectorSettings) -> List[Alert]:
    """Run :func:`detect_port_scan` for every source IP in the capture."""
    attempts = _connection_attempts(frame)
    if attempts.empty:
        return []

    # Cheap pre-filter: a source can only exceed the threshold inside a
    # window if it exceeds it over the whole capture.
    unique_ports = attempts.groupby("src_ip")["dst_port"].nunique()
    candidates = unique_ports[unique_ports >= settings.port_scan_unique_ports]

    alerts = []
    for ip in candidates.index:
        rows = attempts[attempts["src_ip"] == ip]
        events = zip(rows["timestamp"], rows["dst_port"])
        alert = detect_port_scan(
            ip, events,
            threshold=settings.port_scan_unique_ports,
            window_seconds=settings.port_scan_window_seconds,
        )
        if alert:
            alerts.append(alert)
    return alerts


def _connection_attempts(frame):
    """Rows that represent connection attempts towards a port.

    * TCP packets without the ACK flag (SYN, FIN, NULL and Xmas probes).
    * All UDP datagrams.
    """
    has_port = frame["dst_port"].notna() & frame["src_ip"].notna()
    flags = frame["tcp_flags"].fillna("")
    tcp_probe = (frame["transport"] == "TCP") & ~flags.str.contains("A")
    udp_probe = frame["transport"] == "UDP"
    attempts = frame.loc[has_port & (tcp_probe | udp_probe)]
    return attempts[["timestamp", "src_ip", "dst_port"]]


# --------------------------------------------------------------------------
# Rate spike
# --------------------------------------------------------------------------
def detect_rate_spike(
    avg_rate: float,
    bucket_counts: pd.Series,
    multiplier: float = config.RATE_SPIKE_MULTIPLIER,
    min_packets: int = config.RATE_SPIKE_MIN_PACKETS,
    start_ts: float = 0.0,
) -> List[Alert]:
    """Flag time buckets whose packet count is far above the average.

    Args:
        avg_rate: Average packets per bucket over the whole capture.
        bucket_counts: Packets per bucket; index = offset in seconds from
            the first packet (see ``stats.traffic_timeline``).
        multiplier: A bucket is a spike when ``count > avg_rate * multiplier``.
        min_packets: Minimum packets in a bucket to be considered a spike.
        start_ts: Epoch timestamp of the first packet (for alert times).

    Returns:
        One alert per run of consecutive spike buckets.
    """
    if bucket_counts.empty or avg_rate <= 0:
        return []
    limit = max(avg_rate * multiplier, min_packets)
    spikes = bucket_counts[bucket_counts > limit]
    return [
        _spike_alert(run, avg_rate, start_ts)
        for run in _consecutive_runs(spikes, bucket_counts)
    ]


def _consecutive_runs(spikes, bucket_counts):
    """Group spike buckets that are adjacent in the timeline."""
    positions = [bucket_counts.index.get_loc(offset) for offset in spikes.index]
    runs, current = [], []
    for position in positions:
        if current and position != current[-1] + 1:
            runs.append(bucket_counts.iloc[current])
            current = []
        current.append(position)
    if current:
        runs.append(bucket_counts.iloc[current])
    return runs


def _spike_alert(run, avg_rate, start_ts):
    peak = int(run.max())
    peak_offset = float(run.idxmax())
    ratio = peak / avg_rate
    severity = "HIGH" if ratio >= 10 else "MEDIUM"
    description = (
        f"Traffic burst of {peak} packets/bucket at +{peak_offset:g}s "
        f"({ratio:.1f}x the average of {avg_rate:.1f}); "
        f"lasted {len(run)} bucket(s)."
    )
    return Alert(severity, "Rate spike", "capture-wide", description,
                 float(peak), start_ts + peak_offset)


# --------------------------------------------------------------------------
# Heavy talker
# --------------------------------------------------------------------------
def detect_heavy_talkers(frame, settings: DetectorSettings) -> List[Alert]:
    """Flag sources responsible for a disproportionate share of packets."""
    sources = frame["src_ip"].dropna()
    if sources.empty:
        return []
    counts = sources.value_counts()
    alerts = []
    for ip, packets in counts.items():
        share = packets / len(frame)
        if share < settings.heavy_talker_share:
            break
        if packets < settings.heavy_talker_min_packets:
            continue
        description = (
            f"{ip} sent {packets} packets ({share:.1%} of all traffic)."
        )
        alerts.append(Alert("LOW", "Heavy talker", ip, description,
                            float(packets)))
    return alerts


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
def run_all_detectors(frame, timeline, settings=None) -> List[Alert]:
    """Run every detector and return alerts sorted by severity.

    Args:
        frame: Parsed packet DataFrame.
        timeline: Packets per bucket (``stats.traffic_timeline``).
        settings: Optional :class:`DetectorSettings` overrides.
    """
    if frame.empty:
        return []
    settings = settings or DetectorSettings()
    alerts = scan_all_sources(frame, settings)
    alerts += detect_rate_spike(
        avg_rate=float(timeline.mean()) if not timeline.empty else 0.0,
        bucket_counts=timeline,
        multiplier=settings.rate_spike_multiplier,
        min_packets=settings.rate_spike_min_packets,
        start_ts=float(frame["timestamp"].min()),
    )
    alerts += detect_heavy_talkers(frame, settings)
    return sorted(alerts, key=lambda alert: (
        SEVERITY_ORDER.get(alert.severity, 99), -alert.value))


def alerts_to_frame(alerts: List[Alert]) -> pd.DataFrame:
    """Convert alerts to a DataFrame (used by the CSV/HTML reports)."""
    columns = ["severity", "category", "source", "description", "value",
               "timestamp", "time_utc"]
    return pd.DataFrame([alert.to_dict() for alert in alerts],
                        columns=columns)


def _format_ts(timestamp):
    if timestamp is None:
        return ""
    moment = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")
