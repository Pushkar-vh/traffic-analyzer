"""Central configuration: paths, size classes and detection thresholds.

Every value here can be tuned without touching the analysis code. Most
detection thresholds can also be overridden from the command line
(see ``python analyzer.py analyze --help``).
"""

from pathlib import Path

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = BASE_DIR / "samples"
OUTPUT_DIR = BASE_DIR / "output"
LOG_FILE_NAME = "analyzer.log"

# File extensions picked up by the ``batch`` command.
CAPTURE_EXTENSIONS = (".pcap", ".pcapng", ".cap")

# --------------------------------------------------------------------------
# Parsing / statistics
# --------------------------------------------------------------------------
# Number of entries shown in "Top N" tables and charts.
TOP_N = 10

# Packet size classes: (label, inclusive lower bound, exclusive upper bound).
# ``None`` as the upper bound means "no limit".
SIZE_CLASSES = (
    ("Small (<64B)", 0, 64),
    ("Medium (64-511B)", 64, 512),
    ("Large (512-1023B)", 512, 1024),
    ("Jumbo (>=1024B)", 1024, None),
)

# UDP/TCP ports treated as DNS traffic (classic DNS and multicast DNS).
DNS_PORTS = frozenset({53, 5353})

# --------------------------------------------------------------------------
# Detection thresholds
# --------------------------------------------------------------------------
# Port scan: a single source touching at least this many distinct
# destination ports inside the sliding window is flagged.
PORT_SCAN_UNIQUE_PORTS = 100
PORT_SCAN_WINDOW_SECONDS = 60.0

# Rate spike: a time bucket is flagged when its packet count exceeds
# ``RATE_SPIKE_MULTIPLIER`` x the capture's average rate AND is at least
# ``RATE_SPIKE_MIN_PACKETS`` packets (avoids noise on tiny captures).
RATE_BUCKET_SECONDS = 1.0
RATE_SPIKE_MULTIPLIER = 3.0
RATE_SPIKE_MIN_PACKETS = 50

# Heavy talker: one source responsible for at least this share of all
# packets (and at least ``HEAVY_TALKER_MIN_PACKETS`` packets).
HEAVY_TALKER_SHARE = 0.40
HEAVY_TALKER_MIN_PACKETS = 500

# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
CHART_DPI = 110
NO_TRAFFIC_MESSAGE = "No traffic found"
