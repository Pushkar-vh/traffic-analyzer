# traffic-analyzer

A modular Python tool that reads **local** capture files (`.pcap` / `.pcapng`), analyzes the traffic by protocol, finds anomalies such as port scans and rate spikes, and writes CSV and HTML reports with charts.

> **Static analysis only.** The tool never captures live traffic, never opens network sockets and needs no admin rights. It only reads files you give it.

---

## Features

| Module | What it does |
|---|---|
| `parser.py` | Turns a pcap into a pandas DataFrame using Scapy. It pulls out source and destination IPs, ports, TCP flags and packet size. It groups packets by protocol (TCP, UDP, ICMP, DNS, ARP, OTHER) and sorts them into size classes (Small < 64 B, Medium, Large, Jumbo). |
| `stats.py` | Protocol share (%), Top 10 source and destination IPs, packet counts per IP pair, total bytes, size statistics and a traffic timeline. |
| `detectors.py` | `detect_port_scan(ip, ports)` uses a sliding time window. `detect_rate_spike(avg_rate, ...)` flags bursts. A heavy-talker check flags hosts that send a large share of all packets. |
| `report.py` | Writes a summary CSV and one CSV per table. It draws Matplotlib charts (PNG) and builds a self-contained HTML report with a **Security Alerts** section. |
| `analyzer.py` | The `traffic-analyzer` command-line tool (argparse). |
| `config.py` | Paths, size classes and every detection threshold. |

---

## Requirements

* Python **3.9+**
* `scapy`, `pandas`, `matplotlib` (listed in `requirements.txt`)
* You do **not** need Wireshark, Npcap or libpcap, because only files are read.

---

## Step-by-step: install and run

### 1. Get the project and open its folder

```bash
cd traffic-analyzer
```

### 2. Create a virtual environment (recommended)

```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate

# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install the dependencies

```bash
pip install -r requirements.txt
```

### 4. Analyze a capture

```bash
python analyzer.py analyze samples/traffic.pcap report.csv
```

Sample console output:

```
=== samples/traffic.pcap ===
Packets: 6,412   Bytes: 1,574,413   Duration: 119.737 s
Protocols: TCP 70.52%, UDP 23.39%, DNS 4.93%, ICMP 1.15%
Alerts: 2
  [HIGH] Rate spike: Traffic burst of 757 packets/bucket at +90s (14.2x the average of 53.4); lasted 2 bucket(s).
  [HIGH] Port scan: 192.0.2.66 probed 400 distinct ports within 60s (400 distinct ports, 400 attempts in total).
CSV report : .../output/report.csv
HTML report: .../output/report.html
```

### 5. Open the reports

* `output/report.csv`: the summary table
* `output/report.html`: open it in any browser. It works offline because the charts are embedded.

### 6. (Optional) Analyze every file in `samples/`

```bash
python analyzer.py batch
```

This writes `output/<name>_report.csv` and `output/<name>_report.html` for each capture.

### 7. (Optional) Use the short `traffic-analyzer` command

The CLI is named `traffic-analyzer`, so you can run `traffic-analyzer analyze input.pcap report.csv` after adding a shell alias:

```bash
# Linux / macOS (bash/zsh): add to ~/.bashrc or ~/.zshrc
alias traffic-analyzer="python /path/to/traffic-analyzer/analyzer.py"

# Windows PowerShell: add to $PROFILE
function traffic-analyzer { python C:\path\to\traffic-analyzer\analyzer.py @args }
```

```bash
traffic-analyzer analyze samples/eth_test.pcap report.csv
```

---

## CLI reference

```
traffic-analyzer [-v] analyze INPUT REPORT [options]
traffic-analyzer [-v] batch [--samples-dir DIR] [options]
```

| Option | Default | Meaning |
|---|---|---|
| `INPUT` | | `.pcap` / `.pcapng` file to analyze |
| `REPORT` | | Path for the summary CSV. A bare file name such as `report.csv` is saved in `output/`. A path with a folder, such as `./reports/x.csv`, is used as given. |
| `--html PATH` | next to CSV | Where to write the HTML report |
| `--no-html` | off | Write CSVs only (no charts, no HTML) |
| `--output-dir DIR` | `output/` | Folder for charts, detail CSVs and `analyzer.log` |
| `--max-packets N` | all | Read only the first N packets |
| `--top N` | 10 | Number of rows in the top-talker tables |
| `--scan-ports N` | 100 | Distinct ports in one window that count as a port scan |
| `--scan-window S` | 60 | Length of the port-scan sliding window, in seconds |
| `--spike-multiplier X` | 3.0 | A time bucket counts as a spike when it is above the average × X |
| `--bucket S` | 1.0 | Size of each timeline bucket, in seconds |
| `-v / --verbose` | off | Print debug logs to the console |

Exit codes: `0` success, `1` at least one file failed in `batch`, `2` missing or unreadable input file.

---

## Output files

For an input called `traffic.pcap` with `report.csv` as the report name:

| File | Content |
|---|---|
| `report.csv` | Summary table with columns `section, name, packets, bytes, percent, detail`. Sections: `overview`, `protocol`, `top_source`, `top_destination`, `ip_pair`, `size_class`, `size_stat`, `alert` |
| `report.html` | Full report: overview, **Security Alerts**, charts and tables |
| `traffic_protocols.csv`, `traffic_top_sources.csv`, `traffic_top_destinations.csv`, `traffic_ip_pairs.csv`, `traffic_size_classes.csv`, `traffic_alerts.csv` | One table per file, ready for Excel or pandas |
| `traffic_1_protocol_distribution.png` | Protocol distribution bar chart |
| `traffic_2_top_ip_talkers.png` | Top source and destination IPs |
| `traffic_3_traffic_volume_by_size_class.png` | Packets per size class, with byte totals |
| `traffic_4_traffic_timeline.png` | Packets per second compared with the average |
| `analyzer.log` | Run log |

If a capture contains no packets, the CSV and HTML say **"No traffic found"**. No data is made up.

---

## How detection works

* **Port scan**: For each source IP, the tool collects "connection attempts". These are TCP packets without the ACK flag (SYN, FIN, NULL and Xmas probes) and all UDP datagrams. A sliding window of `PORT_SCAN_WINDOW_SECONDS` moves over them, and the tool records the highest number of distinct destination ports seen in one window. Reaching `PORT_SCAN_UNIQUE_PORTS` raises a MEDIUM alert. Reaching twice that number raises a HIGH alert.
* **Rate spike**: Packets are counted per time bucket, and empty buckets count as 0. A bucket is a spike when it is above `avg_rate × RATE_SPIKE_MULTIPLIER` and has at least `RATE_SPIKE_MIN_PACKETS` packets. Spike buckets next to each other are merged into one alert. A spike of 10× the average or more is HIGH.
* **Heavy talker** (LOW): One source sends at least `HEAVY_TALKER_SHARE` of all packets, with a minimum of `HEAVY_TALKER_MIN_PACKETS`.

All thresholds are in `config.py`.

---

## Sample data

`samples/` contains two synthetic captures. They only use the IP ranges reserved for documentation (RFC 5737) and private ranges:

* `eth_test.pcap`: about 260 packets of normal Ethernet traffic (HTTPS sessions, DNS lookups, ping, one ARP). It is expected to produce **no alerts**.
* `traffic.pcap`: about 6,400 packets over 120 seconds. Normal background traffic plus a SYN scan of 400 ports from `192.0.2.66` (starting at +40 s) and a 2-second UDP flood from `192.0.2.99` (starting at +90 s). It is expected to produce **port scan** and **rate spike** alerts.

You can drop your own `.pcap` / `.pcapng` files into `samples/` and run `python analyzer.py batch`.

---

## Notes

* Python 3.9 includes an old built-in module named `parser`. `analyzer.py` loads the project's own `parser.py` by file path so the two can't be mixed up. Always run the tool through `analyzer.py`.
* Very large captures are read packet by packet, but every packet is still kept in memory as a DataFrame row. Use `--max-packets` to analyze only part of a large file.
* Sizes are on-the-wire lengths (`wirelen` if the file records it, otherwise the captured length).
