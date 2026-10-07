# traffic-analyzer

A modular Python tool that reads capture files (`.pcap` / `.pcapng`), analyzes the traffic by protocol, finds anomalies such as port scans and rate spikes, and writes CSV and HTML reports with charts. It can also record live traffic from a network interface (`sniffer.py`) and analyze the recording.

> **File analysis needs no special rights.** The `analyze` and `batch` commands and the dashboard only read files. Live capture (`sniffer.py` / `analyzer.py live`) is optional. It needs Npcap on Windows (or root on Linux/macOS). Only capture on networks and devices you own or are allowed to monitor.

---

## Features

| Module | What it does |
|---|---|
| `parser.py` | Turns a pcap into a pandas DataFrame using Scapy. It pulls out source and destination IPs, ports, TCP flags and packet size. It groups packets by protocol (TCP, UDP, ICMP, DNS, ARP, OTHER) and sorts them into size classes (Small < 64 B, Medium, Large, Jumbo). |
| `stats.py` | Protocol share (%), Top 10 source and destination IPs, packet counts per IP pair, total bytes, size statistics and a traffic timeline. |
| `detectors.py` | `detect_port_scan(ip, ports)` uses a sliding time window. `detect_rate_spike(avg_rate, ...)` flags bursts. A heavy-talker check flags hosts that send a large share of all packets. |
| `report.py` | Writes a summary CSV and one CSV per table. It draws Matplotlib charts (PNG) and builds a self-contained HTML report with a **Security Alerts** section. |
| `analyzer.py` | The `traffic-analyzer` command-line tool (argparse). |
| `app.py` | Interactive **Streamlit** dashboard (same engine as the CLI). |
| `sniffer.py` | Live packet reading with Scapy `sniff()`. It prints a summary of each packet and saves the packets to `output/live_<time>.pcap`. It can run the analysis automatically when the capture stops. |
| `config.py` | Paths, size classes and every detection threshold. |

---

## Requirements

* Python **3.9+**
* `scapy`, `pandas`, `matplotlib`, `streamlit` (listed in `requirements.txt`). Streamlit is only needed for the dashboard.
* To analyze files you do **not** need Wireshark, Npcap or libpcap.
* For **live capture only**: [Npcap](https://npcap.com) on Windows (tick *"WinPcap API-compatible mode"* when installing), or `sudo` on Linux/macOS.

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

### 7. View the results in the Streamlit dashboard

```bash
streamlit run app.py
```

Your browser opens at <http://localhost:8501>. In the sidebar:

1. **Capture file**: choose a file from `samples/` or upload your own `.pcap` / `.pcapng` / `.cap`. You can also limit how many packets are read.
2. **Detection thresholds**: change the top-N count, the port-scan settings, the rate-spike settings and the timeline bucket size. The results update right away. The file is parsed only once and then cached.

The main page shows:

* **Overview cards**: packets, total bytes, duration, average rate and number of alerts.
* **Security Alerts**: HIGH alerts appear in red, MEDIUM in orange and LOW in blue.
* **Tabs**: Protocols, Top talkers, Size classes, an interactive Timeline (you can zoom), IP pairs, and a preview of the raw packets.
* **Export**: download the summary CSV or the alerts CSV. **Save full report to output/** writes the same files as the CLI (CSVs, PNG charts and HTML) and then lets you download the HTML.

> On Windows, if the page does not load and the terminal shows `WinError 64 ... Accept failed on a socket`, start Streamlit on the IPv4 loopback address:
> `streamlit run app.py --server.address 127.0.0.1` and open <http://127.0.0.1:8501>.

### 8. (Optional) Live packet reading with `sniffer.py`

```bash
python sniffer.py --list-interfaces              # find your interface name, e.g. "Wi-Fi"
python sniffer.py                                # print packets until Ctrl+C, save output/live_<time>.pcap
python sniffer.py --iface "Wi-Fi" --count 500    # stop after 500 packets
python sniffer.py --timeout 60 --filter "tcp or udp" --analyze   # 60 s, then full report
python sniffer.py --count 50 --no-save           # print only, do not save
```

Each packet is printed as one line as it arrives, for example:

```
Starting live packet capture on default interface... (Ctrl+C to stop)
Ether / IP / TCP 10.42.36.115:51234 > 203.0.113.10:https S
Ether / ARP who has 10.42.28.59 says 10.42.30.204 / Padding
...
Capture stopped: 500 packets, 182,113 bytes in 12.4 s
Saved to: .../output/live_20261007_122030.pcap
```

You can also capture and analyze in one step from the main CLI:

```bash
python analyzer.py live --timeout 60                 # capture 60 s, then CSV + HTML report
python analyzer.py live live_report.csv --count 1000 --iface "Wi-Fi"
```

To look at a live capture in the dashboard, run `streamlit run app.py` and choose it under **output/** in the sidebar.

| sniffer option | Meaning |
|---|---|
| `-i / --iface NAME` | Interface to read from (default: system default) |
| `-f / --filter BPF` | Capture filter, e.g. `"tcp port 443"`, `"host 10.0.0.5"` |
| `-c / --count N` | Stop after N packets (0 = no limit) |
| `-t / --timeout S` | Stop after S seconds |
| `-w / --write FILE` | Save to this `.pcap` instead of `output/live_<time>.pcap` |
| `--no-save` | Only print packets |
| `-q / --quiet` | Do not print each packet |
| `--analyze` | Run the full analysis when the capture stops (`sniffer.py` only) |
| `--list-interfaces` | Show the available interfaces |

Press **Ctrl+C** to stop at any time. Packets are written to the file as they arrive, so nothing is lost when you stop. If you get a permission error, open the terminal as **Administrator** on Windows or use `sudo` on Linux/macOS.

### 9. (Optional) Use the short `traffic-analyzer` command

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
traffic-analyzer [-v] live [REPORT] [--no-analyze] [sniffer options] [options]
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

Exit codes: `0` success, `1` at least one file failed in `batch`, `2` missing or unreadable input file, or no permission for live capture.

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

You can drop your own `.pcap` / `.pcapng` files into `samples/` and run `python analyzer.py batch`.HELLO

---

## Notes

* Python 3.9 includes an old built-in module named `parser`. `analyzer.py` loads the project's own `parser.py` by file path so the two can't be mixed up. Always run the tool through `analyzer.py`.
* Very large captures are read packet by packet, but every packet is still kept in memory as a DataFrame row. Use `--max-packets` to analyze only part of a large file.
* Sizes are on-the-wire lengths (`wirelen` if the file records it, otherwise the captured length).
#   t r a f f i c - a n a l y z e r 
 
 
