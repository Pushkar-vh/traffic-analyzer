"""Streamlit dashboard for traffic-analyzer.

Run with::

    streamlit run app.py

Pick a capture from ``samples/``, a live capture saved by ``sniffer.py``
in ``output/``, or upload a local ``.pcap``/``.pcapng`` file. The dashboard
uses the same parser, statistics, detectors and report code as the
command-line tool.
"""

import os
import tempfile
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

import config
import detectors
import report
import stats
from analyzer import pcap_parser  # loads the project's parser.py safely

SEVERITY_BOXES = {"HIGH": st.error, "MEDIUM": st.warning, "LOW": st.info}
PACKET_PREVIEW_ROWS = 1000


# --------------------------------------------------------------------------
# Data loading (cached so changing a threshold does not re-parse the file)
# --------------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def load_sample(path_text, modified_time, max_packets):
    """Parse a capture from disk. ``modified_time`` busts the cache."""
    del modified_time  # only part of the cache key
    return pcap_parser.parse_pcap(path_text, max_packets=max_packets)


@st.cache_data(show_spinner=False)
def load_upload(file_bytes, suffix, max_packets):
    """Parse uploaded bytes via a temporary file (Scapy needs a path)."""
    handle, temp_path = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(handle, "wb") as temp_file:
            temp_file.write(file_bytes)
        return pcap_parser.parse_pcap(temp_path, max_packets=max_packets)
    finally:
        os.remove(temp_path)


def run_analysis(frame, settings, top_n):
    """Compute metrics and alerts for a parsed capture."""
    size_classes = pcap_parser.aggregate_size_classes(frame)
    metrics = stats.compute_all(frame, size_classes, top_n,
                                settings.rate_bucket_seconds)
    alerts = detectors.run_all_detectors(frame, metrics["timeline"], settings)
    return metrics, alerts


# --------------------------------------------------------------------------
# Sidebar
# --------------------------------------------------------------------------
def sidebar_source():
    """Return (display_name, frame) for the chosen capture, or (None, None)."""
    st.sidebar.header("Capture file")
    mode = st.sidebar.radio("Source", ["Sample file", "Upload file"])
    max_packets = st.sidebar.number_input(
        "Max packets to read (0 = all)", min_value=0, value=0, step=1000)
    limit = int(max_packets) or None

    if mode == "Upload file":
        uploaded = st.sidebar.file_uploader(
            "Choose a capture",
            type=[ext.lstrip(".") for ext in config.CAPTURE_EXTENSIONS])
        if uploaded is None:
            return None, None
        frame = load_upload(uploaded.getvalue(),
                            Path(uploaded.name).suffix, limit)
        return uploaded.name, frame

    samples = _list_captures(config.SAMPLES_DIR)
    samples += _list_captures(config.OUTPUT_DIR)  # saved live captures
    if not samples:
        st.sidebar.warning("No capture files found in samples/ or output/.")
        return None, None
    chosen = st.sidebar.selectbox(
        "Sample / live capture", samples,
        format_func=lambda path: f"{path.parent.name}/{path.name}")
    frame = load_sample(str(chosen), chosen.stat().st_mtime, limit)
    return chosen.name, frame


def _list_captures(directory):
    """Capture files in ``directory`` (empty list if it does not exist)."""
    if not directory.is_dir():
        return []
    return sorted(path for path in directory.glob("*")
                  if path.suffix.lower() in config.CAPTURE_EXTENSIONS)


def sidebar_settings():
    """Return (DetectorSettings, top_n) from the threshold widgets."""
    st.sidebar.header("Detection thresholds")
    top_n = st.sidebar.slider("Top N talkers", 5, 25, config.TOP_N)
    scan_ports = st.sidebar.number_input(
        "Port scan: distinct ports", min_value=2,
        value=config.PORT_SCAN_UNIQUE_PORTS, step=10)
    scan_window = st.sidebar.number_input(
        "Port scan: window (s)", min_value=1.0,
        value=config.PORT_SCAN_WINDOW_SECONDS, step=5.0)
    multiplier = st.sidebar.slider(
        "Rate spike: x average", 1.5, 20.0, config.RATE_SPIKE_MULTIPLIER, 0.5)
    min_spike = st.sidebar.number_input(
        "Rate spike: min packets/bucket", min_value=1,
        value=config.RATE_SPIKE_MIN_PACKETS, step=10)
    bucket = st.sidebar.select_slider(
        "Timeline bucket (s)", options=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0],
        value=config.RATE_BUCKET_SECONDS)
    settings = detectors.DetectorSettings(
        port_scan_unique_ports=int(scan_ports),
        port_scan_window_seconds=float(scan_window),
        rate_bucket_seconds=float(bucket),
        rate_spike_multiplier=float(multiplier),
        rate_spike_min_packets=int(min_spike),
    )
    return settings, top_n


# --------------------------------------------------------------------------
# Main page sections
# --------------------------------------------------------------------------
def show_overview(metrics, alerts):
    overview = metrics["overview"]
    columns = st.columns(5)
    columns[0].metric("Packets", f"{overview['packets']:,}")
    columns[1].metric("Total bytes", report.human_bytes(overview["bytes"]))
    columns[2].metric("Duration", f"{overview['duration_seconds']:.1f} s")
    columns[3].metric("Avg rate", f"{overview['avg_packets_per_second']} pkt/s")
    columns[4].metric("Alerts", len(alerts))
    st.caption(
        f"{overview['start']} to {overview['end']} | "
        f"{overview['unique_sources']} unique sources, "
        f"{overview['unique_destinations']} unique destinations")


def show_alerts(alerts):
    st.subheader("Security Alerts")
    if not alerts:
        st.success("No anomalies detected with the current thresholds.")
        return
    for alert in alerts:
        box = SEVERITY_BOXES.get(alert.severity, st.info)
        when = alert.to_dict()["time_utc"]
        suffix = f"  \n_{when}_" if when else ""
        box(f"**[{alert.severity}] {alert.category}**: "
            f"{alert.description}{suffix}")


def show_figure(fig):
    st.pyplot(fig)
    plt.close(fig)


def show_tabs(frame, metrics):
    tabs = st.tabs(["Protocols", "Top talkers", "Size classes",
                    "Timeline", "IP pairs", "Packets"])
    with tabs[0]:
        show_figure(report.plot_protocol_distribution(metrics["protocols"]))
        st.dataframe(metrics["protocols"], hide_index=True)
    with tabs[1]:
        show_figure(report.plot_top_talkers(metrics))
        left, right = st.columns(2)
        left.markdown("**Top source IPs**")
        left.dataframe(metrics["top_sources"], hide_index=True)
        right.markdown("**Top destination IPs**")
        right.dataframe(metrics["top_destinations"], hide_index=True)
    with tabs[2]:
        show_figure(report.plot_size_classes(metrics["size_classes"]))
        st.dataframe(metrics["size_classes"], hide_index=True)
        st.json(metrics["size_stats"])
    with tabs[3]:
        show_timeline(metrics)
    with tabs[4]:
        st.dataframe(metrics["ip_pairs"], hide_index=True)
    with tabs[5]:
        st.caption(f"First {PACKET_PREVIEW_ROWS:,} of {len(frame):,} packets")
        preview = frame.head(PACKET_PREVIEW_ROWS).copy()
        preview["size_class"] = preview["size_class"].astype(str)
        st.dataframe(preview, hide_index=True)


def show_timeline(metrics):
    """Interactive line chart of packets per bucket vs. the average."""
    timeline = metrics["timeline"]
    chart = pd.DataFrame({
        "packets": timeline.values,
        "average": float(timeline.mean()),
    }, index=pd.Index(timeline.index, name="seconds since first packet"))
    st.caption(f"Packets per {metrics['bucket_seconds']:g}s bucket "
               "(drag to zoom, double-click to reset)")
    st.line_chart(chart)


def show_exports(source_name, metrics, alerts):
    st.subheader("Export")
    stem = Path(source_name).stem
    col_csv, col_alerts, col_html = st.columns(3)
    col_csv.download_button(
        "Summary CSV", report.summary_csv_text(metrics, alerts),
        file_name=f"{stem}_report.csv", mime="text/csv")
    col_alerts.download_button(
        "Alerts CSV",
        detectors.alerts_to_frame(alerts).to_csv(index=False),
        file_name=f"{stem}_alerts.csv", mime="text/csv")
    if col_html.button("Save full report to output/"):
        html_path = save_full_report(stem, source_name, metrics, alerts)
        st.session_state["html_report"] = (html_path.name,
                                           html_path.read_bytes())
        st.success(f"Saved CSVs, charts and HTML to {config.OUTPUT_DIR}")
    saved = st.session_state.get("html_report")
    if saved and saved[0].startswith(stem):
        col_html.download_button("Download HTML report", saved[1],
                                 file_name=saved[0], mime="text/html")


def save_full_report(stem, source_name, metrics, alerts):
    """Write the same files as the CLI into the output directory."""
    output_dir = config.OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / f"{stem}_report.csv"
    html_path = csv_path.with_suffix(".html")
    report.write_summary_csv(csv_path, metrics, alerts)
    report.write_detail_csvs(output_dir, stem, metrics, alerts)
    charts = report.generate_charts(output_dir, stem, metrics)
    report.write_html_report(html_path, source_name, metrics, alerts, charts)
    return html_path


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def main():
    st.set_page_config(page_title="Traffic Analyzer", layout="wide")
    st.title("Network Traffic Analyzer")
    st.caption("Analysis of .pcap/.pcapng files. Record live traffic with "
               "`python sniffer.py`, then pick it under output/ in the sidebar.")

    try:
        with st.spinner("Parsing capture..."):
            source_name, frame = sidebar_source()
    except (FileNotFoundError, pcap_parser.PcapParseError) as exc:
        st.error(str(exc))
        return
    settings, top_n = sidebar_settings()

    if frame is None:
        st.info("Choose a sample or upload a capture file in the sidebar.")
        return
    if frame.empty:
        st.warning(f"{source_name}: {config.NO_TRAFFIC_MESSAGE}")
        return

    metrics, alerts = run_analysis(frame, settings, top_n)
    st.header(source_name)
    show_overview(metrics, alerts)
    show_alerts(alerts)
    show_tabs(frame, metrics)
    show_exports(source_name, metrics, alerts)


main()
