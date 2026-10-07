"""Report generation: summary CSV, detail CSVs, PNG charts and HTML report.

Charts are rendered with Matplotlib (headless ``Agg`` backend), saved as PNG
files in the output directory and embedded (base64) into a self-contained
HTML report that can be opened offline in any browser.
"""

import base64
import csv
import html
import io
import logging
from datetime import datetime, timezone
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402  (backend must be set first)

import config  # noqa: E402
from detectors import alerts_to_frame  # noqa: E402

LOGGER = logging.getLogger(__name__)

CSV_FIELDS = ["section", "name", "packets", "bytes", "percent", "detail"]
BAR_COLOR = "#2b6cb0"
ALERT_COLOR = "#c53030"


# --------------------------------------------------------------------------
# CSV output
# --------------------------------------------------------------------------
def build_summary_rows(stats, alerts):
    """Rows of the summary table (protocols, top IPs, sizes, alerts)."""
    rows = _overview_rows(stats)
    rows += _protocol_rows(stats["protocols"])
    rows += _ip_rows("top_source", stats["top_sources"])
    rows += _ip_rows("top_destination", stats["top_destinations"])
    rows += _pair_rows(stats["ip_pairs"])
    rows += _size_rows(stats["size_classes"], stats["size_stats"])
    rows += _alert_rows(alerts)
    return rows


def summary_csv_text(stats, alerts):
    """Summary table as CSV text (used for in-memory downloads)."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(build_summary_rows(stats, alerts))
    return buffer.getvalue()


def write_summary_csv(csv_path, stats, alerts):
    """Write the one-file summary table to ``csv_path``."""
    _write_rows(csv_path, build_summary_rows(stats, alerts))
    LOGGER.info("Summary CSV written to %s", csv_path)
    return Path(csv_path)


def write_detail_csvs(output_dir, prefix, stats, alerts):
    """Write one CSV per table for further processing in other tools."""
    output_dir = Path(output_dir)
    tables = {
        "protocols": stats["protocols"],
        "top_sources": stats["top_sources"],
        "top_destinations": stats["top_destinations"],
        "ip_pairs": stats["ip_pairs"],
        "size_classes": stats["size_classes"],
        "alerts": alerts_to_frame(alerts),
    }
    paths = []
    for name, table in tables.items():
        path = output_dir / f"{prefix}_{name}.csv"
        table.to_csv(path, index=False)
        paths.append(path)
    return paths


def write_empty_report(csv_path, html_path, source_file):
    """Write CSV/HTML stating that the capture contained no packets."""
    rows = [_row("overview", config.NO_TRAFFIC_MESSAGE, packets=0, bytes_=0,
                 detail=str(source_file))]
    _write_rows(csv_path, rows)
    if html_path:
        body = f"<p class='empty'>{html.escape(config.NO_TRAFFIC_MESSAGE)}</p>"
        _write_html(html_path, source_file, body)


def _row(section, name, packets="", bytes_="", percent="", detail=""):
    return {"section": section, "name": name, "packets": packets,
            "bytes": bytes_, "percent": percent, "detail": detail}


def _overview_rows(stats):
    overview = stats["overview"]
    return [
        _row("overview", "Total packets", packets=overview["packets"]),
        _row("overview", "Total bytes", bytes_=overview["bytes"]),
        _row("overview", "Duration (s)", detail=overview["duration_seconds"]),
        _row("overview", "Avg packets/s",
             detail=overview["avg_packets_per_second"]),
        _row("overview", "Avg bytes/s",
             detail=overview["avg_bytes_per_second"]),
        _row("overview", "Unique sources", detail=overview["unique_sources"]),
        _row("overview", "Unique destinations",
             detail=overview["unique_destinations"]),
    ]


def _protocol_rows(table):
    return [
        _row("protocol", item.protocol, item.packets, item.bytes, item.percent)
        for item in table.itertuples(index=False)
    ]


def _ip_rows(section, table):
    return [
        _row(section, item.ip, item.packets, item.bytes, item.percent)
        for item in table.itertuples(index=False)
    ]


def _pair_rows(table):
    return [
        _row("ip_pair", f"{item.src_ip} -> {item.dst_ip}",
             item.packets, item.bytes)
        for item in table.itertuples(index=False)
    ]


def _size_rows(table, size_stats):
    rows = [
        _row("size_class", item.size_class, item.packets, item.bytes,
             item.percent)
        for item in table.itertuples(index=False)
    ]
    rows += [_row("size_stat", f"{key} (bytes)", detail=value)
             for key, value in size_stats.items()]
    return rows


def _alert_rows(alerts):
    if not alerts:
        return [_row("alert", "None", detail="No anomalies detected")]
    return [
        _row("alert", f"{alert.severity} {alert.category}",
             packets=alert.value, detail=alert.description)
        for alert in alerts
    ]


def _write_rows(csv_path, rows):
    csv_path = Path(csv_path)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


# --------------------------------------------------------------------------
# Charts
# --------------------------------------------------------------------------
def generate_charts(output_dir, prefix, stats):
    """Render all charts to PNG. Returns {title: png_path}."""
    output_dir = Path(output_dir)
    charts = {
        "Protocol Distribution": (plot_protocol_distribution,
                                  stats["protocols"]),
        "Top IP Talkers": (plot_top_talkers, stats),
        "Traffic Volume by Size Class": (plot_size_classes,
                                         stats["size_classes"]),
        "Traffic Timeline": (plot_timeline, stats),
    }
    paths = {}
    for index, (title, (plot_func, data)) in enumerate(charts.items(), 1):
        slug = title.lower().replace(" ", "_")
        path = output_dir / f"{prefix}_{index}_{slug}.png"
        plot_func(data, path)
        paths[title] = path
    return paths


def plot_protocol_distribution(table, path=None):
    """Bar chart of packets per protocol, annotated with percentages."""
    fig, axis = plt.subplots(figsize=(8, 4.5))
    bars = axis.bar(table["protocol"], table["packets"], color=BAR_COLOR)
    for bar, percent in zip(bars, table["percent"]):
        axis.annotate(f"{percent:.1f}%",
                      (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                      ha="center", va="bottom", fontsize=9)
    axis.set_title("Protocol Distribution")
    axis.set_xlabel("Protocol")
    axis.set_ylabel("Packets")
    return _finish(fig, path)


def plot_top_talkers(stats, path=None):
    """Side-by-side horizontal bars for top sources and destinations."""
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    panels = (("Top Source IPs", stats["top_sources"]),
              ("Top Destination IPs", stats["top_destinations"]))
    for axis, (title, table) in zip(axes, panels):
        ordered = table.iloc[::-1]
        axis.barh(ordered["ip"], ordered["packets"], color=BAR_COLOR)
        axis.set_title(title)
        axis.set_xlabel("Packets")
        axis.tick_params(axis="y", labelsize=8)
    return _finish(fig, path)


def plot_size_classes(table, path=None):
    """Packets per size class with total bytes annotated on each bar."""
    fig, axis = plt.subplots(figsize=(8, 4.5))
    bars = axis.bar(table["size_class"], table["packets"], color=BAR_COLOR)
    for bar, byte_count in zip(bars, table["bytes"]):
        axis.annotate(human_bytes(byte_count),
                      (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                      ha="center", va="bottom", fontsize=9)
    axis.set_title("Traffic Volume by Size Class (labels = bytes)")
    axis.set_xlabel("Size class")
    axis.set_ylabel("Packets")
    return _finish(fig, path)


def plot_timeline(stats, path=None):
    """Packets per bucket over time with the average line."""
    timeline = stats["timeline"]
    fig, axis = plt.subplots(figsize=(12, 4))
    axis.plot(timeline.index, timeline.values, color=BAR_COLOR, linewidth=1)
    if not timeline.empty:
        axis.axhline(timeline.mean(), color=ALERT_COLOR, linestyle="--",
                     linewidth=1, label=f"average ({timeline.mean():.1f})")
        axis.legend(loc="upper right")
    axis.set_title(f"Packets per {stats['bucket_seconds']:g}s bucket")
    axis.set_xlabel("Seconds since first packet")
    axis.set_ylabel("Packets")
    return _finish(fig, path)


def _finish(fig, path):
    """Save the figure to `path` and close it, or return it if path is None.

    Returning the open figure lets the Streamlit dashboard display it.
    """
    fig.tight_layout()
    if path is None:
        return fig
    fig.savefig(path, dpi=config.CHART_DPI)
    plt.close(fig)
    return None


# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------
def write_html_report(html_path, source_file, stats, alerts, chart_paths):
    """Write a self-contained HTML report (charts embedded as base64)."""
    sections = [
        _overview_html(stats),
        _alerts_html(alerts),
        _charts_html(chart_paths),
        _table_html("Protocol Distribution", stats["protocols"]),
        _table_html("Top 10 Source IPs", stats["top_sources"]),
        _table_html("Top 10 Destination IPs", stats["top_destinations"]),
        _table_html("Top IP Pairs", stats["ip_pairs"]),
        _table_html("Size Classes", stats["size_classes"]),
    ]
    _write_html(html_path, source_file, "\n".join(sections))
    LOGGER.info("HTML report written to %s", html_path)
    return Path(html_path)


def _overview_html(stats):
    overview = stats["overview"]
    size_stats = stats["size_stats"]
    items = {
        "Packets": f"{overview['packets']:,}",
        "Total bytes": f"{overview['bytes']:,} ({human_bytes(overview['bytes'])})",
        "Start": str(overview["start"]),
        "End": str(overview["end"]),
        "Duration": f"{overview['duration_seconds']} s",
        "Avg rate": f"{overview['avg_packets_per_second']} pkt/s",
        "Unique sources": overview["unique_sources"],
        "Unique destinations": overview["unique_destinations"],
        "Packet size (min/mean/max)":
            f"{size_stats['min']} / {size_stats['mean']} / {size_stats['max']} B",
    }
    cells = "".join(
        f"<div class='card'><span>{html.escape(key)}</span>"
        f"<strong>{html.escape(str(value))}</strong></div>"
        for key, value in items.items()
    )
    return f"<h2>Overview</h2><div class='cards'>{cells}</div>"


def _alerts_html(alerts):
    if not alerts:
        return ("<h2>Security Alerts</h2>"
                "<p class='ok'>No anomalies detected with current thresholds.</p>")
    items = "".join(
        f"<li class='sev-{html.escape(alert.severity.lower())}'>"
        f"<b>[{html.escape(alert.severity)}] {html.escape(alert.category)}</b>"
        f" &mdash; {html.escape(alert.description)}"
        f"<small>{html.escape(alert.to_dict()['time_utc'])}</small></li>"
        for alert in alerts
    )
    return (f"<h2>Security Alerts ({len(alerts)})</h2>"
            f"<ul class='alerts'>{items}</ul>")


def _charts_html(chart_paths):
    figures = []
    for title, path in chart_paths.items():
        encoded = base64.b64encode(Path(path).read_bytes()).decode("ascii")
        figures.append(
            f"<figure><img alt='{html.escape(title)}' "
            f"src='data:image/png;base64,{encoded}'>"
            f"<figcaption>{html.escape(title)}</figcaption></figure>"
        )
    return "<h2>Charts</h2>" + "".join(figures)


def _table_html(title, table):
    if table.empty:
        body = f"<p>{html.escape(config.NO_TRAFFIC_MESSAGE)}</p>"
    else:
        body = table.to_html(index=False, border=0, classes="data")
    return f"<h2>{html.escape(title)}</h2>{body}"


def _write_html(html_path, source_file, body):
    html_path = Path(html_path)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    document = HTML_TEMPLATE.format(
        title=html.escape(Path(source_file).name),
        source=html.escape(str(source_file)),
        generated=generated,
        body=body,
    )
    html_path.write_text(document, encoding="utf-8")


def human_bytes(value):
    value = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Traffic report - {title}</title>
<style>
 body {{ font-family: Segoe UI, Arial, sans-serif; margin: 2rem auto;
        max-width: 1200px; color: #1a202c; padding: 0 1rem; }}
 h1 {{ margin-bottom: 0; }} .meta {{ color: #718096; margin-top: .3rem; }}
 h2 {{ border-bottom: 2px solid #e2e8f0; padding-bottom: .3rem;
       margin-top: 2rem; }}
 .cards {{ display: grid; gap: .8rem;
           grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); }}
 .card {{ background: #f7fafc; border: 1px solid #e2e8f0; border-radius: 6px;
          padding: .7rem; }}
 .card span {{ display: block; font-size: .8rem; color: #718096; }}
 ul.alerts {{ list-style: none; padding: 0; }}
 ul.alerts li {{ padding: .6rem .8rem; margin-bottom: .5rem;
                 border-left: 5px solid; border-radius: 4px; }}
 ul.alerts small {{ display: block; color: #718096; }}
 .sev-high {{ background: #fff5f5; border-color: #c53030; }}
 .sev-medium {{ background: #fffaf0; border-color: #dd6b20; }}
 .sev-low {{ background: #ebf8ff; border-color: #3182ce; }}
 .ok {{ color: #276749; }} .empty {{ font-size: 1.3rem; color: #c53030; }}
 table.data {{ border-collapse: collapse; width: 100%; font-size: .9rem; }}
 table.data th, table.data td {{ padding: .35rem .6rem; text-align: left;
                                 border-bottom: 1px solid #e2e8f0; }}
 table.data th {{ background: #edf2f7; }}
 figure {{ margin: 1rem 0; }} img {{ max-width: 100%; }}
 figcaption {{ color: #718096; font-size: .9rem; }}
</style>
</head>
<body>
<h1>Network Traffic Report</h1>
<p class="meta">Source: {source} &middot; Generated: {generated}</p>
{body}
</body>
</html>
"""
