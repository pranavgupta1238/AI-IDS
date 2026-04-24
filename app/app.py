from flask import Flask, jsonify, render_template
from datetime import datetime, timezone
import pandas as pd
from zoneinfo import ZoneInfo

import os

app = Flask(__name__)

LOG_PATH = "/logs/conn.log"

def load_dataframe(limit=None):
    if not os.path.exists(LOG_PATH):
        return pd.DataFrame()

    try:
        df = pd.read_csv(LOG_PATH, sep="\t", comment="#", low_memory=False)
        if limit:
            df = df.tail(limit)
        return df
    except Exception as e:
        print("Error reading logs:", e)
        return pd.DataFrame()


def format_timestamp(ts):
    return datetime.fromtimestamp(float(ts), tz=timezone.utc) \
        .astimezone(ZoneInfo("Asia/Kolkata")) \
        .strftime('%Y-%m-%d %H:%M:%S')


def clean_duration(value):
    if value == '-' or pd.isna(value):
        return 0.0
    return float(value)


def read_logs():
    df = load_dataframe(limit=80)
    if df.empty:
        return []

    logs = []

    for _, row in df.iterrows():
        try:
            duration = clean_duration(row[8])
            port = row[5]
            if port == '-' or pd.isna(port):
                port = "N/A"

            logs.append({
                "time": format_timestamp(row[0]),
                "src": row[2],
                "dst": row[4],
                "duration": f"{duration:.6f}",
                "port": port,
                "proto": row[6],
                "state": row[11],
                "orig_pkts": int(row[16]) if row[16] != '-' and not pd.isna(row[16]) else 0,
                "resp_pkts": int(row[18]) if row[18] != '-' and not pd.isna(row[18]) else 0,
            })
        except Exception:
            continue
    return logs


def build_dashboard_data():
    df = load_dataframe(limit=500)
    if df.empty:
        return {
            "metrics": {
                "total_connections": 0,
                "unique_sources": 0,
                "top_source": "N/A",
                "top_source_count": 0,
                "target_port": "N/A",
                "risk_score": 0,
            },
            "timeline": [],
            "top_sources": [],
            "ports": [],
            "protocols": [],
            "status": "Connection issue with log file",
        }

    df = df.copy()
    df["time_label"] = df.iloc[:, 0].apply(format_timestamp)
    df["minute"] = df["time_label"].str.slice(11, 16)
    df["duration_clean"] = df.iloc[:, 8].apply(clean_duration)

    src_counts = df.iloc[:, 2].value_counts()
    port_counts = df.iloc[:, 5].replace("-", "N/A").value_counts()
    proto_counts = df.iloc[:, 6].replace("-", "unknown").value_counts()
    timeline_counts = df.groupby("minute").size().tail(12)

    top_source = str(src_counts.index[0]) if not src_counts.empty else "N/A"
    top_source_count = int(src_counts.iloc[0]) if not src_counts.empty else 0
    target_port = str(port_counts.index[0]) if not port_counts.empty else "N/A"
    total_connections = int(len(df))
    risk_score = min(100, round((top_source_count / max(total_connections, 1)) * 100))

    return {
        "metrics": {
            "total_connections": total_connections,
            "unique_sources": int(df.iloc[:, 2].nunique()),
            "top_source": top_source,
            "top_source_count": top_source_count,
            "target_port": target_port,
            "risk_score": risk_score,
        },
        "timeline": [{"label": str(k), "value": int(v)} for k, v in timeline_counts.items()],
        "top_sources": [{"label": str(k), "value": int(v)} for k, v in src_counts.head(5).items()],
        "ports": [{"label": str(k), "value": int(v)} for k, v in port_counts.head(5).items()],
        "protocols": [{"label": str(k).upper(), "value": int(v)} for k, v in proto_counts.head(4).items()],
        "status": f"Attack Detected from {top_source}" if top_source_count > 150 else "Normal Traffic",
    }


def detect_attack():
    dashboard = build_dashboard_data()
    if dashboard["status"].startswith("Attack"):
        return f"Attack Detected from {dashboard['metrics']['top_source']}"
    return dashboard["status"]

@app.route("/")
def home():
    logs = read_logs()
    dashboard = build_dashboard_data()
    return render_template("index.html", logs=logs, dashboard=dashboard)

@app.route("/status")
def status():
    dashboard = build_dashboard_data()
    return jsonify({
        "status": detect_attack(),
        "dashboard": dashboard,
    })


app.run(host="0.0.0.0", port=5000, debug=True)
