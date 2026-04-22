from flask import Flask, jsonify, render_template
from datetime import datetime
import pandas as pd
import os

app = Flask(__name__)

LOG_PATH = "/logs/conn.log"

def read_logs():
    if not os.path.exists(LOG_PATH):
        return []

    try:
        df = pd.read_csv(LOG_PATH, sep="\t", comment="#")

        # Take last 50 rows (for performance + UI)
        df = df.tail(50)

        logs = []

        for _, row in df.iterrows():
            # Convert timestamp
            timestamp = datetime.fromtimestamp(row[0]).strftime('%Y-%m-%d %H:%M:%S')

            logs.append({
                "time": timestamp,
                "src": row[2],
                "dst": row[4],
                "duration": f"{float(row[8]):.6f}",
                "port": row[5]
            })

        return logs

    except:
        return []

def detect_attack():
    if not os.path.exists(LOG_PATH):
        return "Connection issue with log file"

    try:
        df = pd.read_csv(LOG_PATH, sep="\t", comment="#")

        # Take recent logs only (important)
        df = df.tail(200)

        # Count connections per source IP
        src_counts = df.iloc[:, 2].value_counts()

        # Get top talker
        top_ip = src_counts.idxmax()
        top_count = src_counts.max()

        # Threshold (you can tune this)
        if top_count > 50:
            return f"🚨 Attack Detected from {top_ip}"
        else:
            return "✅ Normal Traffic"

    except:
        return "Processing..."

@app.route("/")
def home():
    logs = read_logs()   # ✅ pass logs to UI
    return render_template("index.html", logs=logs)

@app.route("/status")
def status():
    return jsonify({"status": detect_attack()})


app.run(host="0.0.0.0", port=5000, debug=True)
