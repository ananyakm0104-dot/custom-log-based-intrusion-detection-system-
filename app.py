from flask import Flask, jsonify
import os
from datetime import datetime

app = Flask(__name__)

LOG_FILE = os.path.expanduser("~/ctf/custom-ids/wireshark_ids_log.txt")

def read_alerts():
    alerts = []
    if not os.path.exists(LOG_FILE):
        return alerts
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
    for line in lines:
        line = line.strip()
        if not line or "===" in line or "IDS Session" in line:
            continue
        if "SSH" in line:
            alert_type = "ssh"
            icon = "🔐"
        elif "PORT SCAN" in line:
            alert_type = "portscan"
            icon = "🚨"
        elif "ARP" in line:
            alert_type = "arp"
            icon = "⚠️"
        else:
            continue
        alerts.append({"message": line, "type": alert_type, "icon": icon})
    return alerts[-50:]

@app.route("/")
def index():
    html = open(os.path.expanduser("~/ctf/custom-ids/IDS_Website.html")).read()
    return html

@app.route("/api/alerts")
def get_alerts():
    alerts = read_alerts()
    return jsonify({"alerts": alerts, "total": len(alerts)})

@app.route("/api/stats")
def get_stats():
    alerts = read_alerts()
    return jsonify({
        "ssh": sum(1 for a in alerts if a["type"] == "ssh"),
        "arp": sum(1 for a in alerts if a["type"] == "arp"),
        "portscan": sum(1 for a in alerts if a["type"] == "portscan"),
        "total": len(alerts)
    })

if __name__ == "__main__":
    print("🌐 IDS Dashboard → http://localhost:5000")
    app.run(debug=True, port=5000)
