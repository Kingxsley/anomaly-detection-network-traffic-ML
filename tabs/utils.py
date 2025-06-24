import requests
import sqlite3
import pandas as pd
from datetime import datetime
import streamlit as st

# --- API URL ---
API_URL = st.secrets.get("API_URL", "")

# Function to get DNS data from InfluxDB (replace this with your actual implementation)
def get_dns_data():
    # Placeholder function to simulate DNS data fetching
    return [
        {"timestamp": "2021-07-01 12:00:00", "inter_arrival_time": 0.5, "dns_rate": 5.0, "source_ip": "192.168.1.1", "dest_ip": "192.168.1.2"},
        # Add more rows as needed
    ]

# Function to send Discord alert (replace this with your actual implementation)
def send_discord_alert(result):
    discord_webhook = st.secrets.get("DISCORD_WEBHOOK", "")
    message = {
        "content": (
            f"**DNS Anomaly Detected!**\n"
            f"**Timestamp:** {result.get('timestamp')}\n"
            f"**DNS Rate:** {result.get('dns_rate')}\n"
            f"**Inter-arrival Time:** {result.get('inter_arrival_time')}\n"
            f"**Reconstruction Error:** {float(result.get('reconstruction_error', 0)):.6f}\n"
            f"**Source IP:** {result.get('source_ip')}\n"
            f"**Destination IP:** {result.get('dest_ip')}"
        )
    }
    try:
        requests.post(discord_webhook, json=message, timeout=20)
    except Exception as e:
        st.warning(f"Discord alert failed: {e}")

# Function to log predictions to SQLite Cloud
def log_to_sqlitecloud(record):
    try:
        conn = sqlite3.connect(f"sqlitecloud://{st.secrets['SQLITE_HOST']}:{st.secrets['SQLITE_PORT']}/{st.secrets['SQLITE_DB']}?apikey={st.secrets['SQLITE_APIKEY']}")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                protocol TEXT,
                anomaly_score REAL,
                is_anomaly INTEGER
            );
        """)
        conn.execute("""
            INSERT INTO anomalies (timestamp, source_ip, dest_ip, protocol, anomaly_score, is_anomaly)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            record.get("timestamp", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
            record.get("source_ip", "N/A"),
            record.get("dest_ip", "N/A"),
            "DNS" if st.secrets.get("DASHBOARD_TYPE", "DNS") == "DNS" else "DOS",  # Determine the type (DNS/DOS)
            float(record.get("reconstruction_error", 0)),
            int(record.get("anomaly", 0))
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        st.warning(f"SQLite Cloud insert failed: {e}")
