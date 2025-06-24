import sqlite3
import pandas as pd
from datetime import datetime, timedelta
import requests
import streamlit as st

# --- API URL ---
API_URL = st.secrets.get("API_URL", "")

# Function to get DNS data (replace this with your actual DNS data retrieval logic)
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

# --- Function to Load Predictions from SQLite Cloud ---
def load_predictions_from_sqlitecloud(time_window="-24h"):
    try:
        if "h" in time_window:
            delta = timedelta(hours=int(time_window.strip("-h")))
        elif "d" in time_window:
            delta = timedelta(days=int(time_window.strip("-d")))
        elif "m" in time_window:
            delta = timedelta(minutes=int(time_window.strip("-m")))
        else:
            delta = timedelta(hours=24)

        cutoff = (datetime.utcnow() - delta).strftime("%Y-%m-%d %H:%M:%S")

        # Connecting to SQLite Cloud database
        conn = sqlite3.connect(f"sqlitecloud://{st.secrets['SQLITE_HOST']}:{st.secrets['SQLITE_PORT']}/{st.secrets['SQLITE_DB']}?apikey={st.secrets['SQLITE_APIKEY']}")
        cursor = conn.execute(f"""
            SELECT * FROM anomalies
            WHERE timestamp >= '{cutoff}'
            ORDER BY timestamp DESC
        """)
        rows = cursor.fetchall()
        if not rows:
            return pd.DataFrame()

        cols = [column[0] for column in cursor.description]
        df = pd.DataFrame(rows, columns=cols)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        
        # Close the connection
        conn.close()
        
        return df.dropna(subset=["timestamp"])
    
    except Exception as e:
        st.error(f"SQLite Cloud error: {e}")
        return pd.DataFrame()

# --- Function to Get Historical Data ---
def get_historical(start_date, end_date):
    try:
        # Establish connection to SQLite Cloud
        conn = sqlite3.connect(f"sqlitecloud://{st.secrets['SQLITE_HOST']}:{st.secrets['SQLITE_PORT']}/{st.secrets['SQLITE_DB']}?apikey={st.secrets['SQLITE_APIKEY']}")
        
        # Query to fetch data based on the given start and end dates
        query = f"""
            SELECT * FROM anomalies
            WHERE timestamp >= '{start_date}' AND timestamp <= '{end_date}'
            ORDER BY timestamp DESC
        """
        
        # Execute query
        cursor = conn.execute(query)
        rows = cursor.fetchall()
        if not rows:
            return pd.DataFrame()

        cols = [column[0] for column in cursor.description]
        df = pd.DataFrame(rows, columns=cols)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        
        # Close the connection
        conn.close()
        
        return df.dropna(subset=["timestamp"])
    
    except Exception as e:
        st.error(f"Error retrieving historical data: {e}")
        return pd.DataFrame()
