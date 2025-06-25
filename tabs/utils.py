import streamlit as st
import os
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from sklearn.metrics import precision_score, recall_score, f1_score
from streamlit_autorefresh import st_autorefresh
from influxdb_client import InfluxDBClient
import requests
import sqlitecloud
import warnings

# --- DoS Settings (Hardcoded) ---
API_URL = st.secrets.get("API_URL", "")
DISCORD_WEBHOOK = st.secrets.get("DISCORD_WEBHOOK", "")
INFLUXDB_URL = st.secrets.get("INFLUXDB_URL", "")
INFLUXDB_ORG = st.secrets.get("INFLUXDB_ORG", "")
INFLUXDB_BUCKET = st.secrets.get("INFLUXDB_BUCKET", "")
INFLUXDB_TOKEN = st.secrets.get("INFLUXDB_TOKEN", "")
SQLITE_HOST = st.secrets.get("SQLITE_HOST", "")
SQLITE_PORT = int(st.secrets.get("SQLITE_PORT", 8860))
SQLITE_DB = st.secrets.get("SQLITE_DB", "")
SQLITE_APIKEY = st.secrets.get("SQLITE_APIKEY", "")


# --- Debugging the InfluxDB URL ---
st.write("DoS InfluxDB URL:", DOS_INFLUXDB_URL)  # Debugging line

# --- Discord Alert for DoS ---
def send_discord_alert(result):
    message = {
        "content": (
            f"\U0001f6a8 **DoS Anomaly Detected!**\n"
            f"**Timestamp:** {result.get('timestamp')}\n"
            f"**DoS Rate:** {result.get('dos_rate')}\n"
            f"**Inter-arrival Time:** {result.get('inter_arrival_time')}\n"
            f"**Reconstruction Error:** {float(result.get('reconstruction_error', 0)):.6f}\n"
            f"**Source IP:** {result.get('source_ip')}\n"
            f"**Destination IP:** {result.get('dest_ip')}"
        )
    }
    try:
        requests.post(DOS_DISCORD_WEBHOOK, json=message, timeout=20)
    except Exception as e:
        st.warning(f"Discord alert failed: {e}")

# --- SQLiteCloud Loader for DoS ---
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

        conn = sqlitecloud.connect(f"sqlitecloud://{DOS_SQLITE_HOST}:{DOS_SQLITE_PORT}/{DOS_SQLITE_DB}?apikey={DOS_SQLITE_APIKEY}")
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

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=AttributeError)
            conn.close()

        return df.dropna(subset=["timestamp"])
    except Exception as e:
        st.error(f"SQLite Cloud error: {e}")
        return pd.DataFrame()

# --- SQLiteCloud Logger for DoS ---
def log_to_sqlitecloud(record):
    try:
        conn = sqlitecloud.connect(f"sqlitecloud://{DOS_SQLITE_HOST}:{DOS_SQLITE_PORT}/{DOS_SQLITE_DB}?apikey={DOS_SQLITE_APIKEY}")
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
            "DoS",
            float(record.get("reconstruction_error", 0)),
            int(record.get("anomaly", 0))
        ))
        conn.commit()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=AttributeError)
            conn.close()
    except Exception as e:
        st.warning(f"SQLite Cloud insert failed: {e}")

# --- Get Real-time DoS Data ---
def get_dos_data():
    try:
        if not DOS_INFLUXDB_URL:
            raise ValueError("No host specified.")
        with InfluxDBClient(url=DOS_INFLUXDB_URL, token=DOS_INFLUXDB_TOKEN, org=DOS_INFLUXDB_ORG) as client:
            query = f'''
            from(bucket: "{DOS_INFLUXDB_BUCKET}")
            |> range(start: -5m)
            |> filter(fn: (r) => r._measurement == "dos")
            |> filter(fn: (r) => r._field == "inter_arrival_time" or r._field == "dos_rate")
            |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
            |> sort(columns: ["_time"], desc: false)
            '''
            tables = client.query_api().query(query)
            rows = []
            for table in tables:
                for record in table.records:
                    rows.append({
                        "timestamp": record.get_time().strftime("%Y-%m-%d %H:%M:%S"),
                        "inter_arrival_time": record.values.get("inter_arrival_time", 0.0),
                        "dos_rate": record.values.get("dos_rate", 0.0),
                        "source_ip": record.values.get("source_ip", "unknown"),
                        "dest_ip": record.values.get("dest_ip", "unknown")
                    })
            return rows
    except Exception as e:
        st.warning(f"Failed to fetch live DoS data from InfluxDB: {e}")
        return []

# --- Get Historical DoS Data ---
@st.cache_data(ttl=600)
def get_historical(start, end):
    try:
        if not DOS_INFLUXDB_URL:  # Check if the URL is missing
            raise ValueError("No host specified.")
        
        # Ensure start and end are in the correct string format
        start_str = start.isoformat()
        end_str = end.isoformat()

        with InfluxDBClient(url=DOS_INFLUXDB_URL, token=DOS_INFLUXDB_TOKEN, org=DOS_INFLUXDB_ORG) as client:
            query = f'''
            from(bucket: "{DOS_INFLUXDB_BUCKET}")
            |> range(start: {start_str}, stop: {end_str})
            |> filter(fn: (r) => r._measurement == "dos")
            |> filter(fn: (r) => r._field == "inter_arrival_time" or r._field == "dos_rate")
            |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
            |> sort(columns: ["_time"], desc: false)
            '''
            tables = client.query_api().query(query)
            rows = []
            for table in tables:
                for record in table.records:
                    d = record.values.copy()
                    d["timestamp"] = record.get_time()
                    rows.append(d)
            return pd.DataFrame(rows)
    except Exception as e:
        st.error(f"Error retrieving historical DoS data: {e}")
        return pd.DataFrame()

# --- Summary Dashboard Helpers ---
def generate_attack_summary(df):
    if df.empty:
        return None, None

    top_ips = df["source_ip"].value_counts().nlargest(5).reset_index()
    top_ips.columns = ["source_ip", "count"]

    avg_error = df["anomaly_score"].mean()
    summary = {
        "total_records": len(df),
        "avg_error": round(avg_error, 4),
        "top_ips": top_ips
    }
    return summary, top_ips

def display_summary_cards(summary):
    if not summary:
        st.info("No recent data to summarize.")
        return

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Records", summary["total_records"])
    col2.metric("Avg Reconstruction Error", summary["avg_error"])
    with col3:
        st.markdown("**Top Source IPs**")
        for _, row in summary["top_ips"].iterrows():
            st.write(f"{row['source_ip']}: {row['count']}")
