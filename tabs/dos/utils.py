# tabs/dos/utils.py
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

# --- DOS Secrets ---
API_URL = st.secrets.get("DOS_API_URL", "")
DISCORD_WEBHOOK = st.secrets.get("DOS_DISCORD_WEBHOOK", "")
INFLUXDB_URL = st.secrets.get("DOS_INFLUXDB_URL", "")
INFLUXDB_ORG = st.secrets.get("DOS_INFLUXDB_ORG", "")
INFLUXDB_BUCKET = st.secrets.get("DOS_INFLUXDB_BUCKET", "")
INFLUXDB_TOKEN = st.secrets.get("DOS_INFLUXDB_TOKEN", "")
SQLITE_HOST = st.secrets.get("DOS_SQLITE_HOST", "")
SQLITE_PORT = int(st.secrets.get("DOS_SQLITE_PORT", 8860))
SQLITE_DB = st.secrets.get("DOS_SQLITE_DB", "")
SQLITE_APIKEY = st.secrets.get("DOS_SQLITE_APIKEY", "")

# --- Discord Alert ---
def send_discord_alert(result):
    message = {
        "content": (
            f"\U0001f6a8 **DOS Anomaly Detected!**\n"
            f"**Timestamp:** {result.get('timestamp')}\n"
            f"**Byte Rate:** {result.get('byte_rate')}\n"
            f"**Reconstruction Error:** {float(result.get('reconstruction_error', 0)):.6f}\n"
            f"**Source IP:** {result.get('source_ip')}\n"
            f"**Destination IP:** {result.get('dest_ip')}"
        )
    }
    try:
        requests.post(DISCORD_WEBHOOK, json=message, timeout=20)
    except Exception as e:
        st.warning(f"Discord alert failed: {e}")

# --- SQLiteCloud Loader ---
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

        conn = sqlitecloud.connect(f"sqlitecloud://{SQLITE_HOST}:{SQLITE_PORT}/{SQLITE_DB}?apikey={SQLITE_APIKEY}")
        cursor = conn.execute(f"""
            SELECT * FROM dos_anomalies
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

# --- SQLiteCloud Logger ---
def log_to_sqlitecloud(record, db_path="dos"):
    try:
        conn = sqlitecloud.connect(
            f"sqlitecloud://{SQLITE_HOST}:{SQLITE_PORT}/{db_path}?apikey={SQLITE_APIKEY}",
            uri=True,
            check_hostname=False,
            server_hostname=SQLITE_HOST
        )
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dos_anomalies (
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
            INSERT INTO dos_anomalies (timestamp, source_ip, dest_ip, protocol, anomaly_score, is_anomaly)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            record.get("timestamp"),
            record.get("source_ip", "N/A"),
            record.get("dest_ip", "N/A"),
            "DOS",
            float(record.get("reconstruction_error", 0)),
            int(record.get("anomaly", 0))
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        st.warning(f"SQLite Cloud insert failed: {e}")

# --- Get Real-time DOS Data ---
def get_dos_data():
    try:
        if not INFLUXDB_URL:
            raise ValueError("No host specified.")
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
            |> range(start: -5m)
            |> filter(fn: (r) => r._measurement == "network_traffic")
            |> filter(fn: (r) => r._field == "byte_rate")
            |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
            |> sort(columns: ["_time"], desc: false)
            '''
            tables = client.query_api().query(query)
            rows = []
            for table in tables:
                for record in table.records:
                    rows.append({
                        "timestamp": record.get_time().strftime("%Y-%m-%d %H:%M:%S"),
                        "byte_rate": record.values.get("byte_rate", 0.0),
                        "source_ip": record.values.get("source_ip", "unknown"),
                        "dest_ip": record.values.get("dest_ip", "unknown")
                    })
            return rows
    except Exception as e:
        st.warning(f"Failed to fetch live DOS data from InfluxDB: {e}")
        return []

# --- Get Historical DOS Data ---
@st.cache_data(ttl=600)
def get_historical(start, end):
    try:
        if not INFLUXDB_URL:
            raise ValueError("No host specified.")
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
            |> range(start: {start.isoformat()}, stop: {end.isoformat()})
            |> filter(fn: (r) => r._measurement == "network_traffic")
            |> filter(fn: (r) => r._field == "byte_rate")
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
        st.error(f"Error retrieving historical data: {e}")
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

get_dos_historical_data = get_historical
