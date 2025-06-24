import streamlit as st
import os
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from sklearn.metrics import precision_score, recall_score, f1_score
from streamlit_autorefresh import st_autorefresh
from influxdb_client import InfluxDBClient

# --- Secrets ---
API_URL = st.secrets.get("API_URL", "")
DISCORD_WEBHOOK = st.secrets.get("DISCORD_WEBHOOK", "")
INFLUXDB_URL = st.secrets.get("INFLUXDB_URL", "")
INFLUXDB_ORG = st.secrets.get("INFLUXDB_ORG", "")
INFLUXDB_BUCKET = st.secrets.get("INFLUXDB_BUCKET", "")
INFLUXDB_TOKEN = st.secrets.get("INFLUXDB_TOKEN", "")
SQLITECLOUD_URL = st.secrets.get("SQLITECLOUD_URL", "")

# --- SQLiteCloud Loader ---
def load_predictions_from_sqlitecloud(time_window="-24h"):
    try:
        import sqlite3
        from urllib.parse import urlparse

        parsed_url = urlparse(SQLITECLOUD_URL)
        db_path = f"/mnt/data/{parsed_url.path.lstrip('/')}"

        if "h" in time_window:
            delta = timedelta(hours=int(time_window.strip("-h")))
        elif "d" in time_window:
            delta = timedelta(days=int(time_window.strip("-d")))
        elif "m" in time_window:
            delta = timedelta(minutes=int(time_window.strip("-m")))
        else:
            delta = timedelta(hours=24)

        cutoff = (datetime.utcnow() - delta).strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        query = f"""
            SELECT * FROM anomalies
            WHERE timestamp >= '{cutoff}'
            ORDER BY timestamp DESC
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        if not rows:
            return pd.DataFrame()
        cols = [column[0] for column in cursor.description]
        df = pd.DataFrame(rows, columns=cols)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df.dropna(subset=["timestamp"])
    except Exception as e:
        st.error(f"SQLite Cloud error: {e}")
        return pd.DataFrame()

# --- SQLiteCloud Logger ---
def log_to_sqlitecloud(record):
    try:
        import sqlite3
        from urllib.parse import urlparse

        parsed_url = urlparse(SQLITECLOUD_URL)
        db_path = f"/mnt/data/{parsed_url.path.lstrip('/')}"

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
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
        cursor.execute("""
            INSERT INTO anomalies (timestamp, source_ip, dest_ip, protocol, anomaly_score, is_anomaly)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            record.get("timestamp", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
            record.get("source_ip", "N/A"),
            record.get("dest_ip", "N/A"),
            "DNS",
            float(record.get("reconstruction_error", 0)),
            int(record.get("anomaly", 0))
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        st.warning(f"SQLite Cloud insert failed: {e}")

# --- Get Real-time DNS Data ---
def get_dns_data():
    try:
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
            |> range(start: -5m)
            |> filter(fn: (r) => r._measurement == "dns")
            |> filter(fn: (r) => r._field == "inter_arrival_time" or r._field == "dns_rate")
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
                        "dns_rate": record.values.get("dns_rate", 0.0),
                        "source_ip": record.values.get("source_ip", "unknown"),
                        "dest_ip": record.values.get("dest_ip", "unknown")
                    })
            return rows
    except Exception as e:
        st.warning(f"Failed to fetch live DNS data from InfluxDB: {e}")
        return []

# --- Get Historical Data ---
@st.cache_data(ttl=600)
def get_historical(start, end):
    try:
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
            |> range(start: {start.isoformat()}, stop: {end.isoformat()})
            |> filter(fn: (r) => r._measurement == "dns")
            |> filter(fn: (r) => r._field == "inter_arrival_time" or r._field == "dns_rate")
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
