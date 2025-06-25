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

# --- Secrets ---
API_URL = st.secrets.get("API_URL", "https://huggingface.co/spaces/mizzony/DoS_Anomaly_Detection")  # Updated for DoS
DISCORD_WEBHOOK = st.secrets.get("DISCORD_WEBHOOK", "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7")  # Updated for DoS
INFLUXDB_URL = st.secrets.get("INFLUXDB_URL", "https://us-east-1-1.aws.cloud2.influxdata.com")  # Updated for DoS
INFLUXDB_ORG = st.secrets.get("INFLUXDB_ORG", "Anormally Detection")  # Updated for DoS
INFLUXDB_BUCKET = st.secrets.get("INFLUXDB_BUCKET", "realtime")  # Updated for DoS
INFLUXDB_TOKEN = st.secrets.get("INFLUXDB_TOKEN", "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg==")  # Updated for DoS
SQLITE_HOST = st.secrets.get("SQLITE_HOST", "cfolwawehk.g2.sqlite.cloud")  # Updated for DoS
SQLITE_PORT = int(st.secrets.get("SQLITE_PORT", 8860))  # Updated for DoS
SQLITE_DB = st.secrets.get("SQLITE_DB", "dos")  # Updated for DoS
SQLITE_APIKEY = st.secrets.get("SQLITE_APIKEY", "77cz3yvotfOw3EgNIM9xPLAWaajazSyxcnCWvvbxFEA")  # Updated for DoS

# --- Discord Alert ---
def send_discord_alert(result):
    message = {
        "content": (
            f"\U0001f6a8 **DoS Anomaly Detected!**\n"
            f"**Timestamp:** {result.get('timestamp')}\n"
            f"**DNS Rate:** {result.get('dns_rate')}\n"
            f"**Inter-arrival Time:** {result.get('inter_arrival_time')}\n"
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

# --- SQLiteCloud Logger ---
def log_to_sqlitecloud(record):
    try:
        conn = sqlitecloud.connect(f"sqlitecloud://{SQLITE_HOST}:{SQLITE_PORT}/{SQLITE_DB}?apikey={SQLITE_APIKEY}")
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
        if not INFLUXDB_URL:
            raise ValueError("No host specified.")
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
            |> range(start: -5m)
            |> filter(fn: (r) => r._measurement == "network_traffic")
            |> filter(fn: (r) => r._field == "inter_arrival_time" or r._field == "packet_length"
                            or r._field == "packet_rate" or r._field == "source_port" 
                            or r._field == "dest_port")
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
                        "packet_length": record.values.get("packet_length", 0.0),
                        "packet_rate": record.values.get("packet_rate", 0.0),
                        "source_port": record.values.get("source_port", "unknown"),
                        "dest_port": record.values.get("dest_port", "unknown")
                    })
            return rows
    except Exception as e:
        st.warning(f"Failed to fetch live DoS data from InfluxDB: {e}")
        return []


# --- Get Historical Data ---
@st.cache_data(ttl=600)
def get_historical(start, end):
    try:
        if not INFLUXDB_URL:
            raise ValueError("No host specified.")
        
        # Convert dates to ISO8601 format (InfluxDB requires this format)
        start_str = start.strftime('%Y-%m-%dT%H:%M:%SZ')  # Format as '2025-06-18T00:00:00Z'
        end_str = end.strftime('%Y-%m-%dT%H:%M:%SZ')      # Format as '2025-06-25T23:59:59Z'

        # Query for historical data with correct date format
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
            |> range(start: {start_str}, stop: {end_str})  # Correct date format for InfluxDB
            |> filter(fn: (r) => r._measurement == "network_traffic")  # Correct measurement
            |> filter(fn: (r) => r._field == "inter_arrival_time" or r._field == "packet_length" 
                            or r._field == "packet_rate" or r._field == "source_port" 
                            or r._field == "dest_port")  # Relevant fields
            |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
            |> sort(columns: ["_time"], desc: false)
            '''
            # Debugging output: Print query to check its correctness
            print(f"Query: {query}")  # Debugging the query string
            
            tables = client.query_api().query(query)
            rows = []
            for table in tables:
                for record in table.records:
                    d = record.values.copy()
                    d["timestamp"] = record.get_time()
                    rows.append(d)

            # Debugging output to check data
            st.write("Fetched data:", rows)
            return pd.DataFrame(rows)

    except Exception as e:
        st.error(f"Error retrieving historical data: {e}")
        return pd.DataFrame()
