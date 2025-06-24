# tabs/dos/utils.py
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
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
SQLITE_DB = st.secrets.get("DOS_SQLITE_DB", "dos")
SQLITE_APIKEY = st.secrets.get("DOS_SQLITE_APIKEY", "")

def send_discord_alert(result):
    message = {
        "content": (
            f"\U0001f6a8 **DOS Anomaly Detected!**\n"
            f"**Timestamp:** {result.get('timestamp')}\n"
            f"**Packet Count:** {result.get('packet_count')}\n"
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

def log_to_sqlitecloud(record, db_path=SQLITE_DB):
    try:
        conn = sqlitecloud.connect(f"sqlitecloud://{SQLITE_HOST}:{SQLITE_PORT}/{db_path}?apikey={SQLITE_APIKEY}")
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
            record.get("timestamp", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
            record.get("source_ip", "N/A"),
            record.get("dest_ip", "N/A"),
            "DOS",
            float(record.get("reconstruction_error", 0)),
            int(record.get("anomaly", 0))
        ))
        conn.commit()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=AttributeError)
            conn.close()
    except Exception as e:
        st.warning(f"SQLite Cloud insert failed: {e}")

def get_dos_data(measurement):
    try:
        if not INFLUXDB_URL:
            raise ValueError("No DOS InfluxDB host specified.")
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
            |> range(start: -5m)
            |> filter(fn: (r) => r._measurement == "{measurement}")
            |> filter(fn: (r) => r._field == "packet_count" or r._field == "byte_rate")
            |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
            |> sort(columns: ["_time"], desc: false)
            '''
            tables = client.query_api().query(query)
            rows = []
            for table in tables:
                for record in table.records:
                    rows.append({
                        "timestamp": record.get_time().strftime("%Y-%m-%d %H:%M:%S"),
                        "packet_count": record.values.get("packet_count", 0.0),
                        "byte_rate": record.values.get("byte_rate", 0.0),
                        "source_ip": record.values.get("source_ip", "unknown"),
                        "dest_ip": record.values.get("dest_ip", "unknown")
                    })
            return rows
    except Exception as e:
        st.warning(f"Failed to fetch live DOS data from InfluxDB: {e}")
        return []

def load_predictions_from_sqlitecloud(time_window="-24h"):
    try:
        conn = sqlitecloud.connect(f"sqlitecloud://{SQLITE_HOST}:{SQLITE_PORT}/{SQLITE_DB}?apikey={SQLITE_APIKEY}")
        query = f"""
            SELECT * FROM dos_anomalies
            WHERE timestamp >= datetime('now', '{time_window}')
            ORDER BY timestamp DESC
        """
        df = pd.read_sql_query(query, conn)
        conn.close()
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df
    except Exception as e:
        print(f"[SQLite Load Error]: {e}")
        return pd.DataFrame()
def get_dos_historical_data(start_date, end_date):
    try:
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
            |> range(start: {start_date.isoformat()}, stop: {end_date.isoformat()})
            |> filter(fn: (r) => r._measurement == "network_traffic")
            |> filter(fn: (r) => r._field == "packet_count" or r._field == "byte_rate")
            |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
            |> sort(columns: ["_time"], desc: false)
            '''
            tables = client.query_api().query(query)
            rows = []
            for table in tables:
                for record in table.records:
                    rows.append({
                        "timestamp": record.get_time(),
                        "packet_count": record.values.get("packet_count", 0.0),
                        "byte_rate": record.values.get("byte_rate", 0.0),
                        "source_ip": record.values.get("source_ip", "unknown"),
                        "dest_ip": record.values.get("dest_ip", "unknown")
                    })
            return pd.DataFrame(rows)
    except Exception as e:
        st.warning(f"Failed to fetch historical DOS data: {e}")
        return pd.DataFrame()
