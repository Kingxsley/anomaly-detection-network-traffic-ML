import requests
from datetime import datetime
import sqlitecloud
import pandas as pd
import plotly.express as px

# --- Send Discord Alert ---
def send_discord_alert(result, discord_webhook):
    message = {
        "content": (
            f"\U0001f6a8 **Anomaly Detected!**\n"
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
        print(f"Discord alert failed: {e}")

# --- Fetch Real-time DoS Data ---
def get_dos_data(api_url):
    try:
        response = requests.get(f"{api_url}/realtime")
        if response.status_code == 200:
            return response.json()  # Return real-time DoS data
        else:
            return []
    except Exception as e:
        print(f"Error fetching DoS data: {e}")
        return []

# --- Fetch Historical DoS Data ---
def get_historical_data_for_dos(time_range, sqlite_host, sqlite_port, sqlite_db, sqlite_apikey):
    try:
        query_duration = time_range  # Assuming time_range is in a query-friendly format
        conn = sqlitecloud.connect(f"sqlitecloud://{sqlite_host}:{sqlite_port}/{sqlite_db}?apikey={sqlite_apikey}")
        cursor = conn.execute(f"""
            SELECT * FROM dos_anomalies
            WHERE timestamp >= '{query_duration}'
            ORDER BY timestamp DESC
        """)
        rows = cursor.fetchall()
        if not rows:
            return pd.DataFrame()
        cols = [column[0] for column in cursor.description]
        df = pd.DataFrame(rows, columns=cols)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        conn.close()
        return df
    except Exception as e:
        print(f"SQLite Cloud error: {e}")
        return pd.DataFrame()
