# utils.py

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
# utils.py


# --- DoS Settings (Hardcoded) ---
DOS_API_URL = "https://kingxsley-dos-api.hf.space/predict"
DOS_DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7"
DOS_INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
DOS_INFLUXDB_ORG = "Anormally Detection"
DOS_INFLUXDB_BUCKET = "realtime"
DOS_INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="
DOS_SQLITE_HOST = "cfolwawehk.g2.sqlite.cloud"
DOS_SQLITE_PORT = 8860
DOS_SQLITE_DB = "dos"
DOS_SQLITE_APIKEY = "77cz3yvotfOw3EgNIM9xPLAWaajazSyxcnCWvvbxFEA"

# --- Get Real-time DoS Data ---
def get_data():
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
                        "dos_rate": record.values.get("dos_rate", 0.0),  # Correct field for DoS rate
                        "source_ip": record.values.get("source_ip", "unknown"),
                        "dest_ip": record.values.get("dest_ip", "unknown")
                    })
            return rows
    except Exception as e:
        st.warning(f"Failed to fetch live DoS data from InfluxDB: {e}")
        return []
