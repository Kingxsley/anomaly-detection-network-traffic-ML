# dns_dashboard_app.py
import streamlit as st
import requests
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from streamlit_autorefresh import st_autorefresh
import sqlite3
from influxdb_client import InfluxDBClient
import time
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import plotly.figure_factory as ff

# --- Config ---
st.set_page_config(page_title="DNS Anomaly Detection Dashboard", layout="wide")
WEBHOOK_URL = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7"
API_URL = "https://mizzony-dns-anomalies-detection.hf.space/predict"
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "6gjE97dCC24hgOgWNmRXPqOS0pfc0pMSYeh5psL8e5u2T8jGeV1F17CU-U1z05if0jfTEmPRW9twNPSXN09SRQ=="
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime_dns"
DB_PATH = "attacks.db"

# --- Init DB ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS attacks
                 (timestamp TEXT, inter_arrival_time REAL, dns_rate REAL, request_rate REAL,
                  reconstruction_error REAL, anomaly INTEGER)''')
    conn.commit()
    conn.close()

init_db()

# --- Session State ---
for key in ["predictions", "attacks"]:
    if key not in st.session_state:
        st.session_state[key] = []
if "highlight" not in st.session_state:
    st.session_state.highlight = True
if "live_page" not in st.session_state:
    st.session_state.live_page = 0

# --- Sidebar Controls ---
st.sidebar.header("Dashboard Controls")
time_range = st.sidebar.selectbox(
    "Time Range",
    ["Last 30 min", "Last 1 hour", "Last 24 hours", "Last 7 days", "Last 14 days", "Last 30 days"],
    index=4
)
threshold = st.sidebar.slider("Anomaly Threshold", 0.01, 1.0, 0.1, 0.01)
alerts_enabled = st.sidebar.checkbox("Enable Attack Alerts", value=True)
highlight_anomalies = st.sidebar.checkbox("Highlight Anomalies in Table", value=True)
st.session_state.highlight = highlight_anomalies

# --- Time Conversion ---
time_map = {
    "Last 30 min": ("-30m", "now()"),
    "Last 1 hour": ("-1h", "now()"),
    "Last 24 hours": ("-24h", "now()"),
    "Last 7 days": ("-7d", "now()"),
    "Last 14 days": ("-14d", "now()"),
    "Last 30 days": ("-30d", "now()")
}
start_time, end_time = time_map[time_range]

# --- Influx Query ---
def query_latest_influx(n=100):
    try:
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
              |> range(start: -1m)
              |> filter(fn: (r) => r._measurement == "dns")
              |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
              |> sort(columns: ["_time"], desc: true)
              |> limit(n: {n})
            '''
            tables = client.query_api().query(query)
            if not tables or len(tables) == 0 or len(tables[0].records) == 0:
                return None
            data_list = []
            for record in tables[0].records:
                data_list.append(record.values)
            return data_list if data_list else None
    except Exception as e:
        st.error(f"InfluxDB error: {e}")
        return None

# --- Webhook Sender ---
def send_webhook_alert(timestamp, src_ip, dest_ip):
    message = {
        "content": f"\ud83d\udea8 DNS Anomaly Detected!\nTimestamp: {timestamp}\nSource IP: {src_ip}\nDestination IP: {dest_ip}"
    }
    try:
        requests.post(WEBHOOK_URL, json=message, timeout=5)
    except Exception as e:
        st.warning(f"Webhook failed: {e}")

# --- API Predict ---
def predict_and_log(data):
    try:
        res = requests.post(API_URL, json=data, timeout=5)
        res.raise_for_status()
        result = res.json()
        result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.session_state.predictions.append(result)
        st.session_state.predictions = st.session_state.predictions[-1000:]

        if result["anomaly"] == 1:
            st.session_state.attacks.append(result)
            with sqlite3.connect(DB_PATH) as conn:
                c = conn.cursor()
                c.execute('''INSERT INTO attacks (timestamp, inter_arrival_time, dns_rate, request_rate, reconstruction_error, anomaly)
                             VALUES (?, ?, ?, ?, ?, ?)''',
                          (result["timestamp"], data["inter_arrival_time"], data["dns_rate"],
                           result["request_rate"], result["reconstruction_error"], result["anomaly"]))
                conn.commit()

            if alerts_enabled:
                influx_data_list = query_latest_influx(n=10)
                if influx_data_list:
                    latest = influx_data_list[0]
                    send_webhook_alert(result["timestamp"], latest.get("source_ip", "N/A"), latest.get("dest_ip", "N/A"))
        return result
    except Exception as e:
        st.error(f"Prediction error: {e}")
        return None

# --- Tabs Layout ---
tabs = st.tabs(["Live Monitoring", "Manual Input", "Analysis, Alerts"])

# --- Live Monitoring Tab ---
with tabs[0]:
    st.header("Live Monitoring")
    st_autorefresh(interval=10000, key="auto_refresh")  # auto-fetch every 10s
    # Auto fetch DNS records every 10 seconds
    data_list = query_latest_influx()
    if data_list:
        for data in data_list:
            if "inter_arrival_time" in data and "dns_rate" in data:
                predict_and_log({
                    "inter_arrival_time": data["inter_arrival_time"],
                    "dns_rate": data["dns_rate"]
                })
    else:
        st.warning("No valid DNS data found.")

    if st.session_state.predictions:
        st.subheader("Recent Traffic")
        df = pd.DataFrame(st.session_state.predictions)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp", ascending=False)

        per_page = 100
        total_pages = (len(df) - 1) // per_page + 1
        # Move page control to the bottom
        page = st.session_state.live_page
        
        start = page * per_page
        end = start + per_page

        display_df = df.iloc[start:end]

        if st.session_state.highlight:
            def highlight_anomaly(row):
                return ["background-color: red"] * len(row) if row["anomaly"] == 1 else [""] * len(row)
            st.dataframe(display_df.style.apply(highlight_anomaly, axis=1))

        st.markdown("---")
        page_selector = st.number_input("Page", min_value=1, max_value=total_pages, value=page + 1, step=1) - 1
        st.session_state.live_page = page_selector

# --- Manual Input Tab ---
with tabs[1]:
    st.header("Manual Input")
    col1, col2 = st.columns(2)
    with col1:
        inter_arrival_time = st.number_input("Inter Arrival Time", min_value=0.001, value=0.02)
    with col2:
        dns_rate = st.number_input("DNS Rate", min_value=0.0, value=5.0)

    if st.button("Predict Anomaly"):
        predict_and_log({"inter_arrival_time": inter_arrival_time, "dns_rate": dns_rate})

# --- Analysis, Alerts Tab ---
with tabs[2]:
    st.header("Analysis & Alerts")
    if st.session_state.predictions:
        df = pd.DataFrame(st.session_state.predictions)
        df["timestamp"] = pd.to_datetime(df["timestamp"])

        st.subheader("Recent Predictions")
        if st.session_state.highlight:
            def highlight_anomaly(row):
                return ["background-color: red"] * len(row) if row["anomaly"] == 1 else [""] * len(row)
            st.dataframe(df.style.apply(highlight_anomaly, axis=1))
        else:
            st.dataframe(df)

        st.subheader("Anomaly Distribution")
        fig = px.pie(df, names=df["anomaly"].map({0: "Normal", 1: "Attack"}), title="Anomaly vs Normal")
        st.plotly_chart(fig)

        st.subheader("Reconstruction Error Over Time")
        fig2 = px.line(df, x="timestamp", y="reconstruction_error", title="Reconstruction Error Timeline")
        fig2.add_hline(y=threshold, line_dash="dash", line_color="black")
        st.plotly_chart(fig2)
    else:
        st.info("No predictions yet. Switch tabs to generate.")
