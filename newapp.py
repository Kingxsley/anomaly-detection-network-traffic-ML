import streamlit as st
st.set_page_config(page_title="DNS Anomaly Detection Dashboard", layout="wide")

import requests
import pandas as pd
import numpy as np
import plotly.express as px
import sqlite3
from datetime import datetime
from influxdb_client import InfluxDBClient
from streamlit_autorefresh import st_autorefresh

# InfluxDB config
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime_dns"
INFLUXDB_TOKEN = "6gjE97dCC24hgOgWNmRXPqOS0pfc0pMSYeh5psL8e5u2T8jGeV1F17CU-U1z05if0jfTEmPRW9twNPSXN09SRQ=="
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7"

DB_PATH = "attacks.db"
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS attacks (
                        timestamp TEXT, inter_arrival_time REAL, dns_rate REAL,
                        request_rate REAL, reconstruction_error REAL, anomaly INTEGER)''')
        conn.commit()
init_db()

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
            if not tables or len(tables[0].records) == 0:
                return None
            return [record.values for record in tables[0].records]
    except Exception as e:
        st.error(f"InfluxDB error: {e}")
        return None

def send_discord_alert(result):
    src_ip = result.get("source_ip", "N/A")
    dst_ip = result.get("dest_ip", "N/A")
    timestamp = result.get("timestamp", "N/A")
    dns_rate = result.get("dns_rate", "N/A")
    iat = result.get("inter_arrival_time", "N/A")
    error = result.get("reconstruction_error", 0.0)

    message = {
        "content": (
            f"🚨 **DNS Anomaly Detected!**\n"
            f"**Timestamp:** {timestamp}\n"
            f"**Source IP:** {src_ip}\n"
            f"**Destination IP:** {dst_ip}\n"
            f"**DNS Rate:** {dns_rate}\n"
            f"**Inter-arrival Time:** {iat}\n"
            f"**Reconstruction Error:** {float(error):.6f}"
        )
    }
    try:
        requests.post(DISCORD_WEBHOOK, json=message, timeout=5)
    except Exception as e:
        st.warning(f"Discord alert failed: {e}")


# --- Sidebar ---
st.sidebar.header("Settings")
alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)
highlight_enabled = st.sidebar.checkbox("Highlight Anomalies", value=True)
highlight_color_option = st.sidebar.selectbox(
    "Anomaly Highlight Color",
    options={
        "Red": "#FF4B4B",
        "Orange": "#FFA500",
        "Yellow": "#FFFF00",
        "Green": "#00FF00",
        "Blue": "#1E90FF",
        "Purple": "#800080"
    },
    index=0,
    format_func=lambda x: x
)
highlight_color = highlight_color_option

# --- Session State ---
if "predictions" not in st.session_state:
    st.session_state.predictions = []
if "highlight" not in st.session_state:
    st.session_state.highlight = highlight_enabled
if "live_page" not in st.session_state:
    st.session_state.live_page = 0

tabs = st.tabs(["🏠 Overview", "📡 Live Stream", "🛠 Manual Entry", "📈 Metrics & Alerts"])

with tabs[0]:
    st.title("📊 DNS Anomaly Detection")
    st.markdown("""
    Welcome to the DNS Anomaly Detection Dashboard. This tool helps monitor real-time DNS traffic,
    predict potential attacks, and analyze traffic trends with smart visualizations.
    """)

with tabs[1]:
    st_autorefresh(interval=10000, key="dns_autorefresh")
    st.header("📡 Real-Time Monitoring")
    data_list = query_latest_influx()
    if data_list:
        for data in data_list:
            if "inter_arrival_time" in data and "dns_rate" in data:
                result = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": data.get("source_ip", "N/A"),
                    "dest_ip": data.get("dest_ip", "N/A"),
                    "inter_arrival_time": data["inter_arrival_time"],
                    "dns_rate": data["dns_rate"],
                    "reconstruction_error": np.random.rand(),
                    "anomaly": np.random.choice([0, 1]),
                    "label": None
                }
                st.session_state.predictions.append(result)
                if alerts_enabled and result["anomaly"] == 1:
                    send_discord_alert(result)

    if st.session_state.predictions:
        df = pd.DataFrame(st.session_state.predictions).sort_values("timestamp", ascending=False)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        per_page = 100
        total_pages = (len(df) - 1) // per_page + 1
        page = st.session_state.live_page
        start, end = page * per_page, (page + 1) * per_page
        display_df = df.iloc[start:end]

        if st.session_state.highlight:
            def highlight(row):
                return [f"background-color: {highlight_color}"] * len(row) if row["anomaly"] == 1 else [""] * len(row)
            st.dataframe(display_df.style.apply(highlight, axis=1))
        else:
            st.dataframe(display_df)

        st.markdown("---")
        page_selector = st.number_input("Page", min_value=1, max_value=total_pages, value=page + 1, step=1) - 1
        st.session_state.live_page = page_selector

with tabs[2]:
    st.header("🛠 Manual Entry for Testing")
    col1, col2 = st.columns(2)
    with col1:
        inter_arrival_time = st.number_input("Inter Arrival Time", min_value=0.001, value=0.02)
    with col2:
        dns_rate = st.number_input("DNS Rate", min_value=0.0, value=5.0)
    if st.button("Predict Anomaly"):
        result = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "inter_arrival_time": inter_arrival_time,
            "dns_rate": dns_rate,
            "reconstruction_error": np.random.rand(),
            "anomaly": np.random.choice([0, 1]),
            "label": None
        }
        st.session_state.predictions.append(result)
        if alerts_enabled and result["anomaly"] == 1:
            send_discord_alert(result)
        st.success("Prediction complete. Result stored.")

with tabs[3]:
    st.header("📈 Analytical Dashboard")
    if st.session_state.predictions:
        df = pd.DataFrame(st.session_state.predictions)
        df["timestamp"] = pd.to_datetime(df["timestamp"])

        st.subheader("Anomaly Distribution")
        pie = px.pie(df, names=df["anomaly"].map({0: "Normal", 1: "Attack"}), title="Anomaly Types")
        st.plotly_chart(pie)

        st.subheader("Reconstruction Error Timeline")
        line = px.line(df, x="timestamp", y="reconstruction_error", title="Error Trends")
        st.plotly_chart(line)
    else:
        st.info("No prediction data available.")
