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

# InfluxDB config from secrets
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime_dns"
INFLUXDB_TOKEN = st.secrets["influxdb_token"]

# Initialize SQLite DB for attack logging
DB_PATH = "attacks.db"
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS attacks (
                        timestamp TEXT, inter_arrival_time REAL, dns_rate REAL,
                        request_rate REAL, reconstruction_error REAL, anomaly INTEGER)''')
        conn.commit()
init_db()

# Query latest DNS data from InfluxDB
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

# Dashboard UI
def dashboard():
    st.sidebar.title("⚙️ Controls")
    st.sidebar.markdown(f"**User:** `Guest`")
    if st.sidebar.button("Clear History"):
        if "predictions" in st.session_state:
            del st.session_state.predictions
        st.experimental_rerun()

    if "predictions" not in st.session_state:
        st.session_state.predictions = []
    if "highlight" not in st.session_state:
        st.session_state.highlight = True
    if "live_page" not in st.session_state:
        st.session_state.live_page = 0

    tabs = st.tabs(["🏠 Home", "📡 Live Monitoring", "✍️ Manual Input", "📊 Analysis & Alerts"])

    with tabs[0]:
        st.title("🔍 DNS Anomaly Detection Dashboard")
        st.markdown("Welcome to the **DNS Traffic Monitoring and Anomaly Detection** platform.")

    with tabs[1]:
        st.header("📡 Real-Time DNS Monitoring")
        data_list = query_latest_influx()
        if data_list:
            for data in data_list:
                if "inter_arrival_time" in data and "dns_rate" in data:
                    result = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "inter_arrival_time": data["inter_arrival_time"],
                        "dns_rate": data["dns_rate"],
                        "reconstruction_error": np.random.rand(),
                        "anomaly": np.random.choice([0, 1]),
                        "label": None
                    }
                    st.session_state.predictions.append(result)

        if st.session_state.predictions:
            df = pd.DataFrame(st.session_state.predictions).sort_values("timestamp", ascending=False)
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            per_page = 100
            total_pages = (len(df) - 1) // per_page + 1
            page = st.session_state.live_page
            start, end = page * per_page, (page + 1) * per_page
            display_df = df.iloc[start:end]

            if st.session_state.highlight:
                def highlight(row): return ["background-color: red"] * len(row) if row["anomaly"] == 1 else [""] * len(row)
                st.dataframe(display_df.style.apply(highlight, axis=1))
            else:
                st.dataframe(display_df)

            st.markdown("---")
            page_selector = st.number_input("Page", min_value=1, max_value=total_pages, value=page + 1, step=1) - 1
            st.session_state.live_page = page_selector

    with tabs[2]:
        st.header("✍️ Manual Input")
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
            st.success("Prediction completed and added to history.")

    with tabs[3]:
        st.header("📊 Analysis & Alerts")
        if st.session_state.predictions:
            df = pd.DataFrame(st.session_state.predictions)
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            st.subheader("Anomaly Distribution")
            pie = px.pie(df, names=df["anomaly"].map({0: "Normal", 1: "Attack"}), title="Anomaly Breakdown")
            st.plotly_chart(pie)

            st.subheader("Reconstruction Error Over Time")
            line = px.line(df, x="timestamp", y="reconstruction_error", title="Reconstruction Error Timeline")
            st.plotly_chart(line)
        else:
            st.info("No predictions available yet.")

# Run the dashboard directly without login
dashboard()
