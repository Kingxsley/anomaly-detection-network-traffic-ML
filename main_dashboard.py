import streamlit as st
import pandas as pd
from tabs import overview
from tabs import live_stream
from tabs import manual_entry
from tabs import metrics
from tabs import historical

# --- DNS Settings ---
if st.secrets.get("DASHBOARD_TYPE", "DNS") == "DNS":
    API_URL = st.secrets.get("API_URL")
    DISCORD_WEBHOOK = st.secrets.get("DISCORD_WEBHOOK")
    INFLUXDB_URL = st.secrets.get("INFLUXDB_URL")
    INFLUXDB_ORG = st.secrets.get("INFLUXDB_ORG")
    INFLUXDB_BUCKET = st.secrets.get("INFLUXDB_BUCKET")
    INFLUXDB_TOKEN = st.secrets.get("INFLUXDB_TOKEN")
    SQLITE_HOST = st.secrets.get("SQLITE_HOST")
    SQLITE_PORT = int(st.secrets.get("SQLITE_PORT"))
    SQLITE_DB = st.secrets.get("SQLITE_DB")
    SQLITE_APIKEY = st.secrets.get("SQLITE_APIKEY")

# --- DOS Settings ---
else:  # If the user selects DOS
    API_URL = st.secrets.get("DOS_API_URL")
    DISCORD_WEBHOOK = st.secrets.get("DOS_DISCORD_WEBHOOK")
    INFLUXDB_URL = st.secrets.get("DOS_INFLUXDB_URL")
    INFLUXDB_ORG = st.secrets.get("DOS_INFLUXDB_ORG")
    INFLUXDB_BUCKET = st.secrets.get("DOS_INFLUXDB_BUCKET")
    INFLUXDB_TOKEN = st.secrets.get("DOS_INFLUXDB_TOKEN")
    SQLITE_HOST = st.secrets.get("DOS_SQLITE_HOST")
    SQLITE_PORT = int(st.secrets.get("DOS_SQLITE_PORT"))
    SQLITE_DB = st.secrets.get("DOS_SQLITE_DB")
    SQLITE_APIKEY = st.secrets.get("DOS_SQLITE_APIKEY")

# --- Sidebar Settings ---
time_range_query_map = {
    "Last 30 min": "-30m",
    "Last 1 hour": "-1h",
    "Last 24 hours": "-24h",
    "Last 7 days": "-7d",
    "Last 14 days": "-14d",
    "Last 30 days": "-30d"
}
time_range = st.sidebar.selectbox("Time Range", list(time_range_query_map.keys()), index=2)
thresh = st.sidebar.slider("Anomaly Threshold", 0.01, 1.0, 0.1, 0.01)
highlight_color = st.sidebar.selectbox("Highlight Color", ["Red", "Orange", "Yellow", "Green", "Blue"], index=3)
alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)

# --- State Initialization ---
if "predictions" not in st.session_state:
    st.session_state.predictions = []
if "attacks" not in st.session_state:
    st.session_state.attacks = []

# --- Toggle between DNS and DOS ---
dashboard_type = st.sidebar.radio("Select Dashboard", ("DNS", "DOS"))

# --- Tabs Navigation ---
tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics", "Historical Data"])

if dashboard_type == "DNS":
    with tabs[0]:
        overview.render(time_range, time_range_query_map)
    with tabs[1]:
        live_stream.render(thresh, highlight_color, alerts_enabled)
    with tabs[2]:
        manual_entry.render()
    with tabs[3]:
        metrics.render(thresh)
    with tabs[4]:
        historical.render(thresh, highlight_color)
else:  # DOS Dashboard
    # Similar updates for the DOS-specific tabs, e.g., API calls, SQLite interactions, etc.
    pass
