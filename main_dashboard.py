import streamlit as st
import pandas as pd
from tabs import overview
from tabs import live_stream
from tabs import manual_entry
from tabs import metrics
from tabs import historical

# --- Fetch Secrets from Streamlit's secrets manager ---
# --- DNS Settings ---
if 'DNS' in st.secrets:
    DNS_API_URL = st.secrets["DNS"]["API_URL"]
    DNS_DISCORD_WEBHOOK = st.secrets["DNS"]["DISCORD_WEBHOOK"]
    DNS_INFLUXDB_URL = st.secrets["DNS"]["INFLUXDB_URL"]
    DNS_INFLUXDB_ORG = st.secrets["DNS"]["INFLUXDB_ORG"]
    DNS_INFLUXDB_BUCKET = st.secrets["DNS"]["INFLUXDB_BUCKET"]
    DNS_INFLUXDB_TOKEN = st.secrets["DNS"]["INFLUXDB_TOKEN"]
    DNS_SQLITE_HOST = st.secrets["DNS"]["SQLITE_HOST"]
    DNS_SQLITE_PORT = st.secrets["DNS"]["SQLITE_PORT"]
    DNS_SQLITE_DB = st.secrets["DNS"]["SQLITE_DB"]
    DNS_SQLITE_APIKEY = st.secrets["DNS"]["SQLITE_APIKEY"]

# --- DOS Settings ---
if 'DOS' in st.secrets:
    DOS_API_URL = st.secrets["DOS"]["API_URL"]
    DOS_DISCORD_WEBHOOK = st.secrets["DOS"]["DISCORD_WEBHOOK"]
    DOS_INFLUXDB_URL = st.secrets["DOS"]["INFLUXDB_URL"]
    DOS_INFLUXDB_ORG = st.secrets["DOS"]["INFLUXDB_ORG"]
    DOS_INFLUXDB_BUCKET = st.secrets["DOS"]["INFLUXDB_BUCKET"]
    DOS_INFLUXDB_TOKEN = st.secrets["DOS"]["INFLUXDB_TOKEN"]
    DOS_SQLITE_HOST = st.secrets["DOS"]["SQLITE_HOST"]
    DOS_SQLITE_PORT = st.secrets["DOS"]["SQLITE_PORT"]
    DOS_SQLITE_DB = st.secrets["DOS"]["SQLITE_DB"]
    DOS_SQLITE_APIKEY = st.secrets["DOS"]["SQLITE_APIKEY"]

# --- Toggle between DNS and DOS ---
dashboard_type = st.sidebar.radio("Select Dashboard", ("DNS", "DOS"))

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
