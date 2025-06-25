import streamlit as st
import pandas as pd  # ✅ Added missing import
from tabs import overview
from tabs import live_stream
from tabs import manual_entry
from tabs import metrics
from tabs import historical

st.set_page_config(page_title="DOS Anomaly Detection Dashboard", layout="wide")

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
