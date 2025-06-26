import streamlit as st
import pandas as pd
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

# Sidebar color picker for highlighting
highlight_color = st.sidebar.selectbox(
    "Highlight Color", ["Red", "Orange", "Yellow", "Green", "Blue"], index=3
)

alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)

# --- State Initialization ---
if "predictions" not in st.session_state:
    st.session_state.predictions = []
if "attacks" not in st.session_state:
    st.session_state.attacks = []

# --- Redirect Toggle to DNS Dashboard ---
toggle_redirect = st.sidebar.radio(
    "Switch Dashboard",
    ("Stay on DOS Dashboard", "Go to DNS Dashboard")
)

# Check if the user wants to redirect to DNS
if toggle_redirect == "Go to DNS Dashboard":
    st.markdown(
        """
        <style>
        .redirect-message {
            padding: 20px;
            background-color: #f0f0f5;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            font-size: 18px;
            color: #333;
            text-align: center;
        }
        .redirect-message a {
            color: #0066cc;
            font-weight: bold;
            text-decoration: none;
            font-size: 18px;
        }
        .redirect-message a:hover {
            text-decoration: underline;
        }
        </style>
        <div class="redirect-message">
            <p>You are being redirected to the <b>DNS Anomaly Detection</b> Dashboard.</p>
            <p><a href="https://dnscapstone.streamlit.app/" target="_blank">Click here</a> to go to DNS Dashboard.</p>
        </div>
        """,
        unsafe_allow_html=True
    )
else:
    # --- Tabs Navigation ---
    tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics", "Historical Data"])

    # Rendering tabs with the highlight_color passed to each tab
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
