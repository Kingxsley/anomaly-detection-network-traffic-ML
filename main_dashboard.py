import streamlit as st
from tabs import overview
from tabs import live_stream
from tabs import manual_entry
from tabs import metrics
from tabs import historical

# --- Additional imports for DoS (to be added in DoS tabs)
import requests
import pandas as pd
import plotly.express as px
from datetime import datetime

# --- DoS Specific Helper Functions ---
def get_dos_data():
    # Function to fetch live data for DoS (similar to DNS)
    try:
        response = requests.get(f"{API_URL}/realtime")
        if response.status_code == 200:
            return response.json()  # Return the real-time data for DoS
        else:
            st.warning("Failed to fetch real-time DoS data.")
            return []
    except Exception as e:
        st.warning(f"Error fetching DoS data: {e}")
        return []

def manual_dos_entry(inter_arrival_time, dns_rate):
    # Send manual entry for DoS prediction
    try:
        payload = {
            "inter_arrival_time": inter_arrival_time,
            "dns_rate": dns_rate
        }
        response = requests.post(API_URL, json=payload)
        result = response.json()
        result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
        st.session_state.predictions.append(result)
        st.dataframe(pd.DataFrame([result]))
    except Exception as e:
        st.error(f"Error: {e}")

# --- Sidebar Settings ---
dashboard_toggle = st.sidebar.selectbox("Select Dashboard", ["DNS Dashboard", "DoS Dashboard"])
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

# --- Render the selected dashboard ---
if dashboard_toggle == "DNS Dashboard":
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

elif dashboard_toggle == "DoS Dashboard":
    # DoS Dashboard Content
    st.title("DoS Anomaly Detection Dashboard")

    # --- Real-time Stream
    st.header("Live DoS Stream")
    records = get_dos_data()
    if records:
        df = pd.DataFrame(records)
        if not df.empty:
            st.write(df)
        else:
            st.warning("No real-time DoS data available.")
    else:
        st.warning("No real-time DoS data available.")

    # --- Manual Entry
    st.header("Manual DoS Entry")
    col1, col2 = st.columns(2)
    with col1:
        inter_arrival_time = st.number_input("Inter Arrival Time", value=0.01)
    with col2:
        dns_rate = st.number_input("DNS Rate", value=5.0)

    if st.button("Predict DoS Anomaly"):
        manual_dos_entry(inter_arrival_time, dns_rate)

    # --- Metrics for DoS
    st.header("DoS Model Performance Metrics")
    # Here you can add the same metrics code from the DNS dashboard if required.

    # --- Historical Data
    st.header("DoS Historical Data")
    # Historical data for DoS, similar to the DNS historical implementation.

