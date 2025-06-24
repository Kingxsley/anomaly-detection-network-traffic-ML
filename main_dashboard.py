# main_dashboard.py
import streamlit as st
from layout import render_dashboard

# --- Sidebar Dashboard Selector ---
dashboard_choice = st.sidebar.radio("Select Dashboard", ["DNS", "DOS"], index=0)

if dashboard_choice == "DNS":
    render_dashboard(
        title="DNS Anomaly Detection Dashboard",
        api_url="https://mizzony-dns-anomalies-detection.hf.space/predict",
        influx_measurement="dns",
        db_path="dns",
        mode="dns"
    )
elif dashboard_choice == "DOS":
    render_dashboard(
        title="DOS Anomaly Detection Dashboard",
        api_url="https://violabirech-dos-anomalies-detection.hf.space/predict",
        influx_measurement="network_traffic",
        db_path="dos",
        mode="dos"
    )
