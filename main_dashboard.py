import streamlit as st
from dos_dashboard import render_live_stream, render_manual_entry, render_metrics, render_historical_data, render_overview
from dns_dashboard import render_live_stream as dns_live_stream, render_manual_entry as dns_manual_entry, render_metrics as dns_metrics, render_historical_data as dns_historical_data, render_overview as dns_overview

# --- Sidebar Settings ---
dashboard_toggle = st.sidebar.selectbox("Select Dashboard", ["DNS Dashboard", "DoS Dashboard"])

if dashboard_toggle == "DoS Dashboard":
    dos_tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics", "Historical Data"])
    with dos_tabs[0]:
        render_overview(time_range, SQLITE_HOST, SQLITE_PORT, SQLITE_DB, SQLITE_APIKEY)  # Overview Tab
    with dos_tabs[1]:
        render_live_stream(API_URL, highlight_color, alerts_enabled, DISCORD_WEBHOOK)
    with dos_tabs[2]:
        render_manual_entry(API_URL, DISCORD_WEBHOOK)
    with dos_tabs[3]:
        render_metrics()
    with dos_tabs[4]:
        render_historical_data(time_range, SQLITE_HOST, SQLITE_PORT, SQLITE_DB, SQLITE_APIKEY)
elif dashboard_toggle == "DNS Dashboard":
    dns_tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics", "Historical Data"])
    with dns_tabs[0]:
        dns_overview(time_range, SQLITE_HOST, SQLITE_PORT, SQLITE_DB, SQLITE_APIKEY)  # Overview Tab
    with dns_tabs[1]:
        dns_live_stream()
    with dns_tabs[2]:
        dns_manual_entry()
    with dns_tabs[3]:
        dns_metrics()
    with dns_tabs[4]:
        dns_historical_data()
