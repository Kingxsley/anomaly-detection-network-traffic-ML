# layout.py
import streamlit as st
from tabs.dns.overview import render_overview as render_dns_overview
from tabs.dns.live_stream import render as render_dns_live_stream
from tabs.dns.manual_entry import render as render_dns_manual_entry
from tabs.dns.metrics import render as render_dns_metrics
from tabs.dns.historical import render as render_dns_historical

from tabs.dos.overview import render_overview as render_dos_overview
from tabs.dos.live_stream import render_live_stream as render_dos_live_stream
from tabs.dos.manual_entry import render_manual_entry as render_dos_manual_entry
from tabs.dos.metrics import render_metrics as render_dos_metrics
from tabs.dos.historical import render_historical as render_dos_historical


def render_dashboard(title, api_url, influx_measurement, db_path, mode):
    st.set_page_config(page_title=title, layout="wide")
    st.title(title)

    # Shared sidebar filters
    time_range_query_map = {
        "Last 30 min": "-30m",
        "Last 1 hour": "-1h",
        "Last 24 hours": "-24h",
        "Last 7 days": "-7d",
        "Last 14 days": "-14d",
        "Last 30 days": "-30d"
    }
    time_range = st.sidebar.selectbox("Time Range", list(time_range_query_map.keys()), index=2)
    query_duration = time_range_query_map[time_range]

    thresh = st.sidebar.slider("Anomaly Threshold", 0.01, 1.0, 0.1, 0.01)
    highlight_color = st.sidebar.selectbox("Highlight Color", ["Red", "Orange", "Yellow", "Green", "Blue"], index=3)
    alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Overview",
        "Live Stream",
        "Manual Entry",
        "Metrics & Alerts",
        "Historical Data"
    ])

    if mode == "dns":
        with tab1:
            render_dns_overview(api_url, influx_measurement, query_duration)
        with tab2:
            render_dns_live_stream(thresh, highlight_color, alerts_enabled)
        with tab3:
            render_dns_manual_entry()
        with tab4:
            render_dns_metrics(thresh)
        with tab5:
            render_dns_historical(thresh, highlight_color)

    elif mode == "dos":
        with tab1:
            render_dos_overview(api_url, influx_measurement)
        with tab2:
            render_dos_live_stream(api_url, influx_measurement, db_path)
        with tab3:
            render_dos_manual_entry(api_url)
        with tab4:
            render_dos_metrics(influx_measurement)
        with tab5:
            render_dos_historical(api_url, influx_measurement, db_path)
