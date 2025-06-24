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

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Overview",
        "Live Stream",
        "Manual Entry",
        "Metrics & Alerts",
        "Historical Data"
    ])

    if mode == "dns":
        with tab1:
            render_dns_overview(api_url, influx_measurement)
        with tab2:
            render_dns_live_stream(thresh=0.15, highlight_color="#FFB6C1", alerts_enabled=True)
        with tab3:
            render_dns_manual_entry()
        with tab4:
            render_dns_metrics()
        with tab5:
            render_dns_historical(thresh=0.15)

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
