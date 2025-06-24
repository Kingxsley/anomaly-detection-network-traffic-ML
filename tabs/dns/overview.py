# tabs/dns/overview.py

import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh
from tabs.dns.utils import load_predictions_from_sqlitecloud

def render_overview(api_url, influx_measurement, query_duration):
    st_autorefresh(interval=30000, key="overview_refresh")
    st.title("DNS Anomaly Detection Overview")
    
    df = load_predictions_from_sqlitecloud(time_window=query_duration)

    if not df.empty:
