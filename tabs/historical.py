# historical.py

import streamlit as st
import pandas as pd
from tabs.utils import get_historical  # Import get_historical for DoS data

def render(thresh, highlight_color):
    st.header("DoS Historical Data")  # Update to DoS

    time_range = st.sidebar.selectbox("Select Time Range", ["Last 30 min", "Last 1 hour", "Last 24 hours", "Last 7 days"])
    time_range_query_map = {
        "Last 30 min": "-30m",
        "Last 1 hour": "-1h",
        "Last 24 hours": "-24h",
        "Last 7 days": "-7d"
    }

    start_date = pd.to_datetime("now") - pd.to_timedelta(time_range_query_map.get(time_range, "-24h"))
    end_date = pd.to_datetime("now")

    # Fetch the historical DoS data
    df = get_historical(start_date, end_date)

    if not df.empty:
        st.write("Showing historical DoS data")
        st.write(f"Total records: {len(df)}")
        st.write(f"Total attacks: {df[df['is_anomaly'] == 1].shape[0]}")
        st.write(f"Attack rate: {df['is_anomaly'].mean():.2%}")
        
        st.dataframe(df)
    else:
        st.info("No data for the selected time range.")
