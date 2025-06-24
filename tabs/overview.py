import streamlit as st
import pandas as pd
from utils import load_predictions_from_sqlitecloud

def render(time_range, time_range_query_map):
    st.title("Overview")

    # Load the appropriate predictions based on DNS or DOS dashboard type
    if st.session_state.DASHBOARD_TYPE == "DNS":
        query_duration = time_range_query_map.get(time_range, "-24h")
        df = load_predictions_from_sqlitecloud(time_window=query_duration, dashboard_type="DNS")
    else:  # DOS Dashboard
        query_duration = time_range_query_map.get(time_range, "-24h")
        df = load_predictions_from_sqlitecloud(time_window=query_duration, dashboard_type="DOS")

    if not df.empty:
        total_predictions = len(df)
        attack_rate = df["is_anomaly"].mean()
        avg_error = df["anomaly_score"].mean()

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Predictions", total_predictions)
        col2.metric("Attack Rate", f"{attack_rate:.2%}")
        col3.metric("Average Error", f"{avg_error:.2f}")

        # Add any other metrics or summary data here
    else:
        st.info("No predictions available for the selected time range.")
