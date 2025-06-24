# overview.py

import streamlit as st
import pandas as pd
from tabs.utils import get_data  # Use the correct get_data function for DoS

def render(time_range, time_range_query_map):
    st.title("DoS Overview")  # Static title for DoS

    query_duration = time_range_query_map.get(time_range, "-24h")
    records = get_data()  # Fetch DoS data from the correct API

    # Convert the data into a DataFrame
    df = pd.DataFrame(records)

    if not df.empty:
        total_predictions = len(df)
        attack_rate = df["is_anomaly"].mean() if "is_anomaly" in df else 0
        avg_error = df["anomaly_score"].mean() if "anomaly_score" in df else 0
        max_error = df["anomaly_score"].max() if "anomaly_score" in df else 0
        min_error = df["anomaly_score"].min() if "anomaly_score" in df else 0

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Predictions", total_predictions)
        col2.metric("Attack Rate", f"{attack_rate:.2%}")
        col3.metric("Total Attacks", df[df["is_anomaly"] == 1].shape[0])

        st.markdown("### Attack Summary")
        summary_cols = st.columns(3)
        summary_cols[0].metric("Average Reconstruction Error", f"{avg_error:.4f}")
        summary_cols[1].metric("Max Reconstruction Error", f"{max_error:.4f}")
        summary_cols[2].metric("Min Reconstruction Error", f"{min_error:.4f}")
