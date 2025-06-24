# metrics.py

import streamlit as st
import pandas as pd
from tabs.utils import get_data  # Ensure only get_data is imported for DoS

def render(thresh):
    st.header("DoS Metrics")  # Static header for DoS

    df = load_predictions_from_sqlitecloud(time_window="-24h")

    if not df.empty:
        st.markdown("### Attack Overview")
        st.write(f"Total predictions: {len(df)}")
        st.write(f"Total attacks: {df[df['is_anomaly'] == 1].shape[0]}")
        st.write(f"Attack rate: {df['is_anomaly'].mean():.2%}")

        # Show metrics like reconstruction error, attack distribution, etc.
        st.write(f"Avg Reconstruction Error: {df['anomaly_score'].mean():.4f}")
        st.write(f"Max Reconstruction Error: {df['anomaly_score'].max():.4f}")
        st.write(f"Min Reconstruction Error: {df['anomaly_score'].min():.4f}")
        
        st.bar_chart(df['anomaly_score'])
