import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh
from tabs.utils import load_predictions_from_sqlitecloud

def render(time_range, time_range_query_map):
    st_autorefresh(interval=30000, key="overview_refresh")
    st.title("DNS Anomaly Detection Overview")
    query_duration = time_range_query_map.get(time_range, "-24h")
    df = load_predictions_from_sqlitecloud(time_window=query_duration)

    if not df.empty:
        total_predictions = len(df)
        attack_rate = df["is_anomaly"].mean()
        avg_error = df["anomaly_score"].mean()
        max_error = df["anomaly_score"].max()
        min_error = df["anomaly_score"].min()

        recent_cutoff = pd.Timestamp.now().replace(tzinfo=None) - pd.Timedelta(hours=1)
        recent_attacks = df[(df["timestamp"] >= recent_cutoff) & (df["is_anomaly"] == 1)]

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Predictions", total_predictions)
        col2.metric("Attack Rate", f"{attack_rate:.2%}")
        col3.metric("Recent Attacks", len(recent_attacks))

        with st.expander("Attack Summary", expanded=True):
            st.write(f"**Average Reconstruction Error:** {avg_error:.4f}")
            st.write(f"**Maximum Error:** {max_error:.4f}")
            st.write(f"**Minimum Error:** {min_error:.4f}")

        st.markdown("### Top Source IPs")
        ip_counts = df["source_ip"].value_counts().nlargest(10).reset_index()
        ip_counts.columns = ["source_ip", "count"]

        fig_ip = px.bar(
            ip_counts,
            x="source_ip",
            y="count",
            labels={"source_ip": "Source IP", "count": "Anomaly Count"},
            text_auto=True
        )
        st.plotly_chart(fig_ip, use_container_width=True)

        st.markdown("### Anomaly Score Over Time")
        fig = px.line(
            df,
            x="timestamp",
            y="anomaly_score",
            color=df["is_anomaly"].map({1: "Attack", 0: "Normal"}).astype(str),
            labels={"color": "Anomaly Type"},
            title="Anomaly Score Over Time"
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No predictions available in the selected time range.")
