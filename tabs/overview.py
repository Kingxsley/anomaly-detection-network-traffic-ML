import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh
from tabs.utils import load_predictions_from_sqlitecloud, generate_attack_summary, display_summary_cards

def render(time_range, time_range_query_map):
    st_autorefresh(interval=30000, key="overview_refresh")
    st.title("DNS Anomaly Detection Overview")

    query_duration = time_range_query_map.get(time_range, "-7d")
    df = load_predictions_from_sqlitecloud(time_window=query_duration)

    if df.empty:
        st.info("No predictions available in the selected time range.")
        return

    # Summary metrics
    total_predictions = len(df)
    attack_rate = df["is_anomaly"].mean()
    recent_cutoff = pd.Timestamp.now().replace(tzinfo=None) - pd.Timedelta(hours=1)
    recent_attacks = df[(df["timestamp"] >= recent_cutoff) & (df["is_anomaly"] == 1)]

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Predictions", total_predictions)
    col2.metric("Attack Rate", f"{attack_rate:.2%}")
    col3.metric("Recent Attacks", len(recent_attacks))

    # Attack Summary
    st.subheader("Attack Insights")
    summary, top_ips = generate_attack_summary(df)
    display_summary_cards(summary)

    # Anomaly Score Over Time
    st.subheader("Anomaly Score Over Time")
    fig = px.line(
        df,
        x="timestamp",
        y="anomaly_score",
        color=df["is_anomaly"].map({1: "Attack", 0: "Normal"}).astype(str),
        labels={"color": "Anomaly Type"},
        title="Anomaly Score Over Time"
    )
    st.plotly_chart(fig, use_container_width=True)

    # Top Source IPs Bar Chart
    if top_ips is not None and not top_ips.empty:
        st.subheader("Top Source IPs by Anomaly Count")
        ip_fig = px.bar(
            top_ips,
            x="source_ip",
            y="count",
            title="Top Source IPs with Anomalies",
            labels={"source_ip": "Source IP", "count": "Anomaly Count"},
            text_auto=True
        )
        ip_fig.update_layout(xaxis_tickangle=-45)
        st.plotly_chart(ip_fig, use_container_width=True)
