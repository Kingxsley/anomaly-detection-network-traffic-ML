import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
from sklearn.metrics import precision_score, recall_score, f1_score
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

        # 🆕 Filter recent attacks from loaded SQLite data
        recent_cutoff = pd.Timestamp.now().replace(tzinfo=None) - pd.Timedelta(hours=1)
        recent_attacks_df = df[(df["timestamp"] >= recent_cutoff) & (df["is_anomaly"] == 1)]

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Predictions", total_predictions)
        col2.metric("Attack Rate", f"{attack_rate:.2%}")
        col3.metric("Recent Attacks", len(recent_attacks_df))

        # 🔍 Evaluation metrics
        if "anomaly_score" in df.columns:
            df["predicted"] = (df["anomaly_score"] >= 0.5).astype(int)
            precision = precision_score(df["is_anomaly"], df["predicted"], zero_division=0)
            recall = recall_score(df["is_anomaly"], df["predicted"], zero_division=0)
            f1 = f1_score(df["is_anomaly"], df["predicted"], zero_division=0)

            st.subheader("Model Performance")
            st.write(f"**Precision**: {precision:.2%}")
            st.write(f"**Recall**: {recall:.2%}")
            st.write(f"**F1 Score**: {f1:.2%}")

        # 🔍 Attack Summary Stats
        st.subheader("Attack Summary")
        if len(df[df["is_anomaly"] == 1]) > 0:
            attack_df = df[df["is_anomaly"] == 1].copy()
            avg_score = attack_df["anomaly_score"].mean()
            max_score = attack_df["anomaly_score"].max()
            top_sources = attack_df["source_ip"].value_counts().head(3)
            peak_hour = attack_df["timestamp"].dt.hour.mode()[0]

            st.write(f"**Avg. Reconstruction Error (Attacks)**: {avg_score:.4f}")
            st.write(f"**Max. Reconstruction Error (Attacks)**: {max_score:.4f}")
            st.write("**Top Source IPs:**")
            for ip, count in top_sources.items():
                st.write(f"- {ip}: {count} occurrences")
            st.write(f"**Most Frequent Attack Hour:** {peak_hour}:00")
        else:
            st.info("No attacks recorded in the selected time window.")

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
