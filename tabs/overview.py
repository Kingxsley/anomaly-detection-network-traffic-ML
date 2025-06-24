import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
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
        recent_cutoff = pd.Timestamp.now().replace(tzinfo=None) - pd.Timedelta(hours=1)
        recent_attacks_df = df[(df["timestamp"] >= recent_cutoff) & (df["is_anomaly"] == 1)]

        # 📊 Key Metrics
        st.subheader("Key Metrics")
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Predictions", total_predictions)
        col2.metric("Attack Rate", f"{attack_rate:.2%}")
        col3.metric("Recent Attacks (Last Hour)", len(recent_attacks_df))

        # 🔍 Model Performance
        if "anomaly_score" in df.columns:
            df["predicted"] = (df["anomaly_score"] >= 0.5).astype(int)
            precision = precision_score(df["is_anomaly"], df["predicted"], zero_division=0)
            recall = recall_score(df["is_anomaly"], df["predicted"], zero_division=0)
            f1 = f1_score(df["is_anomaly"], df["predicted"], zero_division=0)

            st.subheader("Model Evaluation")
            eval_col1, eval_col2, eval_col3 = st.columns(3)
            eval_col1.metric("Precision", f"{precision:.2%}")
            eval_col2.metric("Recall", f"{recall:.2%}")
            eval_col3.metric("F1 Score", f"{f1:.2%}")

        # 🧠 Attack Summary
        st.subheader("Attack Insights")
        if len(df[df["is_anomaly"] == 1]) > 0:
            attack_df = df[df["is_anomaly"] == 1].copy()
            avg_score = attack_df["anomaly_score"].mean()
            max_score = attack_df["anomaly_score"].max()
            top_sources = attack_df["source_ip"].value_counts().head(3).reset_index()
            top_sources.columns = ["Source IP", "Anomaly Count"]
            peak_hour = attack_df["timestamp"].dt.hour.mode()[0]

            col1, col2 = st.columns(2)
            with col1:
                st.metric("Avg. Reconstruction Error", f"{avg_score:.4f}")
                st.metric("Max. Reconstruction Error", f"{max_score:.4f}")
                st.metric("Peak Hour of Attacks", f"{peak_hour}:00")

            with col2:
                fig = go.Figure(data=[
                    go.Bar(
                        x=top_sources["Source IP"],
                        y=top_sources["Anomaly Count"],
                        marker_color="crimson"
                    )
                ])
                fig.update_layout(
                    title="Top Source IPs by Anomaly Count",
                    xaxis_title="Source IP",
                    yaxis_title="Count",
                    height=300
                )
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attacks recorded in the selected time window.")

        # 📉 Anomaly Trend Line
        st.subheader("Anomaly Score Over Time")
        fig = px.line(
            df,
            x="timestamp",
            y="anomaly_score",
            color=df["is_anomaly"].map({1: "Attack", 0: "Normal"}).astype(str),
            labels={"color": "Anomaly Type"},
            title=""
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No predictions available in the selected time range.")
