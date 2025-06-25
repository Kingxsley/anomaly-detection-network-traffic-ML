import streamlit as st
import pandas as pd
import plotly.express as px
from utils import get_dos_data, send_discord_alert, get_historical_data_for_dos  # Reuse get_dos_data, send_discord_alert, and get_historical_data_for_dos

# Overview Tab for DNS
def render_overview(time_range, sqlite_host, sqlite_port, sqlite_db, sqlite_apikey):
    st.header("DNS Anomaly Detection Overview")
    df = get_historical_data_for_dos(time_range, sqlite_host, sqlite_port, sqlite_db, sqlite_apikey)  # Adjust if needed for DNS data
    
    if not df.empty:
        total_predictions = len(df)
        attack_rate = df["is_anomaly"].mean()
        avg_error = df["anomaly_score"].mean()
        max_error = df["anomaly_score"].max()
        min_error = df["anomaly_score"].min()

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Predictions", total_predictions)
        col2.metric("Attack Rate", f"{attack_rate:.2%}")
        col3.metric("Total Attacks", df[df["is_anomaly"] == 1].shape[0])

        st.markdown("### Attack Summary")
        summary_cols = st.columns(3)
        summary_cols[0].metric("Average Reconstruction Error", f"{avg_error:.4f}")
        summary_cols[1].metric("Max Reconstruction Error", f"{max_error:.4f}")
        summary_cols[2].metric("Min Reconstruction Error", f"{min_error:.4f}")

        # Times with Most Attacks
        attack_df = df[df["is_anomaly"] == 1].copy()
        attack_df["time"] = pd.to_datetime(attack_df["timestamp"]).dt.strftime('%Y-%m-%d %H:00')
        top_times = attack_df["time"].value_counts().nlargest(5).reset_index()
        top_times.columns = ["Time (Hour Block)", "Attack Count"]
        st.dataframe(top_times.style.format(), use_container_width=True)

        # Top Source IPs
        ip_counts = df[df["is_anomaly"] == 1]["source_ip"].value_counts().nlargest(10).reset_index()
        ip_counts.columns = ["source_ip", "count"]
        fig_ip = px.bar(
            ip_counts,
            x="source_ip",
            y="count",
            labels={"source_ip": "Source IP", "count": "Anomaly Count"},
            text_auto=True
        )
        st.plotly_chart(fig_ip, use_container_width=True)

        # Anomaly Score Over Time
        fig = px.line(
            df,
            x="timestamp",
            y="anomaly_score",
            color=df["is_anomaly"].map({1: "Attack", 0: "Normal"}).astype(str),
            labels={"color": "Anomaly Type"},
            title="Anomaly Score Over Time"
        )
        st.plotly_chart(fig, use_container_width=True)

        # Recent Attack Details
        recent_attacks = df[df["is_anomaly"] == 1].sort_values("timestamp", ascending=False).head(10)
        st.dataframe(recent_attacks[["timestamp", "source_ip", "dest_ip", "anomaly_score"]], use_container_width=True)
    else:
        st.info("No predictions available in the selected time range.")

# Live Stream Tab for DNS
def render_live_stream(api_url, highlight_color, alerts_enabled, discord_webhook):
    st.header("Live DNS Stream")
    records = get_dos_data(api_url)  # Reuse the get_dos_data function for DNS data as well
    if records:
        df = pd.DataFrame(records)
        if not df.empty:
            st.write(df)
        else:
            st.warning("No real-time DNS data available.")
    else:
        st.warning("No real-time DNS data available.")

# Manual Entry Tab for DNS
def render_manual_entry(api_url, discord_webhook):
    st.header("Manual DNS Entry")
    col1, col2 = st.columns(2)
    with col1:
        inter_arrival_time = st.number_input("Inter Arrival Time", value=0.01)
    with col2:
        dns_rate = st.number_input("DNS Rate", value=5.0)

    if st.button("Predict DNS Anomaly"):
        payload = {
            "inter_arrival_time": inter_arrival_time,
            "dns_rate": dns_rate
        }
        try:
            response = requests.post(api_url, json=payload)
            result = response.json()
            result["timestamp"] = pd.to_datetime("now").strftime("%Y-%m-%d %H:%M:%S")
            result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
            st.session_state.predictions.append(result)
            st.dataframe(pd.DataFrame([result]))
            if result["anomaly"] == 1 and alerts_enabled:
                send_discord_alert(result, discord_webhook)
        except Exception as e:
            st.error(f"Error: {e}")

# Metrics Tab for DNS
def render_metrics():
    st.header("DNS Model Performance Metrics")
    df = pd.DataFrame(st.session_state.predictions)
    if not df.empty:
        st.subheader("Performance Metrics")
        valid_df = df.dropna(subset=["label", "anomaly"])
        if len(valid_df) >= 2 and valid_df["label"].nunique() > 1 and valid_df["anomaly"].nunique() > 1:
            y_true = valid_df["anomaly"].astype(int)
            y_pred = valid_df["anomaly"].astype(int)

            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Accuracy", f"{accuracy_score(y_true, y_pred):.2%}")
            col2.metric("Precision", f"{precision_score(y_true, y_pred, zero_division=0):.2%}")
            col3.metric("Recall", f"{recall_score(y_true, y_pred, zero_division=0):.2%}")
            col4.metric("F1-Score", f"{f1_score(y_true, y_pred, zero_division=0):.2%}")

            cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
            if cm.shape == (2, 2):
                fig_cm = px.imshow(cm, text_auto=True, color_continuous_scale="Blues", labels={"x": "Predicted", "y": "Actual"})
                st.plotly_chart(fig_cm)
            else:
                st.warning("Confusion matrix could not be generated due to insufficient class diversity.")
        else:
            st.warning("Insufficient or unbalanced data for performance metrics.")

        st.subheader("Reconstruction Error Distribution")
        fig_hist = px.histogram(
            df,
            x="reconstruction_error",
            color="anomaly",
            title="Reconstruction Error Distribution",
            color_discrete_map={0: "blue", 1: "red"},
            nbins=50
        )
        st.plotly_chart(fig_hist, use_container_width=True)
    else:
        st.info("No predictions available for performance analysis.")

# Historical Data Tab for DNS
def render_historical_data(time_range, sqlite_host, sqlite_port, sqlite_db, sqlite_apikey):
    st.header("DNS Historical Data")
    df_hist = get_historical_data_for_dos(time_range, sqlite_host, sqlite_port, sqlite_db, sqlite_apikey)  # Adjust for DNS data
    if not df_hist.empty:
        st.dataframe(df_hist)
    else:
        st.warning("No historical DNS data available.")
