import streamlit as st
import pandas as pd
import plotly.express as px
from utils import get_dos_data, send_discord_alert, get_historical_data_for_dos

def render_live_stream(api_url, highlight_color, alerts_enabled, discord_webhook):
    st.header("Live DoS Stream")
    records = get_dos_data(api_url)
    if records:
        df = pd.DataFrame(records)
        if not df.empty:
            st.write(df)
        else:
            st.warning("No real-time DoS data available.")
    else:
        st.warning("No real-time DoS data available.")

def render_manual_entry(api_url, discord_webhook):
    st.header("Manual DoS Entry")
    col1, col2 = st.columns(2)
    with col1:
        inter_arrival_time = st.number_input("Inter Arrival Time", value=0.01)
    with col2:
        dns_rate = st.number_input("DNS Rate", value=5.0)

    if st.button("Predict DoS Anomaly"):
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

def render_metrics():
    st.header("DoS Model Performance Metrics")
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

def render_historical_data(time_range, sqlite_host, sqlite_port, sqlite_db, sqlite_apikey):
    st.header("DoS Historical Data")
    df_hist = get_historical_data_for_dos(time_range, sqlite_host, sqlite_port, sqlite_db, sqlite_apikey)
    if not df_hist.empty:
        st.dataframe(df_hist)
    else:
        st.warning("No historical DoS data available.")
