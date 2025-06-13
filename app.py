import streamlit as st
import requests
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
from streamlit_autorefresh import st_autorefresh
import time

# Streamlit page configuration
st.set_page_config(page_title="DNS Anomaly Detection Dashboard", layout="wide")

# Initialize session state for predictions
if "predictions" not in st.session_state:
    st.session_state.predictions = []

# API endpoint (update with Hugging Face URL if deployed)
API_URL = "http://localhost:8000/predict"

# Title and description
st.title("Real-Time DNS Anomaly Detection Dashboard")
st.markdown("""
This dashboard monitors DNS traffic in real-time, detecting anomalies that may indicate attacks.
Use the manual input form for specific tests or watch the live stream of simulated DNS data.
""")

# Auto-refresh for real-time updates (every 3 seconds)
st_autorefresh(interval=3000, key="datarefresh")

# Simulated DNS data stream
def generate_dns_data():
    return {
        "inter_arrival_time": np.random.uniform(0.001, 1.0),  # Realistic range
        "dns_rate": np.random.uniform(0, 100)  # Realistic range
    }

# Input form for manual predictions
st.header("Manual Input")
col1, col2 = st.columns(2)
with col1:
    inter_arrival_time = st.number_input(
        "Inter Arrival Time (seconds)",
        min_value=0.001,
        max_value=10.0,
        value=0.01938,
        step=0.001
    )
with col2:
    dns_rate = st.number_input(
        "DNS Rate",
        min_value=0.0,
        max_value=100.0,
        value=2.0,
        step=0.1
    )

if st.button("Detect Anomaly"):
    payload = {"inter_arrival_time": inter_arrival_time, "dns_rate": dns_rate}
    try:
        response = requests.post(API_URL, json=payload)
        response.raise_for_status()
        result = response.json()
        result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.session_state.predictions.append(result)
        st.success("Manual prediction successful!")
        st.json(result)
    except requests.exceptions.RequestException as e:
        st.error(f"Error calling API: {e}")

# Real-time monitoring
st.header("Real-Time Monitoring")
if st.checkbox("Enable Live Stream", value=True):
    try:
        # Generate and predict new data point
        data = generate_dns_data()
        payload = {
            "inter_arrival_time": data["inter_arrival_time"],
            "dns_rate": data["dns_rate"]
        }
        response = requests.post(API_URL, json=payload)
        response.raise_for_status()
        result = response.json()
        result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.session_state.predictions.append(result)
        
        # Limit to last 100 predictions to prevent memory issues
        st.session_state.predictions = st.session_state.predictions[-100:]
        
    except requests.exceptions.RequestException as e:
        st.error(f"Error in live stream: {e}")

# Display predictions
if st.session_state.predictions:
    df = pd.DataFrame(st.session_state.predictions)
    
    # Table
    st.subheader("Recent Predictions")
    st.dataframe(df[["timestamp", "inter_arrival_time", "dns_rate", "request_rate", "reconstruction_error", "anomaly"]])
    
    # Line plot of reconstruction error
    st.subheader("Reconstruction Error Over Time")
    fig_line = px.line(
        df,
        x="timestamp",
        y="reconstruction_error",
        color="anomaly",
        color_discrete_map={0: "blue", 1: "red"},
        title="Real-Time Reconstruction Error (Red = Attack, Blue = Normal)"
    )
    fig_line.add_hline(y=0.1, line_dash="dash", line_color="green", annotation_text="Threshold (0.1)")
    st.plotly_chart(fig_line, use_container_width=True)
    
    # Bar chart of anomaly counts
    st.subheader("Anomaly Distribution")
    anomaly_counts = df["anomaly"].value_counts().reset_index()
    anomaly_counts.columns = ["Anomaly", "Count"]
    anomaly_counts["Anomaly"] = anomaly_counts["Anomaly"].map({0: "Normal", 1: "Attack"})
    fig_bar = px.bar(
        anomaly_counts,
        x="Anomaly",
        y="Count",
        title="Normal vs. Attack Counts",
        color="Anomaly",
        color_discrete_map={"Normal": "blue", "Attack": "red"}
    )
    st.plotly_chart(fig_bar, use_container_width=True)
    
    # Summary metrics
    st.subheader("Summary")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Predictions", len(df))
    col2.metric("Attack Rate", f"{df['anomaly'].mean():.2%}")
    col3.metric("Recent Attacks", df.tail(10)["anomaly"].sum())
else:
    st.info("No predictions yet. Enable live stream or use manual input.")