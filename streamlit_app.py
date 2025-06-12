import streamlit as st
import pandas as pd
from inference import detect_anomalies

st.set_page_config(page_title="DNS Anomaly Detection", layout="centered")

st.title("🔍 DNS Anomaly Detection")
st.write("Enter DNS traffic data below to detect anomalies using a trained autoencoder.")

with st.form("detection_form"):
    inter_arrival_time = st.number_input("Inter-arrival Time (seconds)", min_value=0.001, value=0.1, step=0.01)
    dns_rate = st.number_input("DNS Rate", min_value=0.0, value=50.0, step=1.0)
    submitted = st.form_submit_button("Run Detection")

if submitted:
    input_df = pd.DataFrame([{
        "inter_arrival_time": inter_arrival_time,
        "dns_rate": dns_rate
    }])
    result = detect_anomalies(input_df)
    if result is not None:
        is_anomaly = result["anomaly"].iloc[0]
        recon_error = result["reconstruction_error"].iloc[0]
        st.subheader("Result")
        st.write(f"**Reconstruction Error:** {recon_error:.5f}")
        st.success("✅ Normal") if is_anomaly == 0 else st.error("⚠️ Anomaly Detected")
    else:
        st.error("Something went wrong during detection.")
