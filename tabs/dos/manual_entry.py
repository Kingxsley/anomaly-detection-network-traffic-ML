# tabs/dos/manual_entry.py
import streamlit as st
import pandas as pd
import requests
from datetime import datetime
from tabs.dos.utils import DOS_API_URL

def render_manual_entry(api_url):
    st.header("Manual Entry - DOS Anomaly Check")
    col1, col2 = st.columns(2)
    with col1:
        packet_count = st.number_input("Packet Count", value=100)
    with col2:
        byte_rate = st.number_input("Byte Rate (bytes/sec)", value=1000.0)

    if st.button("Predict"):
        try:
            response = requests.post(api_url, json={
                "packet_count": packet_count,
                "byte_rate": byte_rate
            })
            result = response.json()
            result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
            st.session_state.predictions.append(result)
            st.dataframe(pd.DataFrame([result]))
        except Exception as e:
            st.error(f"Prediction error: {e}")
