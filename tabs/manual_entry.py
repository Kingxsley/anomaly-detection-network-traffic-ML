import streamlit as st
import requests
import pandas as pd
from datetime import datetime

def render_manual_entry_tab(API_URL):
    st.header("Manual Entry")

    col1, col2 = st.columns(2)
    with col1:
        inter_arrival_time = st.number_input("Inter Arrival Time", value=0.01)
    with col2:
        dns_rate = st.number_input("DNS Rate", value=5.0)

    if st.button("Predict"):
        try:
            res = requests.post(API_URL, json={
                "inter_arrival_time": inter_arrival_time,
                "dns_rate": dns_rate
            })
            result = res.json()
            result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
            st.session_state.predictions.append(result)
            st.dataframe(pd.DataFrame([result]))
        except Exception as e:
            st.error(f"Prediction error: {e}")

