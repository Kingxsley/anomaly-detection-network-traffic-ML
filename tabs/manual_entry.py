# manual_entry.py

import streamlit as st
import requests
from datetime import datetime
from tabs.utils import DASHBOARD_TYPE  # Import DASHBOARD_TYPE here

def render():
    st.header("Manual Entry")
    col1, col2 = st.columns(2)
    with col1:
        inter_arrival_time = st.number_input("Inter Arrival Time", value=0.01)
    with col2:
        dns_rate = st.number_input("DNS Rate", value=5.0)

    # Use the appropriate API URL based on DASHBOARD_TYPE
    API_URL = st.secrets.get(f"{'DOS' if DASHBOARD_TYPE == 'DOS' else 'API'}_URL")

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
            st.error(f"Error: {e}")
