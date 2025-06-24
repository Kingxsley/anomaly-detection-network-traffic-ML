# manual_entry.py

import streamlit as st
import requests
from datetime import datetime

def render(dashboard_type):
    st.header(f"Manual Entry - {dashboard_type}")  # Display DoS in header
    col1, col2 = st.columns(2)
    with col1:
        inter_arrival_time = st.number_input("Inter Arrival Time", value=0.01)  # Inter-arrival time for DoS
    with col2:
        dos_rate = st.number_input("DoS Rate", value=5.0)  # Correct DoS rate field

    # Use the correct API URL for DoS from config
    API_URL = DOS_API_URL

    if st.button("Predict"):
        try:
            res = requests.post(API_URL, json={
                "inter_arrival_time": inter_arrival_time,
                "dos_rate": dos_rate  # Correct DoS rate field
            })
            result = res.json()
            result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
            st.session_state.predictions.append(result)
            st.dataframe(pd.DataFrame([result]))
        except Exception as e:
            st.error(f"Error: {e}")
