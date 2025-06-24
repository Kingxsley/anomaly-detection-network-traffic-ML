# manual_entry.py

import streamlit as st
import pandas as pd
import requests
from datetime import datetime
from tabs.utils import DOS_API_URL

def render():
    st.header("Manual Entry - DoS")  # Static title for DoS
    col1, col2 = st.columns(2)
    with col1:
        inter_arrival_time = st.number_input("Inter Arrival Time", value=0.01)
    with col2:
        dos_rate = st.number_input("DoS Rate", value=5.0)

    if st.button("Predict"):
        try:
            res = requests.post(DOS_API_URL, json={
                "inter_arrival_time": inter_arrival_time,
                "dos_rate": dos_rate
            })
            result = res.json()
            result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
            st.session_state.predictions.append(result)
            st.dataframe(pd.DataFrame([result]))
        except Exception as e:
            st.error(f"Error: {e}")
