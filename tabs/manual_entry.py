import streamlit as st
import pandas as pd
import requests
from datetime import datetime
from tabs.utils import API_URL


def render():
    st.header(f"Manual Entry for {st.secrets.get('DASHBOARD_TYPE', 'DNS')}")

    # Load the appropriate API URL and webhook for DNS/DOS based on selected dashboard
    if st.secrets.get("DASHBOARD_TYPE", "DNS") == "DNS":
        api_url = st.secrets.get("API_URL")
        discord_webhook = st.secrets.get("DISCORD_WEBHOOK")
    else:  # DOS Dashboard
        api_url = st.secrets.get("DOS_API_URL")
        discord_webhook = st.secrets.get("DOS_DISCORD_WEBHOOK")

    # Input fields for the inter-arrival time and DNS rate
    col1, col2 = st.columns(2)
    with col1:
        inter_arrival_time = st.number_input("Inter Arrival Time", value=0.01)
    with col2:
        dns_rate = st.number_input("DNS Rate", value=5.0)

    # Predict button logic
    if st.button("Predict"):
        try:
            res = requests.post(api_url, json={
                "inter_arrival_time": inter_arrival_time,
                "dns_rate": dns_rate
            })
            result = res.json()
            result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
            st.session_state.predictions.append(result)
            st.dataframe(pd.DataFrame([result]))

            # Send Discord alert if the result is an anomaly
            if result["anomaly"] == 1:
                send_discord_alert(result, discord_webhook)

        except Exception as e:
            st.error(f"Error: {e}")
