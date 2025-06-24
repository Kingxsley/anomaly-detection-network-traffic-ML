# live_stream.py

import streamlit as st
import requests
import pandas as pd
from streamlit_autorefresh import st_autorefresh
from tabs.utils import get_data, DASHBOARD_TYPE  # Use DoS-specific functions from utils

def render(thresh, highlight_color, alerts_enabled, dashboard_type):
    st_autorefresh(interval=10000, key="live_refresh")
    st.header("Live DOS Stream")  # Set header for DoS

    # Use the appropriate API URL for DoS
    API_URL = st.secrets.get(f"{'DOS' if dashboard_type == 'DOS' else 'API'}_URL")
    records = get_data(API_URL)

    new_predictions = []
    if records:
        for row in records:
            payload = {
                "inter_arrival_time": row["inter_arrival_time"],
                "dns_rate": row["dns_rate"]
            }
            try:
                response = requests.post(API_URL, json=payload, timeout=20)
                result = response.json()
                if "anomaly" in result and "reconstruction_error" in result:
                    result.update(row)
                    result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
                    new_predictions.append(result)
                    if result["anomaly"] == 1 and alerts_enabled:
                        send_discord_alert(result)
            except Exception as e:
                st.warning(f"API error: {e}")

        if new_predictions:
            st.session_state.predictions.extend(new_predictions)
            st.session_state.attacks.extend([r for r in new_predictions if r["anomaly"] == 1])
            for r in new_predictions:
                log_to_sqlitecloud(r)

    df = pd.DataFrame(st.session_state.predictions)
    if not df.empty:
        st.dataframe(df)
    else:
        st.info("No predictions yet.")
