import streamlit as st
import requests
from utils import get_live_data

def render(thresh, highlight_color, alerts_enabled):
    st.title("Live Stream")

    if st.session_state.DASHBOARD_TYPE == "DNS":
        records = get_live_data("DNS")
    else:  # DOS
        records = get_live_data("DOS")

    # Process and display data (same logic for DNS and DOS)
    for record in records:
        st.write(record)
        # Trigger alert if necessary and log to database
        if alerts_enabled and record["anomaly"] == 1:
            send_alert(record)

# Placeholder for sending alerts (implement as needed)
def send_alert(record):
    # Send an alert (e.g., to Discord or other platforms)
    pass
