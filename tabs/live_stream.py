import streamlit as st
import pandas as pd
import requests
from streamlit_autorefresh import st_autorefresh
from tabs.utils import get_dos_data, send_discord_alert, log_to_sqlitecloud, API_URL

def render(thresh, highlight_color, alerts_enabled):
    # Refresh every 10 seconds
    st_autorefresh(interval=10000, key="live_refresh")
    st.header("Live DoS Stream")

    # Get data from InfluxDB
    records = get_dos_data()  # Fetch real-time DoS data
    new_predictions = []

    # Process each record
    if records:
        for row in records:
            payload = {
                "inter_arrival_time": row["inter_arrival_time"],  # Correct field from InfluxDB
                "packet_rate": row["packet_rate"]  # Replaced dns_rate with packet_rate
            }
            try:
                # Send data to API for anomaly detection
                response = requests.post(API_URL, json=payload, timeout=20)
                result = response.json()
                
                # Check if anomaly data is returned
                if "anomaly" in result and "reconstruction_error" in result:
                    result.update(row)  # Add InfluxDB data to API response
                    result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
                    new_predictions.append(result)

                    # Send Discord alert if anomaly detected
                    if result["anomaly"] == 1 and alerts_enabled:
                        send_discord_alert(result)
            except Exception as e:
                st.warning(f"API error: {e}")

        # Store and manage predictions
        if new_predictions:
            # Append new predictions and attacks
            st.session_state.predictions.extend(new_predictions)
            st.session_state.attacks.extend([r for r in new_predictions if r["anomaly"] == 1])
            
            # Log to SQLite
            for r in new_predictions:
                log_to_sqlitecloud(r)
            
            # Limit the number of records displayed (keep only the last 1000)
            st.session_state.predictions = st.session_state.predictions[-1000:]
            st.session_state.attacks = st.session_state.attacks[-1000:]

    # Display predictions in a paginated format (100 records per page)
    df = pd.DataFrame(st.session_state.predictions)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])  # Convert timestamp to datetime
        rows_per_page = 100  # Number of records per page
        total_pages = (len(df) - 1) // rows_per_page + 1  # Calculate the number of pages
        page_number = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1, key="live_page") - 1
        paged_df = df.iloc[page_number * rows_per_page:(page_number + 1) * rows_per_page]

        # Apply highlighting to rows based on anomaly status
        def highlight(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        # Display the table with highlighted rows
        st.dataframe(paged_df.style.apply(highlight, axis=1), key="live_table")
    else:
        st.info("No predictions yet.")  # If no predictions, show this message
import streamlit as st
import pandas as pd
import requests
from streamlit_autorefresh import st_autorefresh
from tabs.utils import get_dos_data, send_discord_alert, log_to_sqlitecloud, API_URL

def render(thresh, highlight_color, alerts_enabled):
    # Refresh every 10 seconds
    st_autorefresh(interval=10000, key="live_refresh")
    st.header("Live DoS Stream")

    records = get_dos_data()
    new_predictions = []

    if records:
        for row in records:
            payload = {
                "inter_arrival_time": row["inter_arrival_time"],  # Correct field from InfluxDB
                "packet_rate": row["packet_rate"]  # Replaced dns_rate with packet_rate
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
            st.session_state.predictions = st.session_state.predictions[-1000:]
            st.session_state.attacks = st.session_state.attacks[-1000:]

    # Display the predictions in a paginated format (100 records per page)
    df = pd.DataFrame(st.session_state.predictions)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        rows_per_page = 100
        total_pages = (len(df) - 1) // rows_per_page + 1
        page_number = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1, key="live_page") - 1
        paged_df = df.iloc[page_number * rows_per_page:(page_number + 1) * rows_per_page]

        def highlight(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        st.dataframe(paged_df.style.apply(highlight, axis=1), key="live_table")
    else:
        st.info("No predictions yet.")
