import streamlit as st
import pandas as pd
import requests
from streamlit_autorefresh import st_autorefresh
from tabs.utils import get_dos_data, send_discord_alert, log_to_sqlitecloud, DOS_API_URL

def render(thresh, highlight_color, alerts_enabled):
    # Initialize session state if not already initialized
    if "predictions" not in st.session_state:
        st.session_state.predictions = []

    if "attacks" not in st.session_state:
        st.session_state.attacks = []

    # Auto-refresh for live data
    st_autorefresh(interval=10000, key="live_refresh")

    # Title of the stream
    st.header("Live DoS Stream")

    # Fetch DoS data
    records = get_dos_data()
    new_predictions = []

    if records:
        for row in records:
            payload = {
                "inter_arrival_time": row["inter_arrival_time"],
                "dos_rate": row["dos_rate"]
            }
            try:
                # Sending data to the DoS anomaly API
                response = requests.post(DOS_API_URL, json=payload, timeout=20)
                result = response.json()
                if "anomaly" in result and "reconstruction_error" in result:
                    # Update the result with the row data
                    result.update(row)
                    result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
                    new_predictions.append(result)

                    # Send Discord alert if anomaly is detected
                    if result["anomaly"] == 1 and alerts_enabled:
                        send_discord_alert(result)
            except Exception as e:
                st.warning(f"API error: {e}")

        # Update session state with new predictions and attacks
        if new_predictions:
            st.session_state.predictions.extend(new_predictions)
            st.session_state.attacks.extend([r for r in new_predictions if r["anomaly"] == 1])

            # Log predictions to SQLiteCloud
            for r in new_predictions:
                log_to_sqlitecloud(r)

            # Keep the latest 1000 predictions
            st.session_state.predictions = st.session_state.predictions[-1000:]
            st.session_state.attacks = st.session_state.attacks[-1000:]

    # Display predictions as a dataframe with pagination
    df = pd.DataFrame(st.session_state.predictions)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        
        # Pagination settings
        rows_per_page = 100
        total_pages = (len(df) - 1) // rows_per_page + 1
        page_number = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1, key="live_page") - 1
        paged_df = df.iloc[page_number * rows_per_page:(page_number + 1) * rows_per_page]

        # Highlight anomalies in the dataframe
        def highlight(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        # Display the dataframe with highlighted rows
        st.dataframe(paged_df.style.apply(highlight, axis=1), key="live_table")
    else:
        st.info("No predictions yet.")
