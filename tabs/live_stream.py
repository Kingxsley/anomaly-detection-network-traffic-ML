import streamlit as st
import pandas as pd
import requests
from streamlit_autorefresh import st_autorefresh
from tabs.utils import get_dos_data, send_discord_alert, log_to_sqlitecloud

# FastAPI model endpoint
API_URL = "https://mizzony-dos-anomaly-detection.hf.space/predict"

def render(thresh, highlight_color, alerts_enabled):
    # Auto-refresh every 60 seconds
    st_autorefresh(interval=60000, key="live_refresh")
    st.header("🚨 Live DoS Stream Dashboard")

    # Initialize session state
    if "predictions" not in st.session_state:
        st.session_state.predictions = []
    if "attacks" not in st.session_state:
        st.session_state.attacks = []

    # Fetch latest batch from InfluxDB
    records = get_dos_data()
    new_predictions = []

    if records:
        for row in records:
            # Build FastAPI-compatible payload
            payload = [{
                "inter_arrival_time": row["inter_arrival_time"],
                "packet_rate": row["packet_rate"],
                "packet_length": row["packet_length"],
                "protocol": row.get("protocol", "tcp").upper()
            }]

            try:
                response = requests.post(API_URL, json=payload, timeout=20)

                if response.status_code == 200 and response.text.strip():
                    try:
                        result_list = response.json()
                        if isinstance(result_list, list) and result_list:
                            result = result_list[0]
                            result.update(row)
                            result["anomaly"] = int(result.get("anomaly", result.get("is_anomaly", 0)))
                            result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
                            new_predictions.append(result)

                            # Send Discord alert if anomaly
                            if result["anomaly"] == 1 and alerts_enabled:
                                send_discord_alert(result)
                    except Exception as json_err:
                        st.warning(f"❌ JSON decode error: {json_err}")
                else:
                    st.warning(f"⚠️ API status {response.status_code}: {response.text}")
            except Exception as e:
                st.warning(f"🔥 API request failed: {e}")

        # Save new predictions
        if new_predictions:
            st.session_state.predictions.extend(new_predictions)
            st.session_state.attacks.extend([r for r in new_predictions if r["anomaly"] == 1])

            # Log to SQLite
            for r in new_predictions:
                log_to_sqlitecloud(r)

            # Limit to last 1000 entries
            st.session_state.predictions = st.session_state.predictions[-1000:]
            st.session_state.attacks = st.session_state.attacks[-1000:]

    # Display table
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
        st.info("ℹ No predictions available yet.")
