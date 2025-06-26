import streamlit as st
import pandas as pd
import requests
from streamlit_autorefresh import st_autorefresh
from tabs.utils import get_dos_data, send_discord_alert, log_to_sqlitecloud

API_URL = "https://mizzony-dos-anomaly-detection.hf.space/predict"

def render(thresh, highlight_color, alerts_enabled):
    st_autorefresh(interval=60000, key="live_refresh")  # Refresh every 60s
    st.title("🚨 Live DoS Stream Dashboard")

    # Initialize state
    if "predictions" not in st.session_state:
        st.session_state.predictions = []
    if "attacks" not in st.session_state:
        st.session_state.attacks = []

    records = get_dos_data()
    new_predictions = []

    if records:
        for row in records:
            payload = [{
                "inter_arrival_time": row["inter_arrival_time"],
                "packet_length": row["packet_length"],
                "protocol": row.get("protocol", "tcp").lower()
            }]
            try:
                response = requests.post(API_URL, json=payload, timeout=20)

                if response.status_code == 200 and response.text.strip():
                    try:
                        result_list = response.json()
                        if isinstance(result_list, list) and result_list:
                            result = result_list[0]
                            result.update(row)
                            result["anomaly"] = int(result.get("anomaly", 0))
                            result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
                            new_predictions.append(result)

                            # Send alert
                            if result["anomaly"] == 1 and alerts_enabled:
                                send_discord_alert(result)
                    except ValueError:
                        st.warning(f"❌ JSON decode failed:\n{response.text}")
                else:
                    st.warning(f"⚠ API error {response.status_code}: {response.text}")
            except Exception as e:
                st.warning(f"🔥 API request failed: {e}")

        if new_predictions:
            st.session_state.predictions.extend(new_predictions)
            st.session_state.attacks.extend([r for r in new_predictions if r["anomaly"] == 1])
            for r in new_predictions:
                log_to_sqlitecloud(r)

            # Keep recent 1000 entries
            st.session_state.predictions = st.session_state.predictions[-1000:]
            st.session_state.attacks = st.session_state.attacks[-1000:]

    # Show attack count and last alert
    total_attacks = len(st.session_state.attacks)
    st.subheader(f"🛡 Total Attacks Detected: {total_attacks}")

    if total_attacks > 0:
        last_attack = st.session_state.attacks[-1]
        with st.expander("🟥 Most Recent Attack Details", expanded=True):
            st.json(last_attack)

    # Show full prediction table with highlights
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
        st.info("ℹ Waiting for predictions...")
