import streamlit as st
import pandas as pd
import requests
from streamlit_autorefresh import st_autorefresh
from tabs.utils import get_dos_data, send_discord_alert, log_to_sqlitecloud, API_URL

def render(thresh, highlight_color, alerts_enabled):
    # Auto-refresh the page every 10 seconds
    st_autorefresh(interval=10000, key="live_refresh")
    st.header("Live DoS Stream")

    # Get new data from InfluxDB
    records = get_dos_data()
    new_predictions = []

    if records:
        for row in records:
            # Prepare payload (adjust based on your model input)
            payload = {
                "inter_arrival_time": row["inter_arrival_time"],
                "packet_rate": row["packet_rate"]
            }

            try:
                # Send POST request to API — wrapped as list for FastAPI compatibility
                response = requests.post(API_URL, json=[payload], timeout=20)

                if response.status_code == 200:
                    try:
                        result_list = response.json()

                        # Some APIs return a list even for one item
                        if isinstance(result_list, list) and result_list:
                            result = result_list[0]

                            if "anomaly" in result and "reconstruction_error" in result:
                                result.update(row)
                                result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
                                new_predictions.append(result)

                                # Send Discord alert if anomaly is detected
                                if result["anomaly"] == 1 and alerts_enabled:
                                    send_discord_alert(result)
                        else:
                            st.warning(f"API returned unexpected format: {result_list}")
                    except ValueError:
                        st.warning(f"JSON decode error. Raw response:\n{response.text}")
                else:
                    st.warning(f"API error {response.status_code}. Response:\n{response.text}")

            except Exception as e:
                st.warning(f"Request failed: {e}")

        # Store and process predictions
        if new_predictions:
            st.session_state.predictions.extend(new_predictions)
            st.session_state.attacks.extend([r for r in new_predictions if r["anomaly"] == 1])

            for r in new_predictions:
                log_to_sqlitecloud(r)

            st.session_state.predictions = st.session_state.predictions[-1000:]
            st.session_state.attacks = st.session_state.attacks[-1000:]

    # Display predictions in paginated view
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
