import streamlit as st
import pandas as pd
import requests

def render_live_tab(records, API_URL, alerts_enabled, send_discord_alert, log_to_sqlitecloud, highlight_color):
    st.header("Live DNS Stream")

    new_predictions = []
    for row in records:
        payload = {
            "inter_arrival_time": row["inter_arrival_time"],
            "dns_rate": row["dns_rate"]
        }
        try:
            res = requests.post(API_URL, json=payload, timeout=10)
            result = res.json()
            if "anomaly" in result:
                result.update(row)
                result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
                new_predictions.append(result)
                if result["anomaly"] == 1 and alerts_enabled:
                    send_discord_alert(result)
                log_to_sqlitecloud(result)
        except Exception as e:
            st.warning(f"API error: {e}")

    if new_predictions:
        st.session_state.predictions.extend(new_predictions)
        st.session_state.attacks.extend([r for r in new_predictions if r["anomaly"] == 1])
        st.session_state.predictions = st.session_state.predictions[-1000:]
        st.session_state.attacks = st.session_state.attacks[-1000:]

    df = pd.DataFrame(st.session_state.predictions)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        rows_per_page = 100
        total_pages = (len(df) - 1) // rows_per_page + 1
        page_number = st.number_input("Page", 1, total_pages, 1) - 1
        paged_df = df.iloc[page_number * rows_per_page:(page_number + 1) * rows_per_page]

        def highlight(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        st.dataframe(paged_df.style.apply(highlight, axis=1))
    else:
        st.info("No predictions yet.")

