import streamlit as st
from tabs import overview
from tabs import live_stream
from tabs import manual_entry
from tabs import metrics
from tabs import historical
import pandas as pd
import requests
import plotly.express as px
from datetime import datetime
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# --- DoS Specific Helper Functions ---
def get_dos_data():
    try:
        response = requests.get(f"{API_URL}/realtime")
        if response.status_code == 200:
            return response.json()  # Return real-time DoS data
        else:
            st.warning("Failed to fetch real-time DoS data.")
            return []
    except Exception as e:
        st.warning(f"Error fetching DoS data: {e}")
        return []

def manual_dos_entry(inter_arrival_time, dns_rate):
    try:
        payload = {
            "inter_arrival_time": inter_arrival_time,
            "dns_rate": dns_rate
        }
        response = requests.post(API_URL, json=payload)
        result = response.json()
        result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
        st.session_state.predictions.append(result)
        st.dataframe(pd.DataFrame([result]))
        # Send Discord alert if attack detected
        if result["anomaly"] == 1 and alerts_enabled:
            send_discord_alert(result)
    except Exception as e:
        st.error(f"Error: {e}")

def send_discord_alert(result):
    message = {
        "content": (
            f"\U0001f6a8 **DoS Anomaly Detected!**\n"
            f"**Timestamp:** {result.get('timestamp')}\n"
            f"**DNS Rate:** {result.get('dns_rate')}\n"
            f"**Inter-arrival Time:** {result.get('inter_arrival_time')}\n"
            f"**Reconstruction Error:** {float(result.get('reconstruction_error', 0)):.6f}\n"
            f"**Source IP:** {result.get('source_ip')}\n"
            f"**Destination IP:** {result.get('dest_ip')}"
        )
    }
    try:
        requests.post(DISCORD_WEBHOOK, json=message, timeout=20)
    except Exception as e:
        st.warning(f"Discord alert failed: {e}")

def get_historical_data_for_dos(time_range):
    try:
        # Placeholder for actual data fetching based on time range
        query_duration = time_range_query_map.get(time_range, "-24h")
        # You can fetch data from the SQLite database, InfluxDB, or other sources
        conn = sqlitecloud.connect(f"sqlitecloud://{SQLITE_HOST}:{SQLITE_PORT}/{SQLITE_DB}?apikey={SQLITE_APIKEY}")
        cursor = conn.execute(f"""
            SELECT * FROM dos_anomalies
            WHERE timestamp >= '{query_duration}'
            ORDER BY timestamp DESC
        """)
        rows = cursor.fetchall()
        if not rows:
            return pd.DataFrame()
        cols = [column[0] for column in cursor.description]
        df = pd.DataFrame(rows, columns=cols)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        conn.close()
        return df
    except Exception as e:
        st.error(f"SQLite Cloud error: {e}")
        return pd.DataFrame()

# --- Sidebar Settings ---
dashboard_toggle = st.sidebar.selectbox("Select Dashboard", ["DNS Dashboard", "DoS Dashboard"])
time_range_query_map = {
    "Last 30 min": "-30m",
    "Last 1 hour": "-1h",
    "Last 24 hours": "-24h",
    "Last 7 days": "-7d",
    "Last 14 days": "-14d",
    "Last 30 days": "-30d"
}
time_range = st.sidebar.selectbox("Time Range", list(time_range_query_map.keys()), index=2)
thresh = st.sidebar.slider("Anomaly Threshold", 0.01, 1.0, 0.1, 0.01)
highlight_color = st.sidebar.selectbox("Highlight Color", ["Red", "Orange", "Yellow", "Green", "Blue"], index=3)
alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)

# --- State Initialization ---
if "predictions" not in st.session_state:
    st.session_state.predictions = []
if "attacks" not in st.session_state:
    st.session_state.attacks = []

# --- Render the selected dashboard ---
if dashboard_toggle == "DNS Dashboard":
    tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics", "Historical Data"])

    with tabs[0]:
        overview.render(time_range, time_range_query_map)

    with tabs[1]:
        live_stream.render(thresh, highlight_color, alerts_enabled)

    with tabs[2]:
        manual_entry.render()

    with tabs[3]:
        metrics.render(thresh)

    with tabs[4]:
        historical.render(thresh, highlight_color)

elif dashboard_toggle == "DoS Dashboard":
    # DoS Dashboard Content
    st.title("DoS Anomaly Detection Dashboard")

    # --- Tabs for DoS Dashboard
    dos_tabs = st.tabs(["Live Stream", "Manual Entry", "Metrics", "Historical Data"])

    with dos_tabs[0]:
        st.header("Live DoS Stream")
        records = get_dos_data()
        if records:
            df = pd.DataFrame(records)
            if not df.empty:
                st.write(df)
            else:
                st.warning("No real-time DoS data available.")
        else:
            st.warning("No real-time DoS data available.")

    with dos_tabs[1]:
        st.header("Manual DoS Entry")
        col1, col2 = st.columns(2)
        with col1:
            inter_arrival_time = st.number_input("Inter Arrival Time", value=0.01)
        with col2:
            dns_rate = st.number_input("DNS Rate", value=5.0)

        if st.button("Predict DoS Anomaly"):
            manual_dos_entry(inter_arrival_time, dns_rate)

    with dos_tabs[2]:
        st.header("DoS Model Performance Metrics")
        df = pd.DataFrame(st.session_state.predictions)
        if not df.empty:
            st.subheader("Performance Metrics")
            valid_df = df.dropna(subset=["label", "anomaly"])
            if len(valid_df) >= 2 and valid_df["label"].nunique() > 1 and valid_df["anomaly"].nunique() > 1:
                y_true = valid_df["anomaly"].astype(int)
                y_pred = valid_df["anomaly"].astype(int)

                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Accuracy", f"{accuracy_score(y_true, y_pred):.2%}")
                col2.metric("Precision", f"{precision_score(y_true, y_pred, zero_division=0):.2%}")
                col3.metric("Recall", f"{recall_score(y_true, y_pred, zero_division=0):.2%}")
                col4.metric("F1-Score", f"{f1_score(y_true, y_pred, zero_division=0):.2%}")

                cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
                if cm.shape == (2, 2):
                    fig_cm = px.imshow(cm, text_auto=True, color_continuous_scale="Blues", labels={"x": "Predicted", "y": "Actual"})
                    st.plotly_chart(fig_cm)
                else:
                    st.warning("Confusion matrix could not be generated due to insufficient class diversity.")
            else:
                st.warning("Insufficient or unbalanced data for performance metrics.")

            st.subheader("Reconstruction Error Distribution")
            fig_hist = px.histogram(
                df,
                x="reconstruction_error",
                color="anomaly",
                title="Reconstruction Error Distribution",
                color_discrete_map={0: "blue", 1: "red"},
                nbins=50
            )
            fig_hist.add_vline(x=thresh, line_dash="dash", line_color="black", annotation_text="Threshold")
            st.plotly_chart(fig_hist, use_container_width=True)
        else:
            st.info("No predictions available for performance analysis.")

    with dos_tabs[3]:
        st.header("DoS Historical Data")
        df_hist = get_historical_data_for_dos(time_range)
        if not df_hist.empty:
            st.dataframe(df_hist)
        else:
            st.warning("No historical DoS data available.")
