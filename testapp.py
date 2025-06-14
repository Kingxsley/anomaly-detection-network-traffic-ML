import streamlit as st
import requests
import pandas as pd
import plotly.express as px
from datetime import datetime
from streamlit_autorefresh import st_autorefresh
from influxdb_client import InfluxDBClient

# --- Config ---
API_URL = "http://localhost:8000/predict"
influx_url = "https://us-east-1-1.aws.cloud2.influxdata.com"
influx_token = "6gjE97dCC24hgOgWNmRXPqOS0pfc0pMSYeh5psL8e5u2T8jGeV1F17CU-U1z05if0jfTEmPRW9twNPSXN09SRQ=="
influx_org = "Anormally Detection"
influx_bucket = "realtime_dns"
ERROR_THRESHOLD = 0.1
ATTACK_WINDOW = 5
ENABLE_DISCORD = True

# --- Streamlit Setup ---
st.set_page_config(page_title="DNS Anomaly Detection Dashboard", layout="wide")
st_autorefresh(interval=3000, key="data_refresh")
if "predictions" not in st.session_state:
    st.session_state.predictions = []

# --- Discord Alerts ---
def send_discord_alert():
    webhook_url = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7"
    data = {
        "content": "**DNS Anomaly Alert**\nAnomaly spike detected in the last 5 predictions.\nCheck the dashboard immediately.",
        "username": "DNS Anomaly Bot"
    }
    try:
        requests.post(webhook_url, json=data)
    except Exception as e:
        st.error(f"Discord alert failed: {e}")

# --- InfluxDB Data ---
def get_all_influx_data():
    query = f'''
    from(bucket: "{influx_bucket}")
      |> range(start: 0)
      |> filter(fn: (r) => r["_measurement"] == "dns")
      |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
      |> keep(columns: ["_time", "dns_rate", "inter_arrival_time"])
      |> sort(columns: ["_time"], desc: false)
    '''
    try:
        with InfluxDBClient(url=influx_url, token=influx_token, org=influx_org) as client:
            df = client.query_api().query_data_frame(org=influx_org, query=query)
            if isinstance(df, pd.DataFrame) and not df.empty:
                df.rename(columns={"_time": "timestamp"}, inplace=True)
                st.write("Preview of data from InfluxDB:")
                st.dataframe(df.head())
                return df
            else:
                st.warning("InfluxDB query returned no rows.")
                return pd.DataFrame()
    except Exception as e:
        st.error(f"Failed to query InfluxDB: {e}")
        return pd.DataFrame()

# --- Streamlit UI ---
st.title("Real-Time DNS Anomaly Detection Dashboard")

st.header("Manual Prediction")
with st.form("manual_input_form"):
    col1, col2 = st.columns(2)
    inter_arrival_time = col1.number_input("Inter Arrival Time (sec)", 0.001, 10.0, 0.02)
    dns_rate = col2.number_input("DNS Rate", 0.0, 100.0, 2.0)
    submit = st.form_submit_button("Submit")
    if submit:
        payload = {"inter_arrival_time": inter_arrival_time, "dns_rate": dns_rate}
        try:
            response = requests.post(API_URL, json=payload)
            result = response.json()
            result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.session_state.predictions.append(result)
            st.success("Prediction received.")
            st.json(result)
        except Exception as e:
            st.error(f"Manual input error: {e}")

st.header("All Historical DNS Data")
df_all = get_all_influx_data()

if not df_all.empty:
    st.success(f"Loaded {len(df_all)} rows from InfluxDB.")

    st.subheader("DNS Rate Over Time")
    fig_dns = px.line(df_all, x="timestamp", y="dns_rate", title="DNS Rate (Full History)")
    st.plotly_chart(fig_dns, use_container_width=True)

    st.subheader("Inter-Arrival Time Over Time")
    fig_iat = px.line(df_all, x="timestamp", y="inter_arrival_time", title="Inter-Arrival Time (Full History)")
    st.plotly_chart(fig_iat, use_container_width=True)
else:
    st.warning("No data found in InfluxDB.")
