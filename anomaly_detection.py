import streamlit as st
from influxdb_client import InfluxDBClient
import pandas as pd
import altair as alt

# Streamlit app config
st.set_page_config(page_title="Anomaly Detector", layout="wide")

# App title
st.title("Anomaly Detector")

# InfluxDB credentials
url = "https://us-east-1-1.aws.cloud2.influxdata.com"
token = "G2CkNoe-C5GR_IY7_qAJdD2DqHJImDnbUxGhZGOPDKSBB6Jl9cLVp6HjWvOjdLOngp8oIRtbovc_BkE7BGAusw=="
org = "Anormally Detection"

# Define buckets
buckets = ["realtime_dns", "realtime"]
selected_bucket = st.selectbox("Select InfluxDB Bucket", buckets)

# Connect to InfluxDB
client = InfluxDBClient(url=url, token=token, org=org)

# Example Flux query
query = f'''
from(bucket: "{selected_bucket}")
  |> range(start: -1h)
  |> filter(fn: (r) => r["_measurement"] == "dns_traffic")
  |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
'''

# Run query
try:
    tables = client.query_api().query_data_frame(org=org, query=query)
    if tables.empty:
        st.warning("No data returned from InfluxDB.")
    else:
        st.success("Data fetched successfully!")
        st.dataframe(tables)

        # Optional: visualization
        chart = alt.Chart(tables).mark_line().encode(
            x='_time:T',
            y='latency:Q',
            tooltip=['_time', 'latency']
        ).properties(title='Latency Over Time', width=800, height=400)

        st.altair_chart(chart)

except Exception as e:
    st.error(f"Error querying InfluxDB: {e}")
