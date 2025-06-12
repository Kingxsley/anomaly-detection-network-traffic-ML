import streamlit as st
try:
    from influxdb_client import InfluxDBClient
    import pandas as pd
    import altair as alt

    st.set_page_config(page_title="Anomaly Detector", layout="wide")
    st.title("Anomaly Detector")

    # InfluxDB credentials
    url = "https://us-east-1-1.aws.cloud2.influxdata.com"
    token = "G2CkNoe-C5GR_IY7_qAJdD2DqHJImDnbUxGhZGOPDKSBB6Jl9cLVp6HjWvOjdLOngp8oIRtbovc_BkE7BGAusw=="
    org = "Anormally Detection"

    buckets = ["realtime_dns", "realtime"]
    selected_bucket = st.selectbox("Select InfluxDB Bucket", buckets)

    client = InfluxDBClient(url=url, token=token, org=org)

    if selected_bucket == "realtime_dns":
        measurement = "dns_traffic"
    else:
        measurement = "network_traffic"

    query = f'''
    from(bucket: "{selected_bucket}")
      |> range(start: -1h)
      |> filter(fn: (r) => r["_measurement"] == "{measurement}")
      |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
    '''

    tables = client.query_api().query_data_frame(org=org, query=query)
    if tables.empty:
        st.warning("No data returned from InfluxDB.")
    else:
        st.success("Data fetched successfully!")
        st.dataframe(tables)

        chart = alt.Chart(tables).mark_line().encode(
            x='_time:T',
            y='latency:Q' if 'latency' in tables.columns else tables.columns[1],
            tooltip=['_time', 'latency'] if 'latency' in tables.columns else ['_time'] + tables.columns[1:2].tolist()
        ).properties(title=f'{measurement} Over Time', width=800, height=400)

        st.altair_chart(chart)

except Exception as e:
    st.error(f"❌ App crashed: {e}")
