# tabs/dos/historical.py
import streamlit as st
import pandas as pd
import plotly.express as px
import requests
from influxdb_client import InfluxDBClient
from datetime import datetime, timedelta


def render_historical(api_url, influx_measurement, db_path):
    st.header("Historical DOS Data")
    start_date = st.date_input("Start Date", datetime.utcnow().date() - timedelta(days=1))
    end_date = st.date_input("End Date", datetime.utcnow().date())

    if start_date > end_date:
        st.error("Start date must be before end date.")
        return

    try:
        with InfluxDBClient(
            url=st.secrets["INFLUXDB_URL"],
            token=st.secrets["INFLUXDB_TOKEN"],
            org=st.secrets["INFLUXDB_ORG"]
        ) as client:
            query = f'''
                from(bucket: "{st.secrets["INFLUXDB_BUCKET"]}")
                |> range(start: {start_date}T00:00:00Z, stop: {end_date}T23:59:59Z)
                |> filter(fn: (r) => r._measurement == "{influx_measurement}")
                |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
                |> sort(columns: ["_time"], desc: true)
            '''
            tables = client.query_api().query(query)
            rows = []
            for table in tables:
                for record in table.records:
                    row = record.values.copy()
                    row["timestamp"] = record.get_time()
                    rows.append(row)
            df = pd.DataFrame(rows)

            if df.empty:
                st.info("No historical data found for selected range.")
                return

            st.markdown("### Raw Data")
            rows_per_page = 100
            total_pages = (len(df) - 1) // rows_per_page + 1
            page = st.number_input("Page", min_value=1, max_value=total_pages, value=1)
            paginated_df = df.iloc[(page - 1) * rows_per_page : page * rows_per_page]
            st.dataframe(paginated_df, use_container_width=True)

            st.markdown("### Line Chart: Byte Rate Over Time")
            if "byte_rate" in df.columns:
                fig = px.line(df, x="timestamp", y="byte_rate", title="Byte Rate Over Time")
                st.plotly_chart(fig, use_container_width=True)

            st.markdown("### Line Chart: Packet Count Over Time")
            if "packet_count" in df.columns:
                fig2 = px.line(df, x="timestamp", y="packet_count", title="Packet Count Over Time")
                st.plotly_chart(fig2, use_container_width=True)

    except Exception as e:
        st.error(f"Error querying historical data: {e}")
