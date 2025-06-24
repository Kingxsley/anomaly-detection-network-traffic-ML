# utils.py

import streamlit as st
from influxdb_client import InfluxDBClient

# Fetch DoS settings from Streamlit Cloud secrets
DOS_API_URL = st.secrets["DOS"]["API_URL"]
DOS_DISCORD_WEBHOOK = st.secrets["DOS"]["DISCORD_WEBHOOK"]
DOS_INFLUXDB_URL = st.secrets["DOS"]["INFLUXDB_URL"]
DOS_INFLUXDB_ORG = st.secrets["DOS"]["INFLUXDB_ORG"]
DOS_INFLUXDB_BUCKET = st.secrets["DOS"]["INFLUXDB_BUCKET"]
DOS_INFLUXDB_TOKEN = st.secrets["DOS"]["INFLUXDB_TOKEN"]
DOS_SQLITE_HOST = st.secrets["DOS"]["SQLITE_HOST"]
DOS_SQLITE_PORT = int(st.secrets["DOS"]["SQLITE_PORT"])  # Make sure it's cast to int
DOS_SQLITE_DB = st.secrets["DOS"]["SQLITE_DB"]
DOS_SQLITE_APIKEY = st.secrets["DOS"]["SQLITE_APIKEY"]

def get_data():
    try:
        # Fetch DoS data from InfluxDB using the DoS configuration from Streamlit secrets
        if not DOS_INFLUXDB_URL:
            raise ValueError("No host specified.")
        
        with InfluxDBClient(url=DOS_INFLUXDB_URL, token=DOS_INFLUXDB_TOKEN, org=DOS_INFLUXDB_ORG) as client:
            query = f'''
            from(bucket: "{DOS_INFLUXDB_BUCKET}")
            |> range(start: -5m)
            |> filter(fn: (r) => r._measurement == "dos")  # Ensure it's querying DoS data
            |> filter(fn: (r) => r._field == "inter_arrival_time" or r._field == "dos_rate")  # Correct fields for DoS
            |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
            |> sort(columns: ["_time"], desc: false)
            '''
            tables = client.query_api().query(query)
            rows = []
            for table in tables:
                for record in table.records:
                    rows.append({
                        "timestamp": record.get_time().strftime("%Y-%m-%d %H:%M:%S"),
                        "inter_arrival_time": record.values.get("inter_arrival_time", 0.0),
                        "dos_rate": record.values.get("dos_rate", 0.0),  # Correct field for DoS rate
                        "source_ip": record.values.get("source_ip", "unknown"),
                        "dest_ip": record.values.get("dest_ip", "unknown")
                    })
            return rows
    except Exception as e:
        st.warning(f"Failed to fetch live DoS data from InfluxDB: {e}")
        return []
