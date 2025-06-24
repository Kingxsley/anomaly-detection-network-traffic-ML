# tabs/dos/overview.py
import streamlit as st
import os
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from streamlit_autorefresh import st_autorefresh
from influxdb_client import InfluxDBClient
import requests
import sqlitecloud
import warnings

# --- Secrets ---
API_URL = st.secrets.get("API_URL", "")
DISCORD_WEBHOOK = st.secrets.get("DISCORD_WEBHOOK", "")
INFLUXDB_URL = st.secrets.get("INFLUXDB_URL", "")
INFLUXDB_ORG = st.secrets.get("INFLUXDB_ORG", "")
INFLUXDB_BUCKET = st.secrets.get("INFLUXDB_BUCKET", "")
INFLUXDB_TOKEN = st.secrets.get("INFLUXDB_TOKEN", "")
SQLITE_HOST = st.secrets.get("SQLITE_HOST", "")
SQLITE_PORT = int(st.secrets.get("SQLITE_PORT", 8860))
SQLITE_DB = st.secrets.get("SQLITE_DB", "dos")
SQLITE_APIKEY = st.secrets.get("SQLITE_APIKEY", "")


def send_discord_alert(result):
    message = {
        "content": (
            f"\U0001f6a8 **DOS Anomaly Detected!**\n"
            f"**Timestamp:** {result.get('timestamp')}\n"
            f"**Source IP:** {result.get('source_ip')}\n"
            f"**Destination IP:** {result.get('dest_ip')}\n"
            f"**Reconstruction Error:** {float(result.get('reconstruction_error', 0)):.6f}"
        )
    }
    try:
        requests.post(DISCORD_WEBHOOK, json=message, timeout=20)
    except Exception as e:
        st.warning(f"Discord alert failed: {e}")


def load_predictions_from_sqlitecloud(time_window="-24h"):
    try:
        delta = timedelta(hours=int(time_window.strip("-h"))) if "h" in time_window else timedelta(days=1)
        cutoff = (datetime.utcnow() - delta).strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlitecloud.connect(f"sqlitecloud://{SQLITE_HOST}:{SQLITE_PORT}/{SQLITE_DB}?apikey={SQLITE_APIKEY}")
        cursor = conn.execute(f"""
            SELECT * FROM dos_anomalies
            WHERE timestamp >= '{cutoff}'
            ORDER BY timestamp DESC
        """)
        rows = cursor.fetchall()
        if not rows:
            return pd.DataFrame()
        cols = [column[0] for column in cursor.description]
        df = pd.DataFrame(rows, columns=cols)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=AttributeError)
            conn.close()

        return df.dropna(subset=["timestamp"])
    except Exception as e:
        st.error(f"SQLite Cloud error: {e}")
        return pd.DataFrame()


def render_overview(api_url, influx_measurement):
    st_autorefresh(interval=60000, key="overview_refresh")
    st.subheader("DOS Anomaly Detection Overview")
    df = load_predictions_from_sqlitecloud(time_window="-24h")

    if not df.empty:
        total_predictions = len(df)
        attack_rate = df["is_anomaly"].mean()
        avg_error = df["anomaly_score"].mean()
        max_error = df["anomaly_score"].max()
        min_error = df["anomaly_score"].min()

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Predictions", total_predictions)
        col2.metric("Attack Rate", f"{attack_rate:.2%}")
        col3.metric("Total Attacks", df[df["is_anomaly"] == 1].shape[0])

        st.markdown("### Attack Summary")
        summary_cols = st.columns(3)
        summary_cols[0].metric("Average Reconstruction Error", f"{avg_error:.4f}")
        summary_cols[1].metric("Max Reconstruction Error", f"{max_error:.4f}")
        summary_cols[2].metric("Min Reconstruction Error", f"{min_error:.4f}")

        st.markdown("### Times with Most Attacks")
        attack_df = df[df["is_anomaly"] == 1].copy()
        attack_df["time"] = pd.to_datetime(attack_df["timestamp"]).dt.strftime('%Y-%m-%d %H:00')
        top_times = attack_df["time"].value_counts().nlargest(5).reset_index()
        top_times.columns = ["Time (Hour Block)", "Attack Count"]
        st.dataframe(top_times.style.format(), use_container_width=True)

        st.markdown("### Top Source IPs")
        ip_counts = df[df["is_anomaly"] == 1]["source_ip"].value_counts().nlargest(10).reset_index()
        ip_counts.columns = ["source_ip", "count"]
        fig_ip = px.bar(ip_counts, x="source_ip", y="count", labels={"source_ip": "Source IP", "count": "Anomaly Count"}, text_auto=True)
        st.plotly_chart(fig_ip, use_container_width=True)

        st.markdown("### Top Destination IPs")
        dest_counts = df[df["is_anomaly"] == 1]["dest_ip"].value_counts().nlargest(10).reset_index()
        dest_counts.columns = ["dest_ip", "count"]
        fig_dest = px.bar(dest_counts, x="dest_ip", y="count", labels={"dest_ip": "Destination IP", "count": "Anomaly Count"}, text_auto=True)
        st.plotly_chart(fig_dest, use_container_width=True)

        st.markdown("### Anomaly Score Over Time")
        fig = px.line(
            df,
            x="timestamp",
            y="anomaly_score",
            color=df["is_anomaly"].map({1: "Attack", 0: "Normal"}).astype(str),
            labels={"color": "Anomaly Type"},
            title="Anomaly Score Over Time"
        )
        st.plotly_chart(fig, use_container_width=True)

        st.markdown("### Recent Attack Details")
        recent_attacks = df[df["is_anomaly"] == 1].sort_values("timestamp", ascending=False).head(10)
        st.dataframe(recent_attacks[["timestamp", "source_ip", "dest_ip", "anomaly_score"]], use_container_width=True)
    else:
        st.info("No predictions available in the selected time range.")

