import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from sklearn.metrics import precision_score, recall_score, f1_score
from streamlit_autorefresh import st_autorefresh

# --- Secrets ---
API_URL = st.secrets.get("API_URL", "")
DISCORD_WEBHOOK = st.secrets.get("DISCORD_WEBHOOK", "")
INFLUXDB_URL = st.secrets.get("INFLUXDB_URL", "")
INFLUXDB_ORG = st.secrets.get("INFLUXDB_ORG", "")
INFLUXDB_BUCKET = st.secrets.get("INFLUXDB_BUCKET", "")
INFLUXDB_TOKEN = st.secrets.get("INFLUXDB_TOKEN", "")
SQLITECLOUD_URL = st.secrets.get("SQLITECLOUD_URL", "")

# --- SQLiteCloud Loader ---
def load_predictions_from_sqlitecloud(time_window="-24h"):
    try:
        import sqlitecloud

        if "h" in time_window:
            delta = timedelta(hours=int(time_window.strip("-h")))
        elif "d" in time_window:
            delta = timedelta(days=int(time_window.strip("-d")))
        elif "m" in time_window:
            delta = timedelta(minutes=int(time_window.strip("-m")))
        else:
            delta = timedelta(hours=24)

        cutoff = (datetime.utcnow() - delta).strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlitecloud.connect(SQLITECLOUD_URL)
        cursor = conn.cursor()
        query = f"""
            SELECT * FROM anomalies
            WHERE timestamp >= '{cutoff}'
            ORDER BY timestamp DESC
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        if not rows:
            return pd.DataFrame()
        cols = [column[0] for column in cursor.description]
        df = pd.DataFrame(rows, columns=cols)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df.dropna(subset=["timestamp"])
    except Exception as e:
        st.error(f"SQLite Cloud error: {e}")
        return pd.DataFrame()

# --- SQLiteCloud Logger ---
def log_to_sqlitecloud(record):
    try:
        import sqlitecloud
        conn = sqlitecloud.connect(SQLITECLOUD_URL)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                protocol TEXT,
                anomaly_score REAL,
                is_anomaly INTEGER
            );
        """)
        cursor.execute("""
            INSERT INTO anomalies (timestamp, source_ip, dest_ip, protocol, anomaly_score, is_anomaly)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            record.get("timestamp", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
            record.get("source_ip", "N/A"),
            record.get("dest_ip", "N/A"),
            "DNS",
            float(record.get("reconstruction_error", 0)),
            int(record.get("anomaly", 0))
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        st.warning(f"SQLite Cloud insert failed: {e}")

# --- Overview Tab ---
def render(time_range, time_range_query_map):
    st_autorefresh(interval=30000, key="overview_refresh")
    st.title("DNS Anomaly Detection Overview")
    query_duration = time_range_query_map.get(time_range, "-24h")
    df = load_predictions_from_sqlitecloud(time_window=query_duration)

    if not df.empty:
        total_predictions = len(df)
        attack_rate = df["is_anomaly"].mean()
        recent_cutoff = pd.Timestamp.now().replace(tzinfo=None) - pd.Timedelta(hours=1)
        recent_attacks_df = df[(df["timestamp"] >= recent_cutoff) & (df["is_anomaly"] == 1)]

        # 📊 Key Metrics
        st.subheader("Key Metrics")
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Predictions", total_predictions)
        col2.metric("Attack Rate", f"{attack_rate:.2%}")
        col3.metric("Recent Attacks (Last Hour)", len(recent_attacks_df))

        # 📊 Model Performance
        if "anomaly_score" in df.columns:
            df["predicted"] = (df["anomaly_score"] >= 0.5).astype(int)
            precision = precision_score(df["is_anomaly"], df["predicted"], zero_division=0)
            recall = recall_score(df["is_anomaly"], df["predicted"], zero_division=0)
            f1 = f1_score(df["is_anomaly"], df["predicted"], zero_division=0)

            st.subheader("Model Evaluation")
            eval_col1, eval_col2, eval_col3 = st.columns(3)
            eval_col1.metric("Precision", f"{precision:.2%}")
            eval_col2.metric("Recall", f"{recall:.2%}")
            eval_col3.metric("F1 Score", f"{f1:.2%}")

        # 🧐 Attack Summary
        st.subheader("Attack Insights")
        if len(df[df["is_anomaly"] == 1]) > 0:
            attack_df = df[df["is_anomaly"] == 1].copy()
            avg_score = attack_df["anomaly_score"].mean()
            max_score = attack_df["anomaly_score"].max()
            top_sources = attack_df["source_ip"].value_counts().reset_index()
            top_sources.columns = ["Source IP", "Anomaly Count"]
            peak_hour = attack_df["timestamp"].dt.hour.mode()[0]

            ai_col1, ai_col2, ai_col3 = st.columns(3)
            ai_col1.metric("Avg. Reconstruction Error", f"{avg_score:.4f}")
            ai_col2.metric("Max. Reconstruction Error", f"{max_score:.4f}")
            ai_col3.metric("Peak Attack Hour", f"{peak_hour}:00")

            st.markdown("### Top Source IPs by Anomaly Count")
            top_sources_sorted = top_sources.sort_values(by="Anomaly Count", ascending=False)
            fig = px.bar(
                top_sources_sorted.head(10),
                x="Source IP",
                y="Anomaly Count",
                labels={"Anomaly Count": "Count"},
                height=350
            )
            fig.update_layout(
                xaxis_tickangle=-45,
                margin=dict(t=40, b=20),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attacks recorded in the selected time window.")

        # 📉 Anomaly Trend Line
        st.subheader("Anomaly Score Over Time")
        fig = px.line(
            df,
            x="timestamp",
            y="anomaly_score",
            color=df["is_anomaly"].map({1: "Attack", 0: "Normal"}).astype(str),
            labels={"color": "Anomaly Type"},
            title=""
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No predictions available in the selected time range.")
