import sqlite3
import pandas as pd
from datetime import datetime
import streamlit as st


# Function to load predictions from SQLite Cloud
def load_predictions_from_sqlitecloud(time_window="-24h"):
    try:
        if "h" in time_window:
            delta = timedelta(hours=int(time_window.strip("-h")))
        elif "d" in time_window:
            delta = timedelta(days=int(time_window.strip("-d")))
        elif "m" in time_window:
            delta = timedelta(minutes=int(time_window.strip("-m")))
        else:
            delta = timedelta(hours=24)

        cutoff = (datetime.utcnow() - delta).strftime("%Y-%m-%d %H:%M:%S")

        # Connecting to the SQLite Cloud database
        conn = sqlite3.connect(f"sqlitecloud://{st.secrets['SQLITE_HOST']}:{st.secrets['SQLITE_PORT']}/{st.secrets['SQLITE_DB']}?apikey={st.secrets['SQLITE_APIKEY']}")
        cursor = conn.execute(f"""
            SELECT * FROM anomalies
            WHERE timestamp >= '{cutoff}'
            ORDER BY timestamp DESC
        """)
        rows = cursor.fetchall()
        if not rows:
            return pd.DataFrame()

        cols = [column[0] for column in cursor.description]
        df = pd.DataFrame(rows, columns=cols)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

        conn.close()
        return df.dropna(subset=["timestamp"])
    except Exception as e:
        st.error(f"SQLite Cloud error: {e}")
        return pd.DataFrame()


# Function to log predictions to SQLite Cloud
def log_to_sqlitecloud(record):
    try:
        conn = sqlite3.connect(f"sqlitecloud://{st.secrets['SQLITE_HOST']}:{st.secrets['SQLITE_PORT']}/{st.secrets['SQLITE_DB']}?apikey={st.secrets['SQLITE_APIKEY']}")
        conn.execute("""
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
        conn.execute("""
            INSERT INTO anomalies (timestamp, source_ip, dest_ip, protocol, anomaly_score, is_anomaly)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            record.get("timestamp", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
            record.get("source_ip", "N/A"),
            record.get("dest_ip", "N/A"),
            "DNS" if st.secrets.get("DASHBOARD_TYPE", "DNS") == "DNS" else "DOS",
            float(record.get("reconstruction_error", 0)),
            int(record.get("anomaly", 0))
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        st.warning(f"SQLite Cloud insert failed: {e}")
