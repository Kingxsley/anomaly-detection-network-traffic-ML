import requests
from influxdb_client import InfluxDBClient
from datetime import datetime
import sqlitecloud

# --- Configuration ---
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime_dns"
INFLUXDB_TOKEN = "6gjE97dCC24hgOgWNmRXPqOS0pfc0pMSYeh5psL8e5u2T8jGeV1F17CU-U1z05if0jfTEmPRW9twNPSXN09SRQ=="
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7"
SQLITECLOUD_URL = "sqlitecloud://cfolwawehk.g2.sqlite.cloud:8860/anomaly?apikey=77cz3yvotfOw3EgNIM9xPLAWaajazSyxcnCWvvbxFEA"
API_URL = "https://mizzony-dns-anomalies-detection.hf.space/predict"

# --- Fetch DNS Data from InfluxDB ---
def get_dns_data():
    with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
        query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
        |> range(start: -1m)
        |> filter(fn: (r) => r._measurement == "dns")
        |> filter(fn: (r) => r._field == "inter_arrival_time" or r._field == "dns_rate")
        |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
        |> keep(columns: ["_time", "dns_rate", "inter_arrival_time", "source_ip", "dest_ip"])
        '''
        tables = client.query_api().query(query)
        records = []
        for table in tables:
            for row in table.records:
                r = row.values.copy()
                r["timestamp"] = row.get_time().strftime("%Y-%m-%d %H:%M:%S")
                records.append(r)
        return records

# --- Discord Notification ---
def send_discord_alert(result):
    message = {
        "content": (
            f"\U0001f6a8 **DNS Anomaly Detected!**\n"
            f"**Timestamp:** {result.get('timestamp')}\n"
            f"**Reconstruction Error:** {result.get('reconstruction_error')}\n"
            f"**Source IP:** {result.get('source_ip')}\n"
            f"**Destination IP:** {result.get('dest_ip')}"
        )
    }
    try:
        requests.post(DISCORD_WEBHOOK, json=message, timeout=20)
    except Exception as e:
        print(f"Discord alert failed: {e}")

# --- Log to SQLiteCloud ---
def log_to_sqlitecloud(record):
    try:
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
            record.get("timestamp"),
            record.get("source_ip", "N/A"),
            record.get("dest_ip", "N/A"),
            "DNS",
            float(record.get("reconstruction_error", 0)),
            int(record.get("anomaly", 0))
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"SQLiteCloud insert failed: {e}")
