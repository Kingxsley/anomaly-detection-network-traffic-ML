# app_dos.py
from layout import render_dashboard

render_dashboard(
    title="DOS Anomaly Detection Dashboard",
    api_url="https://violabirech-dos-anomalies-detection.hf.space/predict",
    influx_measurement="network_traffic",
    db_path="dos",
    mode="dos"
)
