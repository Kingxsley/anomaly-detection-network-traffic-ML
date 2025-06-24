# app_dns.py
from layout import render_dashboard

render_dashboard(
    title="DNS Anomaly Detection Dashboard",
    api_url="https://mizzony-dns-anomalies-detection.hf.space/predict",
    influx_measurement="dns",
    db_path="dns",
    mode="dns"
)
