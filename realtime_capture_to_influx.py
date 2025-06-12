import pyshark
from influxdb_client import InfluxDBClient, Point, WriteOptions
from influxdb_client.client.write_api import SYNCHRONOUS
from datetime import datetime

# ------------------- Configuration -------------------
influxdb_url = "http://192.168.1.108:8086"
token = "Fc96LmmlJD_KeDRRF-kTyZ7vwxLLFPREwRZpSadzSU0QW_tAw7rKxRDKVEqty72XTPXz-2j0RkYK4c7Jtlmatw=="
org = "AIH"
bucket = "realtime"
interface = "enp0s3"  # Ubuntu's network interface
# -----------------------------------------------------

# Connect to InfluxDB
client = InfluxDBClient(url=influxdb_url, token=token, org=org)
write_api = client.write_api(write_options=SYNCHRONOUS)

previous_time = None

def get_label(packet):
    try:
        dest_port = int(packet.tcp.dstport)
        return 1 if dest_port == 80 else 0
    except:
        return 0

# Start live capture
print(f"?? Starting real-time packet capture on interface: {interface}...")
capture = pyshark.LiveCapture(interface=interface, display_filter="tcp")

for packet in capture.sniff_continuously():
    try:
        current_time = datetime.utcnow()
        label = get_label(packet)

        source_ip = packet.ip.src
        dest_ip = packet.ip.dst
        source_port = int(packet.tcp.srcport)
        dest_port = int(packet.tcp.dstport)
        protocol = packet.transport_layer
        packet_length = int(packet.length)

        # Calculate inter-arrival time
        inter_arrival_time = 0.0 if previous_time is None else (current_time - previous_time).total_seconds()
        previous_time = current_time

        print(f"?? Captured TCP packet: {source_ip}:{source_port} -> {dest_ip}:{dest_port} | label={label}")

        point = (
            Point("network_traffic")
            .tag("protocol", protocol)
            .tag("source_ip", source_ip)
            .tag("dest_ip", dest_ip)
            .field("source_port", source_port)
            .field("dest_port", dest_port)
            .field("packet_length", packet_length)
            .field("inter_arrival_time", inter_arrival_time)
            .field("label", int(label))
            .time(current_time)
        )

        write_api.write(bucket=bucket, org=org, record=point)

    except Exception as e:
        print(f"?? Error processing packet: {e}")
