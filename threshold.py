import pandas as pd
import joblib

df = pd.read_csv("/Users/sutinanthanombun/Desktop/dns_anomaly_detector/dns_anomaly_results.csv")
print("Columns:", df.columns.tolist())
print(df.head())

if 'reconstruction_error' not in df.columns:
    raise ValueError("Column 'reconstruction_error' not found. Available columns: " + str(df.columns.tolist()))

threshold = df[df["label"] == 0]["reconstruction_error"].quantile(0.97)
joblib.dump(threshold, "/Users/sutinanthanombun/Desktop/dns_anomaly_detector/app/threshold.pkl")
print(f"Threshold: {threshold}")