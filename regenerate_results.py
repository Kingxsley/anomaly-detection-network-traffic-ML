import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
import tensorflow.keras.losses
import joblib
import logging

logging.basicConfig(level=logging.INFO, filename="dns_anomaly.log", format="%(asctime)s %(levelname)s %(message)s")

def detect_anomalies(new_data, autoencoder_path="autoencoder_dns.h5", scaler_path="scaler_dns.pkl"):
    try:
        required_cols = ["inter_arrival_time", "dns_rate"]
        if not all(col in new_data.columns for col in required_cols):
            raise ValueError(f"Missing columns: {set(required_cols) - set(new_data.columns)}")
        
        # Validate data
        if new_data[required_cols].isna().any().any():
            logging.warning("NaN values detected. Filling with median.")
            new_data = new_data.copy()
            for col in required_cols:
                new_data[col] = new_data[col].fillna(new_data[col].median())
        
        # Load model and scaler
        logging.info(f"Loading model from {autoencoder_path} and scaler from {scaler_path}")
        autoencoder = load_model(autoencoder_path, custom_objects={"mse": tensorflow.keras.losses.MeanSquaredError()})
        scaler = joblib.load(scaler_path)
        
        # Preprocess data
        new_data = new_data.copy()
        new_data["inter_arrival_time"] = new_data["inter_arrival_time"].clip(lower=0.001)
        new_data["request_rate"] = (1 / new_data["inter_arrival_time"]).clip(upper=1000).fillna(new_data["inter_arrival_time"].median())
        X_new = new_data[["inter_arrival_time", "request_rate"]]
        
        # Scale features
        X_new_scaled = scaler.transform(X_new)
        
        # Compute reconstruction error
        logging.info(f"Predicting for {len(X_new)} samples")
        reconstruction = autoencoder.predict(X_new_scaled, batch_size=128, verbose=0)
        reconstruction_error = np.mean((X_new_scaled - reconstruction) ** 2, axis=1)
        
        new_data["reconstruction_error"] = reconstruction_error
        new_data["anomaly"] = (reconstruction_error > 0.1).astype(int)  # Temporary threshold
        return new_data
    except Exception as e:
        logging.error(f"Inference failed: {str(e)}")
        print(f"Inference failed: {str(e)}")
        return None

# Load existing CSV
df = pd.read_csv("/Users/sutinanthanombun/Desktop/dns_anomaly_detector/dns_anomaly_results.csv")
print("Original columns:", df.columns.tolist())
print(df.head())

# Run inference
results = detect_anomalies(df)
if results is not None:
    results.to_csv("/Users/sutinanthanombun/Desktop/dns_anomaly_results.csv", index=False)
    print("Saved results to dns_anomaly_results.csv")
    print("New columns:", results.columns.tolist())
    print(results.head())
else:
    print("Failed to generate results. Check dns_anomaly.log for details.")