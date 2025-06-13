import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
import joblib
import logging

def detect_anomalies(new_data, autoencoder_path="autoencoder_dns.h5", scaler_path="scaler_dns.pkl", threshold_path="threshold.pkl"):
    """
    Detect anomalies in DNS data using a pre-trained autoencoder.
    
    Args:
        new_data (pd.DataFrame): DataFrame with columns ['inter_arrival_time', 'dns_rate']
        autoencoder_path (str): Path to saved autoencoder model
        scaler_path (str): Path to saved scaler
        threshold_path (str): Path to saved threshold
    
    Returns:
        pd.DataFrame: Input data with 'anomaly' and 'reconstruction_error' columns
    """
    try:
        # Validate input
        required_cols = ["inter_arrival_time", "dns_rate"]
        if not all(col in new_data.columns for col in required_cols):
            raise ValueError(f"Missing columns: {set(required_cols) - set(new_data.columns)}")
        
        # Load model, scaler, and threshold
        autoencoder = load_model(autoencoder_path)
        scaler = joblib.load(scaler_path)
        threshold = joblib.load(threshold_path)
        
        # Preprocess data
        new_data = new_data.copy()
        new_data["inter_arrival_time"] = new_data["inter_arrival_time"].clip(lower=0.001)
        new_data["request_rate"] = (1 / new_data["inter_arrival_time"]).clip(upper=1000).fillna(new_data["inter_arrival_time"].median())
        X_new = new_data[["inter_arrival_time", "request_rate"]]
        
        # Scale features
        X_new_scaled = scaler.transform(X_new)
        
        # Compute reconstruction error
        reconstruction = autoencoder.predict(X_new_scaled, batch_size=128, verbose=0)
        reconstruction_error = np.mean((X_new_scaled - reconstruction) ** 2, axis=1)
        
        # Apply threshold
        new_data["reconstruction_error"] = reconstruction_error
        new_data["anomaly"] = (reconstruction_error > threshold).astype(int)
        
        logging.info(f"Processed {len(new_data)} rows, anomaly rate: {new_data['anomaly'].mean():.4f}")
        return new_data
    except Exception as e:
        logging.error(f"Inference failed: {e}")
        return None