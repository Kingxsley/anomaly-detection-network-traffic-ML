from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.metrics import MeanSquaredError
import joblib
import logging
import os

# Setup logging
logging.basicConfig(level=logging.INFO, filename="dns_anomaly.log", format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="DNS Anomaly Detection API", description="API for detecting anomalies in DNS traffic using a pre-trained autoencoder.")

# Input model for single data point
class DNSDataPoint(BaseModel):
    inter_arrival_time: float
    dns_rate: float

# Input model for batch data
class DNSDataBatch(BaseModel):
    data: List[DNSDataPoint]

# Anomaly detection function
def detect_anomalies(new_data, autoencoder_path="autoencoder_dns.keras", scaler_path="scaler_dns.pkl", threshold_path="threshold.pkl"):
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
        # Validate file paths
        if not os.path.exists(autoencoder_path):
            raise FileNotFoundError(f"Model file not found: {autoencoder_path}")
        if not os.path.exists(scaler_path):
            raise FileNotFoundError(f"Scaler file not found: {scaler_path}")
        if not os.path.exists(threshold_path):
            raise FileNotFoundError(f"Threshold file not found: {threshold_path}")

        # Validate input
        required_cols = ["inter_arrival_time", "dns_rate"]
        if not all(col in new_data.columns for col in required_cols):
            raise ValueError(f"Missing columns: {set(required_cols) - set(new_data.columns)}")
        
        # Load model, scaler, and threshold
        logging.info(f"Loading model from {autoencoder_path}, scaler from {scaler_path}, threshold from {threshold_path}")
        autoencoder = load_model(autoencoder_path, custom_objects={"mse": MeanSquaredError()})
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

@app.get("/")
async def root():
    return {"message": "Welcome to the DNS Anomaly Detection API. Use /predict for single predictions or /predict_batch for batch predictions."}

@app.post("/predict")
async def predict(data: DNSDataPoint):
    try:
        df = pd.DataFrame([data.dict()])
        results = detect_anomalies(df)
        if results is None:
            raise HTTPException(status_code=500, detail="Inference failed")
        return results.to_dict(orient="records")[0]
    except Exception as e:
        logging.error(f"Prediction failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict_batch")
async def predict_batch(batch: DNSDataBatch):
    try:
        df = pd.DataFrame([item.dict() for item in batch.data])
        results = detect_anomalies(df)
        if results is None:
            raise HTTPException(status_code=500, detail="Inference failed")
        return results.to_dict(orient="records")
    except Exception as e:
        logging.error(f"Batch prediction failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))