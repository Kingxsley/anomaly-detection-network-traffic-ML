import streamlit as st
import requests
import pandas as pd
import matplotlib.pyplot as plt

st.set_page_config(page_title="🔍 DNS Anomaly Detection", layout="centered")
st.title("🔍 DNS Anomaly Detection")

st.markdown("Enter values below to detect if the network activity is anomalous based on DNS traffic patterns.")

# User inputs
inter_arrival = st.number_input("Inter-arrival Time (s)", min_value=0.0, value=0.5, step=0.01)
dns_rate = st.number_input("DNS Request Rate", min_value=0.0, value=1.0, step=0.1)

# Predict button
if st.button("🔎 Run Anomaly Detection"):
    payload = {
        "inter_arrival_time": inter_arrival,
        "dns_rate": dns_rate
    }

    try:
        response = requests.post("http://127.0.0.1:7860/predict", json=payload)
        if response.status_code == 200:
            result = response.json()

            # Extract values
            anomaly = result.get("anomaly", None)
            reconstruction_error = result.get("reconstruction_error", None)
            request_rate = result.get("request_rate", None)
            threshold = result.get("threshold", None)  # Optional — add this to FastAPI if not returned

            st.subheader("🧠 Prediction Result")
            st.success(f"Anomaly: {'🛑 YES' if anomaly == 1 else '✅ NO'}")

            st.markdown("### 📊 Detailed Prediction Data")
            df = pd.DataFrame([{
                "Inter-arrival Time": inter_arrival,
                "DNS Rate": dns_rate,
                "Request Rate": request_rate,
                "Reconstruction Error": reconstruction_error,
                "Anomaly": "Yes" if anomaly == 1 else "No"
            }])
            st.dataframe(df)

            # Graph of reconstruction error vs threshold
            if threshold is not None:
                st.markdown("### 📈 Reconstruction Error vs Threshold")
                fig, ax = plt.subplots()
                ax.bar(["Reconstruction Error"], [reconstruction_error], label="Error", color="blue")
                ax.axhline(y=threshold, color="red", linestyle="--", label="Threshold")
                ax.set_ylabel("Error")
                ax.set_title("Reconstruction Error")
                ax.legend()
                st.pyplot(fig)

        else:
            st.error("❌ Prediction failed. Server returned an error.")
            st.json(response.json())

    except Exception as e:
        st.error(f"⚠️ Could not connect to the prediction API: {e}")
