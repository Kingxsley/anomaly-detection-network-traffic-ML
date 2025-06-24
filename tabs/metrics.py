import streamlit as st
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

def render(thresh):
    st.title("Metrics")

    # Fetch metrics data for DNS or DOS
    if st.session_state.DASHBOARD_TYPE == "DNS":
        df = fetch_metrics_data("DNS")
    else:  # DOS
        df = fetch_metrics_data("DOS")

    if not df.empty:
        y_true = df["label"]
        y_pred = df["prediction"]

        st.metric("Accuracy", accuracy_score(y_true, y_pred))
        st.metric("Precision", precision_score(y_true, y_pred))
        st.metric("Recall", recall_score(y_true, y_pred))
        st.metric("F1 Score", f1_score(y_true, y_pred))
    else:
        st.warning("No metrics data found.")
