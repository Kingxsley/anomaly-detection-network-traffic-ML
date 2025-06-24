# metrics.py

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.figure_factory as ff
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

def render(thresh):
    st.header("Model Performance")
    df = pd.DataFrame(st.session_state.predictions)

    if not df.empty:
        st.subheader("Performance Metrics")
        valid_df = df.dropna(subset=["label", "anomaly"])
        if len(valid_df) >= 2 and valid_df["label"].nunique() > 1 and valid_df["anomaly"].nunique() > 1:
            y_true = valid_df["anomaly"].astype(int)
            y_pred = valid_df["anomaly"].astype(int)

            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Accuracy", f"{accuracy_score(y_true, y_pred):.2%}")
            col2.metric("Precision", f"{precision_score(y_true, y_pred, zero_division=0):.2%}")
            col3.metric("Recall", f"{recall_score(y_true, y_pred, zero_division=0):.2%}")
            col4.metric("F1-Score", f"{f1_score(y_true, y_pred, zero_division=0):.2%}")

            cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
            if cm.shape == (2, 2):
                fig_cm = ff.create_annotated_heatmap(
                    z=cm,
                    x=["Predicted Normal", "Predicted Attack"],
                    y=["Normal", "Attack"],
                    annotation_text=cm.astype(str),
                    colorscale="Blues"
                )
                fig_cm.update_layout(title="Confusion Matrix", width=400, height=400)
                st.plotly_chart(fig_cm)
            else:
                st.warning("Confusion matrix could not be generated due to insufficient class diversity.")
        else:
            st.warning("Insufficient or unbalanced data for performance metrics.")

        st.subheader("Reconstruction Error Distribution")
        fig_hist = px.histogram(
            df,
            x="reconstruction_error",
            color="anomaly",
            title="Reconstruction Error Distribution",
            color_discrete_map={0: "blue", 1: "red"},
            nbins=50
        )
        fig_hist.add_vline(x=thresh, line_dash="dash", line_color="black", annotation_text="Threshold")
        st.plotly_chart(fig_hist, use_container_width=True)
    else:
        st.info("No predictions available for performance analysis.")
