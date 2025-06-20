
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.figure_factory as ff
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

def render_metrics_tab(thresh):
    st.header("Model Performance")
    df = pd.DataFrame(st.session_state.predictions)

    if not df.empty:
        st.subheader("Metrics")
        valid_df = df.dropna(subset=["label", "anomaly"])
        if len(valid_df) >= 2 and valid_df["label"].nunique() > 1:
            y_true = valid_df["anomaly"].astype(int)
            y_pred = valid_df["anomaly"].astype(int)
            accuracy = accuracy_score(y_true, y_pred)
            precision = precision_score(y_true, y_pred, zero_division=0)
            recall = recall_score(y_true, y_pred, zero_division=0)
            f1 = f1_score(y_true, y_pred, zero_division=0)

            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Accuracy", f"{accuracy:.2%}")
            col2.metric("Precision", f"{precision:.2%}")
            col3.metric("Recall", f"{recall:.2%}")
            col4.metric("F1", f"{f1:.2%}")

            cm = confusion_matrix(y_true, y_pred)
            if cm.shape == (2, 2):
                fig = ff.create_annotated_heatmap(
                    z=cm,
                    x=["Predicted Normal", "Predicted Attack"],
                    y=["Normal", "Attack"],
                    annotation_text=cm.astype(str),
                    colorscale="Blues"
                )
                fig.update_layout(title="Confusion Matrix")
                st.plotly_chart(fig)
            else:
                st.warning("Confusion matrix not displayable.")

        st.subheader("Reconstruction Error")
        fig = px.histogram(df, x="reconstruction_error", nbins=50, color="anomaly",
                           color_discrete_map={0: "blue", 1: "red"})
        fig.add_vline(x=thresh, line_color="black", line_dash="dash")
        st.plotly_chart(fig)
    else:
        st.info("No data for metrics.")
