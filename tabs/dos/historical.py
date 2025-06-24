import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
from tabs.dos.utils import get_dos_historical_data
import numpy as np  # Ensure numpy is imported

def render_historical(start_date, end_date, thresh, highlight_color):
    st.header("Historical DOS Data")

    df = get_dos_historical_data(start_date, end_date)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp")
        df["reconstruction_error"] = np.random.default_rng().random(len(df))
        df["anomaly"] = (df["reconstruction_error"] > thresh).astype(int)
        df["label"] = df["anomaly"].map({0: "Normal", 1: "Attack"})

        st.subheader("Summary")
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Records", len(df))
        col2.metric("Anomalies Detected", df["anomaly"].sum())
        col3.metric("Anomaly Rate", f"{df['anomaly'].mean():.2%}")

        chart_type = st.selectbox("Chart Type", ["Line", "Bar", "Pie", "Area", "Scatter"], index=0)

        rows_per_page = 100
        total_pages = max((len(df) - 1) // rows_per_page + 1, 1)
        page = st.number_input("Historical Page", 1, total_pages, 1, key="hist_dos_page") - 1
        df_view = df.iloc[page * rows_per_page:(page + 1) * rows_per_page]

        def highlight_hist(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        st.dataframe(df_view.style.apply(highlight_hist, axis=1))

        if chart_type == "Line":
            if "byte_rate" in df.columns:  # Ensure byte_rate exists
                chart = px.line(df, x="timestamp", y="byte_rate", color="label",
                                 color_discrete_map={"Normal": "blue", "Attack": "red"})
                st.plotly_chart(chart)
            else:
                st.warning("byte_rate column is missing from the data.")
        elif chart_type == "Bar":
            if "byte_rate" in df.columns:
                chart = px.bar(df, x="timestamp", y="byte_rate", color="label",
                               color_discrete_map={"Normal": "blue", "Attack": "red"})
                st.plotly_chart(chart)
            else:
                st.warning("byte_rate column is missing from the data.")
        elif chart_type == "Pie":
            chart = px.pie(df, names="label")
            st.plotly_chart(chart)
        elif chart_type == "Area":
            chart = px.area(df, x="timestamp", y="byte_rate", color="label",
                            color_discrete_map={"Normal": "blue", "Attack": "red"})
            st.plotly_chart(chart)
        elif chart_type == "Scatter":
            chart = px.scatter(df, x="timestamp", y="byte_rate", color="label",
                               color_discrete_map={"Normal": "blue", "Attack": "red"})
            st.plotly_chart(chart)
    else:
        st.warning("No historical data found.")
