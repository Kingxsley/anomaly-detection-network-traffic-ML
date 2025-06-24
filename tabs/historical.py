# historical.py

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from datetime import datetime, timedelta
from tabs.utils import get_historical  # Use DoS-specific data fetching function

# Modify the render function to accept time_range, time_range_query_map, thresh, and highlight_color
def render(time_range, time_range_query_map, thresh, highlight_color):
    st.header("DoS Historical Data")  # Update title for DoS

    # Use the time_range passed from main_dashboard.py
    query_duration = time_range_query_map.get(time_range, "-24h")

    start_date = pd.to_datetime("now") - pd.to_timedelta(query_duration)
    end_date = pd.to_datetime("now")

    # Fetch the historical DoS data
    df = get_historical(start_date, end_date)

    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["reconstruction_error"] = np.random.default_rng().random(len(df))  # Simulating reconstruction error
        df["anomaly"] = (df["reconstruction_error"] > thresh).astype(int)
        df["label"] = df["anomaly"].map({0: "Normal", 1: "Attack"})  # Mapping anomalies

        # Summary section
        st.subheader("Summary")
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Records", len(df))
        col2.metric("Anomalies Detected", df["anomaly"].sum())
        col3.metric("Anomaly Rate", f"{df['anomaly'].mean():.2%}")

        # Chart type selection
        chart_type = st.selectbox("Chart Type", ["Line", "Bar", "Pie", "Area", "Scatter"], index=0)

        # Pagination for data table
        rows_per_page = 100
        total_pages = (len(df) - 1) // rows_per_page + 1
        page = st.number_input("Historical Page", 1, total_pages, 1, key="hist_page") - 1
        df_view = df.iloc[page * rows_per_page:(page + 1) * rows_per_page]

        # Highlight anomalies in the dataframe
        def highlight_hist(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        st.dataframe(df_view.style.apply(highlight_hist, axis=1))

        # Generate chart based on selected type
        if chart_type == "Line":
            chart = px.line(df, x="timestamp", y="dos_rate", color="label",
                            color_discrete_map={"Normal": "blue", "Attack": "red"})
        elif chart_type == "Bar":
            chart = px.bar(df, x="timestamp", y="dos_rate", color="label",
                           color_discrete_map={"Normal": "blue", "Attack": "red"})
        elif chart_type == "Pie":
            chart = px.pie(df, names="label")
        elif chart_type == "Area":
            chart = px.area(df, x="timestamp", y="dos_rate", color="label",
                            color_discrete_map={"Normal": "blue", "Attack": "red"})
        elif chart_type == "Scatter":
            chart = px.scatter(df, x="timestamp", y="dos_rate", color="label",
                               color_discrete_map={"Normal": "blue", "Attack": "red"})

        # Display the selected chart
        st.plotly_chart(chart, use_container_width=True)

        # Download option for the historical data
        st.download_button("Download CSV", df.to_csv(index=False), file_name="historical_dos_data.csv")
    else:
        st.warning("No historical data found.")
