import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from datetime import datetime, timedelta

def render_historical_tab(get_historical_data_func, highlight_color, thresh):
    st.header("Historical DNS Data")

    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date", datetime.now() - timedelta(days=7))
    with col2:
        end_date = st.date_input("End Date", datetime.now())

    df = get_historical_data_func(start_date, end_date)

    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["reconstruction_error"] = np.random.default_rng().random(len(df))
        df["anomaly"] = (df["reconstruction_error"] > thresh).astype(int)
        df["label"] = df["anomaly"].map({0: "Normal", 1: "Attack"})

        st.subheader("Summary")
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Records", len(df))
        col2.metric("Anomalies", df["anomaly"].sum())
        col3.metric("Anomaly Rate", f"{df['anomaly'].mean():.2%}")

        chart_type = st.selectbox("Chart Type", ["Line", "Bar", "Pie", "Area", "Scatter"], index=0)
        rows_per_page = 100
        total_pages = (len(df) - 1) // rows_per_page + 1
        page = st.number_input("Page", 1, total_pages, 1) - 1
        df_view = df.iloc[page * rows_per_page:(page + 1) * rows_per_page]

        def highlight(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        st.dataframe(df_view.style.apply(highlight, axis=1))

        if chart_type == "Line":
            chart = px.line(df, x="timestamp", y="dns_rate", color="label")
        elif chart_type == "Bar":
            chart = px.bar(df, x="timestamp", y="dns_rate", color="label")
        elif chart_type == "Pie":
            chart = px.pie(df, names="label")
        elif chart_type == "Area":
            chart = px.area(df, x="timestamp", y="dns_rate", color="label")
        elif chart_type == "Scatter":
            chart = px.scatter(df, x="timestamp", y="dns_rate", color="label")
        st.plotly_chart(chart)

        csv = df.to_csv(index=False)
        st.download_button("Download CSV", csv, file_name="dns_data.csv")
    else:
        st.warning("No data found in selected range.")
