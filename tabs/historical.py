import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from datetime import datetime, timedelta
from tabs.utils import get_historical  # Ensure this import is correct

def render(thresh, highlight_color):
    st.header(f"Historical {st.secrets.get('DASHBOARD_TYPE', 'DNS')} Data")

    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date", datetime.now() - timedelta(days=7))
    with col2:
        end_date = st.date_input("End Date", datetime.now())

    # Load the appropriate historical data based on DNS or DOS
    df = get_historical(start_date, end_date)

    if not df.empty:
        # Add reconstruction_error and anomaly columns for visualization
        df["reconstruction_error"] = np.random.default_rng().random(len(df))  # Simulated for demonstration
        df["anomaly"] = (df["reconstruction_error"] > thresh).astype(int)
        df["label"] = df["anomaly"].map({0: "Normal", 1: "Attack"})

        st.subheader("Summary")
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Records", len(df))
        col2.metric("Anomalies Detected", df["anomaly"].sum())
        col3.metric("Anomaly Rate", f"{df['anomaly'].mean():.2%}")

        chart_type = st.selectbox("Chart Type", ["Line", "Bar", "Pie", "Area", "Scatter"], index=0)

        rows_per_page = 100
        total_pages = (len(df) - 1) // rows_per_page + 1
        page = st.number_input("Historical Page", 1, total_pages, 1, key="hist_page") - 1
        df_view = df.iloc[page * rows_per_page:(page + 1) * rows_per_page]

        def highlight_hist(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        st.dataframe(df_view.style.apply(highlight_hist, axis=1))

        # Plotting the selected chart type based on available columns
        if st.secrets.get('DASHBOARD_TYPE', 'DNS') == 'DNS':
            # DNS: Use dns_rate and inter_arrival_time
            if 'dns_rate' in df.columns and 'inter_arrival_time' in df.columns:
                if chart_type == "Line":
                    chart = px.line(df, x="timestamp", y="dns_rate", color="label",
                                    color_discrete_map={"Normal": "blue", "Attack": "red"})
                elif chart_type == "Bar":
                    chart = px.bar(df, x="timestamp", y="dns_rate", color="label",
                                   color_discrete_map={"Normal": "blue", "Attack": "red"})
                elif chart_type == "Pie":
                    chart = px.pie(df, names="label")
                elif chart_type == "Area":
                    chart = px.area(df, x="timestamp", y="dns_rate", color="label",
                                    color_discrete_map={"Normal": "blue", "Attack": "red"})
                elif chart_type == "Scatter":
                    chart = px.scatter(df, x="timestamp", y="dns_rate", color="label",
                                       color_discrete_map={"Normal": "blue", "Attack": "red"})
            else:
                st.warning("Required columns for DNS are missing.")

        else:
            # DOS: Use packet_rate and inter_arrival_time
            if 'packet_rate' in df.columns and 'inter_arrival_time' in df.columns:
                if chart_type == "Line":
                    chart = px.line(df, x="timestamp", y="packet_rate", color="label",
                                    color_discrete_map={"Normal": "blue", "Attack": "red"})
                elif chart_type == "Bar":
                    chart = px.bar(df, x="timestamp", y="packet_rate", color="label",
                                   color_discrete_map={"Normal": "blue", "Attack": "red"})
                elif chart_type == "Pie":
                    chart = px.pie(df, names="label")
                elif chart_type == "Area":
                    chart = px.area(df, x="timestamp", y="packet_rate", color="label",
                                    color_discrete_map={"Normal": "blue", "Attack": "red"})
                elif chart_type == "Scatter":
                    chart = px.scatter(df, x="timestamp", y="packet_rate", color="label",
                                       color_discrete_map={"Normal": "blue", "Attack": "red"})
            else:
                st.warning("Required columns for DOS are missing.")

        st.plotly_chart(chart, use_container_width=True)
        st.download_button("Download CSV", df.to_csv(index=False), file_name="historical_data.csv")
    else:
        st.warning("No historical data found.")
