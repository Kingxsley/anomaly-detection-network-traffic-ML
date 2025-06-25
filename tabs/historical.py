import streamlit as st
import pandas as pd
import numpy as np  # Ensure NumPy is imported
import plotly.express as px
from datetime import datetime, timedelta
from tabs.utils import get_historical

def render(thresh, highlight_color):
    st.header("Historical DoS Data")

    # Date inputs for start and end date
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date", datetime.now() - timedelta(days=7))
    with col2:
        end_date = st.date_input("End Date", datetime.now())

    # Fetch historical data based on the date range
    df = get_historical(start_date, end_date)
    
    if not df.empty:
        # Ensure the timestamp is in the same format as the DNS version
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

        # Calculate reconstruction error and anomaly flags
        df["reconstruction_error"] = np.random.default_rng().random(len(df))  # Placeholder for demo
        df["anomaly"] = (df["reconstruction_error"] > thresh).astype(int)
        df["label"] = df["anomaly"].map({0: "Normal", 1: "Attack"})

        # Display summary metrics
        st.subheader("Summary")
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Records", len(df))
        col2.metric("Anomalies Detected", df["anomaly"].sum())
        col3.metric("Anomaly Rate", f"{df['anomaly'].mean():.2%}")

        # Pagination setup: 100 rows per page
        rows_per_page = 100
        total_pages = (len(df) - 1) // rows_per_page + 1
        page = st.number_input("Historical Page", 1, total_pages, 1, key="hist_page") - 1
        df_view = df.iloc[page * rows_per_page:(page + 1) * rows_per_page]

        # Apply highlight color to rows dynamically using applymap() (for row highlighting)
        def highlight_attack_rows(row):
            color = f'background-color: {highlight_color}' if row['label'] == "Attack" else ''
            return [color] * len(row)  # Apply color to the entire row

        # Apply the highlighting to the rows
        st.dataframe(df_view.style.apply(highlight_attack_rows, axis=1))

        # Always display Pie Chart
        chart = px.pie(df, names="label", title="Distribution of Anomalies", hole=0.3)  # Pie chart with labels
        st.plotly_chart(chart, use_container_width=True)

        # Download the data as CSV
        st.download_button("Download CSV", df.to_csv(index=False), file_name="historical_dos_data.csv")
    else:
        st.warning("No historical data found.")
