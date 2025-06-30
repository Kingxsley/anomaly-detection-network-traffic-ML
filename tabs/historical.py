import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from datetime import datetime, timedelta
from tabs.utils import load_predictions_from_sqlitecloud

def render(thresh, highlight_color):
    st.header("Historical DNS Data")
    
    # Time range selector
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        time_range = st.selectbox(
            "Time Range",
            options=["1 day", "7 days", "30 days", "90 days"],
            index=0,  # Default to 1 day
            key="time_range_selector"
        )
    
    # Map time range to query format (matching your overview tab)
    time_range_query_map = {
        "1 day": "-24h",
        "7 days": "-7d", 
        "30 days": "-30d",
        "90 days": "-90d"
    }
    
    query_duration = time_range_query_map.get(time_range, "-24h")
    
    # Show selected time range
    with col2:
        st.write(f"*Selected:* {time_range}")
    with col3:
        st.write(f"*Query:* {query_duration}")
    
    # Add data sampling option for large datasets
    st.subheader("Data Processing Options")
    col1, col2 = st.columns(2)
    with col1:
        max_rows = st.number_input(
            "Max rows to display (0 = all)", 
            min_value=0, 
            max_value=10000, 
            value=100,
            step=10,
            help="Limit the number of rows to improve performance"
        )
    with col2:
        sampling_method = st.selectbox(
            "Sampling Method",
            ["Recent data", "Random sample", "Evenly spaced"],
            help="How to select data when limiting rows"
        )
    
    # Get data with error handling
    try:
        with st.spinner("Loading historical data..."):
            df = load_predictions_from_sqlitecloud(time_window=query_duration)
        st.success(f"Data loaded successfully!")
    except Exception as e:
        st.error(f"Error loading data: {str(e)}")
        st.write("Please check your data source and try again.")
        return
    
    if df is None:
        st.error("load_predictions_from_sqlitecloud() returned None")
        return
        
    if not df.empty:
        try:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            df = df.sort_values("timestamp")  # Ensure data is sorted by timestamp
        except Exception as e:
            st.error(f"Error processing timestamp column: {str(e)}")
            st.write("Available columns:", list(df.columns))
            return
        
        # Show original data size
        original_size = len(df)
        st.info(f"Original dataset size: {original_size:,} rows")
        
        # Apply row limiting if specified
        if max_rows > 0 and len(df) > max_rows:
            if sampling_method == "Recent data":
                df = df.tail(max_rows)
            elif sampling_method == "Random sample":
                df = df.sample(n=max_rows, random_state=42)
                df = df.sort_values("timestamp")  # Re-sort after sampling
            elif sampling_method == "Evenly spaced":
                step = len(df) // max_rows
                df = df.iloc[::step][:max_rows]
            
            st.warning(f"Displaying {len(df):,} rows out of {original_size:,} total rows")
        
        # Use existing anomaly data (no need to generate synthetic data)
        # Map is_anomaly to label for consistency with charts
        df["label"] = df["is_anomaly"].map({0: "Normal", 1: "Attack"})
        
        # Summary metrics
        st.subheader("Summary")
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Displayed Records", f"{len(df):,}")
        col2.metric("Total Records", f"{original_size:,}")
        col3.metric("Anomalies Detected", df["is_anomaly"].sum())
        col4.metric("Anomaly Rate", f"{df['is_anomaly'].mean():.2%}")
        
        # Chart type selector
        chart_type = st.selectbox("Chart Type", ["Line", "Bar", "Pie", "Scatter"], index=0)
        
        # Data table with pagination (only for display table, not affecting charts)
        st.subheader("Data Table")
        rows_per_page = st.selectbox("Rows per page", [50, 100, 250, 500], index=1)
        total_pages = (len(df) - 1) // rows_per_page + 1
        
        if total_pages > 1:
            page = st.number_input("Page", 1, total_pages, 1, key="hist_page") - 1
            df_view = df.iloc[page * rows_per_page:(page + 1) * rows_per_page]
            st.write(f"Showing page {page + 1} of {total_pages}")
        else:
            df_view = df
        
        def highlight_hist(row):
            return [f"background-color: {highlight_color}" if row["is_anomaly"] == 1 else ""] * len(row)
        
        st.dataframe(df_view.style.apply(highlight_hist, axis=1), use_container_width=True)
        
        # Charts (using full filtered dataset, not just the paginated view)
        st.subheader("Visualization")
        
        # Add chart performance warning for large datasets
        if len(df) > 5000:
            st.warning(f"Rendering chart with {len(df):,} points. This may take a moment to load.")
        
        if chart_type == "Line":
            try:
                chart = px.line(df, x="timestamp", y="anomaly_score", color="label",
                                color_discrete_map={"Normal": "blue", "Attack": "red"},
                                title=f"Anomaly Score Over Time ({time_range})")
            except Exception as e:
                st.error(f"Error creating line chart: {str(e)}")
                st.write("Required columns: timestamp, anomaly_score, label")
                st.write("Available columns:", list(df.columns))
                return
        elif chart_type == "Bar":
            # For bar charts with many points, consider aggregating by hour/day
            if len(df) > 1000:
                st.info("Aggregating data by hour for better bar chart performance")
                df_agg = df.set_index('timestamp').resample('H').agg({
                    'anomaly_score': 'mean',
                    'is_anomaly': 'max',  # If any point in the hour was anomalous
                    'label': lambda x: 'Attack' if x.eq('Attack').any() else 'Normal'
                }).reset_index()
                chart = px.bar(df_agg, x="timestamp", y="anomaly_score", color="label",
                               color_discrete_map={"Normal": "blue", "Attack": "red"},
                               title=f"Average Anomaly Score by Hour ({time_range})")
            else:
                chart = px.bar(df, x="timestamp", y="anomaly_score", color="label",
                               color_discrete_map={"Normal": "blue", "Attack": "red"},
                               title=f"Anomaly Score Over Time ({time_range})")
        elif chart_type == "Pie":
            chart = px.pie(df, names="label", title=f"Normal vs Attack Distribution ({time_range})")
        elif chart_type == "Scatter":
            chart = px.scatter(df, x="timestamp", y="anomaly_score", color="label",
                               color_discrete_map={"Normal": "blue", "Attack": "red"},
                               title=f"Anomaly Score Over Time ({time_range})")
        
        st.plotly_chart(chart, use_container_width=True)
        
        # Additional analysis sections
        st.subheader("Top Anomalous IPs")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("*Top Source IPs (Anomalies)*")
            if 'source_ip' in df.columns:
                source_anomalies = df[df["is_anomaly"] == 1]["source_ip"].value_counts().head(10).reset_index()
                source_anomalies.columns = ["Source IP", "Anomaly Count"]
                st.dataframe(source_anomalies, use_container_width=True)
            else:
                st.info("Source IP data not available")
        
        with col2:
            st.markdown("*Top Destination IPs (Anomalies)*")
            if 'dest_ip' in df.columns:
                dest_anomalies = df[df["is_anomaly"] == 1]["dest_ip"].value_counts().head(10).reset_index()
                dest_anomalies.columns = ["Destination IP", "Anomaly Count"]
                st.dataframe(dest_anomalies, use_container_width=True)
            else:
                st.info("Destination IP data not available")
        
        # Export data
        st.subheader("Export Data")
        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                "Download Displayed Data (CSV)", 
                df.to_csv(index=False), 
                file_name=f"historical_dns_data_{time_range.replace(' ', '_')}.csv"
            )
        with col2:
            if len(df) < original_size:
                if st.button("Download Full Dataset (CSV)"):
                    full_df = load_predictions_from_sqlitecloud(time_window=query_duration)
                    st.download_button(
                        "Click to Download Full Data", 
                        full_df.to_csv(index=False), 
                        file_name=f"full_historical_dns_data_{time_range.replace(' ', '_')}.csv",
                        key="full_download"
                    )
    else:
        st.warning("No historical data found for the selected time range.")
