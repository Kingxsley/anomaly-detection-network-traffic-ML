import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from datetime import datetime, timedelta
from tabs.utils import get_historical

def render(thresh, highlight_color):
    st.header("Historical DNS Data")
    
    # Time range selector
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        time_range = st.selectbox(
            "Time Range",
            options=["1 day", "7 days", "30 days", "90 days", "Custom"],
            index=0,  # Default to 1 day
            key="time_range_selector"
        )
    
    # Calculate date range based on selection
    if time_range == "1 day":
        start_date = datetime.now() - timedelta(days=1)
        end_date = datetime.now()
    elif time_range == "7 days":
        start_date = datetime.now() - timedelta(days=7)
        end_date = datetime.now()
    elif time_range == "30 days":
        start_date = datetime.now() - timedelta(days=30)
        end_date = datetime.now()
    elif time_range == "90 days":
        start_date = datetime.now() - timedelta(days=90)
        end_date = datetime.now()
    else:  # Custom
        with col2:
            start_date = st.date_input("Start Date", datetime.now() - timedelta(days=7))
        with col3:
            end_date = st.date_input("End Date", datetime.now())
    
    # Show selected date range for non-custom options
    if time_range != "Custom":
        with col2:
            st.write(f"*From:* {start_date.strftime('%Y-%m-%d')}")
        with col3:
            st.write(f"*To:* {end_date.strftime('%Y-%m-%d')}")
    
    # Add data sampling option for large datasets
    st.subheader("Data Processing Options")
    col1, col2 = st.columns(2)
    with col1:
        max_rows = st.number_input(
            "Max rows to display (0 = all)", 
            min_value=0, 
            max_value=50000, 
            value=10000,
            step=1000,
            help="Limit the number of rows to improve performance"
        )
    with col2:
        sampling_method = st.selectbox(
            "Sampling Method",
            ["Recent data", "Random sample", "Evenly spaced"],
            help="How to select data when limiting rows"
        )
    
    # Get data
    df = get_historical(start_date, end_date)
    
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp")  # Ensure data is sorted by timestamp
        
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
        
        # Generate synthetic anomaly data
        df["reconstruction_error"] = np.random.default_rng().random(len(df))
        df["anomaly"] = (df["reconstruction_error"] > thresh).astype(int)
        df["label"] = df["anomaly"].map({0: "Normal", 1: "Attack"})
        
        # Summary metrics
        st.subheader("Summary")
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Displayed Records", f"{len(df):,}")
        col2.metric("Total Records", f"{original_size:,}")
        col3.metric("Anomalies Detected", df["anomaly"].sum())
        col4.metric("Anomaly Rate", f"{df['anomaly'].mean():.2%}")
        
        # Chart type selector
        chart_type = st.selectbox("Chart Type", ["Line", "Bar", "Pie", "Area", "Scatter"], index=0)
        
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
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)
        
        st.dataframe(df_view.style.apply(highlight_hist, axis=1), use_container_width=True)
        
        # Charts (using full filtered dataset, not just the paginated view)
        st.subheader("Visualization")
        
        # Add chart performance warning for large datasets
        if len(df) > 5000:
            st.warning(f"Rendering chart with {len(df):,} points. This may take a moment to load.")
        
        if chart_type == "Line":
            chart = px.line(df, x="timestamp", y="dns_rate", color="label",
                            color_discrete_map={"Normal": "blue", "Attack": "red"},
                            title=f"DNS Rate Over Time ({time_range})")
        elif chart_type == "Bar":
            # For bar charts with many points, consider aggregating by hour/day
            if len(df) > 1000:
                st.info("Aggregating data by hour for better bar chart performance")
                df_agg = df.set_index('timestamp').resample('H').agg({
                    'dns_rate': 'mean',
                    'anomaly': 'max',  # If any point in the hour was anomalous
                    'label': lambda x: 'Attack' if x.eq('Attack').any() else 'Normal'
                }).reset_index()
                chart = px.bar(df_agg, x="timestamp", y="dns_rate", color="label",
                               color_discrete_map={"Normal": "blue", "Attack": "red"},
                               title=f"Average DNS Rate by Hour ({time_range})")
            else:
                chart = px.bar(df, x="timestamp", y="dns_rate", color="label",
                               color_discrete_map={"Normal": "blue", "Attack": "red"},
                               title=f"DNS Rate Over Time ({time_range})")
        elif chart_type == "Pie":
            chart = px.pie(df, names="label", title=f"Normal vs Attack Distribution ({time_range})")
        elif chart_type == "Area":
            chart = px.area(df, x="timestamp", y="dns_rate", color="label",
                            color_discrete_map={"Normal": "blue", "Attack": "red"},
                            title=f"DNS Rate Over Time ({time_range})")
        elif chart_type == "Scatter":
            chart = px.scatter(df, x="timestamp", y="dns_rate", color="label",
                               color_discrete_map={"Normal": "blue", "Attack": "red"},
                               title=f"DNS Rate Over Time ({time_range})")
        
        st.plotly_chart(chart, use_container_width=True)
        
        # Download options
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
                    full_df = get_historical(start_date, end_date)
                    st.download_button(
                        "Click to Download Full Data", 
                        full_df.to_csv(index=False), 
                        file_name=f"full_historical_dns_data_{time_range.replace(' ', '_')}.csv",
                        key="full_download"
                    )
    else:
        st.warning("No historical data found for the selected time range.")
