# tabs/overview.py
import streamlit as st
import pandas as pd
import requests
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta

def render(time_range, time_range_query_map):
    st.header("📊 DOS Anomaly Detection Overview")
    
    query = time_range_query_map[time_range]
    
    try:
        # Replace with your actual API endpoint
        API_URL = "YOUR_API_ENDPOINT_HERE"  # Update this with your actual API URL
        response = requests.get(f"{API_URL}?time_range={query}")
        
        if response.status_code == 200:
            data = response.json()
            
            if data and len(data) > 0:
                # Create DataFrame from the API response
                df = pd.DataFrame(data)
                
                # Display basic stats
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Total Records", len(df))
                
                with col2:
                    anomaly_count = df['anomaly'].sum()
                    st.metric("Anomalies Detected", anomaly_count)
                
                with col3:
                    avg_score = df['anomaly_score'].mean()
                    st.metric("Avg Anomaly Score", f"{avg_score:.3f}")
                
                with col4:
                    max_score = df['anomaly_score'].max()
                    st.metric("Max Anomaly Score", f"{max_score:.3f}")
                
                # Anomaly Score Distribution
                st.subheader("📈 Anomaly Score Distribution")
                fig_hist = px.histogram(df, x='anomaly_score', nbins=20, 
                                       title="Distribution of Anomaly Scores")
                st.plotly_chart(fig_hist, use_container_width=True)
                
                # Anomaly Detection Over Time (simulated time series)
                st.subheader("⏰ Anomaly Detection Timeline")
                
                # Since your API doesn't return timestamps, let's create a simulated timeline
                # based on the data points
                df_with_time = df.copy()
                
                # Create timestamps going backwards from now
                now = datetime.now()
                time_delta = timedelta(minutes=5)  # 5 minutes between each data point
                
                timestamps = []
                for i in range(len(df)):
                    timestamps.append(now - (time_delta * (len(df) - i - 1)))
                
                df_with_time['timestamp'] = timestamps
                
                # Create time series chart
                fig_time = go.Figure()
                
                # Add anomaly score line
                fig_time.add_trace(go.Scatter(
                    x=df_with_time['timestamp'],
                    y=df_with_time['anomaly_score'],
                    mode='lines+markers',
                    name='Anomaly Score',
                    line=dict(color='blue', width=2)
                ))
                
                # Highlight anomalies
                anomaly_data = df_with_time[df_with_time['anomaly'] == 1]
                if not anomaly_data.empty:
                    fig_time.add_trace(go.Scatter(
                        x=anomaly_data['timestamp'],
                        y=anomaly_data['anomaly_score'],
                        mode='markers',
                        name='Detected Anomalies',
                        marker=dict(color='red', size=10, symbol='diamond')
                    ))
                
                fig_time.update_layout(
                    title="Anomaly Scores Over Time",
                    xaxis_title="Time",
                    yaxis_title="Anomaly Score",
                    hovermode='x unified'
                )
                
                st.plotly_chart(fig_time, use_container_width=True)
                
                # Anomaly Status Breakdown
                st.subheader("🔍 Anomaly Status Breakdown")
                
                anomaly_counts = df['anomaly'].value_counts()
                labels = ['Normal', 'Anomaly']
                values = [anomaly_counts.get(0, 0), anomaly_counts.get(1, 0)]
                
                fig_pie = px.pie(values=values, names=labels, 
                               title="Normal vs Anomaly Distribution",
                               color_discrete_map={'Normal': 'lightblue', 'Anomaly': 'red'})
                st.plotly_chart(fig_pie, use_container_width=True)
                
                # Score Range Analysis
                st.subheader("📊 Score Range Analysis")
                
                # Create score ranges
                df['score_range'] = pd.cut(df['anomaly_score'], 
                                         bins=[0, 0.3, 0.6, 0.8, 1.0], 
                                         labels=['Low (0-0.3)', 'Medium (0.3-0.6)', 
                                                'High (0.6-0.8)', 'Critical (0.8-1.0)'])
                
                range_counts = df['score_range'].value_counts()
                
                fig_range = px.bar(x=range_counts.index, y=range_counts.values,
                                  title="Distribution by Score Range",
                                  labels={'x': 'Score Range', 'y': 'Count'})
                st.plotly_chart(fig_range, use_container_width=True)
                
                # Recent High-Score Entries
                st.subheader("⚠️ Recent High-Score Detections")
                high_score_threshold = 0.7
                high_scores = df[df['anomaly_score'] >= high_score_threshold].sort_values('anomaly_score', ascending=False)
                
                if not high_scores.empty:
                    # Add simulated additional details for display
                    display_data = high_scores.copy()
                    display_data['Detection_Time'] = df_with_time.loc[high_scores.index, 'timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
                    display_data['Risk_Level'] = display_data['anomaly_score'].apply(
                        lambda x: 'CRITICAL' if x >= 0.9 else 'HIGH' if x >= 0.8 else 'MEDIUM'
                    )
                    
                    st.dataframe(
                        display_data[['Detection_Time', 'anomaly_score', 'anomaly', 'Risk_Level']].rename(columns={
                            'anomaly_score': 'Anomaly Score',
                            'anomaly': 'Anomaly Flag',
                            'Risk_Level': 'Risk Level'
                        }),
                        use_container_width=True
                    )
                else:
                    st.info(f"No detections with score >= {high_score_threshold} in the selected time range.")
                
            else:
                st.warning("No data available for the selected time range.")
                
        else:
            st.error(f"API Error: {response.status_code} - {response.text}")
            
    except requests.exceptions.RequestException as e:
        st.error(f"Connection Error: {str(e)}")
    except Exception as e:
        st.error(f"Unexpected Error: {str(e)}")


# tabs/live_stream.py
import streamlit as st
import pandas as pd
import requests
import time
import plotly.graph_objects as go
from datetime import datetime

def render(thresh, highlight_color, alerts_enabled):
    st.header("🔴 Live DOS Anomaly Stream")
    
    # Color mapping
    color_map = {
        "Red": "#FF0000",
        "Orange": "#FFA500", 
        "Yellow": "#FFFF00",
        "Green": "#00FF00",
        "Blue": "#0000FF"
    }
    
    selected_color = color_map[highlight_color]
    
    # Auto-refresh controls
    col1, col2, col3 = st.columns(3)
    with col1:
        auto_refresh = st.checkbox("Auto Refresh", value=True)
    with col2:
        refresh_interval = st.selectbox("Refresh Interval", [5, 10, 15, 30], index=1)
    with col3:
        if st.button("🔄 Manual Refresh"):
            st.rerun()
    
    # Placeholder for live data
    live_placeholder = st.empty()
    chart_placeholder = st.empty()
    
    try:
        # Replace with your actual API endpoint
        API_URL = "YOUR_API_ENDPOINT_HERE"
        response = requests.get(f"{API_URL}?time_range=-5m")  # Last 5 minutes for live data
        
        if response.status_code == 200:
            data = response.json()
            
            if data and len(data) > 0:
                df = pd.DataFrame(data)
                
                # Filter by threshold
                filtered_df = df[df['anomaly_score'] >= thresh]
                
                with live_placeholder.container():
                    # Live stats
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.metric("Live Records", len(df))
                    
                    with col2:
                        above_threshold = len(filtered_df)
                        st.metric("Above Threshold", above_threshold)
                    
                    with col3:
                        if len(df) > 0:
                            latest_score = df['anomaly_score'].iloc[-1]
                            st.metric("Latest Score", f"{latest_score:.3f}")
                    
                    with col4:
                        anomaly_count = df['anomaly'].sum()
                        st.metric("Live Anomalies", anomaly_count)
                    
                    # Alert section
                    if alerts_enabled and above_threshold > 0:
                        st.warning(f"🚨 {above_threshold} detections above threshold {thresh}!")
                        
                        # Show recent high-score detections
                        recent_high = filtered_df.nlargest(5, 'anomaly_score')
                        st.subheader("Recent High-Score Detections")
                        
                        for idx, row in recent_high.iterrows():
                            alert_color = selected_color if row['anomaly_score'] >= thresh else "#CCCCCC"
                            st.markdown(
                                f"""
                                <div style="padding: 10px; margin: 5px 0; border-left: 4px solid {alert_color}; background-color: #f9f9f9;">
                                    <strong>Score: {row['anomaly_score']:.4f}</strong> | 
                                    Anomaly: {'YES' if row['anomaly'] == 1 else 'NO'} | 
                                    Risk: {'HIGH' if row['anomaly_score'] >= 0.8 else 'MEDIUM' if row['anomaly_score'] >= 0.6 else 'LOW'}
                                </div>
                                """, 
                                unsafe_allow_html=True
                            )
                
                # Live chart
                with chart_placeholder:
                    st.subheader("📊 Live Anomaly Score Feed")
                    
                    # Create simulated timestamps for the chart
                    timestamps = pd.date_range(end=datetime.now(), periods=len(df), freq='1min')
                    
                    fig = go.Figure()
                    
                    # Add all scores
                    fig.add_trace(go.Scatter(
                        x=timestamps,
                        y=df['anomaly_score'],
                        mode='lines+markers',
                        name='Anomaly Score',
                        line=dict(color='blue', width=2),
                        marker=dict(size=6)
                    ))
                    
                    # Highlight above threshold
                    above_thresh_mask = df['anomaly_score'] >= thresh
                    if above_thresh_mask.any():
                        fig.add_trace(go.Scatter(
                            x=timestamps[above_thresh_mask],
                            y=df['anomaly_score'][above_thresh_mask],
                            mode='markers',
                            name=f'Above Threshold ({thresh})',
                            marker=dict(color=selected_color, size=10, symbol='diamond')
                        ))
                    
                    # Add threshold line
                    fig.add_hline(y=thresh, line_dash="dash", line_color="red", 
                                 annotation_text=f"Threshold: {thresh}")
                    
                    fig.update_layout(
                        title="Live Anomaly Score Stream",
                        xaxis_title="Time",
                        yaxis_title="Anomaly Score",
                        hovermode='x unified',
                        height=400
                    )
                    
                    st.plotly_chart(fig, use_container_width=True)
                
            else:
                st.info("No live data available")
                
        else:
            st.error(f"API Error: {response.status_code}")
            
    except Exception as e:
        st.error(f"Error in live stream: {str(e)}")
    
    # Auto-refresh functionality
    if auto_refresh:
        time.sleep(refresh_interval)
        st.rerun()


# tabs/metrics.py
import streamlit as st
import pandas as pd
import requests
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

def render(thresh):
    st.header("📈 DOS Detection Metrics")
    
    try:
        # Replace with your actual API endpoint
        API_URL = "YOUR_API_ENDPOINT_HERE"
        response = requests.get(f"{API_URL}?time_range=-24h")  # Last 24 hours for metrics
        
        if response.status_code == 200:
            data = response.json()
            
            if data and len(data) > 0:
                df = pd.DataFrame(data)
                
                # Calculate metrics
                total_records = len(df)
                anomaly_count = df['anomaly'].sum()
                normal_count = total_records - anomaly_count
                
                above_threshold = len(df[df['anomaly_score'] >= thresh])
                avg_score = df['anomaly_score'].mean()
                max_score = df['anomaly_score'].max()
                min_score = df['anomaly_score'].min()
                
                # Detection rate
                detection_rate = (anomaly_count / total_records * 100) if total_records > 0 else 0
                
                # Metrics Dashboard
                st.subheader("🎯 Key Performance Metrics")
                
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric(
                        "Detection Rate", 
                        f"{detection_rate:.1f}%",
                        delta=f"{anomaly_count} anomalies"
                    )
                
                with col2:
                    st.metric(
                        "Average Score", 
                        f"{avg_score:.3f}",
                        delta=f"Max: {max_score:.3f}"
                    )
                
                with col3:
                    st.metric(
                        "Above Threshold", 
                        above_threshold,
                        delta=f"Threshold: {thresh}"
                    )
                
                with col4:
                    precision = anomaly_count / above_threshold if above_threshold > 0 else 0
                    st.metric(
                        "Precision", 
                        f"{precision:.2f}",
                        delta="True positives ratio"
                    )
                
                # Score Statistics
                st.subheader("📊 Score Statistics")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    # Box plot for score distribution
                    fig_box = px.box(df, y='anomaly_score', title="Anomaly Score Distribution")
                    fig_box.add_hline(y=thresh, line_dash="dash", line_color="red", 
                                     annotation_text=f"Threshold: {thresh}")
                    st.plotly_chart(fig_box, use_container_width=True)
                
                with col2:
                    # Violin plot
                    fig_violin = px.violin(df, y='anomaly_score', box=True, 
                                          title="Score Density Distribution")
                    fig_violin.add_hline(y=thresh, line_dash="dash", line_color="red")
                    st.plotly_chart(fig_violin, use_container_width=True)
                
                # Performance Metrics
                st.subheader("⚡ Performance Analysis")
                
                # Create performance metrics
                score_ranges = {
                    'Low (0-0.3)': len(df[(df['anomaly_score'] >= 0) & (df['anomaly_score'] < 0.3)]),
                    'Medium (0.3-0.6)': len(df[(df['anomaly_score'] >= 0.3) & (df['anomaly_score'] < 0.6)]),
                    'High (0.6-0.8)': len(df[(df['anomaly_score'] >= 0.6) & (df['anomaly_score'] < 0.8)]),
                    'Critical (0.8-1.0)': len(df[(df['anomaly_score'] >= 0.8) & (df['anomaly_score'] <= 1.0)])
                }
                
                # Horizontal bar chart for score ranges
                fig_ranges = px.bar(
                    x=list(score_ranges.values()),
                    y=list(score_ranges.keys()),
                    orientation='h',
                    title="Count by Score Range",
                    color=list(score_ranges.values()),
                    color_continuous_scale='Reds'
                )
                st.plotly_chart(fig_ranges, use_container_width=True)
                
                # Threshold Analysis
                st.subheader("🎚️ Threshold Analysis")
                
                # Calculate metrics for different thresholds
                thresholds = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
                threshold_metrics = []
                
                for t in thresholds:
                    above_t = len(df[df['anomaly_score'] >= t])
                    true_positives = len(df[(df['anomaly_score'] >= t) & (df['anomaly'] == 1)])
                    precision_t = true_positives / above_t if above_t > 0 else 0
                    recall_t = true_positives / anomaly_count if anomaly_count > 0 else 0
                    
                    threshold_metrics.append({
                        'threshold': t,
                        'detections': above_t,
                        'precision': precision_t,
                        'recall': recall_t
                    })
                
                threshold_df = pd.DataFrame(threshold_metrics)
                
                # Create subplot for threshold analysis
                fig_thresh = make_subplots(
                    rows=2, cols=2,
                    subplot_titles=('Detections vs Threshold', 'Precision vs Threshold',
                                  'Recall vs Threshold', 'F1-Score vs Threshold')
                )
                
                # Detections
                fig_thresh.add_trace(
                    go.Scatter(x=threshold_df['threshold'], y=threshold_df['detections'],
                              name='Detections', line=dict(color='blue')),
                    row=1, col=1
                )
                
                # Precision
                fig_thresh.add_trace(
                    go.Scatter(x=threshold_df['threshold'], y=threshold_df['precision'],
                              name='Precision', line=dict(color='green')),
                    row=1, col=2
                )
                
                # Recall
                fig_thresh.add_trace(
                    go.Scatter(x=threshold_df['threshold'], y=threshold_df['recall'],
                              name='Recall', line=dict(color='orange')),
                    row=2, col=1
                )
                
                # F1-Score
                threshold_df['f1_score'] = 2 * (threshold_df['precision'] * threshold_df['recall']) / (threshold_df['precision'] + threshold_df['recall'])
                threshold_df['f1_score'] = threshold_df['f1_score'].fillna(0)
                
                fig_thresh.add_trace(
                    go.Scatter(x=threshold_df['threshold'], y=threshold_df['f1_score'],
                              name='F1-Score', line=dict(color='red')),
                    row=2, col=2
                )
                
                # Add current threshold line to all subplots
                for row in range(1, 3):
                    for col in range(1, 3):
                        fig_thresh.add_vline(x=thresh, line_dash="dash", line_color="red", row=row, col=col)
                
                fig_thresh.update_layout(height=600, showlegend=False, 
                                       title_text="Threshold Performance Analysis")
                st.plotly_chart(fig_thresh, use_container_width=True)
                
                # Summary table
                st.subheader("📋 Summary Statistics")
                
                summary_data = {
                    'Metric': ['Total Records', 'Anomalies Detected', 'Normal Records', 
                              'Above Threshold', 'Average Score', 'Max Score', 'Min Score'],
                    'Value': [total_records, anomaly_count, normal_count, above_threshold,
                             f"{avg_score:.4f}", f"{max_score:.4f}", f"{min_score:.4f}"]
                }
                
                summary_df = pd.DataFrame(summary_data)
                st.dataframe(summary_df, use_container_width=True, hide_index=True)
                
            else:
                st.warning("No data available for metrics calculation.")
                
        else:
            st.error(f"API Error: {response.status_code}")
            
    except Exception as e:
        st.error(f"Error loading metrics: {str(e)}")


# Update your main app.py with the correct API URL
# Replace "YOUR_API_ENDPOINT_HERE" in all the tab files with your actual API endpoint
