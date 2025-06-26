# Fixed DOS Dashboard Implementation for Real-time Prediction API

# tabs/overview.py
import streamlit as st
import pandas as pd
import requests
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
from datetime import datetime, timedelta
import json

def generate_sample_traffic(num_samples=50):
    """Generate sample network traffic data for testing"""
    np.random.seed(42)  # For reproducible results
    
    protocols = ['tcp', 'udp', 'http', 'https', 'dns']
    traffic_data = []
    
    for i in range(num_samples):
        # Generate realistic network traffic patterns
        if i < 40:  # Normal traffic (80%)
            inter_arrival_time = np.random.uniform(0.05, 0.2)
            packet_length = np.random.randint(64, 1500)
            protocol = np.random.choice(['tcp', 'http', 'https'], p=[0.4, 0.3, 0.3])
        else:  # Potential DOS attack patterns (20%)
            inter_arrival_time = np.random.uniform(0.001, 0.01)  # Very fast
            packet_length = np.random.randint(1400, 1500)  # Large packets
            protocol = np.random.choice(['tcp', 'udp'], p=[0.7, 0.3])
        
        traffic_data.append({
            "inter_arrival_time": round(inter_arrival_time, 4),
            "packet_length": packet_length,
            "protocol": protocol
        })
    
    return traffic_data

def render(time_range, time_range_query_map):
    st.header("📊 DOS Anomaly Detection Overview")
    
    API_URL = "https://mizzony-dos-anomaly-detection.hf.space"
    
    # API Health Check
    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("🔄 Check API Status"):
            try:
                health_response = requests.get(f"{API_URL}/health", timeout=10)
                if health_response.status_code == 200:
                    health_data = health_response.json()
                    st.success(f"✅ API Status: {health_data.get('status', 'Unknown')}")
                    if health_data.get('models_loaded'):
                        st.info("🤖 Models loaded successfully")
                else:
                    st.error(f"❌ API Error: {health_response.status_code}")
            except Exception as e:
                st.error(f"❌ Connection failed: {str(e)}")
    
    with col1:
        st.subheader("Real-time Network Traffic Analysis")
    
    # Generate and analyze sample traffic
    col1, col2 = st.columns(2)
    
    with col1:
        num_samples = st.slider("Number of Traffic Samples", 10, 100, 50)
        
    with col2:
        if st.button("🔍 Analyze Traffic Sample"):
            with st.spinner("Analyzing network traffic..."):
                # Generate sample data
                traffic_data = generate_sample_traffic(num_samples)
                
                try:
                    # Make prediction request
                    response = requests.post(
                        f"{API_URL}/predict",
                        headers={"Content-Type": "application/json"},
                        json=traffic_data,
                        timeout=30
                    )
                    
                    if response.status_code == 200:
                        predictions = response.json()
                        
                        # Store in session state for other tabs
                        st.session_state.predictions = predictions
                        st.session_state.traffic_data = traffic_data
                        st.session_state.last_analysis_time = datetime.now()
                        
                        # Create DataFrame for analysis
                        df = pd.DataFrame(predictions)
                        traffic_df = pd.DataFrame(traffic_data)
                        
                        # Combine traffic data with predictions
                        combined_df = pd.concat([traffic_df, df], axis=1)
                        
                        # Display results
                        st.success(f"✅ Analyzed {len(predictions)} traffic samples")
                        
                        # Key Metrics
                        st.subheader("📈 Analysis Results")
                        
                        col1, col2, col3, col4 = st.columns(4)
                        
                        with col1:
                            total_samples = len(df)
                            st.metric("Total Samples", total_samples)
                        
                        with col2:
                            anomaly_count = df['anomaly'].sum()
                            st.metric("Anomalies Detected", anomaly_count)
                        
                        with col3:
                            avg_score = df['anomaly_score'].mean()
                            st.metric("Avg Anomaly Score", f"{avg_score:.3f}")
                        
                        with col4:
                            detection_rate = (anomaly_count / total_samples * 100) if total_samples > 0 else 0
                            st.metric("Detection Rate", f"{detection_rate:.1f}%")
                        
                        # Visualization
                        st.subheader("📊 Traffic Analysis Visualization")
                        
                        # Create tabs for different views
                        viz_tabs = st.tabs(["Score Distribution", "Traffic Patterns", "Anomaly Timeline", "Protocol Analysis"])
                        
                        with viz_tabs[0]:
                            # Score Distribution
                            fig_hist = px.histogram(
                                df, x='anomaly_score', nbins=20,
                                title="Anomaly Score Distribution",
                                color='anomaly',
                                color_discrete_map={0: 'lightblue', 1: 'red'}
                            )
                            st.plotly_chart(fig_hist, use_container_width=True)
                        
                        with viz_tabs[1]:
                            # Traffic Patterns
                            fig_scatter = px.scatter(
                                combined_df, 
                                x='inter_arrival_time', 
                                y='packet_length',
                                color='anomaly',
                                size='anomaly_score',
                                title="Traffic Patterns (Packet Length vs Inter-arrival Time)",
                                color_discrete_map={0: 'blue', 1: 'red'},
                                hover_data=['protocol', 'anomaly_score']
                            )
                            st.plotly_chart(fig_scatter, use_container_width=True)
                        
                        with viz_tabs[2]:
                            # Timeline
                            combined_df['sample_id'] = range(len(combined_df))
                            fig_timeline = px.line(
                                combined_df, 
                                x='sample_id', 
                                y='anomaly_score',
                                title="Anomaly Scores Over Sample Sequence",
                                markers=True
                            )
                            
                            # Highlight anomalies
                            anomaly_data = combined_df[combined_df['anomaly'] == 1]
                            if not anomaly_data.empty:
                                fig_timeline.add_scatter(
                                    x=anomaly_data['sample_id'],
                                    y=anomaly_data['anomaly_score'],
                                    mode='markers',
                                    marker=dict(color='red', size=10, symbol='diamond'),
                                    name='Detected Anomalies'
                                )
                            
                            st.plotly_chart(fig_timeline, use_container_width=True)
                        
                        with viz_tabs[3]:
                            # Protocol Analysis
                            protocol_analysis = combined_df.groupby(['protocol', 'anomaly']).size().reset_index(name='count')
                            fig_protocol = px.bar(
                                protocol_analysis,
                                x='protocol',
                                y='count',
                                color='anomaly',
                                title="Anomaly Distribution by Protocol",
                                color_discrete_map={0: 'lightblue', 1: 'red'}
                            )
                            st.plotly_chart(fig_protocol, use_container_width=True)
                        
                        # Detailed Results Table
                        st.subheader("🔍 Detailed Analysis Results")
                        
                        # Show high-risk samples
                        high_risk = combined_df[combined_df['anomaly_score'] >= 0.7].sort_values('anomaly_score', ascending=False)
                        
                        if not high_risk.empty:
                            st.write("*High-Risk Traffic Samples:*")
                            display_columns = ['inter_arrival_time', 'packet_length', 'protocol', 'anomaly_score', 'anomaly']
                            st.dataframe(
                                high_risk[display_columns].rename(columns={
                                    'inter_arrival_time': 'Inter-arrival Time (s)',
                                    'packet_length': 'Packet Length (bytes)',
                                    'protocol': 'Protocol',
                                    'anomaly_score': 'Anomaly Score',
                                    'anomaly': 'Is Anomaly'
                                }),
                                use_container_width=True
                            )
                        else:
                            st.info("No high-risk samples detected (score >= 0.7)")
                        
                    else:
                        st.error(f"API Error: {response.status_code} - {response.text}")
                        
                except requests.exceptions.Timeout:
                    st.error("⏱ Request timeout. The API might be processing or unavailable.")
                except requests.exceptions.RequestException as e:
                    st.error(f"🔗 Connection error: {str(e)}")
                except Exception as e:
                    st.error(f"❌ Unexpected error: {str(e)}")
    
    # Show previous analysis if available
    if 'predictions' in st.session_state and st.session_state.predictions:
        st.subheader("📋 Previous Analysis Summary")
        
        last_predictions = st.session_state.predictions
        last_time = st.session_state.get('last_analysis_time', 'Unknown')
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Last Analysis", str(last_time)[:19] if last_time != 'Unknown' else 'Unknown')
        
        with col2:
            df = pd.DataFrame(last_predictions)
            st.metric("Samples Analyzed", len(df))
        
        with col3:
            anomalies = df['anomaly'].sum()
            st.metric("Anomalies Found", anomalies)
        
        with col4:
            avg_score = df['anomaly_score'].mean()
            st.metric("Average Score", f"{avg_score:.3f}")


# tabs/live_stream.py
import streamlit as st
import pandas as pd
import requests
import numpy as np
import plotly.graph_objects as go
import time
from datetime import datetime

def render(thresh, highlight_color, alerts_enabled):
    st.header("🔴 Live DOS Anomaly Detection Stream")
    
    API_URL = "https://mizzony-dos-anomaly-detection.hf.space"
    
    # Color mapping
    color_map = {
        "Red": "#FF0000",
        "Orange": "#FFA500", 
        "Yellow": "#FFFF00",
        "Green": "#00FF00",
        "Blue": "#0000FF"
    }
    
    selected_color = color_map[highlight_color]
    
    # Live monitoring controls
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        auto_refresh = st.checkbox("Auto Refresh", value=False)
    
    with col2:
        refresh_interval = st.selectbox("Refresh Interval (s)", [5, 10, 15, 30], index=1)
    
    with col3:
        batch_size = st.selectbox("Batch Size", [5, 10, 15, 20], index=1)
    
    with col4:
        if st.button("🔄 Generate New Batch"):
            st.rerun()
    
    # Initialize session state for live stream
    if 'live_data' not in st.session_state:
        st.session_state.live_data = []
    
    if 'stream_active' not in st.session_state:
        st.session_state.stream_active = False
    
    # Stream controls
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🚀 Start Live Stream"):
            st.session_state.stream_active = True
            st.success("Live stream started!")
    
    with col2:
        if st.button("⏹ Stop Stream"):
            st.session_state.stream_active = False
            st.info("Live stream stopped.")
    
    # Generate and analyze live traffic
    if st.session_state.stream_active or st.button("📊 Analyze Single Batch"):
        with st.spinner(f"Analyzing {batch_size} traffic samples..."):
            # Generate realistic traffic data
            traffic_batch = []
            current_time = datetime.now()
            
            for i in range(batch_size):
                # Simulate different types of traffic
                if np.random.random() < 0.8:  # 80% normal traffic
                    inter_arrival = np.random.uniform(0.05, 0.3)
                    packet_len = np.random.randint(64, 1200)
                    protocol = np.random.choice(['tcp', 'http', 'https'])
                else:  # 20% suspicious traffic
                    inter_arrival = np.random.uniform(0.001, 0.05)  # Fast packets
                    packet_len = np.random.randint(1300, 1500)  # Large packets
                    protocol = np.random.choice(['tcp', 'udp'])
                
                traffic_batch.append({
                    "inter_arrival_time": round(inter_arrival, 4),
                    "packet_length": packet_len,
                    "protocol": protocol
                })
            
            try:
                # Make prediction
                response = requests.post(
                    f"{API_URL}/predict",
                    headers={"Content-Type": "application/json"},
                    json=traffic_batch,
                    timeout=15
                )
                
                if response.status_code == 200:
                    predictions = response.json()
                    
                    # Combine with traffic data and add timestamps
                    for i, (traffic, pred) in enumerate(zip(traffic_batch, predictions)):
                        combined_sample = {
                            **traffic,
                            **pred,
                            'timestamp': current_time,
                            'sample_id': len(st.session_state.live_data) + i
                        }
                        st.session_state.live_data.append(combined_sample)
                    
                    # Keep only last 100 samples
                    if len(st.session_state.live_data) > 100:
                        st.session_state.live_data = st.session_state.live_data[-100:]
                    
                    # Create DataFrame for analysis
                    df = pd.DataFrame(st.session_state.live_data)
                    current_batch_df = pd.DataFrame(predictions)
                    
                    # Display live metrics
                    st.subheader("📊 Live Stream Metrics")
                    
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.metric("Total Samples", len(df))
                    
                    with col2:
                        current_anomalies = current_batch_df['anomaly'].sum()
                        st.metric("Current Batch Anomalies", current_anomalies)
                    
                    with col3:
                        above_threshold = len(current_batch_df[current_batch_df['anomaly_score'] >= thresh])
                        st.metric("Above Threshold", above_threshold)
                    
                    with col4:
                        if len(current_batch_df) > 0:
                            max_score = current_batch_df['anomaly_score'].max()
                            st.metric("Max Score in Batch", f"{max_score:.3f}")
                    
                    # Alert system
                    if alerts_enabled and above_threshold > 0:
                        st.error(f"🚨 ALERT: {above_threshold} samples above threshold {thresh}!")
                        
                        high_risk_samples = current_batch_df[current_batch_df['anomaly_score'] >= thresh]
                        for idx, sample in high_risk_samples.iterrows():
                            risk_level = "CRITICAL" if sample['anomaly_score'] >= 0.9 else "HIGH" if sample['anomaly_score'] >= 0.7 else "MEDIUM"
                            st.markdown(
                                f"""
                                <div style="padding: 10px; margin: 5px 0; border-left: 4px solid {selected_color}; background-color: #fff2f2;">
                                    <strong>🔥 {risk_level} RISK</strong> - Score: {sample['anomaly_score']:.4f} | 
                                    Anomaly: {'YES' if sample['anomaly'] == 1 else 'NO'}
                                </div>
                                """, 
                                unsafe_allow_html=True
                            )
                    
                    # Live visualization
                    st.subheader("📈 Live Traffic Analysis")
                    
                    if len(df) > 1:
                        # Real-time score chart
                        fig = go.Figure()
                        
                        # Plot all scores
                        fig.add_trace(go.Scatter(
                            x=list(range(len(df))),
                            y=df['anomaly_score'],
                            mode='lines+markers',
                            name='Anomaly Score',
                            line=dict(color='blue', width=2),
                            marker=dict(size=4)
                        ))
                        
                        # Highlight current batch
                        if len(df) >= batch_size:
                            current_batch_x = list(range(len(df) - batch_size, len(df)))
                            current_batch_y = df['anomaly_score'].tail(batch_size)
                            
                            fig.add_trace(go.Scatter(
                                x=current_batch_x,
                                y=current_batch_y,
                                mode='markers',
                                name='Current Batch',
                                marker=dict(color='orange', size=8, symbol='diamond')
                            ))
                        
                        # Highlight anomalies
                        anomaly_mask = df['anomaly'] == 1
                        if anomaly_mask.any():
                            anomaly_indices = df.index[anomaly_mask]
                            fig.add_trace(go.Scatter(
                                x=anomaly_indices,
                                y=df.loc[anomaly_indices, 'anomaly_score'],
                                mode='markers',
                                name='Detected Anomalies',
                                marker=dict(color='red', size=10, symbol='x')
                            ))
                        
                        # Add threshold line
                        fig.add_hline(y=thresh, line_dash="dash", line_color="red",
                                     annotation_text=f"Threshold: {thresh}")
                        
                        fig.update_layout(
                            title="Live Anomaly Score Stream",
                            xaxis_title="Sample Number",
                            yaxis_title="Anomaly Score",
                            hovermode='x unified',
                            height=400
                        )
                        
                        st.plotly_chart(fig, use_container_width=True)
                        
                        # Current batch details
                        st.subheader("🔍 Current Batch Analysis")
                        
                        batch_traffic_df = pd.DataFrame(traffic_batch)
                        combined_current = pd.concat([batch_traffic_df, current_batch_df], axis=1)
                        
                        # Show samples above threshold
                        high_score_current = combined_current[combined_current['anomaly_score'] >= thresh]
                        
                        if not high_score_current.empty:
                            st.write(f"*Samples above threshold ({thresh}):*")
                            display_cols = ['inter_arrival_time', 'packet_length', 'protocol', 'anomaly_score', 'anomaly']
                            st.dataframe(
                                high_score_current[display_cols],
                                use_container_width=True
                            )
                        else:
                            st.info(f"No samples above threshold {thresh} in current batch.")
                    
                else:
                    st.error(f"API Error: {response.status_code}")
                    
            except Exception as e:
                st.error(f"Error in live analysis: {str(e)}")
    
    # Auto-refresh functionality
    if auto_refresh and st.session_state.stream_active:
        time.sleep(refresh_interval)
        st.rerun()


# tabs/manual_entry.py
import streamlit as st
import requests
import json

def render():
    st.header("✏ Manual Traffic Entry & Analysis")
    
    API_URL = "https://mizzony-dos-anomaly-detection.hf.space"
    
    st.write("Enter network traffic parameters manually for anomaly detection analysis.")
    
    # Manual entry form
    st.subheader("📝 Traffic Parameters")
    
    col1, col2 = st.columns(2)
    
    with col1:
        inter_arrival_time = st.number_input(
            "Inter-arrival Time (seconds)", 
            min_value=0.001, 
            max_value=10.0, 
            value=0.1, 
            step=0.001,
            format="%.3f",
            help="Time between consecutive packets. Lower values may indicate DOS attacks."
        )
        
        packet_length = st.number_input(
            "Packet Length (bytes)", 
            min_value=64, 
            max_value=1500, 
            value=1000,
            help="Size of the network packet. Large packets with fast arrival may be suspicious."
        )
    
    with col2:
        protocol = st.selectbox(
            "Protocol", 
            ["tcp", "udp", "http", "https", "dns", "icmp"],
            help="Network protocol used"
        )
        
        # Preset patterns
        st.subheader("🎯 Quick Presets")
        
        preset = st.selectbox(
            "Load Preset Pattern",
            ["Custom", "Normal Web Traffic", "Potential DOS Attack", "Large File Transfer", "DNS Query", "Video Streaming"]
        )
        
        if preset != "Custom":
            if st.button("Load Preset"):
                if preset == "Normal Web Traffic":
                    st.session_state.manual_inter_arrival = 0.1
                    st.session_state.manual_packet_length = 800
                    st.session_state.manual_protocol = "http"
                elif preset == "Potential DOS Attack":
                    st.session_state.manual_inter_arrival = 0.005
                    st.session_state.manual_packet_length = 1450
                    st.session_state.manual_protocol = "tcp"
                elif preset == "Large File Transfer":
                    st.session_state.manual_inter_arrival = 0.02
                    st.session_state.manual_packet_length = 1500
                    st.session_state.manual_protocol = "tcp"
                elif preset == "DNS Query":
                    st.session_state.manual_inter_arrival = 0.5
                    st.session_state.manual_packet_length = 128
                    st.session_state.manual_protocol = "dns"
                elif preset == "Video Streaming":
                    st.session_state.manual_inter_arrival = 0.03
                    st.session_state.manual_packet_length = 1200
                    st.session_state.manual_protocol = "udp"
                st.rerun()
    
    # Use session state values if available
    if 'manual_inter_arrival' in st.session_state:
        inter_arrival_time = st.session_state.manual_inter_arrival
    if 'manual_packet_length' in st.session_state:
        packet_length = st.session_state.manual_packet_length
    if 'manual_protocol' in st.session_state:
        protocol = st.session_state.manual_protocol
    
    # Batch entry option
    st.subheader("📊 Batch Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        num_samples = st.slider("Number of identical samples to analyze", 1, 20, 5)
    
    with col2:
        add_variation = st.checkbox("Add slight variation to samples", value=True)
    
    # Analysis buttons
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🔍 Analyze Single Sample", type="primary"):
            analyze_manual_traffic(API_URL, inter_arrival_time, packet_length, protocol, 1, False)
    
    with col2:
        if st.button("📈 Analyze Batch"):
            analyze_manual_traffic(API_URL, inter_arrival_time, packet_length, protocol, num_samples, add_variation)
    
    # JSON input option
    st.subheader("📄 JSON Input")
    
    json_input = st.text_area(
        "Enter JSON traffic data directly:",
        value='[{"inter_arrival_time": 0.1, "packet_length": 1000, "protocol": "tcp"}]',
        height=100,
        help="Enter an array of traffic samples in JSON format"
    )
    
    if st.button("🔍 Analyze JSON Input"):
        try:
            traffic_data = json.loads(json_input)
            if isinstance(traffic_data, list):
                analyze_json_traffic(API_URL, traffic_data)
            else:
                st.error("JSON input must be an array of traffic samples")
        except json.JSONDecodeError as e:
            st.error(f"Invalid JSON format: {str(e)}")

def analyze_manual_traffic(api_url, inter_arrival, packet_len, protocol, num_samples, add_variation):
    """Analyze manually entered traffic data"""
    
    traffic_data = []
    
    for i in range(num_samples):
        if add_variation and num_samples > 1:
            # Add ±10% variation
            varied_inter_arrival = inter_arrival * (0.9 + 0.2 * (i / num_samples))
            varied_packet_len = int(packet_len * (0.9 + 0.2 * (i / num_samples)))
        else:
            varied_inter_arrival = inter_arrival
            varied_packet_len = packet_len
        
        traffic_data.append({
            "inter_arrival_time": round(varied_inter_arrival, 4),
            "packet_length": varied_packet_len,
            "protocol": protocol
        })
    
    analyze_json_traffic(api_url, traffic_data)

def analyze_json_traffic(api_url, traffic_data):
    """Analyze traffic data and display results"""
    
    with st.spinner(f"Analyzing {len(traffic_data)} traffic sample(s)..."):
        try:
            response = requests.post(
                f"{api_url}/predict",
                headers={"Content-Type": "application/json"},
                json=traffic_data,
                timeout=15
            )
            
            if response.status_code == 200:
                predictions = response.json()
                
                # Display results
                st.success(f"✅ Analysis complete! Processed {len(predictions)} samples.")
                
                # Create results DataFrame
                import pandas as pd
                traffic_df = pd.DataFrame(traffic_data)
                predictions_df = pd.DataFrame(predictions)
                combined_df = pd.concat([traffic_df, predictions_df], axis=1)
                
                # Summary metrics
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Samples Analyzed", len(combined_df))
                
                with col2:
                    anomaly_count = predictions_df['anomaly'].sum()
                    st.metric("Anomalies Detected", anomaly_count)
                
                with col3:
                    avg_score = predictions_df['anomaly_score'].mean()
                    st.metric("Average Score", f"{avg_score:.3f}")
                
                with col4:
                    max_score = predictions_df['anomaly_score'].max()
                    st.metric("Max Score", f"{max_score:.3f}")
                
                # Results interpretation
                st.subheader("🎯 Analysis Results")
                
                max_score_val = predictions_df['anomaly_score'].max()
                
                if max_score_val >= 0.8:
                    st.error("🚨 HIGH RISK: Strong indicators of DOS attack patterns detected!")
                elif max_score_val >= 0.6:
                    st.warning("⚠ MEDIUM RISK: Suspicious traffic patterns detected.")
                elif max_score_val >= 0.3:
                    st.info("ℹ LOW RISK: Some unusual patterns but likely normal traffic.")
                else:
                    st.success("✅ NORMAL: Traffic patterns appear normal.")
                
                # Detailed results table
                st.subheader("📋 Detailed Results")
                
                # Format the results for better display
                display_df = combined_df.copy()
                display_df['Risk Level'] = display_df['anomaly_score'].apply(
                    lambda x: 'CRITICAL' if x >= 0.9 else 'HIGH' if x >= 0.8 else 'MEDIUM' if x >= 0.6 else 'LOW'
                )
                display_df['Is Anomaly'] = display_df['anomaly'].apply(lambda x: 'YES' if x == 1 else 'NO')
                
                # Rename columns for better display
                display_df = display_df.rename(columns={
                    'inter_arrival_time': 'Inter-arrival Time (s)',
                    'packet_length': 'Packet Length (bytes)',
                    'protocol': 'Protocol',
                    'anomaly_score': 'Anomaly Score'
                })
                
                st.dataframe(
                    display_df[['Inter-arrival Time (s)', 'Packet Length (bytes)', 'Protocol', 'Anomaly Score', 'Is Anomaly', 'Risk Level']],
                    use_container
