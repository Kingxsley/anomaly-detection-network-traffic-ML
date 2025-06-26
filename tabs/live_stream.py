import streamlit as st
import pandas as pd
import requests
from streamlit_autorefresh import st_autorefresh
from tabs.utils import get_dos_data, send_discord_alert, log_to_sqlitecloud
import time
from datetime import datetime

API_URL = "https://mizzony-dos-anomaly-detection.hf.space/predict"

def render(thresh, highlight_color, alerts_enabled):
    # Add debug mode toggle
    debug_mode = st.sidebar.checkbox("🐛 Debug Mode", value=False)
    
    st_autorefresh(interval=60000, key="live_refresh")  # Refresh every 60s
    st.title("🚨 Live DoS Stream Dashboard")
    
    # Add refresh timestamp
    if debug_mode:
        st.info(f"🕒 Last refresh: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Initialize state
    if "predictions" not in st.session_state:
        st.session_state.predictions = []
    if "attacks" not in st.session_state:
        st.session_state.attacks = []
    if "debug_logs" not in st.session_state:
        st.session_state.debug_logs = []
    
    # Add debug function
    def debug_log(message):
        if debug_mode:
            timestamp = datetime.now().strftime('%H:%M:%S')
            st.session_state.debug_logs.append(f"[{timestamp}] {message}")
            # Keep only last 50 debug messages
            st.session_state.debug_logs = st.session_state.debug_logs[-50:]
    
    debug_log("Starting data fetch...")
    
    # Get data with error handling
    try:
        records = get_dos_data()
        debug_log(f"Fetched {len(records) if records else 0} records")
        
        if debug_mode and records:
            st.sidebar.write(f"📊 Raw records count: {len(records)}")
            with st.sidebar.expander("Sample Raw Data"):
                st.json(records[:2] if len(records) >= 2 else records)
    except Exception as e:
        debug_log(f"Error fetching data: {str(e)}")
        st.error(f"❌ Error fetching data: {str(e)}")
        records = []
    
    new_predictions = []
    
    if records:
        debug_log(f"Processing {len(records)} records...")
        
        for i, row in enumerate(records):
            debug_log(f"Processing record {i+1}/{len(records)}")
            
            # Validate required fields
            required_fields = ["inter_arrival_time", "packet_length"]
            missing_fields = [field for field in required_fields if field not in row or row[field] is None]
            
            if missing_fields:
                debug_log(f"Skipping record {i+1} - missing fields: {missing_fields}")
                continue
            
            # Determine protocol based on destination port if not provided
            protocol = "tcp"  # default
            if "protocol" in row and row["protocol"]:
                protocol = str(row["protocol"]).lower()
            elif "dest_port" in row:
                # Common protocol inference based on port
                dest_port = int(row["dest_port"])
                if dest_port == 53:
                    protocol = "udp"  # DNS
                elif dest_port in [80, 443, 8080, 8443]:
                    protocol = "tcp"  # HTTP/HTTPS
                elif dest_port in [21, 22, 23, 25, 110, 143, 993, 995]:
                    protocol = "tcp"  # Common TCP services
                else:
                    protocol = "tcp"  # Default to TCP
            
            debug_log(f"Using protocol: {protocol} for dest_port: {row.get('dest_port', 'unknown')}")
            
            payload = [{
                "inter_arrival_time": float(row["inter_arrival_time"]),
                "packet_length": float(row["packet_length"]),
                "protocol": protocol
            }]
            
            debug_log(f"Sending payload: {payload}")
            
            try:
                start_time = time.time()
                response = requests.post(API_URL, json=payload, timeout=20)
                api_time = time.time() - start_time
                
                debug_log(f"API response time: {api_time:.2f}s")
                debug_log(f"API status: {response.status_code}")
                
                if response.status_code == 200 and response.text.strip():
                    try:
                        result_list = response.json()
                        debug_log(f"API response: {result_list}")
                        
                        if isinstance(result_list, list) and result_list:
                            result = result_list[0]
                            result.update(row)
                            result["anomaly"] = int(result.get("anomaly", 0))
                            result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
                            result["api_response_time"] = api_time
                            
                            # Add timestamp if not present
                            if "timestamp" not in result:
                                result["timestamp"] = datetime.now().isoformat()
                            
                            new_predictions.append(result)
                            
                            debug_log(f"Prediction: {result['label']} (anomaly={result['anomaly']})")
                            
                            # Send alert for attacks
                            if result["anomaly"] == 1 and alerts_enabled:
                                debug_log("🚨 ATTACK DETECTED - Sending alert")
                                try:
                                    send_discord_alert(result)
                                    debug_log("✅ Discord alert sent")
                                except Exception as alert_error:
                                    debug_log(f"❌ Alert failed: {alert_error}")
                        else:
                            debug_log(f"Invalid response format: {result_list}")
                    except ValueError as json_error:
                        debug_log(f"JSON decode failed: {json_error}")
                        st.warning(f"❌ JSON decode failed for record {i+1}:\n{response.text}")
                else:
                    debug_log(f"API error - Status: {response.status_code}, Response: {response.text}")
                    st.warning(f"⚠ API error {response.status_code} for record {i+1}: {response.text}")
                    
            except requests.exceptions.Timeout:
                debug_log(f"API timeout for record {i+1}")
                st.warning(f"⏰ API timeout for record {i+1}")
            except Exception as e:
                debug_log(f"API request failed for record {i+1}: {str(e)}")
                st.warning(f"🔥 API request failed for record {i+1}: {e}")
        
        # Update session state
        if new_predictions:
            debug_log(f"Adding {len(new_predictions)} new predictions")
            
            # Count new attacks
            new_attacks = [r for r in new_predictions if r["anomaly"] == 1]
            debug_log(f"New attacks detected: {len(new_attacks)}")
            
            st.session_state.predictions.extend(new_predictions)
            st.session_state.attacks.extend(new_attacks)
            
            # Log to database
            for r in new_predictions:
                try:
                    log_to_sqlitecloud(r)
                except Exception as log_error:
                    debug_log(f"Database logging failed: {log_error}")
            
            # Keep recent 1000 entries
            st.session_state.predictions = st.session_state.predictions[-1000:]
            st.session_state.attacks = st.session_state.attacks[-1000:]
            
            debug_log(f"Total predictions in state: {len(st.session_state.predictions)}")
            debug_log(f"Total attacks in state: {len(st.session_state.attacks)}")
        else:
            debug_log("No new predictions generated")
    else:
        debug_log("No records to process")
    
    # Display debug logs
    if debug_mode and st.session_state.debug_logs:
        with st.sidebar.expander("🐛 Debug Logs", expanded=False):
            for log in st.session_state.debug_logs[-20:]:  # Show last 20 logs
                st.text(log)
    
    # Show attack statistics
    total_attacks = len(st.session_state.attacks)
    total_predictions = len(st.session_state.predictions)
    
    # Create metrics display
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("🛡 Total Attacks", total_attacks)
    with col2:
        st.metric("📊 Total Predictions", total_predictions)
    with col3:
        if total_predictions > 0:
            attack_rate = (total_attacks / total_predictions) * 100
            st.metric("⚠ Attack Rate", f"{attack_rate:.1f}%")
        else:
            st.metric("⚠ Attack Rate", "0%")
    
    # Show recent attack details
    if total_attacks > 0:
        last_attack = st.session_state.attacks[-1]
        with st.expander("🟥 Most Recent Attack Details", expanded=True):
            st.json(last_attack)
        
        # Show recent attacks summary
        if len(st.session_state.attacks) > 1:
            recent_attacks = st.session_state.attacks[-5:]  # Last 5 attacks
            st.subheader("🕐 Recent Attacks")
            attacks_df = pd.DataFrame(recent_attacks)
            if "timestamp" in attacks_df.columns:
                attacks_df["timestamp"] = pd.to_datetime(attacks_df["timestamp"])
                attacks_df = attacks_df.sort_values("timestamp", ascending=False)
            st.dataframe(attacks_df[["timestamp", "label", "inter_arrival_time", "packet_length", "protocol"]])
    
    # Show full prediction table with highlights
    df = pd.DataFrame(st.session_state.predictions)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp", ascending=False)  # Most recent first
        
        # Pagination
        rows_per_page = 100
        total_pages = (len(df) - 1) // rows_per_page + 1
        
        if total_pages > 1:
            page_number = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1, key="live_page") - 1
        else:
            page_number = 0
            
        paged_df = df.iloc[page_number * rows_per_page:(page_number + 1) * rows_per_page]
        
        # Highlighting function
        def highlight(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)
        
        st.subheader(f"📋 Prediction History (Page {page_number + 1}/{total_pages})")
        st.dataframe(paged_df.style.apply(highlight, axis=1), key="live_table")
        
        # Show summary statistics
        if debug_mode:
            st.subheader("📈 Data Statistics")
            col1, col2 = st.columns(2)
            with col1:
                st.write("*Anomaly Distribution:*")
                st.write(df["label"].value_counts())
            with col2:
                st.write("*Protocol Distribution:*")
                if "protocol" in df.columns:
                    st.write(df["protocol"].value_counts())
    else:
        st.info("ℹ Waiting for predictions...")
        
    # Add manual test button
    if debug_mode:
        st.sidebar.subheader("🧪 Manual Test")
        if st.sidebar.button("Test Single Prediction"):
            test_payload = [{
                "inter_arrival_time": 0.001,
                "packet_length": 1500,
                "protocol": "tcp"
            }]
            try:
                response = requests.post(API_URL, json=test_payload, timeout=10)
                st.sidebar.write(f"Status: {response.status_code}")
                st.sidebar.json(response.json())
            except Exception as e:
                st.sidebar.error(f"Test failed: {e}")
