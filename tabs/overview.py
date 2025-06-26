import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh
from tabs.utils import load_predictions_from_sqlitecloud

def render(time_range, time_range_query_map):
    st_autorefresh(interval=30000, key="overview_refresh")
    st.title("DoS Anomaly Detection Overview")
    
    query_duration = time_range_query_map.get(time_range, "-24h")
    df = load_predictions_from_sqlitecloud(time_window=query_duration)
    
    if not df.empty:
        # Debug info - remove in production
        st.write(f"Debug: DataFrame shape: {df.shape}")
        st.write(f"Debug: Columns: {list(df.columns)}")
        st.write(f"Debug: is_anomaly values: {df['is_anomaly'].value_counts().to_dict()}")
        
        total_predictions = len(df)
        attack_rate = df["is_anomaly"].mean()
        avg_score = df["anomaly_score"].mean()
        max_score = df["anomaly_score"].max()
        min_score = df["anomaly_score"].min()
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Predictions", total_predictions)
        col2.metric("Attack Rate", f"{attack_rate:.2%}")
        col3.metric("Total Attacks", df[df["is_anomaly"] == 1].shape[0])
        
        st.markdown("### Anomaly Score Summary")
        summary_cols = st.columns(3)
        summary_cols[0].metric("Average Anomaly Score", f"{avg_score:.4f}")
        summary_cols[1].metric("Max Anomaly Score", f"{max_score:.4f}")
        summary_cols[2].metric("Min Anomaly Score", f"{min_score:.4f}")
        
        st.markdown("### Times with Most Attacks")
        attack_df = df[df["is_anomaly"] == 1].copy()
        
        if not attack_df.empty:
            attack_df["time"] = pd.to_datetime(attack_df["timestamp"]).dt.strftime('%Y-%m-%d %H:00')
            top_times = attack_df["time"].value_counts().nlargest(5).reset_index()
            top_times.columns = ["Time (Hour Block)", "Attack Count"]
            st.dataframe(top_times.style.format(), use_container_width=True)
        else:
            st.info("No attacks detected in the selected time range.")
        
        # Top Source IPs
        st.markdown("### Top Source IPs")
        if not attack_df.empty and 'source_ip' in attack_df.columns:
            ip_counts = attack_df["source_ip"].value_counts().nlargest(10).reset_index()
            ip_counts.columns = ["source_ip", "count"]
            
            if not ip_counts.empty:
                fig_ip = px.bar(
                    ip_counts,
                    x="source_ip",
                    y="count",
                    labels={"source_ip": "Source IP", "count": "Anomaly Count"},
                    title="Top Source IPs with Anomalies",
                    text_auto=True
                )
                fig_ip.update_layout(xaxis_tickangle=-45)
                st.plotly_chart(fig_ip, use_container_width=True)
            else:
                st.info("No source IP data available for anomalies.")
        else:
            st.info("No source IP data available - either no attacks or missing source_ip column.")
        
        # Top Destination IPs
        st.markdown("### Top Destination IPs")
        if not attack_df.empty and 'dest_ip' in attack_df.columns:
            dest_counts = attack_df["dest_ip"].value_counts().nlargest(10).reset_index()
            dest_counts.columns = ["dest_ip", "count"]
            
            if not dest_counts.empty:
                fig_dest = px.bar(
                    dest_counts,
                    x="dest_ip",
                    y="count",
                    labels={"dest_ip": "Destination IP", "count": "Anomaly Count"},
                    title="Top Destination IPs with Anomalies",
                    text_auto=True
                )
                fig_dest.update_layout(xaxis_tickangle=-45)
                st.plotly_chart(fig_dest, use_container_width=True)
            else:
                st.info("No destination IP data available for anomalies.")
        else:
            st.info("No destination IP data available - either no attacks or missing dest_ip column.")
        
        # Anomaly Score Over Time
        st.markdown("### Anomaly Score Over Time")
        if 'timestamp' in df.columns and 'anomaly_score' in df.columns:
            # Ensure timestamp is datetime
            df['timestamp_parsed'] = pd.to_datetime(df['timestamp'])
            
            # Create color mapping for anomalies
            df['anomaly_type'] = df["is_anomaly"].map({1: "Attack", 0: "Normal"}).astype(str)
            
            fig_time = px.line(
                df,
                x="timestamp_parsed",
                y="anomaly_score",
                color="anomaly_type",
                labels={
                    "timestamp_parsed": "Timestamp", 
                    "anomaly_score": "Anomaly Score",
                    "anomaly_type": "Type"
                },
                title="Anomaly Score Over Time"
            )
            fig_time.update_layout(
                xaxis_title="Time",
                yaxis_title="Anomaly Score"
            )
            st.plotly_chart(fig_time, use_container_width=True)
        else:
            st.info("Missing timestamp or anomaly_score columns for time series plot.")
        
        # Recent Attack Details
        st.markdown("### Recent Attack Details")
        if not attack_df.empty:
            recent_attacks = attack_df.sort_values("timestamp", ascending=False).head(10)
            display_columns = []
            
            # Check which columns exist before displaying
            for col in ["timestamp", "source_ip", "dest_ip", "anomaly_score"]:
                if col in recent_attacks.columns:
                    display_columns.append(col)
            
            if display_columns:
                st.dataframe(recent_attacks[display_columns], use_container_width=True)
            else:
                st.info("No attack detail columns available to display.")
        else:
            st.info("No recent attacks to display.")
            
    else:
        st.info("No predictions available in the selected time range.")
        
        # Debug: Show what the API is returning
        st.markdown("### Debug Information")
        st.write("API Response Debug:")
        try:
            # You might want to add a test API call here to see what's being returned
            st.write(f"Time range: {time_range}")
            st.write(f"Query duration: {query_duration}")
        except Exception as e:
            st.error(f"Debug error: {str(e)}")
