import streamlit as st
from streamlit_autorefresh import st_autorefresh  # Import missing function
from tabs.dos.utils import load_predictions_from_sqlitecloud

def render_overview(api_url, influx_measurement, time_range, time_range_query_map):
    st_autorefresh(interval=30000, key="overview_refresh")  # Refresh every 30 seconds
    st.title("DOS Anomaly Detection Overview")
    
    # Adjusting the query duration based on the selected time range
    query_duration = time_range_query_map.get(time_range, "-24h")
    df = load_predictions_from_sqlitecloud(time_window=query_duration)  # Pass the adjusted query duration
    
    if not df.empty:
        total_predictions = len(df)
        attack_rate = df["is_anomaly"].mean()
        avg_error = df["anomaly_score"].mean()
        max_error = df["anomaly_score"].max()
        min_error = df["anomaly_score"].min()

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Predictions", total_predictions)
        col2.metric("Attack Rate", f"{attack_rate:.2%}")
        col3.metric("Total Attacks", df[df["is_anomaly"] == 1].shape[0])

        st.markdown("### Attack Summary")
        summary_cols = st.columns(3)
        summary_cols[0].metric("Average Reconstruction Error", f"{avg_error:.4f}")
        summary_cols[1].metric("Max Reconstruction Error", f"{max_error:.4f}")
        summary_cols[2].metric("Min Reconstruction Error", f"{min_error:.4f}")

        st.markdown("### Times with Most Attacks")
        attack_df = df[df["is_anomaly"] == 1].copy()
        attack_df["time"] = pd.to_datetime(attack_df["timestamp"]).dt.strftime('%Y-%m-%d %H:00')
        top_times = attack_df["time"].value_counts().nlargest(5).reset_index()
        top_times.columns = ["Time (Hour Block)", "Attack Count"]
        st.dataframe(top_times.style.format(), use_container_width=True)

        st.markdown("### Top Source IPs")
        ip_counts = df[df["is_anomaly"] == 1]["source_ip"].value_counts().nlargest(10).reset_index()
        ip_counts.columns = ["source_ip", "count"]
        fig_ip = px.bar(
            ip_counts,
            x="source_ip",
            y="count",
            labels={"source_ip": "Source IP", "count": "Anomaly Count"},
            text_auto=True
        )
        st.plotly_chart(fig_ip, use_container_width=True)

        st.markdown("### Top Destination IPs")
        dest_counts = df[df["is_anomaly"] == 1]["dest_ip"].value_counts().nlargest(10).reset_index()
        dest_counts.columns = ["dest_ip", "count"]
        fig_dest = px.bar(
            dest_counts,
            x="dest_ip",
            y="count",
            labels={"dest_ip": "Destination IP", "count": "Anomaly Count"},
            text_auto=True
        )
        st.plotly_chart(fig_dest, use_container_width=True)

        st.markdown("### Anomaly Score Over Time")
        fig = px.line(
            df,
            x="timestamp",
            y="anomaly_score",
            color=df["is_anomaly"].map({1: "Attack", 0: "Normal"}).astype(str),
            labels={"color": "Anomaly Type"},
            title="Anomaly Score Over Time"
        )
        st.plotly_chart(fig, use_container_width=True)

        st.markdown("### Recent Attack Details")
        recent_attacks = df[df["is_anomaly"] == 1].sort_values("timestamp", ascending=False).head(10)
        st.dataframe(recent_attacks[["timestamp", "source_ip", "dest_ip", "anomaly_score"]], use_container_width=True)
    else:
        st.info("No predictions available in the selected time range.")
