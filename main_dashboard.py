import streamlit as st
from tabs import overview, live_stream, manual_entry, metrics, historical

# Sidebar for selecting the dashboard type (DNS or DOS)
dashboard_type = st.sidebar.radio("Select Dashboard Type", ["DNS", "DOS"], index=0)

# Sidebar for settings and configurations
st.sidebar.header("Settings")

# Time Range Selection
time_range = st.sidebar.selectbox("Select Time Range", ["-24h", "-48h", "-7d", "-30d"], index=0)

# Toggle for enabling/disabling alerts
alerts_enabled = st.sidebar.checkbox("Enable Alerts", value=True)

# Add any additional settings (e.g., threshold, highlight color, etc.)
threshold = st.sidebar.slider("Anomaly Detection Threshold", 0.0, 1.0, 0.5, 0.01)
highlight_color = st.sidebar.color_picker("Highlight Color", value="#FFFF00")

# Set the selected dashboard type in session state (for toggling)
if "DASHBOARD_TYPE" not in st.session_state:
    st.session_state.DASHBOARD_TYPE = "DNS"  # Default to DNS if not set

# Set the dashboard type to session state based on the selection
st.session_state.DASHBOARD_TYPE = dashboard_type

# Display the selected dashboard in the main content area
if st.session_state.DASHBOARD_TYPE == "DNS":
    st.title("DNS Anomaly Detection Dashboard")
else:
    st.title("DOS Anomaly Detection Dashboard")

# Add tabs for each section (Overview, Live Stream, Manual Entry, Metrics, Historical)
tabs = ["Overview", "Live Stream", "Manual Entry", "Metrics", "Historical"]
selected_tab = st.sidebar.selectbox("Select a Tab", tabs)

# Render the selected tab content
if selected_tab == "Overview":
    overview.render(time_range, {"-24h": "-24h", "-48h": "-48h", "-7d": "-7d", "-30d": "-30d"})
elif selected_tab == "Live Stream":
    live_stream.render(thresh=threshold, highlight_color=highlight_color, alerts_enabled=alerts_enabled)
elif selected_tab == "Manual Entry":
    manual_entry.render()
elif selected_tab == "Metrics":
    metrics.render(thresh=threshold)
elif selected_tab == "Historical":
    historical.render(thresh=threshold, highlight_color=highlight_color)
