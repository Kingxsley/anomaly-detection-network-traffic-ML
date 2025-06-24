import streamlit as st
from tabs import overview, live_stream, manual_entry, metrics, historical

# Use a selectbox or radio button to choose between DNS and DOS dashboards
dashboard_type = st.selectbox("Select Dashboard Type", ["DNS", "DOS"])

# Set the selected dashboard type in Streamlit's secrets
st.secrets["DASHBOARD_TYPE"] = dashboard_type

# Display the selected dashboard
if dashboard_type == "DNS":
    st.title("DNS Anomaly Detection Dashboard")
else:
    st.title("DOS Anomaly Detection Dashboard")

# Add tabs for each section (Overview, Live Stream, Manual Entry, Metrics, Historical)
tabs = ["Overview", "Live Stream", "Manual Entry", "Metrics", "Historical"]
selected_tab = st.selectbox("Select a Tab", tabs)

# Rendering the corresponding tab content
if selected_tab == "Overview":
    overview.render(time_range="-24h", time_range_query_map={})
elif selected_tab == "Live Stream":
    live_stream.render(thresh=0.5, highlight_color="yellow", alerts_enabled=True)
elif selected_tab == "Manual Entry":
    manual_entry.render()
elif selected_tab == "Metrics":
    metrics.render(thresh=0.5)
elif selected_tab == "Historical":
    historical.render(thresh=0.5, highlight_color="yellow")
