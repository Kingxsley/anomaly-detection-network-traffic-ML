import streamlit as st
import pandas as pd
from utils import get_historical_data

def render(thresh, highlight_color):
    st.title("Historical Data")

    # Fetch historical data based on DNS or DOS
    if st.session_state.DASHBOARD_TYPE == "DNS":
        df = get_historical_data("DNS")
    else:  # DOS
        df = get_historical_data("DOS")

    # Display historical data and visualizations
    if not df.empty:
        st.write(df)
    else:
        st.warning("No historical data available.")
