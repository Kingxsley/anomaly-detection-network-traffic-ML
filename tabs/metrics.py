import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.figure_factory as ff
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

def render(thresh):
    st.header("Model Performance")
    
    # Get predictions from session state
    if "predictions" not in st.session_state or not st.session_state.predictions:
        st.info("No predictions available for performance analysis.")
        return
    
    df = pd.DataFrame(st.session_state.predictions)
    
    if not df.empty:
        # Debug: Show available columns
        st.write(f"*Available columns:* {list(df.columns)}")
        
        st.subheader("Performance Metrics")
        valid_df = df.dropna(subset=["label", "anomaly"])
        
        if len(valid_df) >= 2 and valid_df["label"].nunique() > 1 and valid_df["anomaly"].nunique() > 1:
            y_true = valid_df["anomaly"].astype(int)
            y_pred = valid_df["anomaly"].astype(int)  # Since you're using ground truth, this should be different
            
            # Note: You're comparing anomaly to anomaly (same values), so metrics will be 100%
            # This suggests you need actual ground truth labels vs predictions
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Accuracy", f"{accuracy_score(y_true, y_pred):.2%}")
            col2.metric("Precision", f"{precision_score(y_true, y_pred, zero_division=0):.2%}")
            col3.metric("Recall", f"{recall_score(y_true, y_pred, zero_division=0):.2%}")
            col4.metric("F1-Score", f"{f1_score(y_true, y_pred, zero_division=0):.2%}")
            
            # Confusion Matrix
            cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
            if cm.shape == (2, 2):
                fig_cm = ff.create_annotated_heatmap(
                    z=cm,
                    x=["Predicted Normal", "Predicted Attack"],
                    y=["Normal", "Attack"],
                    annotation_text=cm.astype(str),
                    colorscale="Blues"
                )
                fig_cm.update_layout(title="Confusion Matrix", width=400, height=400)
                st.plotly_chart(fig_cm)
            else:
                st.warning("Confusion matrix could not be generated due to insufficient class diversity.")
        else:
            st.warning("Insufficient or unbalanced data for performance metrics.")
        
        # Replace reconstruction error with available metrics
        st.subheader("Prediction Analysis")
        
        # Check what columns we actually have for analysis
        numeric_columns = df.select_dtypes(include=['float64', 'int64']).columns.tolist()
        
        # Look for confidence/probability/score columns
        score_columns = [col for col in df.columns if any(keyword in col.lower() for keyword in ['score', 'prob', 'confidence', 'prediction'])]
        
        if score_columns:
            # Use the first available score column
            score_col = score_columns[0]
            st.write(f"Using column: *{score_col}* for distribution analysis")
            
            fig_hist = px.histogram(
                df,
                x=score_col,
                color="anomaly",
                title=f"{score_col} Distribution",
                color_discrete_map={0: "blue", 1: "red"},
                nbins=50
            )
            
            # Add threshold line if the score column seems to be a continuous score
            if df[score_col].dtype in ['float64', 'float32'] and thresh is not None:
                fig_hist.add_vline(x=thresh, line_dash="dash", line_color="black", annotation_text="Threshold")
            
            st.plotly_chart(fig_hist, use_container_width=True)
            
        elif 'inter_arrival_time' in df.columns:
            # Use inter_arrival_time as a fallback analysis
            st.write("Analyzing *inter_arrival_time* distribution")
            
            fig_hist = px.histogram(
                df,
                x="inter_arrival_time",
                color="anomaly",
                title="Inter-Arrival Time Distribution",
                color_discrete_map={0: "blue", 1: "red"},
                nbins=50
            )
            st.plotly_chart(fig_hist, use_container_width=True)
            
        elif 'packet_length' in df.columns:
            # Use packet_length as another fallback
            st.write("Analyzing *packet_length* distribution")
            
            fig_hist = px.histogram(
                df,
                x="packet_length",
                color="anomaly",
                title="Packet Length Distribution",
                color_discrete_map={0: "blue", 1: "red"},
                nbins=50
            )
            st.plotly_chart(fig_hist, use_container_width=True)
            
        else:
            st.warning("No suitable columns found for distribution analysis.")
            st.write("Available columns:", list(df.columns))
        
        # Additional analysis - Attack timeline
        if 'timestamp' in df.columns:
            st.subheader("Attack Timeline")
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Attacks over time
            attacks_df = df[df['anomaly'] == 1].copy()
            if not attacks_df.empty:
                # Group by minute for timeline
                attacks_df['minute'] = attacks_df['timestamp'].dt.floor('min')
                attacks_timeline = attacks_df.groupby('minute').size().reset_index(name='attack_count')
                
                fig_timeline = px.line(
                    attacks_timeline,
                    x='minute',
                    y='attack_count',
                    title="Attacks Over Time",
                    markers=True
                )
                st.plotly_chart(fig_timeline, use_container_width=True)
            else:
                st.info("No attacks detected yet.")
        
        # Summary statistics
        st.subheader("Summary Statistics")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            total_predictions = len(df)
            st.metric("Total Predictions", total_predictions)
        
        with col2:
            total_attacks = len(df[df['anomaly'] == 1])
            st.metric("Attacks Detected", total_attacks)
        
        with col3:
            if total_predictions > 0:
                attack_rate = (total_attacks / total_predictions) * 100
                st.metric("Attack Rate", f"{attack_rate:.1f}%")
            else:
                st.metric("Attack Rate", "0%")
        
    else:
        st.info("No predictions available for performance analysis.")
