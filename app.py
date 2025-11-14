# app.py - Updated to download models from Google Drive
import streamlit as st
import pandas as pd
import numpy as np
import pickle
import json
import os
import gdown

# Configure the page
st.set_page_config(
    page_title="DDoS Attack Detector",
    page_icon="🚨",
    layout="wide"
)

st.title("🚨 DDoS Attack Classification System")
st.write("Upload network traffic data to detect and classify DDoS attacks")

# Download model files if they don't exist
@st.cache_resource
def download_models():
    # Your Google Drive file IDs
    MODEL_FILE_ID = "1aV1lbMz1sT6Andxh12rKjshtf67y8R-O"  # best_model_random_forest.pkl
    METADATA_FILE_ID = "1clxhBORrc2DW6f5mvSlSMZsqMAxAhZN2"  # model_metadata.json
    
    model_url = f"https://drive.google.com/uc?id={MODEL_FILE_ID}"
    metadata_url = f"https://drive.google.com/uc?id={METADATA_FILE_ID}"
    
    if not os.path.exists("best_model_random_forest.pkl"):
        with st.spinner("📥 Downloading model file... (348MB - This may take 2-5 minutes)"):
            gdown.download(model_url, "best_model_random_forest.pkl", quiet=False)
        st.success("✅ Model file downloaded!")
    
    if not os.path.exists("model_metadata.json"):
        with st.spinner("📥 Downloading metadata file..."):
            gdown.download(metadata_url, "model_metadata.json", quiet=False)
        st.success("✅ Metadata file downloaded!")

# Check if we need to download models
if not os.path.exists("best_model_random_forest.pkl") or not os.path.exists("model_metadata.json"):
    st.info("🔍 Model files not found locally. Downloading from Google Drive...")
    download_models()

# Load model
@st.cache_resource
def load_model():
    try:
        with open('best_model_random_forest.pkl', 'rb') as f:
            model_data = pickle.load(f)
        
        with open('model_metadata.json', 'r') as f:
            metadata = json.load(f)
        
        return model_data, metadata
    except Exception as e:
        st.error(f"❌ Error loading model: {e}")
        return None, None

model_data, metadata = load_model()

if model_data is None:
    st.stop()

st.sidebar.success("✅ Model loaded successfully!")
st.sidebar.write(f"**Model:** {metadata.get('model_name', 'Random Forest')}")
st.sidebar.write(f"**Features:** {len(model_data['selected_features'])}")
st.sidebar.write(f"**Classes:** {', '.join(model_data['label_encoder'].classes_)}")

# Main app
tab1, tab2, tab3 = st.tabs(["🎯 Real-time Analysis", "📊 Batch Analysis", "ℹ️ Instructions"])

with tab1:
    st.header("Real-time Traffic Analysis")
    
    with st.form("prediction_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            flow_duration = st.number_input("Flow Duration", value=1000, min_value=0)
            total_fwd_packets = st.number_input("Total Fwd Packets", value=10, min_value=0)
            total_bwd_packets = st.number_input("Total Bwd Packets", value=5, min_value=0)
            total_length_fwd = st.number_input("Total Fwd Length", value=500, min_value=0)
            total_length_bwd = st.number_input("Total Bwd Length", value=250, min_value=0)
        
        with col2:
            fwd_packet_len_max = st.number_input("Fwd Packet Max", value=100, min_value=0)
            fwd_packet_len_min = st.number_input("Fwd Packet Min", value=10, min_value=0)
            fwd_packet_len_mean = st.number_input("Fwd Packet Mean", value=50, min_value=0)
            bwd_packet_len_max = st.number_input("Bwd Packet Max", value=80, min_value=0)
            bwd_packet_len_min = st.number_input("Bwd Packet Min", value=8, min_value=0)
        
        submitted = st.form_submit_button("🔍 Classify Traffic")
    
    if submitted:
        try:
            # Prepare input
            input_features = {}
            for feature in model_data['selected_features']:
                # Map common features
                if feature == 'Flow Duration':
                    input_features[feature] = [flow_duration]
                elif feature == 'Total Fwd Packets':
                    input_features[feature] = [total_fwd_packets]
                elif feature == 'Total Backward Packets':
                    input_features[feature] = [total_bwd_packets]
                elif feature == 'Total Length of Fwd Packets':
                    input_features[feature] = [total_length_fwd]
                elif feature == 'Total Length of Bwd Packets':
                    input_features[feature] = [total_length_bwd]
                elif feature == 'Fwd Packet Length Max':
                    input_features[feature] = [fwd_packet_len_max]
                elif feature == 'Fwd Packet Length Min':
                    input_features[feature] = [fwd_packet_len_min]
                elif feature == 'Fwd Packet Length Mean':
                    input_features[feature] = [fwd_packet_len_mean]
                elif feature == 'Bwd Packet Length Max':
                    input_features[feature] = [bwd_packet_len_max]
                elif feature == 'Bwd Packet Length Min':
                    input_features[feature] = [bwd_packet_len_min]
                else:
                    input_features[feature] = [0]  # Fill missing with 0
            
            input_df = pd.DataFrame(input_features)
            X_scaled = model_data['scaler'].transform(input_df)
            
            # Predict
            prediction = model_data['model'].predict(X_scaled)
            probabilities = model_data['model'].predict_proba(X_scaled)
            
            predicted_label = model_data['label_encoder'].inverse_transform(prediction)[0]
            confidence = np.max(probabilities[0])
            
            # Display results
            st.subheader("🎯 Prediction Result")
            
            if predicted_label == 'Benign':
                st.success(f"✅ **Normal Traffic**")
            else:
                st.error(f"🚨 **{predicted_label} Attack**")
            
            st.write(f"**Confidence:** {confidence:.1%}")
            
            # Show probabilities
            st.subheader("Probability Distribution")
            prob_dict = dict(zip(model_data['label_encoder'].classes_, probabilities[0]))
            prob_df = pd.DataFrame({
                'Class': list(prob_dict.keys()),
                'Probability': list(prob_dict.values())
            }).sort_values('Probability', ascending=False)
            
            st.dataframe(prob_df)
                
        except Exception as e:
            st.error(f"❌ Prediction error: {e}")

with tab2:
    st.header("Batch File Analysis")
    
    uploaded_file = st.file_uploader("Upload CSV file with network traffic data", type=['csv'])
    
    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            st.write(f"📊 Loaded {len(df)} samples")
            st.dataframe(df.head())
            
            if st.button("🔍 Analyze Entire File"):
                with st.spinner("Analyzing network traffic..."):
                    # Process all samples
                    results = []
                    
                    for i, row in df.iterrows():
                        try:
                            # Prepare input
                            input_features = {}
                            for feature in model_data['selected_features']:
                                if feature in df.columns:
                                    input_features[feature] = [row[feature]]
                                else:
                                    input_features[feature] = [0]
                            
                            input_df = pd.DataFrame(input_features)
                            X_scaled = model_data['scaler'].transform(input_df)
                            
                            prediction = model_data['model'].predict(X_scaled)
                            probability = model_data['model'].predict_proba(X_scaled)
                            
                            predicted_label = model_data['label_encoder'].inverse_transform(prediction)[0]
                            confidence = np.max(probability[0])
                            
                            results.append({
                                'Sample': i+1,
                                'Prediction': predicted_label,
                                'Confidence': confidence,
                                'Is_Attack': predicted_label != 'Benign'
                            })
                            
                        except Exception as e:
                            st.warning(f"Error processing sample {i+1}: {e}")
                    
                    # Display batch results
                    results_df = pd.DataFrame(results)
                    
                    st.subheader("📈 Batch Analysis Results")
                    
                    # Summary
                    col1, col2, col3, col4 = st.columns(4)
                    total = len(results_df)
                    attacks = len(results_df[results_df['Is_Attack'] == True])
                    avg_confidence = results_df['Confidence'].mean()
                    
                    with col1:
                        st.metric("Total Samples", total)
                    with col2:
                        st.metric("Normal Traffic", total - attacks)
                    with col3:
                        st.metric("Attack Traffic", attacks)
                    with col4:
                        st.metric("Avg Confidence", f"{avg_confidence:.1%}")
                    
                    # Detailed results
                    st.dataframe(results_df)
                    
                    # Download
                    csv = results_df.to_csv(index=False)
                    st.download_button(
                        "📥 Download Results",
                        data=csv,
                        file_name="ddos_detection_results.csv",
                        mime="text/csv"
                    )
                    
        except Exception as e:
            st.error(f"❌ File processing error: {e}")

with tab3:
    st.header("Instructions")
    st.markdown("""
    ### How to Use This DDoS Detection System
    
    **🎯 Real-time Analysis Tab:**
    - Enter network traffic feature values
    - Click "Classify Traffic" for instant prediction
    - View confidence scores and probability distributions
    
    **📊 Batch Analysis Tab:**
    - Upload CSV files with multiple network traffic samples
    - Get batch analysis results
    - Download comprehensive reports
    
    **🔧 Model Information:**
    - Random Forest classifier trained on CICDDoS2019 dataset
    - Automatically downloads model files from Google Drive
    - Handles missing features by filling with zeros
    
    **📈 Key Features to Monitor:**
    - Flow Duration
    - Packet counts and sizes  
    - Traffic patterns and volumes
    - Connection characteristics
    """)
    
    # Show available features
    st.subheader("Model Features")
    st.write(f"Total features used: {len(model_data['selected_features'])}")
    st.write("First 15 features:")
    st.write(model_data['selected_features'][:15])

# Add deployment info
st.sidebar.markdown("---")
st.sidebar.header("Deployment Info")
st.sidebar.success("✅ Ready for Streamlit Cloud Deployment")
st.sidebar.info("Model files are hosted on Google Drive and download automatically on first run.")