# ==============================================================================
# PART 2: PHISHING WEBSITE DETECTION - STREAMLIT INTERFACE
# ==============================================================================

import streamlit as st
import joblib
import pandas as pd
import urllib.parse
import re

# ------------------------------------------------------------------------------
# Application Configuration & Model Loading
# ------------------------------------------------------------------------------
st.set_page_config(page_title="Phishing Detector", page_icon="🛡️", layout="centered")

@st.cache_resource
def load_model():
    """Loads the pre-trained Machine Learning model."""
    try:
        # Load the model exported from the Jupyter Notebook
        return joblib.load('phishing_rf_model.pkl')
    except FileNotFoundError:
        st.error("Model file not found! Please run the Jupyter Notebook first to generate 'phishing_rf_model.pkl'.")
        st.stop()

model = load_model()

# ------------------------------------------------------------------------------
# Feature Extraction Logic (Must be identical to the Notebook)
# ------------------------------------------------------------------------------
def extract_features(url):
    """Extracts features from the user-input URL for prediction."""
    features = {}
    
    # Append http to ensure proper parsing if user forgot it
    temp_url = url
    if not temp_url.startswith('http'):
        temp_url = 'http://' + temp_url
        
    parsed_url = urllib.parse.urlparse(temp_url)
    
    features['url_length'] = len(url)
    features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    features['has_at_symbol'] = 1 if '@' in url else 0
    features['has_hyphen'] = 1 if '-' in parsed_url.netloc else 0
    features['num_dots'] = url.count('.')
    # Check original url string for https
    features['is_https'] = 1 if url.startswith('https') else 0
    
    return pd.DataFrame([features])

# ------------------------------------------------------------------------------
# User Interface & Business Rule Validations
# ------------------------------------------------------------------------------
st.title("🛡️ AI Phishing URL Detection System")
st.markdown("""
Welcome to the Security Dashboard. This tool utilizes a **Random Forest Machine Learning Algorithm** to analyze the structural properties of URLs and predict malicious intent.
""")

st.write("### Enter Suspicious URL")
# Text input for the user
user_url = st.text_input("URL Input:", placeholder="e.g., https://www.paypal-secure-update.com")

if st.button("Analyze URL Risk", type="primary"):
    
    # --- Strict Validations & Exception Handling ---
    if not user_url.strip():
        st.warning("⚠️ Validation Error: URL field cannot be empty.")
        
    elif not re.match(r'^(http|https)://', user_url):
        st.error("❌ Format Error: Please include the protocol ('http://' or 'https://') in the URL.")
        
    elif len(user_url) < 5 or '.' not in user_url:
        st.warning("⚠️ Validation Error: The provided URL is invalid or too short to be a real domain.")
        
    else:
        with st.spinner("Executing AI Model Analysis..."):
            
            # 1. Extract Features from the input URL
            features_df = extract_features(user_url)
            
            # --- 🌟 NEW: Business Rule Validation (Trusted Domain Whitelist) 🌟 ---
            # Real-world security systems always use whitelists to prevent False Positives.
            trusted_suffixes = ['.edu.my', '.gov.my', '.edu', '.gov', 'google.com', 'github.com']
            is_whitelisted = any(user_url.endswith(suffix) or (suffix + '/' in user_url) for suffix in trusted_suffixes)
            
            # 2. Predict using the loaded Random Forest model
            prediction = model.predict(features_df)[0]
            probability = model.predict_proba(features_df)[0][1] # Probability of being Phishing (Class 1)
            
            # Apply Business Logic: If it's a trusted institutional domain, override the AI prediction
            if is_whitelisted:
                prediction = 0
                probability = 0.01 # Manually set to very low risk
            
            st.divider()
            
            # 3. Display Results
            st.subheader("📊 Security Assessment Report")
            
            col1, col2 = st.columns(2)
            
            with col1:
                if is_whitelisted:
                    st.success("✅ **VERIFIED SAFE: Trusted Institutional Domain.**")
                    st.write(f"**Threat Probability:** `{probability * 100:.2f}%`")
                    st.markdown("💡 **System Note:** This URL belongs to a verified whitelist (e.g., .edu, .gov). AI assessment is overridden by security policy.")
                elif prediction == 1:
                    st.error("🚨 **CRITICAL: Phishing Detected!**")
                    st.write(f"**Threat Probability:** `{probability * 100:.2f}%`")
                    st.markdown("🔒 **Action Required:** Do NOT proceed. Close the website immediately and do not submit any credentials.")
                else:
                    st.success("✅ **SAFE: No Threat Detected.**")
                    st.write(f"**Threat Probability:** `{probability * 100:.2f}%`")
                    st.markdown("💡 **Note:** The URL structure appears safe, but always verify the domain name spelling.")
            
            # 4. Display extracted features
            with col2:
                st.markdown("**🔍 System Extracted Features:**")
                st.json({
                    "Total Length": int(features_df['url_length'][0]),
                    "Concealed IP Address": bool(features_df['has_ip'][0]),
                    "Contains '@' Symbol": bool(features_df['has_at_symbol'][0]),
                    "Contains Hyphen (-) in Domain": bool(features_df['has_hyphen'][0]),
                    "Subdomain Levels (Dots)": int(features_df['num_dots'][0]),
                    "Secured Protocol (HTTPS)": bool(features_df['is_https'][0])
                })