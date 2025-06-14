import streamlit as st
import pickle
from feature_extractor import extract_features
import requests
from urllib.parse import urlparse

# Load trained model
with open("phishing_model_final.pkl", "rb") as file:
    model = pickle.load(file)

# VirusTotal API
API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

# UI Setup
st.title("🔍 Phishing URL Detector")
st.markdown("Enter a URL to check if it's **Phishing or Legitimate** using **AI + VirusTotal**")
url_input = st.text_input("Enter URL...")

# ✅ Function to check with VirusTotal
def check_virustotal(url):
    try:
        response = requests.post(
            VIRUSTOTAL_URL,
            headers={"x-apikey": API_KEY},
            data={"url": url}
        )
        if response.status_code == 200:
            url_id = response.json()["data"]["id"]
            analysis = requests.get(
                f"{VIRUSTOTAL_URL}/{url_id}",
                headers={"x-apikey": API_KEY}
            )
            results = analysis.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = results.get("malicious", 0)
            total = sum(results.values())
            confidence = round((malicious / total) * 100, 2) if total > 0 else 0
            return confidence
    except Exception as e:
        st.warning(f"VirusTotal lookup failed: {e}")
    return 0.0

# 🔍 Handle Prediction
if st.button("🔍 Analyze"):
    if not url_input.strip():
        st.warning("⚠️ Please enter a URL.")
        st.stop()

    try:
        # Feature extraction
        features = extract_features(url_input)

        # Model prediction
        prediction = model.predict([features])[0]
        model_conf = model.predict_proba([features])[0][1] * 100  # % phishing

        # VirusTotal confidence
        vt_conf = check_virustotal(url_input)
        vt_safe_score = 100 - vt_conf  # Higher is safer

        # Weighted final confidence
        final_conf = round((0.6 * model_conf) + (0.4 * vt_safe_score), 2)

        # 🧠 Final verdict
        st.subheader("Result:")
        if model_conf > 70 and vt_conf == 0:
            st.success("✅ This URL is likely **Legitimate**")
        elif final_conf < 50:
            st.error("⚠️ This URL is likely **Phishing**")
        else:
            st.warning("🔍 This URL appears **Suspicious** – needs further investigation")

        # Confidence breakdown
        st.markdown(f"""
        #### 🔒 Confidence Meter (AI + VirusTotal)
        - 🤖 Model Confidence: `{round(model_conf, 2)}%`
        - 🧪 VirusTotal Score: `{vt_conf}%`
        - 🧠 Final Combined Confidence: `{final_conf}%`
        """)

    except Exception as e:
        st.error(f"❌ Error during analysis: {e}")
