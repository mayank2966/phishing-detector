import streamlit as st
import pickle
from feature_extractor import extract_features
import requests
import base64

# === 🔐 Load VirusTotal API Key from secrets ===
API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]

# === 📦 VirusTotal URL Checker ===
def base64_url(url):
    url_bytes = url.encode('utf-8')
    return base64.urlsafe_b64encode(url_bytes).decode().strip('=')

def check_virustotal(url):
    try:
        encoded_url = base64_url(url)
        headers = {
            "x-apikey": API_KEY
        }
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{encoded_url}",
            headers=headers
        )
        if response.status_code == 200:
            result = response.json()
            stats = result['data']['attributes']['last_analysis_stats']
            positives = stats.get('malicious', 0)
            total = sum(stats.values())
            confidence = max(0, 1 - positives / total) * 100
            return round(confidence, 2)
        else:
            return 50.0
    except:
        return 50.0

# === 🎯 Load the trained ML model ===
with open("phishing_model_final.pkl", "rb") as file:
    model = pickle.load(file)

# === 🌐 Streamlit Interface ===
st.set_page_config(page_title="🔍 Phishing URL Detector", layout="centered")
st.title("🔍 Phishing URL Detector")
st.markdown("Enter a URL to check if it's **Phishing or Legitimate** using AI + VirusTotal")

url_input = st.text_input("Enter URL...")

if st.button("Analyze"):
    if not url_input:
        st.warning("⚠️ Please enter a URL.")
    else:
        # 🔍 Extract Features and Predict
        features = extract_features(url_input)
        prediction = model.predict([features])[0]
        model_conf = model.predict_proba([features])[0][1] * 100  # Phishing confidence %

        # 🧪 VirusTotal Check
        vt_conf = check_virustotal(url_input)

        # 📊 Combine Confidence
        final_conf = round((model_conf + vt_conf) / 2, 2)

        st.markdown("---")
        if prediction == 1:
            st.error("⚠️ This URL is likely **Phishing**")
        else:
            st.success("✅ This URL is likely **Legitimate**")

        # Confidence Meter
        st.markdown("#### 🔒 Confidence Meter (AI + VirusTotal):")
        st.progress(int(final_conf))
        st.text(f"🤖 Model Confidence: {round(model_conf, 2)}%")
        st.text(f"🧪 VirusTotal Score: {vt_conf}%")
        st.text(f"🧠 Final Combined Confidence: {final_conf}%")

        with st.expander("🧬 View Extracted Features"):
            st.write(features)
