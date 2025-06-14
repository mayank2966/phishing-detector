import streamlit as st
import pickle
from feature_extractor import extract_features
import requests
from urllib.parse import urlparse

# Load trained model
with open("phishing_model_final.pkl", "rb") as file:
    model = pickle.load(file)

# VirusTotal API key from secrets
API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

# App UI
st.title("🔍 Phishing URL Detector")
st.markdown("Enter a URL to check if it's **Phishing or Legitimate** using **AI + VirusTotal**")
url_input = st.text_input("Enter URL...")

# Helper to check VirusTotal
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
    except:
        pass
    return 0.0

# Handle prediction
if st.button("🔍 Analyze"):
    if not url_input.strip():
        st.warning("⚠️ Please enter a URL.")
        st.stop()

    try:
        features = extract_features(url_input)

        # Model Prediction
        prediction = model.predict([features])[0]
        model_conf = model.predict_proba([features])[0][1] * 100

        # VirusTotal Confidence
        vt_conf = check_virustotal(url_input)

        # Combined confidence
        final_conf = round((model_conf + vt_conf) / 2, 2)

        # Output
        st.subheader("Result:")
        if final_conf >= 70:
            st.error("⚠️ This URL is likely **Phishing**")
        else:
            st.success("✅ This URL is likely **Legitimate**")

        # Confidence Display
        st.markdown(f"""
        #### 🔒 Confidence Meter (AI + VirusTotal)
        - 🤖 Model Confidence: `{round(model_conf, 2)}%`
        - 🧪 VirusTotal Score: `{vt_conf}%`
        - 🧠 Final Combined Confidence: `{final_conf}%`
        """)

    except Exception as e:
        st.error(f"❌ Error: {e}")
