import streamlit as st
import pickle
from feature_extractor import extract_features
import requests
from urllib.parse import urlparse
import re

# Load trained model
with open("phishing_model_final.pkl", "rb") as file:
    model = pickle.load(file)

# VirusTotal API
API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

# === Streamlit UI ===
st.set_page_config(page_title="Phishing URL Detector", page_icon="🔍")
st.title("🔍 Phishing URL Detector")
st.markdown("Enter a URL to check if it's **Phishing or Legitimate** using **AI + VirusTotal**")

url_input = st.text_input("🔗 Enter URL...")

# === Function to check URL extension risk ===
def is_dangerous_file(url):
    return url.lower().endswith(('.exe', '.apk', '.zip', '.scr', '.bat', '.sh'))

# === Function to check impersonation using keywords ===
def has_impersonation_risk(url):
    phishing_keywords = ["login", "secure", "update", "account", "verify", "webscr", "signin", "support"]
    trusted_domains = ["instagram.com", "paypal.com", "hdfcbank.com", "google.com"]
    return any(kw in url.lower() for kw in phishing_keywords) and not any(td in url.lower() for td in trusted_domains)

# ✅ Function to check with VirusTotal
def check_virustotal(url):
    try:
        response = requests.post(
            VIRUSTOTAL_URL,
            headers={"x-apikey": API_KEY},
            data={"url": url}
        )
        if response.status_code == 200 and "data" in response.json():
            url_id = response.json()["data"]["id"]
            analysis = requests.get(
                f"{VIRUSTOTAL_URL}/{url_id}",
                headers={"x-apikey": API_KEY}
            )
            if analysis.status_code == 200 and "data" in analysis.json():
                results = analysis.json()["data"]["attributes"]["last_analysis_stats"]
                malicious = results.get("malicious", 0)
                total = sum(results.values())
                confidence = round((malicious / total) * 100, 2) if total > 0 else 0
                return confidence
    except Exception as e:
        st.warning(f"⚠️ VirusTotal lookup failed: {e}")
    return 0.0

# === Final Analysis Trigger ===
if st.button("🔍 Analyze"):
    if not url_input.strip():
        st.warning("⚠️ Please enter a URL.")
        st.stop()

    st.markdown("🔎 **Analyzing URL...**")

    if is_dangerous_file(url_input):
        st.warning("⚠️ This URL links to a suspicious file type (e.g., `.exe`, `.apk`). Be cautious!")

    if has_impersonation_risk(url_input):
        st.warning("⚠️ This URL may impersonate a trusted service. Double check the domain carefully.")

    try:
        # Extract features from URL
        features = extract_features(url_input)

        # Predict using ML model
        prediction = model.predict([features])[0]
        model_conf = model.predict_proba([features])[0][1] * 100  # % phishing

        # Get VirusTotal Score
        vt_conf = check_virustotal(url_input)
        vt_safe_score = 100 - vt_conf  # Higher = safer

        # Final Combined Confidence (weighted)
        final_conf = round((0.6 * model_conf) + (0.4 * vt_safe_score), 2)

        # === Show Result ===
        st.subheader("📋 Result:")

        if model_conf > 70 and vt_conf == 0:
            st.success("✅ This URL is likely **Legitimate**")
        elif final_conf < 50:
            st.error("🚨 This URL is likely **Phishing**")
        else:
            st.warning("⚠️ This URL appears **Suspicious** – needs further investigation")

        # === Show Confidence Metrics ===
        st.markdown(f"""
        ---
        ### 🔒 Confidence Meter (AI + VirusTotal)
        - 🤖 **Model Confidence**: `{round(model_conf, 2)}%`
        - 🧪 **VirusTotal Score**: `{vt_conf}%`
        - 🧠 **Final Combined Confidence**: `{final_conf}%`
        """)

    except Exception as e:
        st.error(f"❌ Error during analysis: {e}")
