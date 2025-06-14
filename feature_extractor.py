import re
import socket
from urllib.parse import urlparse
import whois
from datetime import datetime

# ✅ Check if IP is used in place of domain
def has_ip(url):
    try:
        ip = urlparse(url).netloc
        socket.inet_aton(ip)
        return 1
    except:
        return -1

# ✅ WHOIS-based features: domain age, registration length
def extract_whois_features(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        # Normalize if list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if creation_date and expiration_date:
            age = (datetime.now() - creation_date).days
            reg_length = (expiration_date - creation_date).days
            return (1 if age >= 180 else -1), (1 if reg_length >= 365 else -1)
    except:
        pass
    return -1, -1

# ✅ Feature extractor
def extract_features(url):
    features = []
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    # 🔍 Basic URL-based features
    features.append(has_ip(url))                                     # IP present
    features.append(1 if len(url) >= 75 else -1)                     # Long URL
    features.append(1 if re.search(r"bit\.ly|goo\.gl|tinyurl|ow\.ly", url) else -1)  # Shortener
    features.append(1 if "@" in url else -1)                         # @ symbol
    features.append(1 if url.count("//") > 1 else -1)                # Redirection
    features.append(1 if '-' in domain else -1)                      # Prefix-Suffix
    features.append(1 if len(domain.split('.')) >= 4 else -1)        # Subdomains
    features.append(1 if url.startswith("https") else -1)            # HTTPS
    features.append(1 if re.search(r"(login|secure|account|update|verify)", path, re.IGNORECASE) else -1)  # Suspicious keywords

    # 🔍 WHOIS features
    age_of_domain, domain_reg_len = extract_whois_features(domain)
    features.append(age_of_domain)
    features.append(domain_reg_len)

    # ⚠️ Fill rest to 30 features (if model trained on 30)
    while len(features) < 30:
        features.append(0)

    return features
