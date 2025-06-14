import re
import socket
from urllib.parse import urlparse
import whois
from datetime import datetime

def has_ip(url):
    try:
        ip = socket.inet_aton(urlparse(url).netloc)
        return 1
    except:
        return -1

def extract_whois_features(url):
    try:
        domain_info = whois.whois(url)
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if creation_date and expiration_date:
            domain_age_days = (datetime.now() - creation_date).days
            domain_reg_length_days = (expiration_date - creation_date).days
            age_of_domain = 1 if domain_age_days >= 180 else -1
            domain_reg_len = 1 if domain_reg_length_days >= 365 else -1
        else:
            age_of_domain = -1
            domain_reg_len = -1
    except:
        age_of_domain = -1
        domain_reg_len = -1

    return age_of_domain, domain_reg_len

def extract_features(url):
    features = []
    parsed = urlparse(url)
    domain = parsed.netloc

    features.append(has_ip(url))
    features.append(1 if len(url) >= 75 else -1)
    features.append(1 if re.search(r"bit\.ly|goo\.gl|tinyurl|ow\.ly", url) else -1)
    features.append(1 if "@" in url else -1)
    features.append(1 if url.count('//') > 1 else -1)
    features.append(1 if '-' in domain else -1)
    features.append(1 if len(domain.split('.')) >= 4 else -1)

    # Dummy features (fill as 0)
    for _ in range(21):
        features.append(0)

    # Append WHOIS features
    age_of_domain, domain_reg_len = extract_whois_features(domain)
    features.append(age_of_domain)
    features.append(domain_reg_len)

    return features
