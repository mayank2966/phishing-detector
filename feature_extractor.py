import re
import socket
from urllib.parse import urlparse, parse_qs
import whois
from datetime import datetime

def count_char(s, char):
    return s.count(char)

def extract_whois_features(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if creation_date and expiration_date:
            age = (datetime.now() - creation_date).days
            reg_length = (expiration_date - creation_date).days
            return age, reg_length
    except:
        pass
    return -1, -1

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    filename = path.split("/")[-1] if "/" in path else path
    params = parse_qs(query)

    features = []

    # === URL Part ===
    features.append(count_char(url, '.'))              # qty_dot_url
    features.append(count_char(url, '-'))              # qty_hyphen_url
    features.append(count_char(url, '_'))              # qty_underline_url
    features.append(count_char(url, '/'))              # qty_slash_url
    features.append(count_char(url, '?'))              # qty_questionmark_url
    features.append(count_char(url, '='))              # qty_equal_url
    features.append(count_char(url, '@'))              # qty_at_url
    features.append(count_char(url, '&'))              # qty_and_url
    features.append(count_char(url, '!'))              # qty_exclamation_url
    features.append(count_char(url, ' '))              # qty_space_url
    features.append(count_char(url, '~'))              # qty_tilde_url
    features.append(count_char(url, ','))              # qty_comma_url
    features.append(count_char(url, '+'))              # qty_plus_url
    features.append(count_char(url, '*'))              # qty_asterisk_url
    features.append(count_char(url, '#'))              # qty_hashtag_url
    features.append(count_char(url, '$'))              # qty_dollar_url
    features.append(count_char(url, '%'))              # qty_percent_url
    features.append(1 if '.' in domain else 0)         # qty_tld_url (basic tld present)

    features.append(len(url))                          # length_url

    # === Domain Part ===
    features.append(count_char(domain, '.'))           # qty_dot_domain
    features.append(count_char(domain, '-'))           # qty_hyphen_domain
    features.append(count_char(domain, '_'))           # qty_underline_domain
    features.append(count_char(domain, '/'))           # qty_slash_domain
    features.append(count_char(domain, '?'))           # qty_questionmark_domain
    features.append(count_char(domain, '='))           # qty_equal_domain
    features.append(count_char(domain, '@'))           # qty_at_domain
    features.append(count_char(domain, '&'))           # qty_and_domain
    features.append(count_char(domain, '!'))           # qty_exclamation_domain
    features.append(count_char(domain, ' '))           # qty_space_domain
    features.append(count_char(domain, '~'))           # qty_tilde_domain
    features.append(count_char(domain, ','))           # qty_comma_domain
    features.append(count_char(domain, '+'))           # qty_plus_domain
    features.append(count_char(domain, '*'))           # qty_asterisk_domain
    features.append(count_char(domain, '#'))           # qty_hashtag_domain
    features.append(count_char(domain, '$'))           # qty_dollar_domain
    features.append(count_char(domain, '%'))           # qty_percent_domain
    features.append(len(re.findall(r'[aeiou]', domain.lower())))  # qty_vowels_domain
    features.append(len(domain))                       # domain_length

    try:
        socket.inet_aton(domain)
        features.append(1)                             # domain_in_ip
    except:
        features.append(0)

    # === Directory (path) Part ===
    features.append(count_char(path, '.'))
    features.append(count_char(path, '-'))
    features.append(count_char(path, '_'))
    features.append(count_char(path, '/'))
    features.append(count_char(path, '?'))
    features.append(count_char(path, '='))
    features.append(count_char(path, '@'))
    features.append(count_char(path, '&'))
    features.append(count_char(path, '!'))
    features.append(count_char(path, ' '))
    features.append(count_char(path, '~'))
    features.append(count_char(path, ','))
    features.append(count_char(path, '+'))
    features.append(count_char(path, '*'))
    features.append(count_char(path, '#'))
    features.append(count_char(path, '$'))
    features.append(count_char(path, '%'))
    features.append(len(path))

    # === File Name ===
    features.append(count_char(filename, '.'))
    features.append(count_char(filename, '-'))
    features.append(count_char(filename, '_'))
    features.append(count_char(filename, '/'))
    features.append(count_char(filename, '?'))
    features.append(count_char(filename, '='))
    features.append(count_char(filename, '@'))
    features.append(count_char(filename, '&'))
    features.append(count_char(filename, '!'))
    features.append(count_char(filename, ' '))
    features.append(count_char(filename, '~'))
    features.append(count_char(filename, ','))
    features.append(count_char(filename, '+'))
    features.append(count_char(filename, '*'))
    features.append(count_char(filename, '#'))
    features.append(count_char(filename, '$'))
    features.append(count_char(filename, '%'))
    features.append(len(filename))

    # === Parameters ===
    param_str = query
    features.append(count_char(param_str, '.'))
    features.append(count_char(param_str, '-'))
    features.append(count_char(param_str, '_'))
    features.append(count_char(param_str, '/'))
    features.append(count_char(param_str, '?'))
    features.append(count_char(param_str, '='))
    features.append(count_char(param_str, '@'))
    features.append(count_char(param_str, '&'))
    features.append(count_char(param_str, '!'))
    features.append(count_char(param_str, ' '))
    features.append(count_char(param_str, '~'))
    features.append(count_char(param_str, ','))
    features.append(count_char(param_str, '+'))
    features.append(count_char(param_str, '*'))
    features.append(count_char(param_str, '#'))
    features.append(count_char(param_str, '$'))
    features.append(count_char(param_str, '%'))
    features.append(len(param_str))

    features.append(1 if len(param_str) > 0 and "." in param_str else 0)  # tld_present_params
    features.append(len(params))                                          # qty_params

    # === WHOIS-based features ===
    age_days, reg_length_days = extract_whois_features(domain)
    features.append(age_days)
    features.append(reg_length_days)

    # Pad to 111 if still missing
    while len(features) < 111:
        features.append(0)

    return features
