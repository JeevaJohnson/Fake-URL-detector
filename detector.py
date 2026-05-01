import pandas as pd
import math
from collections import Counter
import requests
import socket
import ssl
import whois
from datetime import datetime
from functools import lru_cache
import random
import re
import numpy as np
from urllib.parse import urlparse
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, Conv1D, GlobalMaxPooling1D, Dense
from difflib import SequenceMatcher
import tldextract
import joblib
import json
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.text import tokenizer_from_json



calibrated_model = joblib.load("ml_model.pkl")
dl_model = load_model("dl_model.keras")
with open("tokenizer.json") as f:
    data = f.read()   # ✅ read as STRING

tokenizer = tokenizer_from_json(data)
tokenizer = tokenizer_from_json(data)




API_KEY = "YOUR_ACTUAL_API_KEY"
# -------------------------
# Constants
# -------------------------
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "secure", "verify", "verification",
    "account", "update", "confirm", "password",
    "authentication", "session", "validate", "validation",
    "auth", "access", "security", "alert", "bank", "payment"
]

TRUSTED_DOMAINS = [
    "google.com", "github.com", "microsoft.com","apple.com",
    "amazon.in","amazon.com", "irctc.co.in", "wikipedia.org","paypal.com",
    "python.org", "stackoverflow.com","amazon.com", "facebook.com"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]

TRUSTED_BRANDS = [
    "google", "amazon", "paypal", "microsoft", "bank", "apple","hdfc","icici","sbi"]

KNOWN_BRANDS = [
    "google","amazon","paypal","facebook",
    "hdfc","icici","sbi" ]

LEGIT_WORDS = ["wiki", "docs", "api", "github", "stackoverflow"]

TRUSTED_DOMAINS = [
    "google.com", "amazon.in", "amazon.com",
    "facebook.com", "paypal.com", "microsoft.com","wikipedia.org"
]

HOSTING_DOMAINS = [
    "github.io", "netlify.app", "vercel.app",
    "firebaseapp.com", "herokuapp.com",
    "onrender.com", "pages.dev", "glitch.me"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl"
]
KNOWN_BRANDS = ["google", "facebook", "amazon", "paypal", "microsoft", "apple"]

brands = ["google", "facebook", "amazon", "paypal", "apple", "microsoft"]

def google_safe_check(url):
    
    
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    body = {
        "client": {"clientId": "project", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        res = requests.post(endpoint, json=body)
        return 1 if res.status_code == 200 and res.json() else 0
    except:
        return 0


def domain_age(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        return (datetime.now() - creation).days
    except:
        return -1

@lru_cache(maxsize=1000)
def has_dns(domain):
    try:
        import socket
        socket.gethostbyname(domain)
        return 1
    except:
        return None   # ← CRITICAL CHANGE


@lru_cache(maxsize=1000)
def has_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return 1
    except:
        return None   # ← NOT False



def detect_protocol(domain):
    try:
        requests.get("https://" + domain, timeout=2)
        return "https"
    except:
        return "http"


# -------------------------
# Helper Functions
# -------------------------
def shannon_entropy(string):
    probs = [float(string.count(c)) / len(string) for c in set(string)]
    return -sum(p * np.log2(p) for p in probs)


def domain_entropy(domain):
    if len(domain) == 0:
        return 0
    probs = [float(domain.count(c)) / len(domain) for c in set(domain)]
    return -sum(p * np.log2(p) for p in probs)


def brand_mismatch(domain):
    for brand in TRUSTED_BRANDS:
        if brand in domain:
            if domain.endswith(brand + ".com") or domain.endswith(brand + ".in"):
                return 0
            return 1
    return 0


def detect_fake_brand(url,domain):
    suspicious_patterns = [
        ("google", ["g00gle", "goog1e"]),
        ("facebook", ["faceb00k"]),
        ("amazon", ["amaz0n"]),
        ("paypal", ["paypa1"]),
    ]

    for brand, variants in suspicious_patterns:
        for v in variants:
            if v in domain:
                return 1
    return 0


def detect_repeated_chars(domain):
    domain = domain.replace(".", "")
    return 1 if re.search(r'(.)\1{3,}', domain) else 0

def looks_like_typo(domain):
    swaps = {'0':'o','1':'l','5':'s','@':'a'}
    return any(k in domain for k in swaps)

def dl_predict(url,dl_model):
    seq = tokenizer.texts_to_sequences([url])
    pad = pad_sequences(seq, maxlen=100)
    prob = dl_model.predict(pad)[0][0]
    return prob
    
def heuristic_checks(url, domain, features):
    h_score = 0
    reasons = []

    # 🔸 HTTP login (important)
    if features.get('http_login', 0):
        h_score += 0.3
        reasons.append("Login page over HTTP")

    # 🔸 Suspicious symbol
    if "@" in url:
        h_score += 0.2
        reasons.append("Contains @ symbol")

    # 🔸 Too many hyphens
    if domain.count('-') >= 2:
        h_score += 0.2
        reasons.append("Too many hyphens in domain")

    # 🔸 IP address usage
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        h_score += 0.3
        reasons.append("Uses IP address instead of domain")

    # 🔸 Keyword penalty (only if NOT trusted)
    if not any(domain.endswith(d) for d in TRUSTED_DOMAINS):
        if features.get('num_keywords', 0) > 2:
            h_score += 0.2
            reasons.append("Too many suspicious keywords")

    return h_score, reasons


def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()  
    
def has_repeated_chars(domain):
    return 1 if re.search(r'(.)\1{2,}', domain) else 0    



def detect_fake_brand(url, domain):
    url = url.lower()
    domain = domain.lower()

    brands = ["google", "facebook", "amazon", "paypal", "apple", "microsoft"]

    for brand in brands:
        if brand in url and not domain.endswith(brand + ".com"):
            return 1

    return 0

def detect_repeated_chars(domain):
    # Remove dots (so subdomains don't interfere)
    domain = domain.replace(".", "")
    
    # Only flag if 4+ repeated characters
    return 1 if re.search(r'(.)\1{3,}', domain) else 0
    

def has_ip(url):
    return 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0        

def normalize_text(s):
    return s.lower().replace("0", "o").replace("1", "l").replace("3", "e")

    
def strong_phishing_check(url, domain):
    norm_domain = normalize_text(domain)
    original_domain = domain.lower()

    brands = ["google", "facebook", "amazon", "paypal", "apple", "microsoft"]

    # ✅ Extract real domain (IMPORTANT FIX)
    ext = tldextract.extract(original_domain)
    real_domain = ext.domain + "." + ext.suffix   # e.g. amazon.in

    core = ext.domain   # cleaner than split(".")[0]
    norm_core = normalize_text(core)

    for brand in brands:

        # =========================
        # ✅ 0. Allow real trusted domains
        # =========================
        if real_domain in TRUSTED_DOMAINS:
            return False, ""

        # =========================
        # 🔥 1. Exact brand misuse
        # =========================
        if brand in norm_domain and real_domain not in TRUSTED_DOMAINS:
            return True, f"Impersonates {brand}"

        # =========================
        # 🔥 2. Typo attack
        # =========================
        if is_similar(norm_core, brand) and norm_core != brand:
            return True, f"Looks similar to {brand} (possible typo attack)"

    return False, ""

def model_predict(url, model):
    feats = extract_features(url)
    X = pd.DataFrame([feats])
    prob = model.predict_proba(X)[0][1]
    return prob, 
    
def reputation_check(domain):
    for d in TRUSTED_DOMAINS:
        if domain == d or domain.endswith("." + d):
            return "trusted"
    return "unknown"

def is_similar(a, b, threshold=0.8):
    return SequenceMatcher(None, a, b).ratio() > threshold


def brand_mismatch(domain):
    legit_domains = [
        "microsoftonline.com",
        "google.com",
        "amazon.com",
        "github.com"
    ]

    for legit in legit_domains:
        if legit in domain:
            return 0

    for brand in TRUSTED_BRANDS:
        if brand in domain:
            if not domain.endswith(brand + ".com") and not domain.endswith(brand + ".in"):
                return 1

    return 0    
    
def predict_url(url, model):
    # extract features
    features = extract_features(url)
    
    # convert to dataframe
    import pandas as pd
    X = pd.DataFrame([features])
    
    # predict probability
    prob = model.predict_proba(X)[0][1]  # phishing probability
    
    # prediction
    label = "Phishing" if prob > 0.5 else "Legitimate"
    
    return label, prob, features

def build_output(label, confidence, reasons, is_https):
    # 🌐 Protocol
    protocol_msg = "Uses HTTPS (secure connection)" if is_https else "Uses HTTP (not secure)"

    # ⚠️ Safety
    if label == "Phishing":
        safety_msg = "🚨 Dangerous site – do not use"
    elif label == "Suspicious":
        safety_msg = "⚠ Not secure – use with caution"
    else:
        safety_msg = "✔ Safe to use"

    final_reasons = [
        f"⚠️ Safety: {safety_msg}",
        f"🌐 {protocol_msg}"
    ]

    final_reasons += ["- " + r for r in reasons]

    return label, confidence, final_reasons

def normalize_url(url):
    url = url.strip().lower()
    
    # remove spaces
    url = url.replace(" ", "")
    
    # add scheme if missing (prefer HTTPS)
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url
    
def explain_prediction(features):
    reasons = []

    if features.get('domain_random', 0) == 1:
        reasons.append("Random-looking domain")

    if features.get('entropy', 0) > 4:
        reasons.append("High randomness in URL")

    if features.get('num_digits', 0) > 5:
        reasons.append("Contains many digits")

    if features.get('num_keywords', 0) > 0:
        reasons.append("Contains phishing-related keywords")

    if features.get('has_ip', 0) == 1:
        reasons.append("Uses IP address instead of domain")

    if features.get('is_shortened', 0) == 1:
        reasons.append("Uses URL shortener")

    if features.get('num_subdomains', 0) > 3:
        reasons.append("Too many subdomains")

    if features.get('has_at', 0) == 1:
        reasons.append("Contains '@' symbol")

    if features.get('brand_mismatch', 0) == 1:
        reasons.append("Brand impersonation pattern")

    if features.get('fake_brand', 0) == 1:
        reasons.append("Fake brand spelling detected")

    if not reasons:
        reasons.append("Looks normal")

    return reasons


def basic_url_sanity(url, domain):
    reasons = []

    if not domain or domain.startswith("."):
        reasons.append("Invalid domain structure")

    if "///" in url:
        reasons.append("Malformed URL")

    if ".." in domain:
        reasons.append("Suspicious domain (double dots)")

    return reasons


def final_decision(url, calibrated_model, dl_model):
    url = normalize_url(url)

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    is_https = parsed.scheme == "https"

    ext = tldextract.extract(domain)
    real_domain = ext.domain + "." + ext.suffix

    # =========================
    # 🔗 SHORTENER CHECK
    # =========================
    if any(domain.endswith(s) for s in SHORTENERS):
        return build_output(
            "Suspicious",
            0.7,
            ["Shortened URL – destination unknown"],
            is_https
        )

    # =========================
    # 🌐 HOSTING PLATFORM CHECK (FIXED)
    # =========================
    if any(domain.endswith(h) for h in HOSTING_DOMAINS):

        # 🚨 Phishing ONLY if brand misuse
        if any(b in domain for b in ["google","amazon","paypal","facebook","hdfc","icici","sbi"]):
            return build_output(
                "Phishing",
                0.9,
                ["Brand misuse on hosting platform"],
                is_https
            )

        # ⚠ Otherwise → always suspicious
        return build_output(
            "Suspicious",
            0.7,
            ["Hosted on public platform (user-controlled content)"],
            is_https
        )

    # =========================
    # 🌐 CORE FLAGS
    # =========================
    dns_status = has_dns(domain)
    ssl_status = has_ssl(domain)

    if not is_https:
        ssl_status = 0

    sanity_reasons = basic_url_sanity(url, domain)

    # =========================
    # 🚨 STRONG BRAND CHECK
    # =========================
    is_phish, reason = strong_phishing_check(url, domain)
    if is_phish:
        return build_output(
            "Phishing",
            0.95,
            ["Strong brand impersonation detected", reason],
            is_https
        )

    # =========================
    # 🤖 MODEL + HEURISTICS
    # =========================
    prob, features = model_predict(url, calibrated_model)
    dl_prob = dl_predict(url, dl_model)
    h_score, _ = heuristic_checks(url, domain, features)
    rep = reputation_check(domain)

    reasons = {"positive": [], "negative": [], "neutral": []}

    # =========================
    # 🟢 POSITIVE
    # =========================
    if rep == "trusted":
        reasons["positive"].append("Trusted domain")

    if is_https and ssl_status == 1:
        reasons["positive"].append("Uses secure HTTPS")

    # =========================
    # 🔴 NEGATIVE
    # =========================
    if features.get("fake_brand", 0):
        reasons["negative"].append("Brand impersonation")
        h_score += 0.4

    if features.get("brand_mismatch", 0):
        reasons["negative"].append("Domain mismatch")
        h_score += 0.4

    if features.get("domain_random", 0):
        reasons["negative"].append("Random-looking domain")
        h_score += 0.2

    if looks_like_typo(domain) and any(b in domain for b in ["google","amazon","paypal","facebook"]):
        reasons["negative"].append("Possible typo-squatting domain")
        h_score += 0.3

    # =========================
    # 🌐 NETWORK / SSL
    # =========================
    if dns_status is None:
        reasons["negative"].append("Domain could not be verified")
        h_score += 0.15

    if ssl_status == 0:
        h_score += 0.2
    elif ssl_status is None:
        reasons["negative"].append("SSL status unknown")
        h_score += 0.1

    # =========================
    # 🚨 HARD RULES
    # =========================
    if "xn--" in domain:
        return build_output(
            "Phishing",
            0.95,
            ["Encoded (punycode) domain"],
            is_https
        )

    if has_ip(url):
        return build_output(
            "Suspicious",
            0.7,
            ["Uses IP instead of domain"],
            is_https
        )

    # =========================
    # 🚨 SANITY CHECK
    # =========================
    if "Invalid domain structure" in sanity_reasons:
        return build_output(
            "Phishing",
            0.95,
            sanity_reasons,
            is_https
        )

    if len(sanity_reasons) >= 2:
        return build_output(
            "Phishing",
            0.9,
            sanity_reasons,
            is_https
        )

    if len(sanity_reasons) == 1:
        reasons["negative"].extend(sanity_reasons)
        h_score += 0.2

    # =========================
    # 🔑 KEYWORDS
    # =========================
    suspicious_words = ["secure", "login", "verify", "account", "update", "auth"]
    keyword_count = sum(word in url.lower() for word in suspicious_words)

    if keyword_count > 0:
        reasons["negative"].append("Suspicious keywords")
        h_score += 0.2

    # =========================
    # 🚨 PHISHING RULES
    # =========================
    KNOWN_BRANDS = ["amazon","paypal","facebook","google","netflix","hdfc","icici","sbi"]

    if features.get("fake_brand", 0) and features.get("brand_mismatch", 0):
        return build_output(
            "Phishing",
            0.95,
            ["Strong brand impersonation"],
            is_https
        )

    if keyword_count >= 2 and real_domain not in TRUSTED_DOMAINS:

        if any(b in domain for b in KNOWN_BRANDS):
            return build_output(
                "Phishing",
                0.9,
                ["Generic phishing-style domain"],
                is_https
            )

        return build_output(
            "Suspicious",
            0.75,
            ["Multiple suspicious keywords"],
            is_https
        )

    for brand in KNOWN_BRANDS:
        if brand in domain:

            if real_domain in TRUSTED_DOMAINS:
                break

            if keyword_count >= 1:

                # 🚨 Strong phishing if domain looks like fake brand site
                if "-" in domain or len(domain.split(".")) == 2:
                    return build_output(
                        "Phishing",
                        0.9,
                        ["Brand-based phishing domain"],
                        is_https
                    )

    # =========================
    # ⚖️ FINAL SCORE
    # =========================
    risk_score = 0.3 * prob + 0.4 * dl_prob + 0.3 * h_score
    risk_score = max(0, min(risk_score, 1))

    if risk_score >= 0.84:
        label = "Phishing"
    elif risk_score >= 0.53:
        label = "Suspicious"
    else:
        label = "Legitimate"

    # =========================
    # 🛡 TRUST OVERRIDE
    # =========================
    if rep == "trusted" and is_https and ssl_status == 1:
        return build_output(
            "Legitimate",
            0.95,
            ["Trusted domain", "Uses secure HTTPS"],
            is_https
        )

    # =========================
    # 🚨 FINAL PHISHING GUARD
    # =========================
    if label == "Phishing":
        strong_signal = (
            features.get("fake_brand", 0) or
            features.get("brand_mismatch", 0) or
            any(b in domain for b in KNOWN_BRANDS)
        )

        if not strong_signal:
            label = "Suspicious"
            risk_score = min(risk_score, 0.8)

    # =========================
    # 🔄 FINAL CORRECTIONS
    # =========================
    if label == "Legitimate" and not is_https:
        label = "Suspicious"

    if label == "Legitimate" and (dns_status is None or ssl_status is None):
        label = "Suspicious"

    # =========================
    # 📊 CONFIDENCE
    # =========================
    if label == "Phishing":
        confidence = risk_score
    elif label == "Suspicious":
        confidence = 0.5 + (risk_score / 2)
    else:
        confidence = min(1 - risk_score, 0.85)

    # =========================
    # 📢 OUTPUT FORMAT
    # =========================
    protocol_msg = "Uses HTTPS (secure connection)" if is_https else "Uses HTTP (not secure)"

    if label == "Phishing":
        safety_msg = "🚨 Dangerous site – do not use"
    elif label == "Suspicious":
        safety_msg = "⚠ Not secure – use with caution"
    else:
        safety_msg = "✔ Safe to use"

    final_reasons = [f"⚠️ Safety: {safety_msg}", f"🌐 {protocol_msg}"]

    clean_reasons = [r.lstrip("- ").strip() for r in reasons["positive"] + reasons["negative"] + reasons["neutral"]]
    final_reasons += [f"- {r}" for r in clean_reasons]

    return label, round(confidence, 2), final_reasons





def detect_url(url):
    label, confidence, reasons = final_decision(
        url,
        calibrated_model,
        dl_model
    )

    return {
        "url": url,
        "prediction": label,
        "confidence": float(confidence),
        "reasons": reasons
    }

    




    