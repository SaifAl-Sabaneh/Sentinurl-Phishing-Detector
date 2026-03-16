# phishing_train_test.py
# FINAL VERSION — Threshold frozen at 0.30
# Run:
#   python phishing_train_test.py
# Optional:
#   python phishing_train_test.py --subset_text 250000
#   python phishing_train_test.py --save_dir "models"

import argparse
import math
import os
import re
from collections import Counter
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_recall_fscore_support,
)

# =====================
# CONFIG (FROZEN)
# =====================
DEFAULT_DATA_PATH = r"C:\Users\Asus\Desktop\Graduation Project\Phishing Dataset.csv"
PHISHING_THRESHOLD = 0.30   # 🔒 FROZEN THRESHOLD

# =====================
# URL FEATURE HELPERS
# =====================
SUSPICIOUS_WORDS = ["login", "verify", "update", "secure", "account", "bank", "confirm", "password", "paypal", "signin"]
RISKY_TLDS = ["tk", "ml", "ga", "cf", "gq"]
BRANDS = ["paypal", "google", "apple", "amazon", "facebook"]

def url_entropy(url):
    url = url or ""
    if not url:
        return 0.0
    probs = [c / len(url) for c in Counter(url).values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)

def suspicious_keyword_count(url):
    u = (url or "").lower()
    return sum(w in u for w in SUSPICIOUS_WORDS)

def digit_ratio(url):
    url = url or ""
    return sum(c.isdigit() for c in url) / max(1, len(url))

def uses_ip_address(url):
    return 1 if re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", url or "") else 0

def risky_tld(url):
    u = (url or "").lower()
    return 1 if any(u.endswith("." + t) for t in RISKY_TLDS) else 0

def brand_in_url(url):
    u = (url or "").lower()
    return 1 if any(b in u for b in BRANDS) else 0

def normalize_url(url):
    u = (url or "").strip()
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    return u

def get_domain(url):
    try:
        return urlparse(normalize_url(url)).netloc or ""
    except Exception:
        return ""

def path_depth(url):
    try:
        return urlparse(normalize_url(url)).path.count("/")
    except Exception:
        return 0

def extract_custom_features(url):
    raw = (url or "").strip()
    domain = get_domain(raw)
    return {
        "cust_url_len": len(raw),
        "cust_dots": raw.count("."),
        "cust_hyphens": raw.count("-"),
        "cust_https": 1 if raw.lower().startswith("https") else 0,
        "cust_susp_kw": suspicious_keyword_count(raw),
        "cust_entropy": url_entropy(raw),
        "cust_ip": uses_ip_address(raw),
        "cust_digit_ratio": digit_ratio(raw),
        "cust_domain_len": len(domain),
        "cust_subdomains": domain.count("."),
        "cust_path_depth": path_depth(raw),
        "cust_risky_tld": risky_tld(raw),
        "cust_brand_abuse": brand_in_url(raw),
    }

# =====================
# UTILS
# =====================
def find_column(df, candidates):
    cols = {c.lower(): c for c in df.columns}
    for cand in candidates:
        if cand.lower() in cols:
            return cols[cand.lower()]
    for c in df.columns:
        if any(cand.lower() in c.lower() for cand in candidates):
            return c
    raise ValueError("Required column not found")

def binarize_labels(s):
    s = s.astype(str).str.lower().str.strip()
    def f(x):
        if any(k in x for k in ["phish", "scam", "fraud", "mal"]):
            return "phishing"
        return "safe"
    return s.map(f)

# =====================
# ARGUMENTS
# =====================
parser = argparse.ArgumentParser()
parser.add_argument("--data", default=DEFAULT_DATA_PATH)
parser.add_argument("--test_size", type=float, default=0.2)
parser.add_argument("--seed", type=int, default=42)
parser.add_argument("--subset_text", type=int, default=250000)
parser.add_argument("--save_dir", default="")
args = parser.parse_args()

# =====================
# LOAD DATA
# =====================
df = pd.read_csv(args.data, encoding="latin1", low_memory=False)
df = df.loc[:, ~df.columns.str.contains("^Unnamed", na=False)]
df = df.dropna(axis=1, how="all")

url_col = find_column(df, ["url"])
type_col = find_column(df, ["type", "label", "class"])

df = df.dropna(subset=[url_col, type_col])
df[url_col] = df[url_col].astype(str)
df[type_col] = binarize_labels(df[type_col])

# =====================
# SPLIT
# =====================
idx = np.arange(len(df))
y_all = df[type_col].values

idx_train, idx_test = train_test_split(
    idx, test_size=args.test_size, random_state=args.seed, stratify=y_all
)

df_train = df.iloc[idx_train].reset_index(drop=True)
df_test = df.iloc[idx_test].reset_index(drop=True)

le = LabelEncoder()
y_train = le.fit_transform(df_train[type_col])
y_test = le.transform(df_test[type_col])

# Ensure phishing = 1
if list(le.classes_) == ["phishing", "safe"]:
    y_train = 1 - y_train
    y_test = 1 - y_test

# =====================
# STRUCTURED FEATURES
# =====================
numeric_cols = [
    c for c in df.columns
    if c not in [url_col, type_col] and df[c].dtype.kind in "biufc"
]

X_train_struct = pd.concat([
    df_train[numeric_cols].reset_index(drop=True),
    pd.DataFrame([extract_custom_features(u) for u in df_train[url_col]])
], axis=1).fillna(0)

X_test_struct = pd.concat([
    df_test[numeric_cols].reset_index(drop=True),
    pd.DataFrame([extract_custom_features(u) for u in df_test[url_col]])
], axis=1).fillna(0)

rf = RandomForestClassifier(
    n_estimators=500,
    class_weight="balanced",
    random_state=args.seed,
    n_jobs=-1
)
rf.fit(X_train_struct, y_train)
rf_prob = rf.predict_proba(X_test_struct)[:, 1]

# =====================
# TEXT MODEL
# =====================
train_urls = df_train[url_col].values
test_urls = df_test[url_col].values

if args.subset_text and len(train_urls) > args.subset_text:
    rng = np.random.default_rng(args.seed)
    idx_sub = rng.choice(len(train_urls), args.subset_text, replace=False)
    train_urls = train_urls[idx_sub]
    y_train_text = y_train[idx_sub]
else:
    y_train_text = y_train

tfidf = TfidfVectorizer(
    analyzer="char",
    ngram_range=(2, 6),
    min_df=2,
    max_df=0.95,
    max_features=100000,
    sublinear_tf=True,
    strip_accents="unicode",
)

X_train_text = tfidf.fit_transform(train_urls)
X_test_text = tfidf.transform(test_urls)

lr = LogisticRegression(
    max_iter=5000,
    C=10.0,
    class_weight="balanced",
    solver="liblinear"
)
lr.fit(X_train_text, y_train_text)
text_prob = lr.predict_proba(X_test_text)[:, 1]

# =====================
# FINAL DECISION (FROZEN)
# =====================
final_prob = text_prob   # 🔒 text-only (best performer)
y_pred = (final_prob >= PHISHING_THRESHOLD).astype(int)

# =====================
# RESULTS
# =====================
print("\n==============================")
print("FINAL MODEL (Threshold = 0.30)")
print("==============================")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred, digits=4))
print("ROC-AUC:", roc_auc_score(y_test, final_prob))

# =====================
# SAVE (OPTIONAL)
# =====================
if args.save_dir:
    os.makedirs(args.save_dir, exist_ok=True)
    joblib.dump(tfidf, os.path.join(args.save_dir, "tfidf.pkl"))
    joblib.dump(lr, os.path.join(args.save_dir, "text_model.pkl"))
    joblib.dump(le, os.path.join(args.save_dir, "label_encoder.pkl"))
    joblib.dump({"threshold": PHISHING_THRESHOLD}, os.path.join(args.save_dir, "config.pkl"))
    print("\nModels saved to:", args.save_dir)
