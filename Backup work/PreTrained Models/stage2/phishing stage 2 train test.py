import os
import re
import math
import joblib
from collections import Counter
from urllib.parse import urlparse, unquote

import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, confusion_matrix, classification_report,
    roc_auc_score, precision_recall_fscore_support
)
from sklearn.ensemble import HistGradientBoostingClassifier


# =========================================================
# CONFIG (NO CLI ARGS)
# =========================================================
DATASET_PATH = r"C:\Users\Asus\Desktop\Graduation Project\Phishing Dataset.csv"
TEST_SIZE = 0.2
RANDOM_SEED = 42
TFIDF_SUBSET = 250_000

# Stage-1/Stage-2 save dirs
SAVE_DIR_STAGE1 = r"C:\Users\Asus\Desktop\Graduation Project\PreTrained Models\stage1"
SAVE_DIR_STAGE2 = r"C:\Users\Asus\Desktop\Graduation Project\PreTrained Models\stage2"

# Decision bands (after calibration)
SAFE_MAX = 0.20
PHISH_MIN = 0.65

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "update", "secure", "account", "bank",
    "confirm", "password", "pay", "billing", "invoice", "support", "token"
]
BRANDS = [
    "paypal", "google", "apple", "amazon", "microsoft",
    "facebook", "instagram", "whatsapp", "netflix", "dhl", "fedex"
]
RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq"}

# Optional: small "top domains" bias feature (safe big brands)
TOP_DOMAINS = {
    "google.com", "www.google.com",
    "amazon.com", "www.amazon.com",
    "microsoft.com", "www.microsoft.com",
    "apple.com", "www.apple.com",
    "paypal.com", "www.paypal.com",
    "facebook.com", "www.facebook.com"
}


# =========================================================
# HELPERS
# =========================================================
def normalize_label(x):
    s = str(x).strip().lower()
    if "phish" in s:
        return "phishing"
    return "safe"


def normalize_url(u):
    u = str(u).strip()
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    return u


def entropy(s):
    if not s:
        return 0.0
    p = [c / len(s) for c in Counter(s).values()]
    return -sum(x * math.log2(x) for x in p if x > 0)


def has_ipv4(host):
    return 1 if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host or "") else 0


def safe_urlparse(u: str):
    """
    Robust URL parser that never crashes on malformed bracketed hosts.
    """
    try:
        return urlparse(u)
    except Exception:
        cleaned = re.sub(r"\[([^\]]+)\]", r"\1", u)
        try:
            return urlparse(cleaned)
        except Exception:
            return urlparse("http://invalid")


def decision_band(p: float) -> str:
    if p <= SAFE_MAX:
        return "SAFE"
    if p >= PHISH_MIN:
        return "PHISHING"
    return "SUSPICIOUS"


# =========================================================
# STAGE 2 FEATURE ENGINEERING (IMPROVED)
# =========================================================
def url_features(url):
    raw = str(url)
    decoded = unquote(raw)
    low = decoded.lower()

    u = normalize_url(decoded)
    p = safe_urlparse(u)

    host = (p.netloc or "").lower()
    path = p.path or ""
    query = p.query or ""

    # Strip port for pure host
    host_no_port = host.split(":")[0] if host else ""
    port_present = 1 if (host and ":" in host) else 0

    digits = sum(c.isdigit() for c in decoded)
    specials = sum((not c.isalnum()) for c in decoded)

    host_tokens = [t for t in re.split(r"[.\-]", host_no_port) if t]
    path_tokens = [t for t in path.split("/") if t]
    query_params = [t for t in query.split("&") if t]

    tld = host_no_port.split(".")[-1] if "." in host_no_port else ""

    # common obfuscation / redirect signals
    redirect_like = 1 if re.search(r"(redirect|next|url|continue|dest|destination)=", low) else 0
    double_slash_path = 1 if ("//" in path) else 0

    return {
        # lengths
        "url_len": len(decoded),
        "host_len": len(host_no_port),
        "path_len": len(path),
        "query_len": len(query),

        # counts
        "dots": decoded.count("."),
        "hyphens": decoded.count("-"),
        "slashes": decoded.count("/"),
        "underscores": decoded.count("_"),
        "digits": digits,
        "specials": specials,

        # ratios
        "digit_ratio": digits / max(len(decoded), 1),
        "special_ratio": specials / max(len(decoded), 1),

        # structure
        "subdomains": host_no_port.count("."),
        "host_tokens": len(host_tokens),
        "path_tokens": len(path_tokens),
        "query_params": len(query_params),
        "path_depth": path.count("/"),

        # suspicious patterns
        "https": 1 if decoded.startswith("https") else 0,
        "has_ipv4": has_ipv4(host_no_port),
        "punycode": 1 if "xn--" in host_no_port else 0,
        "at_count": decoded.count("@"),
        "pct_count": decoded.count("%"),
        "eq_count": decoded.count("="),
        "port_present": port_present,
        "double_slash_path": double_slash_path,

        "suspicious_kw": sum(w in low for w in SUSPICIOUS_WORDS),
        "brand_hits": sum(b in low for b in BRANDS),
        "redirect_like": redirect_like,

        # entropy
        "entropy_url": entropy(decoded),
        "entropy_host": entropy(host_no_port),
        "entropy_path": entropy(path),
        "entropy_query": entropy(query),

        # risky tld
        "risky_tld": 1 if tld in RISKY_TLDS else 0,

        # top-domain bias (helps reduce false positives on real big brands)
        "top_domain": 1 if host_no_port in TOP_DOMAINS else 0,
    }


# EXACT feature order for Stage-2
STAGE2_FEATURES = list(url_features("http://example.com").keys())


# =========================================================
# EVAL
# =========================================================
def evaluate(y_true, y_pred, y_prob, title):
    acc = accuracy_score(y_true, y_pred)
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)

    print("\n==============================")
    print(title)
    print("==============================")
    print(f"Accuracy: {acc:.6f}")
    print(f"Precision: {p:.4f} | Recall: {r:.4f} | F1: {f1:.4f}")
    print("Confusion matrix:\n", confusion_matrix(y_true, y_pred))
    print("Classification report:\n", classification_report(y_true, y_pred, digits=4))
    try:
        print("ROC-AUC:", roc_auc_score(y_true, y_prob))
    except Exception:
        print("ROC-AUC: (could not compute)")


# =========================================================
# MAIN
# =========================================================
print("Loading dataset...")
df = pd.read_csv(DATASET_PATH, encoding="latin1", low_memory=False)
df = df.loc[:, ~df.columns.str.contains(r"^Unnamed", na=False)]
df = df.dropna(axis=1, how="all")

if "URL" not in df.columns or "Type" not in df.columns:
    raise ValueError("Dataset must contain columns: URL and Type")

df["URL"] = df["URL"].astype(str).str.strip()
df["Type"] = df["Type"].apply(normalize_label)
df = df[df["URL"].astype(bool)].copy()

print("Dataset shape:", df.shape)

# Split
idx = np.arange(len(df))
y_str = df["Type"].values

idx_tr, idx_te = train_test_split(
    idx, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y_str
)

train_df = df.iloc[idx_tr].reset_index(drop=True)
test_df = df.iloc[idx_te].reset_index(drop=True)

# Encode labels so that phishing = 1, safe = 0
le = LabelEncoder()
le.fit(["safe", "phishing"])  # force stable mapping
y_train = le.transform(train_df["Type"].values)
y_test = le.transform(test_df["Type"].values)

# =========================================================
# STAGE 1 — TF-IDF + LR (CALIBRATED)
# =========================================================
print("\nTraining Stage 1 (TF-IDF + Calibrated LR)...")

train_urls = train_df["URL"].values
test_urls = test_df["URL"].values

rng = np.random.default_rng(RANDOM_SEED)
subset_idx = rng.choice(len(train_urls), size=min(TFIDF_SUBSET, len(train_urls)), replace=False)

tfidf = TfidfVectorizer(
    analyzer="char",
    ngram_range=(2, 6),
    max_features=100_000,
    sublinear_tf=True,
)

X_tr_text = tfidf.fit_transform(train_urls[subset_idx])
X_te_text = tfidf.transform(test_urls)

lr_base = LogisticRegression(
    max_iter=5000,
    C=10.0,
    class_weight="balanced",
    solver="liblinear",
)

# Calibrate probabilities (IMPORTANT)
lr = CalibratedClassifierCV(lr_base, method="sigmoid", cv=3)
lr.fit(X_tr_text, y_train[subset_idx])

stage1_prob = lr.predict_proba(X_te_text)[:, 1]

# Convert probability to "phishing class" using PHISH_MIN for binary evaluation
stage1_pred = (stage1_prob >= PHISH_MIN).astype(int)
evaluate(y_test, stage1_pred, stage1_prob, "STAGE 1 — TF-IDF + Calibrated LR")


# =========================================================
# STAGE 2 — OFFLINE TABULAR MODEL (IMPROVED FEATURES)
# =========================================================
print("\nBuilding Stage 2 offline features...")

X_tr_tab_df = pd.DataFrame(
    [url_features(u) for u in train_df["URL"].values],
    columns=STAGE2_FEATURES
)
X_te_tab_df = pd.DataFrame(
    [url_features(u) for u in test_df["URL"].values],
    columns=STAGE2_FEATURES
)

X_tr_tab = X_tr_tab_df.to_numpy(dtype=np.float32)
X_te_tab = X_te_tab_df.to_numpy(dtype=np.float32)

print("Training Stage 2 (HistGradientBoosting)...")
hgb = HistGradientBoostingClassifier(
    max_depth=6,
    learning_rate=0.07,
    max_iter=300,
    min_samples_leaf=50,
    random_state=RANDOM_SEED,
)
hgb.fit(X_tr_tab, y_train)

stage2_prob = hgb.predict_proba(X_te_tab)[:, 1]
stage2_pred = (stage2_prob >= PHISH_MIN).astype(int)
evaluate(y_test, stage2_pred, stage2_prob, "STAGE 2 — HGB (Tabular)")


# =========================================================
# FINAL ENSEMBLE (LESS AGGRESSIVE THAN MAX)
# Weighted blend reduces false positives
# =========================================================
final_prob = 0.60 * stage1_prob + 0.40 * stage2_prob
final_pred = (final_prob >= PHISH_MIN).astype(int)

evaluate(y_test, final_pred, final_prob, "FINAL ENSEMBLE (0.60*S1 + 0.40*S2)")


# =========================================================
# SAVE MODELS + STAGE2 FEATURE SCHEMA
# =========================================================
os.makedirs(SAVE_DIR_STAGE1, exist_ok=True)
os.makedirs(SAVE_DIR_STAGE2, exist_ok=True)

joblib.dump(tfidf, os.path.join(SAVE_DIR_STAGE1, "tfidf.joblib"))
joblib.dump(lr, os.path.join(SAVE_DIR_STAGE1, "calibrated_logreg.joblib"))
print("✅ Saved Stage 1: tfidf.joblib, calibrated_logreg.joblib ->", SAVE_DIR_STAGE1)

joblib.dump(hgb, os.path.join(SAVE_DIR_STAGE2, "stage2_hgb.joblib"))
joblib.dump(STAGE2_FEATURES, os.path.join(SAVE_DIR_STAGE2, "stage2_feature_columns.joblib"))
print("✅ Saved Stage 2: stage2_hgb.joblib + stage2_feature_columns.joblib ->", SAVE_DIR_STAGE2)

print("\n✅ DONE: Training + Evaluation + Saving completed successfully.")

# Optional quick sanity check:
# print("google.com stage1 prob:", stage1_prob[0], "band:", decision_band(stage1_prob[0]))
