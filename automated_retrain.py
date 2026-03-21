import os
import re
import math
import json
import joblib
from collections import Counter
from urllib.parse import urlparse, unquote

import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import roc_auc_score, accuracy_score, precision_recall_fscore_support
from sklearn.ensemble import HistGradientBoostingClassifier


# =========================================================
# CONFIG
# =========================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

# Check multiple possible locations for the dataset
possible_paths = [
    os.path.join(BASE_DIR, "Master_SentinURL_Dataset.csv"),
    os.path.join(BASE_DIR, "Merged_Ultimate_Dataset.csv"),
    os.path.join(PROJECT_ROOT, "Backup work", "Phishing Dataset.csv"),
    os.path.join(PROJECT_ROOT, "Phishing Dataset.csv")
]
DATASET_PATH = None
for p in possible_paths:
    if os.path.exists(p):
        DATASET_PATH = p
        break

if not DATASET_PATH:
    raise FileNotFoundError("Could not find Phishing Dataset.csv in expected locations.")

print(f"Using dataset: {DATASET_PATH}")
RANDOM_SEED = 42

SAVE_DIR_STAGE1 = os.path.join(BASE_DIR, "stage1_sandbox")
LIVE_DIR_STAGE1 = os.path.join(BASE_DIR, "stage1")
SAVE_DIR_STAGE2 = os.path.join(BASE_DIR, "stage2_sandbox")
LIVE_DIR_STAGE2 = os.path.join(BASE_DIR, "stage2")
os.makedirs(SAVE_DIR_STAGE1, exist_ok=True)
os.makedirs(SAVE_DIR_STAGE2, exist_ok=True)

TFIDF_SUBSET = 250_000
MAX_FEATURES = 100_000

# You want "almost no false positives"
TARGET_SAFE_FP_RATE_FOR_PHISH = 0.0002  

SUSPICIOUS_WORDS = [
    "login","signin","verify","update","secure","account","bank",
    "confirm","password","pay","billing","invoice","support","token"
]
BRANDS = [
    "paypal","google","apple","amazon","microsoft",
    "facebook","instagram","whatsapp","netflix","dhl","fedex"
]
RISKY_TLDS = {"tk","ml","ga","cf","gq"}

# Used only as metadata + for runtime allowlist suggestions
KNOWN_GOOD_DOMAINS = {
    "wikipedia.org","bbc.com","nytimes.com","oracle.com","cloudflare.com",
    "mozilla.org","gnu.org","openai.com"
}


# =========================================================
# URL HELPERS
# =========================================================
def normalize_label(x):
    s = str(x).strip().lower()
    return "phishing" if "phish" in s else "safe"


def normalize_url(u):
    u = str(u).strip()
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    return u


def safe_urlparse(u: str):
    try:
        return urlparse(u)
    except Exception:
        cleaned = re.sub(r"\[([^\]]+)\]", r"\1", u)
        try:
            return urlparse(cleaned)
        except Exception:
            return urlparse("http://invalid")


def entropy(s):
    if not s:
        return 0.0
    p = [c / len(s) for c in Counter(s).values()]
    return -sum(x * math.log2(x) for x in p if x > 0)


def has_ipv4(host):
    return 1 if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host or "") else 0


# =========================================================
# STAGE 2 FEATURES (stable; no "brand forgiveness" here)
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

    host_no_port = host.split(":")[0] if host else ""

    digits = sum(c.isdigit() for c in decoded)
    specials = sum((not c.isalnum()) for c in decoded)

    host_tokens = [t for t in re.split(r"[.\-]", host_no_port) if t]
    path_tokens = [t for t in path.split("/") if t]
    query_params = [t for t in query.split("&") if t]

    tld = host_no_port.split(".")[-1] if "." in host_no_port else ""

    return {
        "url_len": len(decoded),
        "host_len": len(host_no_port),
        "path_len": len(path),
        "query_len": len(query),

        "dots": decoded.count("."),
        "hyphens": decoded.count("-"),
        "slashes": decoded.count("/"),
        "underscores": decoded.count("_"),
        "digits": digits,
        "specials": specials,

        "digit_ratio": digits / max(len(decoded), 1),
        "special_ratio": specials / max(len(decoded), 1),

        "subdomains": host_no_port.count("."),
        "host_tokens": len(host_tokens),
        "path_tokens": len(path_tokens),
        "query_params": len(query_params),

        "https": 1 if decoded.startswith("https") else 0,
        "has_ipv4": has_ipv4(host_no_port),
        "punycode": 1 if "xn--" in host_no_port else 0,
        "at_count": decoded.count("@"),
        "pct_count": decoded.count("%"),
        "eq_count": decoded.count("="),

        "suspicious_kw": sum(w in low for w in SUSPICIOUS_WORDS),
        "brand_hits": sum(b in low for b in BRANDS),
        "redirect_like": 1 if re.search(r"(redirect|next|url|continue|dest|destination)=", low) else 0,

        "entropy_url": entropy(decoded),
        "entropy_host": entropy(host_no_port),
        "entropy_path": entropy(path),

        "risky_tld": 1 if tld in RISKY_TLDS else 0,
    }


def build_tabular(urls):
    cols = list(url_features("http://example.com").keys())
    Xdf = pd.DataFrame([url_features(u) for u in urls], columns=cols)
    return Xdf, cols


# =========================================================
# LOAD DATA
# =========================================================
print("Loading dataset...")
df = pd.read_csv(DATASET_PATH, encoding="latin1", low_memory=False)
if len(df.columns) > 0 and 'url' in df.columns[0].lower():
    df.rename(columns={df.columns[0]: 'URL'}, inplace=True)
if len(df.columns) > 1 and 'type' in df.columns[1].lower():
    df.rename(columns={df.columns[1]: 'Type'}, inplace=True)

df = df.loc[:, ~df.columns.str.contains(r"^Unnamed", na=False)]
df = df.dropna(axis=1, how="all")

if "URL" not in df.columns or "Type" not in df.columns:
    raise ValueError("Dataset must contain columns: URL and Type")

df["URL"] = df["URL"].astype(str).str.strip()
df["Type"] = df["Type"].apply(normalize_label)
df = df[df["URL"].astype(bool)].copy()

# Explicit label mapping: safe=0, phishing=1
y = (df["Type"].values == "phishing").astype(int)
urls = df["URL"].values

print("Dataset shape:", df.shape, "| phishing%:", float(y.mean()))


# =========================================================
# SPLITS: train / test (threshold tuned on test SAFE quantile)
# (Simple + stable for your environment)
# =========================================================
idx = np.arange(len(df))
idx_train, idx_test, y_train, y_test = train_test_split(
    idx, y, test_size=0.20, random_state=RANDOM_SEED, stratify=y
)

urls_train = urls[idx_train]
urls_test  = urls[idx_test]


# =========================================================
# STAGE 1: TF-IDF + LR (CALIBRATED, MODERN SKLEARN)
# =========================================================
print("\nTraining Stage 1 TF-IDF + LR (calibrated)...")

rng = np.random.default_rng(RANDOM_SEED)
subset_idx = rng.choice(len(urls_train), size=min(TFIDF_SUBSET, len(urls_train)), replace=False)

tfidf = TfidfVectorizer(
    analyzer="char",
    ngram_range=(2, 6),
    max_features=MAX_FEATURES,
    sublinear_tf=True,
)

X1_tr = tfidf.fit_transform(urls_train[subset_idx])

lr_base = LogisticRegression(
    max_iter=5000,
    C=10.0,
    class_weight="balanced",
    solver="liblinear",
)

# ✅ Works on modern sklearn (no cv="prefit")
s1_cal = CalibratedClassifierCV(lr_base, method="sigmoid", cv=3)
s1_cal.fit(X1_tr, y_train[subset_idx])

X1_te = tfidf.transform(urls_test)
p1_test = s1_cal.predict_proba(X1_te)[:, 1]
s1_auc = roc_auc_score(y_test, p1_test)
print("Stage1 ROC-AUC:", s1_auc)

# ── NEW: K-Fold Validation for Stage 1 ──
print("\nRunning 5-Fold Cross-Validation for Stage 1...")
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
s1_cv_scores = cross_val_score(s1_cal, X1_tr, y_train[subset_idx], cv=skf, scoring='roc_auc')
print(f"Stage 1 Mean CV ROC-AUC: {s1_cv_scores.mean():.4f} (+/- {s1_cv_scores.std() * 2:.4f})")


# =========================================================
# STAGE 2: HGB (TABULAR)
# =========================================================
print("\nTraining Stage 2 HGB (tabular)...")
X2_tr_df, STAGE2_COLS = build_tabular(urls_train)
X2_te_df, _ = build_tabular(urls_test)

X2_tr = X2_tr_df.to_numpy(np.float32)
X2_te = X2_te_df.to_numpy(np.float32)

s2_hgb = HistGradientBoostingClassifier(
    max_depth=6,
    learning_rate=0.07,
    max_iter=300,
    min_samples_leaf=50,
    random_state=RANDOM_SEED,
)
s2_hgb.fit(X2_tr, y_train)

p2_test = s2_hgb.predict_proba(X2_te)[:, 1]
s2_auc = roc_auc_score(y_test, p2_test)
print("Stage2 ROC-AUC:", s2_auc)

# ── NEW: K-Fold Validation for Stage 2 ──
print("\nRunning 5-Fold Cross-Validation for Stage 2...")
s2_cv_scores = cross_val_score(s2_hgb, X2_tr, y_train, cv=skf, scoring='roc_auc')
print(f"Stage 2 Mean CV ROC-AUC: {s2_cv_scores.mean():.4f} (+/- {s2_cv_scores.std() * 2:.4f})")


# =========================================================
# FUSION (Stage-2 dominant to prevent Stage-1 spikes)
# =========================================================
W1, W2 = 0.20, 0.80
p_test = W1 * p1_test + W2 * p2_test
print("Fusion ROC-AUC:", roc_auc_score(y_test, p_test))


# =========================================================
# FP-CONTROLLED THRESHOLDS
# Choose PHISH_MIN so SAFE FP rate is <= target.
# =========================================================
safe_mask = (y_test == 0)
safe_probs = p_test[safe_mask]

q = 1.0 - TARGET_SAFE_FP_RATE_FOR_PHISH
PHISH_MIN = float(np.quantile(safe_probs, q))

# Bands (you can adjust later)
SAFE_MAX = float(np.quantile(safe_probs, 0.50))   # median safe
SUSP_SAFE_MAX = float(np.quantile(safe_probs, 0.95))

print("\nChosen thresholds:")
print("SAFE_MAX:", SAFE_MAX)
print("SUSP_SAFE_MAX:", SUSP_SAFE_MAX)
print("PHISH_MIN:", PHISH_MIN)


# =========================================================
# SAVE ARTIFACTS + POLICY META
# =========================================================
joblib.dump(tfidf, os.path.join(SAVE_DIR_STAGE1, "tfidf.joblib"))
joblib.dump(s1_cal, os.path.join(SAVE_DIR_STAGE1, "calibrated_logreg.joblib"))
print("[v] Saved Stage 1: tfidf.joblib + calibrated_logreg.joblib ->", SAVE_DIR_STAGE1)

joblib.dump(s2_hgb, os.path.join(SAVE_DIR_STAGE2, "stage2_hgb.joblib"))
joblib.dump(STAGE2_COLS, os.path.join(SAVE_DIR_STAGE2, "stage2_feature_columns.joblib"))
print("[v] Saved Stage 2: stage2_hgb.joblib + stage2_feature_columns.joblib ->", SAVE_DIR_STAGE2)

meta = {
    "label_map": {"safe": 0, "phishing": 1},
    "fusion": {"w_stage1": W1, "w_stage2": W2},
    "bands": {
        "SAFE_MAX": SAFE_MAX,
        "SUSP_SAFE_MAX": SUSP_SAFE_MAX,
        "PHISH_MIN": PHISH_MIN
    },
    "fp_target_on_safe_for_phish": TARGET_SAFE_FP_RATE_FOR_PHISH,
    "known_good_domains": sorted(list(KNOWN_GOOD_DOMAINS)),
}
with open(os.path.join(SAVE_DIR_STAGE2, "policy_meta.json"), "w", encoding="utf-8") as f:
    json.dump(meta, f, indent=2)

# =========================================================
# FINAL SCIENTIFIC VALIDATION REPORT
# =========================================================
print("\n" + "="*65)
print("             SCIENTIFIC VALIDATION REPORT")
print("="*65)
print(f"Methodology: 5-Fold Stratified Cross-Validation")
print(f"Dataset Size: {len(df):,} URLs")
print("-" * 65)
print(f"STAGE 1 (TF-IDF + LR):")
print(f"  • Holdout ROC-AUC : {s1_auc:.4f}")
print(f"  • Cross-Val Mean  : {s1_cv_scores.mean():.4f}")
print(f"  • Cross-Val Std   : ±{s1_cv_scores.std():.4f}")
print("-" * 65)
print(f"STAGE 2 (HGB Tabular):")
print(f"  • Holdout ROC-AUC : {s2_auc:.4f}")
print(f"  • Cross-Val Mean  : {s2_cv_scores.mean():.4f}")
print(f"  • Cross-Val Std   : ±{s2_cv_scores.std():.4f}")
print("-" * 65)
print(f"HYBRID FUSION:")
print(f"  • Holdout ROC-AUC : {roc_auc_score(y_test, p_test):.4f}")
print("="*65)


# =========================================================
# GOLDEN GATE CI/CD VALIDATION
# =========================================================
import shutil
from datetime import datetime

final_auc = roc_auc_score(y_test, p_test)
THRESHOLD = 0.9960

log_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Automatic Retrain Run\n"
log_msg += f"  - Dataset Size: {len(df):,} URLs\n"
log_msg += f"  - New Model AUC: {final_auc:.4f}\n"

if final_auc >= THRESHOLD:
    log_msg += f"  [SUCCESS] Accuracy {final_auc:.4f} >= {THRESHOLD}. Deploying new weights!\n"
    print(f"\n>>> [GOLDEN GATE PASSED] Accuracy {final_auc:.4f} >= {THRESHOLD}. Deploying... <<<")
    
    # ── NEW: ARCHIVE SYSTEM ──
    archive_root = os.path.join(BASE_DIR, "models", "archive")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ts_dir = os.path.join(archive_root, ts)
    os.makedirs(ts_dir, exist_ok=True)
    
    # Overwrite Live Directories
    for d in [LIVE_DIR_STAGE1, LIVE_DIR_STAGE2]:
        os.makedirs(d, exist_ok=True)
        
    for f in os.listdir(SAVE_DIR_STAGE1):
        src = os.path.join(SAVE_DIR_STAGE1, f)
        shutil.copy2(src, os.path.join(LIVE_DIR_STAGE1, f))
        shutil.copy2(src, os.path.join(ts_dir, "s1_" + f))
        
    for f in os.listdir(SAVE_DIR_STAGE2):
        src = os.path.join(SAVE_DIR_STAGE2, f)
        shutil.copy2(src, os.path.join(LIVE_DIR_STAGE2, f))
        shutil.copy2(src, os.path.join(ts_dir, "s2_" + f))
        
    # Cleanup Sandbox
    shutil.rmtree(SAVE_DIR_STAGE1)
    shutil.rmtree(SAVE_DIR_STAGE2)
    print("[v] Models Live and Sandbox Destroyed.")
    
else:
    log_msg += f"  [ABORT] Accuracy {final_auc:.4f} < {THRESHOLD}. Rejecting new models!\n"
    print(f"\n>>> [GOLDEN GATE FAILED] Accuracy {final_auc:.4f} < {THRESHOLD}. Aborting Deployment... <<<")
    
    # Destroy sandbox to prevent accidental usage
    shutil.rmtree(SAVE_DIR_STAGE1)
    shutil.rmtree(SAVE_DIR_STAGE2)
    print("[x] Sandbox Destroyed. Reverting to Previous Models.")

with open(os.path.join(BASE_DIR, "retrain_log.txt"), "a", encoding="utf-8") as f:
    f.write(log_msg + "\n")

print("\n[v] Automated Retrain Pipeline Finished!")

