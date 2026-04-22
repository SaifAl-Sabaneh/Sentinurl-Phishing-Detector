"""
model_evaluation.py
====================
Evaluates the pre-trained SentinURL Stage 1 + Stage 2 models against
a large, ground-truth labelled dataset.

Test composition: 100,000 URLs total
  - 70,000 Phishing  (70%)
  - 30,000 Safe      (30%)

Uses ONLY the saved .joblib models — no retraining.
"""

import os
import sys
import time
import warnings
import numpy as np
import pandas as pd
import joblib
from concurrent.futures import ThreadPoolExecutor
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    precision_recall_fscore_support,
)

warnings.filterwarnings("ignore")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Import feature extractor from existing codebase ──────────────────────────
try:
    from enhanced_original import url_features
    print("[OK] Loaded url_features from enhanced_original.py")
except Exception:
    # Fallback: use the feature extractor embedded in train_stage2.py
    import re, math
    from collections import Counter
    from urllib.parse import urlparse, unquote

    BRANDS = ["paypal","google","apple","amazon","microsoft",
              "facebook","instagram","whatsapp","netflix","dhl","fedex"]
    RISKY_TLDS = {"tk","ml","ga","cf","gq"}
    TOP_DOMAINS = {"google.com","www.google.com","amazon.com","www.amazon.com",
                   "microsoft.com","apple.com","paypal.com","facebook.com"}

    def entropy(s):
        if not s: return 0.0
        p = [c/len(s) for c in Counter(s).values()]
        return -sum(x*math.log2(x) for x in p if x > 0)

    def get_vowel_consonant_ratio(s):
        if not s: return 0.0
        v = sum(c in "aeiou" for c in s)
        c = sum(c in "bcdfghjklmnpqrstvwxyz" for c in s)
        return v/c if c else float(v)

    def url_features(url):
        raw = str(url)
        decoded = unquote(raw)
        low = decoded.lower()
        u = raw if raw.startswith(("http://","https://")) else "http://"+raw
        try: p = urlparse(u)
        except Exception: p = urlparse("http://invalid")
        host = (p.netloc or "").lower()
        path = p.path or ""
        query = p.query or ""
        host_no_port = host.split(":")[0] if host else ""
        port_present = 1 if (":" in host) else 0
        digits = sum(c.isdigit() for c in decoded)
        specials = sum((not c.isalnum()) for c in decoded)
        host_tokens = [t for t in re.split(r"[.\-]", host_no_port) if t]
        path_tokens = [t for t in path.split("/") if t]
        query_params = [t for t in query.split("&") if t]
        max_host_token_len = max([len(t) for t in host_tokens]) if host_tokens else 0
        max_path_token_len = max([len(t) for t in path_tokens]) if path_tokens else 0
        tld = host_no_port.split(".")[-1] if "." in host_no_port else ""
        redirect_like = 1 if re.search(r"(redirect|next|url|continue|dest)=", low) else 0
        has_login = 1 if any(w in low for w in ["login","signin","verify","secure","account","auth"]) else 0
        has_finance = 1 if any(w in low for w in ["bank","pay","billing","invoice","crypto","wallet"]) else 0
        has_scam = 1 if any(w in low for w in ["free","bonus","winner","hack","adware","malware"]) else 0
        has_ipv4 = 1 if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host_no_port or "") else 0
        return {
            "url_len": len(decoded), "host_len": len(host_no_port), "path_len": len(path),
            "query_len": len(query), "max_host_token_len": max_host_token_len,
            "max_path_token_len": max_path_token_len, "dots": decoded.count("."),
            "hyphens": decoded.count("-"), "slashes": decoded.count("/"),
            "underscores": decoded.count("_"), "digits": digits, "specials": specials,
            "digit_ratio": digits/max(len(decoded),1), "special_ratio": specials/max(len(decoded),1),
            "vc_ratio_host": get_vowel_consonant_ratio(host_no_port),
            "subdomains": host_no_port.count("."), "host_tokens": len(host_tokens),
            "path_tokens": len(path_tokens), "query_params": len(query_params),
            "path_depth": path.count("/"), "https": 1 if decoded.startswith("https") else 0,
            "has_ipv4": has_ipv4, "punycode": 1 if "xn--" in host_no_port else 0,
            "at_count": decoded.count("@"), "pct_count": decoded.count("%"),
            "eq_count": decoded.count("="), "port_present": port_present,
            "double_slash_path": 1 if "//" in path else 0, "has_login": has_login,
            "has_finance": has_finance, "has_scam": has_scam,
            "brand_hits": sum(b in low for b in BRANDS), "redirect_like": redirect_like,
            "entropy_url": entropy(decoded), "entropy_host": entropy(host_no_port),
            "entropy_path": entropy(path), "entropy_query": entropy(query),
            "risky_tld": 1 if tld in RISKY_TLDS else 0,
            "top_domain": 1 if host_no_port in TOP_DOMAINS else 0,
        }
    print("[OK] Using built-in url_features fallback")


# ── Config ────────────────────────────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH  = os.path.join(os.path.dirname(BASE_DIR), "steps", "Merged Files.csv")
S1_TFIDF      = os.path.join(BASE_DIR, os.path.join("models", "stage1"), "tfidf.joblib")
S1_MODEL      = os.path.join(BASE_DIR, os.path.join("models", "stage1"), "calibrated_logreg.joblib")
S2_MODEL      = os.path.join(BASE_DIR, os.path.join("models", "stage2"), "stage2_hgb.joblib")
S2_COLS       = os.path.join(BASE_DIR, os.path.join("models", "stage2"), "stage2_feature_columns.joblib")

N_PHISHING    = 70_000
N_SAFE        = 30_000
THRESHOLD     = 0.25
FUSION_W1     = 0.40   # Stage 1 weight
FUSION_W2     = 0.60   # Stage 2 weight
RANDOM_SEED   = 42

# ── Banner ────────────────────────────────────────────────────────────────────
print("\n" + "="*65)
print("  SENTINURL — LARGE-SCALE MODEL ACCURACY EVALUATION")
print(f"  Test Set: {N_PHISHING:,} Phishing + {N_SAFE:,} Safe = {N_PHISHING+N_SAFE:,} URLs")
print("="*65 + "\n")

# ── Load models ───────────────────────────────────────────────────────────────
print("[1/5] Loading pre-trained models...")
tfidf   = joblib.load(S1_TFIDF)
logreg  = joblib.load(S1_MODEL)
hgb     = joblib.load(S2_MODEL)
s2_cols = joblib.load(S2_COLS)
print("      Stage 1: TF-IDF + Calibrated LogReg  [OK]")
print("      Stage 2: HistGradientBoosting         [OK]\n")

# ── Load dataset ──────────────────────────────────────────────────────────────
print("[2/5] Loading dataset...")
df = pd.read_csv(DATASET_PATH, encoding="latin1", low_memory=False, usecols=["url", "Type"])
df.columns = ["url", "Type"]
df["url"]  = df["url"].astype(str).str.strip()
df["Type"] = df["Type"].astype(str).str.strip().str.lower()

# Normalise labels
df["label"] = df["Type"].apply(lambda x: 1 if "phish" in x else 0)

phishing_df = df[df["label"] == 1]
safe_df     = df[df["label"] == 0]

print(f"      Total rows in dataset: {len(df):,}")
print(f"      Phishing rows available: {len(phishing_df):,}")
print(f"      Safe rows available:     {len(safe_df):,}\n")

# ── Sample test set ───────────────────────────────────────────────────────────
print("[3/5] Building evaluation set...")
rng = np.random.default_rng(RANDOM_SEED)

n_phish_sample = min(N_PHISHING, len(phishing_df))
n_safe_sample  = min(N_SAFE, len(safe_df))

phish_sample = phishing_df.sample(n=n_phish_sample, random_state=RANDOM_SEED)
safe_sample  = safe_df.sample(n=n_safe_sample,  random_state=RANDOM_SEED)

eval_df = pd.concat([phish_sample, safe_sample]).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
urls    = eval_df["url"].tolist()
y_true  = eval_df["label"].values

print(f"      Evaluation URLs: {len(urls):,}  (Phishing: {n_phish_sample:,} | Safe: {n_safe_sample:,})\n")

# ── Stage 1: TF-IDF + LogReg ─────────────────────────────────────────────────
print("[4/5] Running inference...")
print("      Stage 1: TF-IDF vectorisation + Logistic Regression...")
t0 = time.time()
X_text   = tfidf.transform(urls)
s1_probs = logreg.predict_proba(X_text)[:, 1]
print(f"             Done in {time.time()-t0:.1f}s")

# ── Stage 2: Structural features + HGB ────────────────────────────────────────
print("      Stage 2: Feature extraction + HGB classifier...")
t1 = time.time()
with ThreadPoolExecutor(max_workers=os.cpu_count()) as ex:
    feats = list(ex.map(url_features, urls))
s2_df = pd.DataFrame(feats)
for col in s2_cols:
    if col not in s2_df.columns:
        s2_df[col] = 0
X_s2     = s2_df[s2_cols]
s2_probs = hgb.predict_proba(X_s2)[:, 1]
print(f"             Done in {time.time()-t1:.1f}s")

# ── Fusion ────────────────────────────────────────────────────────────────────
final_probs = (FUSION_W1 * s1_probs) + (FUSION_W2 * s2_probs)
y_pred      = (final_probs >= THRESHOLD).astype(int)

# Stage 1 + Stage 2 individual predictions
s1_pred = (s1_probs >= THRESHOLD).astype(int)
s2_pred = (s2_probs >= THRESHOLD).astype(int)

elapsed = time.time() - t0

# ── Results ───────────────────────────────────────────────────────────────────
print("\n" + "="*65)
print(f"[5/5] RESULTS  ({elapsed:.1f} seconds | {len(urls)/elapsed:,.0f} URLs/sec)")
print("="*65)

def print_metrics(title, y_t, y_p, y_prob):
    acc   = accuracy_score(y_t, y_p)
    p, r, f1, _ = precision_recall_fscore_support(y_t, y_p, average="binary", zero_division=0)
    cm    = confusion_matrix(y_t, y_p)
    try:   auc = roc_auc_score(y_t, y_prob)
    except: auc = float("nan")
    tn, fp, fn, tp = cm.ravel()
    print(f"\n--- {title} ---")
    print(f"   Accuracy  : {acc*100:.2f}%")
    print(f"   Precision : {p*100:.2f}%   (of predicted phishing, how many were really phishing)")
    print(f"   Recall    : {r*100:.2f}%   (catch rate - of all real phishing, how many caught)")
    print(f"   F1 Score  : {f1*100:.2f}%")
    print(f"   ROC-AUC   : {auc:.4f}")
    print(f"   Confusion Matrix:")
    print(f"     True Negatives  (Safe   -> Safe)    : {tn:,}")
    print(f"     False Positives (Safe   -> Phishing) : {fp:,}  << false alarms")
    print(f"     False Negatives (Phish  -> Safe)    : {fn:,}  << missed threats")
    print(f"     True Positives  (Phish  -> Phishing): {tp:,}")

print_metrics("Stage 1 Only  (TF-IDF + LogReg)", y_true, s1_pred, s1_probs)
print_metrics("Stage 2 Only  (HGB Structural)",  y_true, s2_pred, s2_probs)
print_metrics("FINAL ENSEMBLE (40% S1 + 60% S2)", y_true, y_pred,  final_probs)

print("\n" + "="*65)
print("  CLASSIFICATION REPORT — FINAL ENSEMBLE")
print("="*65)
print(classification_report(y_true, y_pred,
                             target_names=["Safe","Phishing"], digits=4))
print("="*65 + "\n")
