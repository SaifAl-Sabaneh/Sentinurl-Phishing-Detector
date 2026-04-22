"""
online_evaluation.py
=====================
Tests the FULL SentinURL online pipeline on 200 labeled URLs.
  - Stage 1: TF-IDF + Logistic Regression
  - Stage 2: HistGradientBoosting  
  - Stage 3: Google Safe Browsing API
  - Domain age heuristic (WHOIS)

Test set: 140 phishing + 60 safe = 200 URLs total
"""

import os, sys, time, warnings
import numpy as np
import pandas as pd
import joblib
import hashlib
import requests

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from enhanced_original import (
    url_features, stage1_prob, stage2_prob,
    gsb_check, get_whois_info, get_host, registrable_domain,
    normalize_url, W1, W2, SAFE_MAX, PHISH_MIN,
    is_allowlisted_reg_domain
)

from sklearn.metrics import (
    accuracy_score, confusion_matrix,
    classification_report, precision_recall_fscore_support
)

# ── Config ────────────────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(os.path.dirname(BASE_DIR), "steps", "Merged Files.csv")
GSB_KEY      = os.environ.get("SENTINURL_GSB_API_KEY", "")

N_PHISHING   = 140
N_SAFE       = 60
RANDOM_SEED  = 99
THRESHOLD    = 0.25

# The GSB key is now loaded from environment variables for security.
# To run locally, set the variable: $env:SENTINURL_GSB_API_KEY="your_key_here"

print("\n" + "="*65)
print("  SENTINURL — FULL ONLINE PIPELINE EVALUATION")
print(f"  Test Set: {N_PHISHING} Phishing + {N_SAFE} Safe = {N_PHISHING+N_SAFE} URLs")
print("  Includes: Stage1 + Stage2 + Google Safe Browsing + WHOIS")
print("="*65 + "\n")

# ── Load dataset ──────────────────────────────────────────────────────────────
print("[1/4] Loading dataset and sampling 200 URLs...")
df = pd.read_csv(DATASET_PATH, encoding="latin1", low_memory=False, usecols=["url","Type"])
df["url"]   = df["url"].astype(str).str.strip()
df["label"] = df["Type"].astype(str).str.lower().apply(lambda x: 1 if "phish" in x else 0)

phish_df = df[df["label"]==1].sample(n=N_PHISHING, random_state=RANDOM_SEED)
safe_df  = df[df["label"]==0].sample(n=N_SAFE,     random_state=RANDOM_SEED)

eval_df  = pd.concat([phish_df, safe_df]).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
urls     = eval_df["url"].tolist()
y_true   = eval_df["label"].values
print(f"      Sampled: {N_PHISHING} phishing + {N_SAFE} safe\n")

# ── Full online pipeline per URL ──────────────────────────────────────────────
print("[2/4] Running full online pipeline (this will take a few minutes)...\n")

results = []
t0 = time.time()

for i, url in enumerate(urls):
    tick = time.time()

    # Stage 1 + Stage 2 (offline ML)
    try: s1 = stage1_prob(url)
    except: s1 = 0.5
    try: s2 = stage2_prob(url)
    except: s2 = 0.5

    ml_prob = W1 * s1 + W2 * s2

    # Google Safe Browsing
    gsb_hit = False
    try:
        gsb = gsb_check(url)
        if gsb and gsb.get("hit"):
            gsb_hit = True
    except: pass

    # WHOIS age check
    age_days = None
    try:
        host = get_host(url)
        reg  = registrable_domain(host)
        if reg:
            w = get_whois_info(reg)
            age_days = w.get("age_days")
    except: pass

    # Fusion: if GSB flags it, boost probability significantly
    final_prob = ml_prob
    if gsb_hit:
        final_prob = max(final_prob, 0.95)

    # Age boost: if domain is very new (<30 days) and ML is already suspicious
    if age_days is not None and age_days < 30 and final_prob > 0.3:
        final_prob = min(final_prob + 0.15, 1.0)

    # Age guard: if domain is very old (>3 years) and ML is borderline, lower risk
    if age_days is not None and age_days > 1095 and final_prob < 0.6:
        final_prob = max(final_prob - 0.10, 0.0)

    pred = 1 if final_prob >= THRESHOLD else 0

    elapsed_url = time.time() - tick
    elapsed_total = time.time() - t0
    eta = (elapsed_total / (i+1)) * (len(urls) - i - 1)

    results.append({
        "url": url[:60],
        "true_label": y_true[i],
        "pred_label": pred,
        "s1_prob": round(s1, 4),
        "s2_prob": round(s2, 4),
        "ml_prob": round(ml_prob, 4),
        "gsb_hit": gsb_hit,
        "age_days": age_days,
        "final_prob": round(final_prob, 4),
    })

    status = "CORRECT" if pred == y_true[i] else "WRONG  "
    true_str = "Phishing" if y_true[i] == 1 else "Safe    "
    pred_str = "Phishing" if pred == 1 else "Safe    "
    gsb_str  = "[GSB!]" if gsb_hit else ""
    print(f"  [{i+1:3d}/200] {status} | True:{true_str} Pred:{pred_str} | "
          f"Score:{final_prob:.2f} {gsb_str} | ETA:{eta:.0f}s")

total_time = time.time() - t0

# ── Results ───────────────────────────────────────────────────────────────────
res_df = pd.DataFrame(results)
y_pred = res_df["pred_label"].values

acc = accuracy_score(y_true, y_pred)
p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
cm = confusion_matrix(y_true, y_pred)
tn, fp, fn, tp = cm.ravel()

gsb_catches = res_df[res_df["gsb_hit"] == True].shape[0]

print("\n" + "="*65)
print(f"[3/4] FULL ONLINE PIPELINE RESULTS  ({total_time:.0f} sec | {200/total_time:.1f} URLs/sec)")
print("="*65)
print(f"\n   Accuracy  : {acc*100:.2f}%")
print(f"   Precision : {p*100:.2f}%")
print(f"   Recall    : {r*100:.2f}%  (catch rate)")
print(f"   F1 Score  : {f1*100:.2f}%")
print(f"\n   Confusion Matrix:")
print(f"     True Negatives  (Safe    -> Safe)    : {tn}")
print(f"     False Positives (Safe    -> Phishing): {fp}  << false alarms")
print(f"     False Negatives (Phishing-> Safe)    : {fn}  << missed threats")
print(f"     True Positives  (Phishing-> Phishing): {tp}")
print(f"\n   Google Safe Browsing hits : {gsb_catches} URLs flagged by GSB")
print(f"   Avg time per URL          : {total_time/200:.1f}s")

print("\n" + "="*65)
print("  CLASSIFICATION REPORT")
print("="*65)
print(classification_report(y_true, y_pred, target_names=["Safe","Phishing"], digits=4))
print("="*65)

# ── Save results ──────────────────────────────────────────────────────────────
out_path = os.path.join(BASE_DIR, "online_eval_results.csv")
res_df.to_csv(out_path, index=False)
print(f"\n[4/4] Detailed results saved to: online_eval_results.csv\n")
