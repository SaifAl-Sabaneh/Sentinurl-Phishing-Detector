"""
evaluate_million.py
===================
Optimized evaluation script for SentinURL.
Corrects labeling priority and handles ~510,000 unique URLs.
"""

import os
import sys
import time
import pandas as pd
import numpy as np
import joblib
from multiprocessing import Pool, cpu_count
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, classification_report

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.dirname(BASE_DIR)

S1_TFIDF  = os.path.join(BASE_DIR, "stage1", "tfidf.joblib")
S1_MODEL  = os.path.join(BASE_DIR, "stage1", "calibrated_logreg.joblib")
S2_MODEL  = os.path.join(BASE_DIR, "stage2", "stage2_hgb.joblib")
S2_COLS   = os.path.join(BASE_DIR, "stage2", "stage2_feature_columns.joblib")

# ── Feature Extractor ─────────────────────────────────────────────────────────
import re, math
from collections import Counter
from urllib.parse import urlparse, unquote

BRANDS = ["paypal","google","apple","amazon","microsoft","facebook","instagram","whatsapp","netflix","dhl","fedex"]
RISKY_TLDS = {"tk","ml","ga","cf","gq"}
TOP_DOMAINS = {"google.com","www.google.com","amazon.com","www.amazon.com","microsoft.com","apple.com","paypal.com","facebook.com"}

def entropy(s):
    if not s: return 0.0
    p = [c/len(s) for c in Counter(s).values()]
    return -sum(x*math.log2(x) for x in p if x > 0)

def vc_ratio(s):
    if not s: return 0.0
    v = sum(c in "aeiou" for c in s)
    c = sum(c in "bcdfghjklmnpqrstvwxyz" for c in s)
    return v/c if c else float(v)

def extract_row_features(url):
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
    tld = host_no_port.split(".")[-1] if "." in host_no_port else ""
    host_tokens = [t for t in re.split(r"[.\-]", host_no_port) if t]
    path_tokens = [t for t in path.split("/") if t]
    
    digits = sum(c.isdigit() for c in decoded)
    specials = sum((not c.isalnum()) for c in decoded)
    
    return [
        len(decoded), len(host_no_port), len(path), len(query),
        max([len(t) for t in host_tokens]) if host_tokens else 0,
        max([len(t) for t in path_tokens]) if path_tokens else 0,
        decoded.count("."), decoded.count("-"), decoded.count("/"), decoded.count("_"),
        digits, specials, digits/max(len(decoded),1), specials/max(len(decoded),1),
        vc_ratio(host_no_port), host_no_port.count("."), len(host_tokens), len(path_tokens),
        len([t for t in query.split("&") if t]), path.count("/"),
        1 if decoded.startswith("https") else 0,
        1 if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host_no_port) else 0,
        1 if "xn--" in host_no_port else 0,
        decoded.count("@"), decoded.count("%"), decoded.count("="),
        1 if (":" in host) else 0,
        1 if "//" in path else 0,
        1 if any(w in low for w in ["login","signin","verify","secure","account","auth"]) else 0,
        1 if any(w in low for w in ["bank","pay","billing","invoice","crypto","wallet"]) else 0,
        1 if any(w in low for w in ["free","bonus","winner","hack","adware","malware"]) else 0,
        sum(b in low for b in BRANDS),
        1 if re.search(r"(redirect|next|url|continue|dest)=", low) else 0,
        entropy(decoded), entropy(host_no_port), entropy(path), entropy(query),
        1 if tld in RISKY_TLDS else 0,
        1 if host_no_port in TOP_DOMAINS else 0
    ]

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*70)
    print("  SENTINURL — ULTIMATE LARGE-SCALE ML EVALUATION")
    print("="*70 + "\n")

    # 1. Load Data with Label Priority
    print("[1/5] Aggregating unique URLs from your datasets...")
    
    # Priority 1: Merged Files (Has Ground Truth labels)
    f1 = os.path.join(DATA_DIR, "steps", "Merged Files.csv")
    df_gt = pd.read_csv(f1, encoding="latin1", low_memory=False)
    df_gt.columns = [c.strip() for c in df_gt.columns]
    df_gt = df_gt[["url", "Type"]]
    df_gt["label"] = df_gt["Type"].apply(lambda x: 1 if "phish" in str(x).lower() else 0)
    df_gt = df_gt[["url", "label"]].drop_duplicates(subset=["url"])
    print(f"      Verified ground truth loaded: {len(df_gt):,} URLs")
    
    # Priority 2: Phishing Dataset (Assumed phishing for remaining unique ones)
    f2 = os.path.join(DATA_DIR, "Phishing Dataset.csv")
    df_phish = pd.read_csv(f2, usecols=[0], names=["url"], header=0, encoding="latin1")
    df_phish = df_phish.drop_duplicates(subset=["url"])
    
    # Find unique ones not in ground truth
    new_urls = set(df_phish["url"]) - set(df_gt["url"])
    df_new = pd.DataFrame({"url": list(new_urls), "label": 1})
    print(f"      Supplemental threats added:   {len(df_new):,} URLs")
    
    df_final = pd.concat([df_gt, df_new]).sample(frac=1, random_state=42).reset_index(drop=True)
    
    urls = df_final["url"].astype(str).tolist()
    y_true = df_final["label"].values
    print(f"      Total unique evaluation set:  {len(df_final):,} URLs")
    print(f"      Set composition: {y_true.sum():,} Phishing | {len(y_true)-y_true.sum():,} Safe\n")

    # 2. Load Models
    print("[2/5] Initialising Inference Engine...")
    tfidf = joblib.load(S1_TFIDF)
    logreg = joblib.load(S1_MODEL)
    hgb = joblib.load(S2_MODEL)
    s2_cols = joblib.load(S2_COLS)
    print("      Models loaded successfully.\n")

    # 3. Inference
    print("[3/5] Running Unified ML Fusion Engine...")
    t0 = time.time()
    
    # Stage 1
    X_text = tfidf.transform(urls)
    s1_probs = logreg.predict_proba(X_text)[:, 1]
    
    # Stage 2 (Parallel)
    num_cores = min(8, cpu_count())
    with Pool(num_cores) as pool:
        feat_matrix = pool.map(extract_row_features, urls)
    
    X_s2 = pd.DataFrame(feat_matrix, columns=s2_cols)
    s2_probs = hgb.predict_proba(X_s2)[:, 1]
    
    # 4. Analysis
    final_probs = (0.40 * s1_probs) + (0.60 * s2_probs)
    y_pred = (final_probs >= 0.25).astype(int)
    elapsed = time.time() - t0
    
    print(f"      Inference complete in {elapsed:.1f}s ({len(urls)/elapsed:,.0f} URLs/sec)\n")

    # 5. Final Metrics
    acc = accuracy_score(y_true, y_pred)
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary")
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    print("="*70)
    print(f"  FINAL PERFORMANCE REPORT (N={len(urls):,})")
    print("="*70)
    print(f"  SYSTEM ACCURACY : {acc*100:.2f}%")
    print(f"  PRECISION       : {p*100:.2f}%")
    print(f"  RECALL          : {r*100:.2f}%")
    print(f"  F1-SCORE        : {f1*100:.2f}%")
    print("-" * 35)
    print(f"  Total False Positives (Safe Site Blocked): {fp:,} ({fp/len(urls)*100:.2f}%)")
    print(f"  Total False Negatives (Missed Threat):    {fn:,} ({fn/len(urls)*100:.2f}%)")
    print("="*70 + "\n")
    
    print("DETAILED CLASSIFICATION ANALYSIS:")
    print(classification_report(y_true, y_pred, target_names=["Safe", "Phishing"], digits=4))
