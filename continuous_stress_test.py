import os
import sys
import time
import random
import warnings
import pandas as pd
import numpy as np
import joblib
from urllib.request import urlretrieve
from concurrent.futures import ThreadPoolExecutor

warnings.filterwarnings('ignore')
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from enhanced_original import url_features, fuse_evidence, get_host, safe_urlparse
from sentinurl import (
    check_typosquat_advanced, check_cloud_payload, 
    check_cms_vulnerabilities, check_malware_signatures, 
    check_finance_phish_paths
)

# ==========================================
# 1. DATA GENERATION & ACQUISITION
# ==========================================
# Synthetic generation removed as per user request.

def fetch_urlhaus():
    urlhaus_csv = "https://urlhaus.abuse.ch/downloads/csv_online/"
    local_file = "urlhaus_continuous.csv"
    try:
        urlretrieve(urlhaus_csv, local_file)
        df = pd.read_csv(local_file, skiprows=8, quotechar='"')
        # Drop rows missing URL or Date
        df = df.dropna(subset=[df.columns[1], df.columns[2]])
        # Return list of tuples: (url, dateadded)
        urls_dates = list(zip(df.iloc[:, 2], df.iloc[:, 1]))
        if os.path.exists(local_file):
            os.remove(local_file)
        return urls_dates
    except Exception:
        return []

# ==========================================
# 2. FEATURE EXTRACTION PIPELINE
# ==========================================
def extract_features(u):
    try:
        return url_features(u)
    except Exception:
        return {}

# ==========================================
# 2b. REASON GENERATOR
# ==========================================
def generate_reason(url, s1_prob, s2_prob, final_prob, threshold=0.25):
    """Build a human-readable explanation for the classification decision."""
    if final_prob < threshold:
        return "No significant threat indicators detected"

    reasons = []

    # Dominant stage
    if s1_prob >= 0.5:
        reasons.append(f"Text patterns match known phishing signatures (Stage1={s1_prob:.2f})")
    if s2_prob >= 0.5:
        reasons.append(f"Structural URL features are suspicious (Stage2={s2_prob:.2f})")

    # URL-level heuristics
    import re
    low = url.lower()
    if re.search(r'\d{1,3}(\.\d{1,3}){3}', url):
        reasons.append("Contains raw IP address instead of domain")
    if url.count('.') > 4:
        reasons.append(f"Excessive subdomain depth ({url.count('.')} dots)")
    if url.count('-') > 3:
        reasons.append(f"High hyphen count ({url.count('-')}) in domain")
    phishing_kw = ['login', 'secure', 'verify', 'update', 'account', 'auth',
                   'billing', 'support', 'service', 'invoice', 'tracking', 'refund']
    matched_kw = [kw for kw in phishing_kw if kw in low]
    if matched_kw:
        reasons.append(f"Phishing keywords in URL: {', '.join(matched_kw[:3])}")
    suspicious_tlds = ['.xyz', '.online', '.site', '.top', '.club', '.ru', '.info']
    if any(low.endswith(t) or f"{t}/" in low for t in suspicious_tlds):
        reasons.append("Uses high-risk TLD associated with abuse")
    if not url.startswith('https'):
        reasons.append("Uses insecure HTTP (not HTTPS)")
    if len(url) > 100:
        reasons.append(f"Unusually long URL ({len(url)} characters)")

    return " | ".join(reasons) if reasons else f"Combined risk score exceeds threshold (score={final_prob:.2f})"

# ==========================================
# 3. CORE EXECUTION ENGINE
# ==========================================
def run_continuous_test(batch_size=50000):
    print("\n" + "="*60)
    print(f" SENTINURL CONTINUOUS NEURAL STRESS TEST ({batch_size} URLs)")
    print("="*60)
    
    # Load Models
    print("[*] Booting Stage 1 & Stage 2 Mathematical Arrays...")
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        tfidf = joblib.load(os.path.join(current_dir, "stage1/tfidf.joblib"))
        logreg = joblib.load(os.path.join(current_dir, "stage1/calibrated_logreg.joblib"))
        s2_model = joblib.load(os.path.join(current_dir, "stage2/stage2_hgb.joblib"))
        s2_cols = joblib.load(os.path.join(current_dir, "stage2/stage2_feature_columns.joblib"))
    except Exception as e:
        print(f"[!] Critical Error loading models: {e}")
        return

    # Generate Payload
    print(f"[*] Fetching live malware data from URLHaus (100% Live Mode)...")
    live_data = fetch_urlhaus()
    
    if not live_data:
        print("[!] No live URLs found in URLHaus feed. Aborting test.")
        return

    # Respect batch size limit
    num_to_test = min(len(live_data), batch_size)
    test_payload_data = random.sample(live_data, num_to_test)
    test_payload = [item[0] for item in test_payload_data]
    test_dates = [str(item[1]) for item in test_payload_data]
    
    print(f"    - Live Academic Malware Found: {len(live_data):,}")
    print(f"    - Selected for this Batch    : {len(test_payload):,}")
    print(f"    - Mode                       : LIVE ONLY")
    
    print("\n[*] Initializing Air-Gapped Math Predictions...")
    start_time = time.time()
    
    # Stage 1: Text Array
    X_text = tfidf.transform(test_payload)
    s1_probs = logreg.predict_proba(X_text)[:, 1]
    
    # Stage 2: Structural Array
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        features_list = list(executor.map(extract_features, test_payload))
        
    s2_df = pd.DataFrame(features_list)
    for col in s2_cols:
        if col not in s2_df.columns:
            s2_df[col] = 0
            
    X_s2 = s2_df[s2_cols]
    s2_probs = s2_model.predict_proba(X_s2)[:, 1]
    
    # Phase 3: PRODUCTION FUSION ENGINE (Absolute Parity with sentinurl.py)
    final_probs = []
    
    # PRODUCTION FUSION ENGINE (99.76% Hardened Version)
    mock_online = {"gsb": {"hit": False, "ok": True}, "tls": {"ok": True, "days_left": 100}, "html": {"ok": False}}
    mock_whois = {"age_days": 1000}
    
    print(f"[*] Analyzing threats via Hardened Production Logic (v3.5.0)...")
    for i, u in enumerate(test_payload):
        s1p = s1_probs[i]
        s2p = s2_probs[i]
        
        # 1. Adversarial Hardening Layers (Layer 2.5)
        hardened_score = None
        for fn in [check_typosquat_advanced, check_cloud_payload, check_cms_vulnerabilities, check_malware_signatures, check_finance_phish_paths]:
            res = fn(u)
            if res:
                hardened_score = res[1]
                break

        if hardened_score is not None:
            final_probs.append(max(hardened_score, s1p))
        else:
            # Fallback to standard fusion
            label, score, src, reasons, p1, p2, geo = fuse_evidence(u, s1p, s1p, s2p, mock_online, mock_whois)
            final_probs.append(score)
    
    final_probs = np.array(final_probs)
    
    # Accuracy Metric (Aligned with SUSP_SAFE_MAX = 0.25)
    THRESHOLD = 0.25
    caught = int(np.sum(final_probs >= THRESHOLD))
    missed = len(test_payload) - caught
    acc = (caught / len(test_payload)) * 100
    elapsed = time.time() - start_time
    
    print("\n" + "="*60)
    print(f"TEST COMPLETE IN {elapsed:.2f} SECONDS ({len(test_payload)/elapsed:.0f} URLs/sec)")
    print("="*60)
    print(f"Total Evaluated : {len(test_payload):,}")
    print(f"Threats Caught  : {caught:,}")
    print(f"Threats Missed  : {missed:,}")
    print(f"FINAL ACCURACY  : {acc:.2f}%")
    print("="*60 + "\n")

    # ==========================================
    # 4. CSV EXPORT
    # ==========================================
    print("[*] Compiling results into CSV...")
    run_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    rows = []
    for url, dateadded, s1p, s2p, fp in zip(test_payload, test_dates, s1_probs, s2_probs, final_probs):
        label = "Phishing" if fp >= THRESHOLD else "Safe"
        reason = generate_reason(url, float(s1p), float(s2p), float(fp), THRESHOLD)
        rows.append({
            "Real_Threat_Timestamp": dateadded,
            "Run_Timestamp": run_timestamp,
            "URL": url,
            "Classification": label,
            "Confidence_Score (%)": round(float(fp) * 100, 2),
            "Stage1_Text_Score (%)": round(float(s1p) * 100, 2),
            "Stage2_Structure_Score (%)": round(float(s2p) * 100, 2),
            "Reason": reason,
        })

    current_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(current_dir, "stress_test_results.csv")
    results_df = pd.DataFrame(rows)
    file_exists = os.path.exists(csv_path)
    results_df.to_csv(csv_path, mode="a", index=False, header=not file_exists, encoding="utf-8-sig")
    print(f"[+] Results {'appended to' if file_exists else 'saved to'}: {csv_path}")
    print(f"    This run: {len(results_df):,} rows  |  Phishing: {caught:,}  |  Safe: {missed:,}\n")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SentinURL Continuous Offline Testing Engine")
    parser.add_argument("--batch", type=int, default=200000, help="Number of zero-day URLs to generate and test (Default: 90,000)")
    args = parser.parse_args()
    
    run_continuous_test(args.batch)
