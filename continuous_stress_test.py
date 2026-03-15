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
sys.path.append('.')
from enhanced_original import url_features

# ==========================================
# 1. DATA GENERATION & ACQUISITION
# ==========================================
def generate_synthetic_phishing(count):
    brands = ['paypal', 'apple', 'microsoft', 'netflix', 'amazon', 'google', 'facebook', 'bankofamerica', 'chase', 'wellsfargo', 'dhl', 'fedex', 'usps']
    keywords = ['login', 'secure', 'verify', 'update', 'account', 'auth', 'billing', 'support', 'service', 'center', 'invoice', 'tracking', 'refund']
    tlds = ['.com', '.net', '.org', '.info', '.xyz', '.online', '.site', '.top', '.club', '.ru', '.io', '.co']
    
    urls = []
    for _ in range(count):
        brand = random.choice(brands)
        kw1 = random.choice(keywords)
        kw2 = random.choice(keywords)
        tld = random.choice(tlds)
        
        chance = random.random()
        if chance < 0.25:
            urls.append(f"https://{brand}-{kw1}-{kw2}{tld}/{random.choice(keywords)}?token={random.randint(1000,9999)}")
        elif chance < 0.50:
            urls.append(f"http://{kw1}.{kw2}.{brand}.security-check-{random.randint(100,999)}.com/{kw1}.php")
        elif chance < 0.75:
            ip = f"{random.randint(11,250)}.{random.randint(11,250)}.{random.randint(11,250)}.{random.randint(11,250)}"
            urls.append(f"http://{ip}/{brand}/{kw1}/index.html")
        else:
            gibberish = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(12,25)))
            urls.append(f"https://{gibberish}{tld}/{brand}-{kw1}")
            
    return urls

def fetch_urlhaus():
    urlhaus_csv = "https://urlhaus.abuse.ch/downloads/csv_online/"
    local_file = "urlhaus_continuous.csv"
    try:
        urlretrieve(urlhaus_csv, local_file)
        df = pd.read_csv(local_file, skiprows=8, quotechar='"')
        urls = df.iloc[:, 2].dropna().tolist()
        if os.path.exists(local_file):
            os.remove(local_file)
        return urls
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
def run_continuous_test(batch_size=200000):
    print("\n" + "="*60)
    print(f" SENTINURL CONTINUOUS NEURAL STRESS TEST ({batch_size} URLs)")
    print("="*60)
    
    # Load Models
    print("[*] Booting Stage 1 & Stage 2 Mathematical Arrays...")
    try:
        tfidf = joblib.load("stage1/tfidf.joblib")
        logreg = joblib.load("stage1/calibrated_logreg.joblib")
        s2_model = joblib.load("stage2/stage2_hgb.joblib")
        s2_cols = joblib.load("stage2/stage2_feature_columns.joblib")
    except Exception as e:
        print(f"[!] Critical Error loading models: {e}")
        return

    # Generate Payload
    print(f"[*] Fetching live malware data & synthesizing zero-day threats...")
    live_urls = fetch_urlhaus()
    
    # Try to grab up to half the batch from URLhaus if available
    target_live = min(len(live_urls), batch_size // 2)
    selected_live = random.sample(live_urls, target_live) if live_urls else []
    
    synthetic_needed = batch_size - len(selected_live)
    synthetic_urls = generate_synthetic_phishing(synthetic_needed)
    
    test_payload = selected_live + synthetic_urls
    random.shuffle(test_payload)
    
    print(f"    - Live Academic Malware  : {len(selected_live):,}")
    print(f"    - Synthesized Zero-Days  : {len(synthetic_urls):,}")
    print(f"    - Total Testing Array    : {len(test_payload):,}")
    
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
    
    # Fusion Engine
    final_probs = (s1_probs * 0.4) + (s2_probs * 0.6)
    
    # Accuracy Metric
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
    for url, s1p, s2p, fp in zip(test_payload, s1_probs, s2_probs, final_probs):
        label = "Phishing" if fp >= THRESHOLD else "Safe"
        reason = generate_reason(url, float(s1p), float(s2p), float(fp), THRESHOLD)
        rows.append({
            "Run_Timestamp": run_timestamp,
            "URL": url,
            "Classification": label,
            "Confidence_Score": f"{float(fp)*100:.2f}%",
            "Stage1_Text_Score": f"{float(s1p)*100:.2f}%",
            "Stage2_Structure_Score": f"{float(s2p)*100:.2f}%",
            "Reason": reason,
        })

    csv_path = "stress_test_results.csv"
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
