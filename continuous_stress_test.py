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
# 3. CORE EXECUTION ENGINE
# ==========================================
def run_continuous_test(batch_size=90000):
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
    caught = np.sum(final_probs >= 0.25)
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

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SentinURL Continuous Offline Testing Engine")
    parser.add_argument("--batch", type=int, default=90000, help="Number of zero-day URLs to generate and test (Default: 90,000)")
    args = parser.parse_args()
    
    run_continuous_test(args.batch)
