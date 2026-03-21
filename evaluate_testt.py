import sys
import os
import time
import pandas as pd
import numpy as np
import joblib
from concurrent.futures import ThreadPoolExecutor
import warnings
warnings.filterwarnings('ignore')

sys.path.append('.')
from enhanced_original import url_features

def main():
    print(f"\n{'='*60}")
    print(" SENTINURL BULK ACCURACY TESTER ")
    print(f"{'='*60}")
    
    # 1. Load Models
    print("[*] Loading Neural Weights & Heuristics...")
    tfidf = joblib.load("stage1/tfidf.joblib")
    logreg = joblib.load("stage1/calibrated_logreg.joblib")
    s2_model = joblib.load("stage2/stage2_hgb.joblib")
    s2_cols = joblib.load("stage2/stage2_feature_columns.joblib")
    
    # 2. Load Data
    print("[*] Loading testt.csv...")
    try:
        with open("testt.csv", "r", encoding="utf-8", errors="ignore") as f:
            urls = [line.strip() for line in f if line.strip()]
        if urls and urls[0].lower() == "url":
            urls = urls[1:]
    except Exception as e:
        print(f"[!] Error reading csv: {e}")
        return
        
    print(f"[*] Loaded {len(urls):,} URLs.")
    
    start_time = time.time()
    
    # 3. Stage 1
    print("[*] Running Stage 1 (Text Features)...")
    X_text = tfidf.transform(urls)
    s1_probs = logreg.predict_proba(X_text)[:, 1]
    
    # 4. Stage 2
    print("[*] Extracting Structural Features (Parallel)...")
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
        feats_list = list(executor.map(url_features, urls))
        
    print("[*] Running Stage 2 (Structural Features)...")
    s2_df = pd.DataFrame(feats_list)
    for col in s2_cols:
        if col not in s2_df.columns:
            s2_df[col] = 0
    X_s2 = s2_df[s2_cols]
    s2_probs = s2_model.predict_proba(X_s2)[:, 1]
    
    # 5. Fusion
    print("[*] Applying Fusion Logic...")
    from enhanced_original import fuse_evidence
    final_probs = []
    
    # Using offline mock env
    mock_online = {"gsb": {"hit": False, "ok": True}, "tls": {"ok": True, "days_left": 100}, "html": {"ok": False}}
    mock_whois = {"age_days": 1000}
    
    for i in range(len(urls)):
        label, score, src, reasons, p1, p2, geo = fuse_evidence(urls[i], s1_probs[i], s1_probs[i], s2_probs[i], mock_online, mock_whois)
        final_probs.append(score)
        
    final_probs = np.array(final_probs)
    
    THRESHOLD = 0.40
    caught = np.sum(final_probs >= THRESHOLD)
    missed = len(urls) - caught
    acc = (caught / len(urls)) * 100
    elapsed = time.time() - start_time
    
    print("\n" + "="*60)
    print(f"TEST COMPLETE IN {elapsed:.2f} SECONDS ({len(urls)/elapsed:.0f} URLs/sec)")
    print("="*60)
    print(f"Total Evaluated : {len(urls):,}")
    print(f"Threats Caught  : {caught:,}")
    print(f"Threats Missed  : {missed:,}")
    print(f"FINAL ACCURACY  : {acc:.2f}%")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
