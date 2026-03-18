import sys
import os
import argparse
from termcolor import colored

# Add project dir to path
sys.path.append('.')
import joblib
import pandas as pd

def load_models():
    tfidf = joblib.load("stage1/tfidf.joblib")
    logreg = joblib.load("stage1/calibrated_logreg.joblib")
    s2_model = joblib.load("stage2/stage2_hgb.joblib")
    s2_cols = joblib.load("stage2/stage2_feature_columns.joblib")
    return tfidf, logreg, s2_model, s2_cols

from enhanced_original import fuse_evidence, url_features

def main():
    print(colored("\n--- SENTINURL REAL-WORLD TESTER ---", "blue", attrs=["bold"]))
    
    # Load Models
    print("[*] Loading Neural Weights & Heuristics...")
    tfidf, logreg, s2_model, s2_cols = load_models()
    
    url = input("\n[?] Enter a Phishing URL to analyze: ").strip()
    if not url:
        return

    # 1. Stage 1 (URL string only)
    s1p = logreg.predict_proba(tfidf.transform([url]))[0, 1]
    
    # 2. Stage 2 (Structural Features)
    feats = url_features(url)
    import pandas as pd
    s2_input = pd.DataFrame([feats])
    for col in s2_cols:
        if col not in s2_input.columns: s2_input[col] = 0
    s2p = s2_model.predict_proba(s2_input[s2_cols])[0, 1]
    
    # 3. Fusion (Simulating Offline Mode by default unless user wants online)
    online_mock = {"gsb": {"hit": False}, "tls": {"ok": True}, "html": {"ok": False}}
    whois_mock = {"age_days": 1000}
    
    label, score, src, reasons, p1, p2, geo = fuse_evidence(url, s1p, s1p, s2p, online_mock, whois_mock)
    
    print("\n" + "="*50)
    print(f"ANALYSIS FOR: {url}")
    print("="*50)
    
    color = "red" if score >= 0.70 else ("yellow" if score >= 0.40 else "green")
    print(f"RESULT      : {colored(label, color, attrs=['bold'])}")
    print(f"RISK SCORE  : {colored(f'{score*100:.1f}%', color)}")
    print(f"SOURCE      : {src}")
    
    print("\nDETECTION REASONS:")
    for r in reasons:
        print(f" - {r}")
        
    print("\nMODEL CONFIDENCE:")
    print(f" - Neural Pattern (URL String): {s1p*100:.1f}%")
    print(f" - Structural Logic (Features): {s2p*100:.1f}%")
    print("="*50 + "\n")

if __name__ == "__main__":
    main()
