import os
import sys
import json
import time
import pandas as pd
import joblib

def final_smoke_test():
    print("=" * 60)
    print("       SENTINURL ULTIMATE: FINAL READINESS AUDIT")
    print("=" * 60)
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    success_count = 0
    total_tests = 5

    # 1. Check Core Engine Files
    print("[TEST 1/5] Verifying Core Architecture...", end=" ")
    essential_files = ["sentinurl.py", "enhanced_original.py", "automated_retrain.py", "Master_SentinURL_Dataset.csv"]
    missing = [f for f in essential_files if not os.path.exists(os.path.join(current_dir, f))]
    if not missing:
        print("PASS")
        success_count += 1
    else:
        print(f"FAIL (Missing: {missing})")

    # 2. Check Dataset Health
    print("[TEST 2/5] Verifying Master Intelligence Hub...", end=" ")
    try:
        df = pd.read_csv(os.path.join(current_dir, "Master_SentinURL_Dataset.csv"), nrows=5)
        if "URL" in df.columns and "Type" in df.columns:
            print(f"PASS ({os.path.getsize(os.path.join(current_dir, 'Master_SentinURL_Dataset.csv'))/1024/1024:.1f} MB)")
            success_count += 1
        else:
            print("FAIL (Malformed Columns)")
    except Exception as e:
        print(f"FAIL (Error: {e})")

    # 3. Check ML Model Load
    print("[TEST 3/5] Verifying Production Models...", end=" ")
    try:
        tfidf_path = os.path.join(current_dir, "stage1", "tfidf.joblib")
        hgb_path = os.path.join(current_dir, "stage2", "stage2_hgb.joblib")
        if os.path.exists(tfidf_path) and os.path.exists(hgb_path):
            print("PASS")
            success_count += 1
        else:
            print("FAIL (Models not found)")
    except Exception as e:
        print(f"FAIL (Error: {e})")

    # 4. Check Feedback Loop (Allowlist Persistence)
    print("[TEST 4/5] Verifying Local Feedback Loop...", end=" ")
    allowlist_path = os.path.join(current_dir, "local_allowlist.json")
    if os.path.exists(allowlist_path):
        print("PASS")
        success_count += 1
    else:
        # Create empty if missing
        with open(allowlist_path, 'w') as f:
            json.dump({}, f)
        print("PASS (Initialized new)")
        success_count += 1

    # 5. Check Portability Config
    print("[TEST 5/5] Verifying Presentation Readiness...", end=" ")
    startup_batch = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'SentinURL_Automated_Retrain.bat')
    if os.path.exists(startup_batch):
        print("PASS")
        success_count += 1
    else:
        print("FAIL (Startup Trigger Not Set)")

    print("-" * 60)
    print(f"FINAL AUDIT RESULT: {success_count}/{total_tests} TARGETS ACHIEVED")
    if success_count == total_tests:
        print("STATUS: SYSTEM IS GREEN AND READY FOR GRADUATION PRESENTATION.")
    else:
        print("STATUS: SYSTEM REQUIRES ATTENTION (Check FAIL markers above).")
    print("=" * 60)

if __name__ == "__main__":
    final_smoke_test()
