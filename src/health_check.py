import os
import sys

# Ensure imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def run_health_check():
    print("="*50)
    print("SentinURL System Health Check")
    print("="*50)
    
    # Check Models
    print("\n[1] Checking Core Machine Learning Models...")
    models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
    
    required_models = [
        "stage1/calibrated_logreg.joblib",
        "stage1/tfidf.joblib",
        "stage2/stage2_hgb.joblib",
        "stage2/stage2_feature_columns.joblib"
    ]
    
    missing_models = False
    for mod in required_models:
        mod_path = os.path.join(models_dir, mod)
        if os.path.exists(mod_path):
            print(f"  [OK] {mod} found.")
        else:
            print(f"  [FAIL] {mod} is missing.")
            missing_models = True
            
    if missing_models:
        print("\nERROR: Required ML models are missing. Pipeline will fail.")
        return False
        
    print("\n[2] Checking API Import and Neural Pipeline Initialization...")
    try:
        from sentinurl import predict_ultimate
        print("  [OK] sentinurl.predict_ultimate imported successfully.")
    except Exception as e:
        print(f"  [FAIL] Failed to import predict_ultimate: {e}")
        return False
        
    print("\n[3] Testing Neural Pipeline Prediction...")
    test_urls = [
        ("https://www.google.com", "EXPECTED: SAFE"),
        ("http://192.168.1.1/login.php", "EXPECTED: PHISHING")
    ]
    
    for url, desc in test_urls:
        print(f"\n  Testing: {url} ({desc})")
        try:
            lbl, score, src, reasons, p1, p2, _, _, _ = predict_ultimate(url)
            print(f"  [RESULT] Label: {lbl} | Risk Score: {score:.4f} | Engine: {src}")
            print(f"  [OK] Prediction pipeline is functional.")
        except Exception as e:
            print(f"  [FAIL] Pipeline crashed during prediction: {e}")
            import traceback
            traceback.print_exc()
            return False
            
    print("\n" + "="*50)
    print("SYSTEM HEALTH CHECK: PASSED")
    print("All core components, models, and neural pipelines are fully functional.")
    print("="*50)
    return True

if __name__ == "__main__":
    success = run_health_check()
    sys.exit(0 if success else 1)
