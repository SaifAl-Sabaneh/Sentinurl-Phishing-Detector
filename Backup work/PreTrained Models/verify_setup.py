"""
SentinURL Ultimate Setup Verification Script
Run this to verify all files are in the correct location
"""

import os
import sys

print("=" * 70)
print("SENTINURL ULTIMATE - SETUP VERIFICATION")
print("=" * 70)

# Expected directory structure
current_dir = os.path.dirname(os.path.abspath(__file__))
print(f"\nCurrent directory: {current_dir}")

# Check for required files
required_files = {
    "Core Engine": "enhanced_original.py",
    "Visual Similarity": "visual_similarity_detection.py",
    "Threat Intelligence": "threat_intelligence.py",
    "Certificate Analysis": "certificate_analysis.py",
    "Ultimate System": "sentinurl_ultimate.py",
}

print("\n" + "-" * 70)
print("CHECKING FILES:")
print("-" * 70)

all_found = True
for name, filename in required_files.items():
    # Check in current directory
    filepath_current = os.path.join(current_dir, filename)
    # Check in parent directory (Desktop)
    filepath_parent = os.path.join(os.path.dirname(current_dir), filename)
    
    if os.path.exists(filepath_current):
        print(f"✓ {name:20} : {filename} (FOUND in current dir)")
    elif os.path.exists(filepath_parent):
        print(f"✓ {name:20} : {filename} (FOUND in parent dir)")
    else:
        print(f"✗ {name:20} : {filename} (MISSING)")
        all_found = False

# Check for model directories
print("\n" + "-" * 70)
print("CHECKING MODEL DIRECTORIES:")
print("-" * 70)

model_dirs = {
    "Stage1 Directory": "stage1",
    "Stage2 Directory": "stage2",
}

for name, dirname in model_dirs.items():
    dirpath = os.path.join(current_dir, dirname)
    if os.path.exists(dirpath) and os.path.isdir(dirpath):
        print(f"✓ {name:20} : {dirname}/ (FOUND)")
        
        # List files in the directory
        files = os.listdir(dirpath)
        for f in files:
            print(f"    • {f}")
    else:
        print(f"✗ {name:20} : {dirname}/ (MISSING)")
        all_found = False

# Check for model files
print("\n" + "-" * 70)
print("CHECKING MODEL FILES:")
print("-" * 70)

model_files = {
    "Stage1 TFIDF": os.path.join("stage1", "tfidf.joblib"),
    "Stage1 Model": os.path.join("stage1", "calibrated_logreg.joblib"),
    "Stage2 Model": os.path.join("stage2", "stage2_hgb.joblib"),
    "Stage2 Features": os.path.join("stage2", "stage2_feature_columns.joblib"),
    "Policy Config": os.path.join("stage2", "policy_meta.json"),
}

for name, filepath in model_files.items():
    fullpath = os.path.join(current_dir, filepath)
    if os.path.exists(fullpath):
        size_mb = os.path.getsize(fullpath) / (1024 * 1024)
        print(f"✓ {name:20} : {filepath} ({size_mb:.2f} MB)")
    else:
        print(f"✗ {name:20} : {filepath} (MISSING)")
        all_found = False

# Check Python packages
print("\n" + "-" * 70)
print("CHECKING PYTHON PACKAGES:")
print("-" * 70)

packages = {
    "numpy": "numpy",
    "pandas": "pandas",
    "scikit-learn": "sklearn",
    "joblib": "joblib",
    "tldextract": "tldextract",
    "python-whois": "whois",
    "requests": "requests",
}

for display_name, import_name in packages.items():
    try:
        __import__(import_name)
        print(f"✓ {display_name:20} : Installed")
    except ImportError:
        print(f"✗ {display_name:20} : NOT INSTALLED")
        all_found = False

# Summary
print("\n" + "=" * 70)
if all_found:
    print("✓ ALL CHECKS PASSED! System is ready to run.")
    print("\nTo start the system, run:")
    print(f"  python {os.path.join(current_dir, 'sentinurl_ultimate.py')}")
else:
    print("✗ SOME CHECKS FAILED! Please fix the issues above.")
    print("\nMissing files should be placed in:")
    print(f"  {current_dir}")
print("=" * 70)

# Offer to run a quick test
if all_found:
    print("\n" + "-" * 70)
    response = input("Would you like to run a quick test? (y/n): ").strip().lower()
    
    if response == 'y':
        print("\nRunning quick test...")
        print("-" * 70)
        
        try:
            # Try to import and run a basic test
            sys.path.insert(0, current_dir)
            
            from visual_similarity_detection import check_visual_similarity
            
            # Test cases
            test_urls = [
                ("google.com", False),
                ("g00gle.com", True),
                ("paypal.com", False),
                ("paypa1.com", True),
            ]
            
            print("\nVisual Similarity Detection Test:")
            for url, should_detect in test_urls:
                is_susp, brand, score, attack_type = check_visual_similarity(url)
                status = "✓" if is_susp == should_detect else "✗"
                result = "SUSPICIOUS" if is_susp else "SAFE"
                print(f"  {status} {url:20} → {result:12} {f'({brand}, {attack_type})' if is_susp else ''}")
            
            print("\n✓ Quick test completed successfully!")
            
        except Exception as e:
            print(f"\n✗ Test failed: {e}")
            print("But don't worry - you can still run the main system.")

print("\n")
