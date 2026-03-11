import sys
import time
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.append('.')
from sentinurl import predict_ultimate
import os
import io

def test_url(url):
    try:
        lbl, score, src, reasons, p1, p2, _, _ = predict_ultimate(url)
        return {"url": url, "label": lbl, "score": score, "src": src, "p1": p1, "p2": p2, "reasons": reasons}
    except Exception as e:
        return {"url": url, "label": "ERROR", "score": 0.0, "src": str(e), "p1": 0.0, "p2": 0.0, "reasons": []}

def run_bulk_test(num_samples=100):
    print("Loading dataset...")
    df = pd.read_csv("Phishing Dataset.csv", encoding="latin1", low_memory=False)
    
    url_col = df.columns[0]
    type_col = df.columns[1]
    
    phishing_df = df[df[type_col].astype(str).str.lower().str.contains("phish")]
    
    print(f"Found {len(phishing_df)} phishing URLs in dataset.")
    samples = phishing_df[url_col].sample(n=num_samples, random_state=42).tolist()
    
    print(f"Testing {num_samples} random phishing URLs...")
    results_counts = {"PHISHING": 0, "HIGH RISK": 0, "LOW RISK": 0, "SAFE": 0, "ERROR": 0}
    
    start_time = time.time()
    
    misses = []
    
    # 10 workers to speed up the GSB/TLS online checks
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(test_url, u): u for u in samples}
        for i, future in enumerate(as_completed(futures), 1):
            res = future.result()
            label = res["label"]
            
            if label not in results_counts:
                results_counts[label] = 0
            results_counts[label] += 1
            
            # If it missed the phishing threat, log it
            if label in ["SAFE", "LOW RISK"]:
                misses.append(res)
            
            if i % 10 == 0:
                print(f"Processed {i}/{num_samples} (Found {len(misses)} misses so far)...")
                
    elapsed = time.time() - start_time
    
    print("\n" + "="*50)
    print(f"BULK TEST RESULTS ({num_samples} True Phishing URLs)")
    print("="*50)
    print(f"Time Taken: {elapsed:.1f} seconds")
    
    caught = results_counts.get("PHISHING", 0) + results_counts.get("HIGH RISK", 0) + results_counts.get("SUSPICIOUS", 0)
    accuracy = (caught / num_samples) * 100
    
    for k, v in sorted(results_counts.items()):
        if v > 0:
            print(f"  {k}: {v} ({v/num_samples*100:.1f}%)")
            
    print(f"\nModel True Positive Rate (Accuracy): {accuracy:.1f}%")
    
    if misses:
        print("\n" + "="*50)
        print(f"MISSED URLs (False Negatives Overview)")
        print("="*50)
        for m in misses[:5]:
            print(f"URL: {m['url']}")
            print(f"Label: {m['label']} | Confidence: {m['score']:.3f} | S1 AI: {m['p1']:.3f} | S2 AI: {m['p2']:.3f}")
            print(f"Triggered Override Rule: {m['src']}")
            print("-" * 30)

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings('ignore')
    run_bulk_test(100)
