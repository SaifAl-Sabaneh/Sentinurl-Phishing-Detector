import os
import pandas as pd
import numpy as np

def consolidate_datasets():
    print("--- SentinURL Master Dataset Consolidator ---")
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 1. Define source files (relative paths)
    sources = [
        {"path": "Merged_Ultimate_Dataset.csv", "label_default": None},
        {"path": "Phishing Dataset.csv", "label_default": None},
        {"path": "phishing-urls.csv", "label_default": "phishing"},
        {"path": "testt.csv", "label_default": "phishing"},
        {"path": "phishing_test_urls.csv", "label_default": "phishing"},
        {"path": "documents/phishing-urls.csv", "label_default": "phishing"},
        {"path": "documents/phishing_test_urls.csv", "label_default": "phishing"},
        {"path": "steps/URL dataset.csv", "label_default": "phishing"}
    ]
    
    all_data = []
    total_loaded = 0
    
    for src in sources:
        fpath = os.path.join(current_dir, src['path'])
        if not os.path.exists(fpath):
            print(f"[!] Skipping missing file: {src['path']}")
            continue
            
        print(f"[*] Processing: {src['path']}...", end=" ", flush=True)
        try:
            # Load with flexible encoding
            try:
                df = pd.read_csv(fpath, encoding="utf-8", low_memory=False)
            except:
                df = pd.read_csv(fpath, encoding="latin1", low_memory=False)
            
            # Normalize Columns
            # Find the URL column
            url_col = None
            for col in df.columns:
                if 'url' in col.lower() or 'link' in col.lower() or col.strip() == '':
                    url_col = col
                    break
            
            if url_col is None:
                # If no clear URL column, and it's 1 column, assume it's the URL
                if len(df.columns) == 1:
                    url_col = df.columns[0]
                else:
                    print(f"FAILED (No URL column found)")
                    continue
            
            # Find the Type column
            type_col = None
            for col in df.columns:
                if 'type' in col.lower() or 'label' in col.lower() or 'class' in col.lower():
                    type_col = col
                    break
            
            temp_df = pd.DataFrame()
            temp_df['URL'] = df[url_col].astype(str).str.strip()
            
            if type_col is not None:
                temp_df['Type'] = df[type_col].astype(str).str.strip().str.lower()
            elif src['label_default']:
                temp_df['Type'] = src['label_default']
            else:
                temp_df['Type'] = 'safe' 
            
            # Clean Labels
            temp_df['Type'] = temp_df['Type'].apply(lambda x: 'phishing' if 'phish' in str(x) or '1' == str(x) else 'safe')
            
            all_data.append(temp_df)
            total_loaded += len(temp_df)
            print(f"DONE ({len(temp_df):,} rows)")
            
        except Exception as e:
            print(f"FAILED ({e})")
            
    if not all_data:
        print("\n[x] No data loaded. Aborting.")
        return
        
    print("\n--- Merging and Deduplicating ---")
    master_df = pd.concat(all_data, ignore_index=True)
    initial_count = len(master_df)
    
    # Deduplicate by URL
    master_df = master_df.drop_duplicates(subset=['URL'], keep='first')
    final_count = len(master_df)
    
    print(f"Initial Total : {initial_count:,} rows")
    print(f"Duplicates Removed: {initial_count - final_count:,}")
    print(f"Final Master Set  : {final_count:,} unique URLs")
    
    # Check Phishing/Safe balance
    stats = master_df['Type'].value_counts()
    print("\nDistribution:")
    for k, v in stats.items():
        print(f"  • {k.upper()}: {v:,} ({v/final_count*100:.2f}%)")
    
    # Save
    out_path = os.path.join(current_dir, "Master_SentinURL_Dataset.csv")
    master_df.to_csv(out_path, index=False, encoding="utf-8")
    print(f"\n[v] Master Dataset Saved: {out_path}")

if __name__ == "__main__":
    consolidate_datasets()
