import os
import pandas as pd

def deduplicate_master_dataset():
    print("--- SentinURL Master Dataset Deduplicator ---")
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    master_path = os.path.join(current_dir, "SentinURl DataSet.csv")
    
    if not os.path.exists(master_path):
        print(f"[!] Error: Master dataset not found at {master_path}")
        return

    print(f"[*] Loading dataset: {master_path}...")
    try:
        # Load the dataset
        # We use low_memory=False to prevent DtypeWarnings for mixed types
        df = pd.read_csv(master_path, low_memory=False)
        initial_count = len(df)
        print(f"[*] Initial row count: {initial_count:,}")

        # Remove duplicates based on the 'URL' column
        # Standardizing URL to catch variations (though they should be unique strings)
        df['URL'] = df['URL'].astype(str).str.strip()
        df.drop_duplicates(subset=['URL'], keep='first', inplace=True)
        
        final_count = len(df)
        removed = initial_count - final_count
        
        if removed > 0:
            print(f"[+] Found and removed {removed:,} duplicate URLs.")
            print(f"[*] Saving cleaned dataset...")
            # Save back to CSV
            df.to_csv(master_path, index=False)
            print(f"[v] Cleanup complete. Final count: {final_count:,} rows.")
        else:
            print("[v] No duplicate URLs found. Dataset is already clean.")

    except Exception as e:
        print(f"[!] Critical Error during deduplication: {e}")

if __name__ == "__main__":
    deduplicate_master_dataset()
