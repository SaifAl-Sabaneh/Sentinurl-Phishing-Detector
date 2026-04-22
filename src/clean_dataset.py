import pandas as pd
import os

MASTER_DATASET = os.path.join("data", "raw", "SentinURl DataSet.csv")

def deduplicate_master_dataset():
    """Reads the master dataset, removes duplicate URLs, and saves it back."""
    print(f"[*] Starting deduplication on: {MASTER_DATASET}")
    
    if not os.path.exists(MASTER_DATASET):
        print(f"[!] Error: {MASTER_DATASET} not found.")
        return

    try:
        # Load the dataset
        df = pd.read_csv(MASTER_DATASET, low_memory=False)
        initial_count = len(df)
        
        if 'URL' not in df.columns:
            print("[!] Error: 'URL' column not found in dataset.")
            return

        # Deduplicate
        # Keep the first occurrence (usually the original or earliest added)
        df_clean = df.drop_duplicates(subset=['URL'], keep='first')
        final_count = len(df_clean)
        removed_count = initial_count - final_count

        if removed_count > 0:
            # Save back to disk
            df_clean.to_csv(MASTER_DATASET, index=False, encoding='utf-8')
            print(f"[v] Deduplication complete. Removed {removed_count:,} duplicate rows.")
            print(f"[v] New total rows: {final_count:,}")
        else:
            print("[*] No duplicate rows found. Dataset is already clean.")

    except Exception as e:
        print(f"[!] Error during deduplication: {e}")

if __name__ == "__main__":
    deduplicate_master_dataset()
