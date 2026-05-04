import pandas as pd
import numpy as np
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
import os
import sys

# Ensure imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from comprehensive_features import extract_all_features

input_csv = r"C:\Users\Asus\Desktop\Graduation Project\PreTrained Models\data\processed\SentinURL Processed Dataset.csv"
output_csv = r"C:\Users\Asus\Desktop\Graduation Project\PreTrained Models\data\processed\SentinURL_Processed_Dataset_Features.csv"

def process_chunk(chunk):
    results = []
    for _, row in chunk.iterrows():
        url = str(row.get("url", ""))
        label = str(row.get("Type", "Benign"))
        try:
            feats = extract_all_features(url, label=label)
            results.append(feats)
        except Exception:
            pass
    return pd.DataFrame(results)

if __name__ == '__main__':
    print(f"Loading {input_csv}...")
    try:
        df = pd.read_csv(input_csv)
    except Exception as e:
        print(f"Error reading CSV: {e}")
        sys.exit(1)
        
    print(f"Loaded {len(df)} rows.")
    
    # We will process in chunks to save memory and show progress
    num_cores = os.cpu_count() or 4
    num_chunks = num_cores * 10
    chunk_size = len(df) // num_chunks + 1
    chunks = [df.iloc[i:i + chunk_size] for i in range(0, len(df), chunk_size)]
    num_chunks = len(chunks)
    print(f"Processing in {num_chunks} chunks using {num_cores} cores...")
    
    start_time = time.time()
    header_written = False
    
    with ProcessPoolExecutor(max_workers=num_cores) as executor:
        futures = {executor.submit(process_chunk, chunk): i for i, chunk in enumerate(chunks)}
        
        for i, future in enumerate(as_completed(futures)):
            result_df = future.result()
            
            # Write to CSV incrementally
            if not header_written:
                result_df.to_csv(output_csv, index=False, mode='w')
                header_written = True
            else:
                result_df.to_csv(output_csv, index=False, mode='a', header=False)
                
            elapsed = time.time() - start_time
            print(f"Completed chunk {i+1}/{num_chunks} - Time elapsed: {elapsed:.2f}s")

    print(f"Extraction complete! Saved to {output_csv}")
    print(f"Total time: {(time.time() - start_time):.2f}s")
