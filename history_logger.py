import pandas as pd
import os
from datetime import datetime, timedelta
import threading

HISTORY_FILE = "global_scan_history.csv"
LOCK = threading.Lock()

def initialize_history():
    """Ensure the history file exists with correct headers."""
    if not os.path.exists(HISTORY_FILE):
        df = pd.DataFrame(columns=[
            "Timestamp", "URL", "Domain", "Status", 
            "Risk Score", "Engine", "User Agent", "Source"
        ])
        df.to_csv(HISTORY_FILE, index=False)

def prune_old_logs(days=30):
    """Remove entries older than the specified number of days."""
    if not os.path.exists(HISTORY_FILE):
        return

    try:
        df = pd.read_csv(HISTORY_FILE)
        if df.empty:
            return

        cutoff = datetime.now() - timedelta(days=days)
        # Convert Timestamp column to datetime for comparison
        df['dt_temp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        
        # Keep rows newer than cutoff (or rows where parsing failed to be safe)
        mask = (df['dt_temp'] > cutoff) | (df['dt_temp'].isna())
        df_pruned = df[mask].drop(columns=['dt_temp'])

        if len(df_pruned) < len(df):
            df_pruned.to_csv(HISTORY_FILE, index=False)
    except Exception as e:
        print(f"Error pruning logs: {e}")

def log_scan(url, domain, status, score, engine, user_agent, source):
    """Log a scan result thread-safely and prune old logs."""
    initialize_history()
    
    with LOCK:
        try:
            # Prepare the new record
            new_record = {
                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "URL": url,
                "Domain": domain,
                "Status": status,
                "Risk Score": score,
                "Engine": engine,
                "User Agent": user_agent,
                "Source": source
            }
            
            # Efficiently append to CSV
            df_new = pd.DataFrame([new_record])
            df_new.to_csv(HISTORY_FILE, mode='a', header=False, index=False)
            
            # Periodically prune (e.g., every 10 scan writes) to optimize performance
            import random
            if random.random() < 0.10: # 10% chance per scan to run pruning
                prune_old_logs(days=30)
            
        except Exception as e:
            print(f"Error logging scan: {e}")

def get_history_df():
    """Load the history as a DataFrame."""
    if os.path.exists(HISTORY_FILE):
        try:
            return pd.read_csv(HISTORY_FILE)
        except:
            pass
    return pd.DataFrame(columns=[
        "Timestamp", "URL", "Domain", "Status", 
        "Risk Score", "Engine", "User Agent", "Source"
    ])
