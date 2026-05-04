import webview
import json
import threading
import time
import os
import sys

# Setup paths
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from sentinurl import predict_ultimate
try:
    from history_logger import get_history_df
except ImportError:
    get_history_df = lambda: None

class Api:
    def __init__(self):
        self.window = None

    def set_window(self, window):
        self.window = window

    def scan_url(self, url):
        threading.Thread(target=self._run_scan, args=(url,)).start()
        return "Scanning started"

    def _run_scan(self, url):
        try:
            t0 = time.perf_counter()
            lbl, p, src, reasons, p1, p2, whois_data, geo_info, _ = predict_ultimate(url)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            
            result = {
                "status": "success",
                "label": lbl,
                "score": p,
                "engine": src,
                "reasons": reasons,
                "whois": whois_data or {},
                "geo": geo_info or {},
                "time_ms": elapsed_ms
            }
        except Exception as e:
            result = {"status": "error", "message": str(e)}
            
        self.window.evaluate_js(f"window.onScanComplete({json.dumps(result)})")

    def get_history(self):
        df = get_history_df()
        if df is None or df.empty:
            return []
        
        recent = df.tail(15).iloc[::-1]
        history = []
        for _, row in recent.iterrows():
            history.append({
                "domain": row.get("Domain", "Unknown"),
                "status": str(row.get("Status", "Unknown")).upper(),
                "time": str(row.get("Timestamp", ""))
            })
        return history

if __name__ == '__main__':
    api = Api()
    ui_path = os.path.join(current_dir, 'ui', 'index.html')
    
    # Create webview window
    window = webview.create_window(
        'SentinURL Ultimate Enterprise Edition', 
        ui_path, 
        js_api=api,
        width=1350, 
        height=850,
        background_color='#080A10'
    )
    api.set_window(window)
    
    # Start app
    webview.start()
