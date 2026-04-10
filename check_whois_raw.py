import whois
from datetime import datetime

domain = "render.com"
print(f"Checking WHOIS for {domain}...")
try:
    w = whois.whois(domain)
    print(f"Type: {type(w)}")
    print(f"Attributes: {dir(w)}")
    print(f"Creation Date: {w.creation_date}")
    print(f"Creation Date Type: {type(w.creation_date)}")
    
    if isinstance(w.creation_date, list):
        for i, d in enumerate(w.creation_date):
            print(f"  [{i}]: {d} ({type(d)})")
            
except Exception as e:
    print(f"Error: {e}")
