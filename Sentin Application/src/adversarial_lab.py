import random
import pandas as pd
import os

# Configuration
SAFE_DOMAINS = ["google.com", "paypal.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com", "binary.com", "netflix.com"]
SCAM_KEYWORDS = ["secure", "login", "verify", "account", "update", "free", "gift", "bonus", "winner", "prize"]
RISKY_TLDS = ["tk", "ml", "ga", "cf", "gq", "top", "xyz", "site", "online", "pw"]

def generate_adversarial_urls(count=500):
    urls = []
    
    for _ in range(count):
        strategy = random.choice(["subdomain", "path", "homograph", "ip", "nested"])
        brand = random.choice(SAFE_DOMAINS).split('.')[0]
        tld = random.choice(RISKY_TLDS)
        keyword = random.choice(SCAM_KEYWORDS)
        
        if strategy == "subdomain":
            # Tactic: Use brand as a subdomain of a risky TLD
            url = f"http://{brand}.{keyword}-profile-check.{tld}/index.php"
            
        elif strategy == "path":
            # Tactic: Put a full legitimate URL inside the path
            url = f"http://secure-access-{random.randint(100,999)}.{tld}/{brand}.com/login/verification"
            
        elif strategy == "homograph":
            # Tactic: Visual mimicry (replacing 'a' with 'α', 'o' with '0')
            mimic = brand.replace('a', 'α').replace('o', '0').replace('e', '3')
            url = f"http://www.{mimic}.com.auth-update.{tld}/"
            
        elif strategy == "ip":
            # Tactic: Direct IP with brand path
            ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            url = f"http://{ip}/{brand}/login?session={random.getrandbits(64)}"
            
        elif strategy == "nested":
            # Tactic: Extreme subdomain nesting
            url = f"http://{brand}.secure.{keyword}.update.account.verify.{tld}/"
            
        urls.append(url)
    
    return list(set(urls))

if __name__ == "__main__":
    print("[*] Starting SentinURL Adversarial Lab...")
    adversarial_list = generate_adversarial_urls(1000)
    print(f"[+] Generated {len(adversarial_list)} unique adversarial URLs.")
    
    # Save to a temporary CSV for inspection
    df = pd.DataFrame({"URL": adversarial_list, "Type": "phishing"})
    output_path = "adversarial_mutants.csv"
    df.to_csv(output_path, index=False)
    print(f"[+] Saved to {output_path}")
    
    # Optional: Append to Master Dataset automatically
    master_path = "Master_SentinURL_Dataset.csv"
    if os.path.exists(master_path):
        df.to_csv(master_path, mode='a', header=False, index=False)
        print(f"[+] Injected {len(adversarial_list)} mutants into {master_path} for immunization.")
    else:
        print(f"⚠️ Master dataset not found at {master_path}")
