import re
import math
from urllib.parse import urlparse, unquote
from collections import Counter
import tldextract

# Import existing helpers if available, or redefine
try:
    from enhanced_original import BRAND_KEYWORDS, RISKY_TLDS, SHORTENERS, SUSPICIOUS_PATHS, CRED_INTENT_WORDS
except ImportError:
    BRAND_KEYWORDS = ["google", "paypal", "microsoft", "apple", "amazon", "facebook", "instagram", "whatsapp", "youtube", "netflix"]
    RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq"}
    SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"}
    SUSPICIOUS_PATHS = ["wp-content", "wp-includes", "cgi-bin", "login.php", "signin.php"]
    CRED_INTENT_WORDS = ["login", "signin", "verify", "password", "account", "update", "secure"]

EXTRACT = tldextract.TLDExtract()

def entropy(s):
    if not s: return 0.0
    p = [c / len(s) for c in Counter(s).values()]
    return -sum(x * math.log2(x) for x in p if x > 0)

def get_vowel_consonant_ratio(s):
    if not s: return 0.0
    vowels = sum(c in "aeiou" for c in s.lower())
    consonants = sum(c in "bcdfghjklmnpqrstvwxyz" for c in s.lower())
    if consonants == 0: return float(vowels)
    return vowels / consonants

def min_edit_distance(s1, s2):
    if len(s1) < len(s2): return min_edit_distance(s2, s1)
    if not s2: return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def extract_all_features(url, label="phishing"):
    decoded = unquote(str(url))
    low = decoded.lower()
    
    # Pre-parsing
    p = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
    host = (p.netloc or "").lower().split(":")[0]
    path = p.path or ""
    query = p.query or ""
    
    ext = EXTRACT(host)
    domain_label = ext.domain
    suffix = ext.suffix
    tld = suffix.split('.')[-1] if suffix else ""
    
    # Basic Lengths
    feats = {
        "URL": url,
        "Type": label,
        "url_len": len(decoded),
        "host_len": len(host),
        "path_len": len(path),
        "query_len": len(query)
    }
    
    # Tokens
    host_tokens = [t for t in re.split(r"[.\-]", host) if t]
    path_tokens = [t for t in path.split("/") if t]
    feats["max_host_token_len"] = max([len(t) for t in host_tokens]) if host_tokens else 0
    feats["max_path_token_len"] = max([len(t) for t in path_tokens]) if path_tokens else 0
    
    # Counts
    for char, name in [('.', 'dots'), ('-', 'hyphens'), ('/', 'slashes'), ('_', 'underscores')]:
        feats[name] = decoded.count(char)
    
    feats["digits"] = sum(c.isdigit() for c in decoded)
    feats["letters"] = sum(c.isalpha() for c in decoded)
    feats["specials"] = sum(not c.isalnum() for c in decoded)
    
    for char, name in [('@', 'at_count'), ('%', 'pct_count'), ('=', 'eq_count'), ('&', 'amp_count'), 
                       ('?', 'ques_count'), ('~', 'tilde_count'), ('#', 'hash_count'), ('!', 'excl_count'), 
                       ('+', 'plus_count'), (':', 'colon_count'), (';', 'semi_count'), (',', 'comma_count'), ('*', 'star_count')]:
        feats[name] = decoded.count(char)
        
    # Ratios
    total_len = max(len(decoded), 1)
    feats["digit_ratio"] = feats["digits"] / total_len
    feats["special_ratio"] = feats["specials"] / total_len
    feats["letter_ratio"] = feats["letters"] / total_len
    feats["vc_ratio_host"] = get_vowel_consonant_ratio(host)
    
    # Structure
    feats["subdomains"] = host.count(".")
    feats["num_dots_host"] = host.count(".")
    feats["num_dots_path"] = path.count(".")
    feats["host_token_count"] = len(host_tokens)
    feats["path_token_count"] = len(path_tokens)
    feats["query_param_count"] = len(query.split("&")) if query else 0
    feats["path_depth"] = path.count("/")
    feats["port_present"] = 1 if ":" in p.netloc else 0
    feats["double_slash_path"] = 1 if "//" in path else 0
    
    # Metadata
    feats["tld_len"] = len(suffix)
    feats["is_https"] = 1 if url.startswith("https") else 0
    feats["is_ipv4"] = 1 if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) else 0
    feats["punycode"] = 1 if "xn--" in host else 0
    feats["has_encoded_chars"] = 1 if "%" in low else 0
    feats["has_double_encoding"] = 1 if re.search(r"%[0-9a-f]{2}%[0-9a-f]{2}", low) else 0
    feats["has_suspicious_port"] = 1 if feats["port_present"] and p.port not in [80, 443] else 0
    
    # Entropy
    feats["entropy_url"] = entropy(decoded)
    feats["entropy_host"] = entropy(host)
    feats["entropy_path"] = entropy(path)
    feats["entropy_query"] = entropy(query)
    feats["entropy_domain_label"] = entropy(domain_label)
    
    # Keywords
    feats["has_login"] = 1 if any(w in low for w in ["login", "signin", "verify", "secure", "account", "auth"]) else 0
    feats["has_finance"] = 1 if any(w in low for w in ["bank", "pay", "payment", "billing", "invoice", "crypto", "wallet"]) else 0
    feats["has_scam"] = 1 if any(w in low for w in ["free", "bonus", "winner", "hack", "porn", "adware", "malware"]) else 0
    feats["brand_hits"] = sum(1 for b in BRAND_KEYWORDS if b in low)
    feats["suspicious_path"] = 1 if any(sp in low for sp in SUSPICIOUS_PATHS) else 0
    feats["redirect_like"] = 1 if re.search(r"(redirect|next|url|continue|dest|destination)=", low) else 0
    feats["cred_intent_path"] = 1 if any(w in path.lower() for w in CRED_INTENT_WORDS) else 0
    
    # Dummy placeholder for log_odds (can't compute without original model coefficients)
    feats["log_odds_hits"] = 0 
    
    # Keyword counts
    keyword_map = {
        "login": "login_kw_count", "verify": "verify_kw_count", "secure": "secure_kw_count",
        "account": "account_kw_count", "update": "update_kw_count", "confirm": "confirm_kw_count",
        "pay": "pay_kw_count", "bank": "bank_kw_count", "free": "free_kw_count",
        "win": "win_kw_count", "crypto": "crypto_kw_count"
    }
    for kw, f_name in keyword_map.items():
        feats[f_name] = low.count(kw)
        
    # Flags
    feats["risky_tld"] = 1 if tld in RISKY_TLDS else 0
    feats["is_shortener"] = 1 if host in SHORTENERS else 0
    feats["is_free_hosting"] = 1 if any(fh in host for fh in ["weebly", "wix", "webflow", "000webhost", "github.io"]) else 0
    feats["is_ipfs"] = 1 if "ipfs" in low else 0
    
    # Host/Path Digits/Hyphens
    feats["digits_in_host"] = sum(c.isdigit() for c in host)
    feats["digits_in_path"] = sum(c.isdigit() for c in path)
    feats["hyphens_in_host"] = host.count("-")
    feats["hyphens_in_path"] = path.count("-")
    
    # Brand positions
    feats["brand_in_domain"] = 1 if any(b in domain_label for b in BRAND_KEYWORDS) else 0
    feats["brand_in_path"] = 1 if any(b in path.lower() for b in BRAND_KEYWORDS) else 0
    feats["brand_in_query"] = 1 if any(b in query.lower() for b in BRAND_KEYWORDS) else 0
    feats["subdomain_brand"] = 1 if any(b in ext.subdomain for b in BRAND_KEYWORDS) else 0
    feats["many_subdomains"] = 1 if feats["subdomains"] > 3 else 0
    
    # Deception
    feats["combo_squat"] = 1 if feats["brand_in_domain"] and any(kw in domain_label for kw in ["secure", "login", "update", "verify"]) else 0
    # Placeholder for typosquat/dga/edit_dist
    feats["likely_typosquat"] = 0
    feats["min_edit_dist_to_brand"] = 100
    if domain_label:
        dists = [min_edit_distance(domain_label, b) for b in BRAND_KEYWORDS]
        min_d = min(dists)
        feats["min_edit_dist_to_brand"] = min_d
        if 0 < min_d <= 2: feats["likely_typosquat"] = 1
            
    feats["looks_dga"] = 1 if feats["entropy_host"] > 4.5 and len(host) > 15 else 0
    
    # File Exts
    for ext_name, col_name in [('.php', 'has_php_ext'), ('.html', 'has_html_ext'), ('.asp', 'has_asp_ext'), 
                              ('.js', 'has_js_ext'), ('.exe', 'has_exe_ext'), ('.zip', 'has_zip_ext'), ('.doc', 'has_doc_ext')]:
        feats[col_name] = 1 if path.endswith(ext_name) or f"{ext_name}?" in low else 0
    feats["has_wp_path"] = 1 if "wp-content" in low or "wp-includes" in low else 0
    
    # TOKENS (Binary indicators for specific words)
    tokens = [
        "login", "verify", "secure", "account", "update", "confirm", "payment", 
        "signin", "billing", "recover", "support", "helpdesk", "webscr", "php", "https", "http"
    ]
    for tok in tokens:
        feats[f"tok_{tok}"] = 1 if tok in low else 0
        
    return feats
