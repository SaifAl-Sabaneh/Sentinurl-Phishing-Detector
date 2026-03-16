import os
import re
import json
import math
import time
import joblib
import hashlib
import socket
import ssl
from functools import lru_cache
from collections import Counter
from urllib.parse import urlparse, unquote
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import tldextract

# Try to import WHOIS - handle the python-whois package correctly
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    whois = None
    print("Warning: python-whois not installed. WHOIS lookups disabled.")
    print("Install with: pip install python-whois")

from PIL import Image
import io

try:
    import requests
except Exception:
    requests = None


# =========================================================
# CONFIG
# =========================================================
MODE = "PROTECT"  # security-first; avoids embarrassing false alarms
DEBUG_MODE = False  # Set to True to see WHOIS lookup debug info

HTTP_TIMEOUT = (2.0, 6.0)
TLS_TIMEOUT_S = 3.0
MAX_HTML_BYTES = 30000
CACHE_TTL_SECONDS = 6 * 3600

UNCERTAIN_LOW = 0.20
UNCERTAIN_HIGH = 0.75

# Production floors (prevents absurd SAFE<0.83% policy from causing warnings)
PROTECT_SAFE_FLOOR = 0.05         # 5%
PROTECT_SUSP_SAFE_FLOOR = 0.35    # 35%
PROTECT_PHISH_FLOOR = 0.85        # 85%

ENGINE_VERSION = "2.2.3-protect-enhanced"


# =========================================================
# MODEL PATHS
# =========================================================
STAGE1_DIR = r"C:\Users\Asus\Desktop\Graduation Project\PreTrained Models\stage1"
STAGE2_DIR = r"C:\Users\Asus\Desktop\Graduation Project\PreTrained Models\stage2"

S1_TFIDF_PATH = os.path.join(STAGE1_DIR, "tfidf.joblib")
S1_MODEL_PATH = os.path.join(STAGE1_DIR, "calibrated_logreg.joblib")

S2_MODEL_PATH = os.path.join(STAGE2_DIR, "stage2_hgb.joblib")
S2_COLS_PATH = os.path.join(STAGE2_DIR, "stage2_feature_columns.joblib")
POLICY_PATH = os.path.join(STAGE2_DIR, "policy_meta.json")

RESULTS_LOG_BASENAME = "scan_results"


# =========================================================
# LOAD MODELS + POLICY
# =========================================================
print("Starting to load models...")

try:
    tfidf = joblib.load(S1_TFIDF_PATH)
    print("Stage1 TFIDF model loaded successfully.")
except Exception as e:
    print(f"Error loading Stage1 TFIDF model: {e}")
    tfidf = None

try:
    s1_model = joblib.load(S1_MODEL_PATH)
    print("Stage1 LogReg model loaded successfully.")
except Exception as e:
    print(f"Error loading Stage1 LogReg model: {e}")
    s1_model = None

try:
    s2_model = joblib.load(S2_MODEL_PATH)
    print("Stage2 HGB model loaded successfully.")
except Exception as e:
    print(f"Error loading Stage2 HGB model: {e}")
    s2_model = None

try:
    STAGE2_COLS = joblib.load(S2_COLS_PATH)
    print("Stage2 feature columns loaded successfully.")
except Exception as e:
    print(f"Error loading Stage2 feature columns: {e}")
    STAGE2_COLS = []

try:
    with open(POLICY_PATH, "r", encoding="utf-8") as f:
        policy = json.load(f)
    print("Policy loaded successfully.")
except Exception as e:
    print(f"Error loading policy: {e}")
    policy = {"bands": {"SAFE_MAX": 0.01, "SUSP_SAFE_MAX": 0.5, "PHISH_MIN": 0.9}, "fusion": {"w_stage1": 0.2, "w_stage2": 0.8}}

SAFE_MAX = float(policy["bands"]["SAFE_MAX"])
SUSP_SAFE_MAX = float(policy["bands"]["SUSP_SAFE_MAX"])
PHISH_MIN = float(policy["bands"]["PHISH_MIN"])

W1 = float(policy["fusion"]["w_stage1"])
W2 = float(policy["fusion"]["w_stage2"])

metrics = policy.get("metrics", {})

print("Models and policy loaded successfully.")


# =========================================================
# CONSTANTS
# =========================================================
SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "update", "secure", "account", "bank",
    "confirm", "password", "pay", "billing", "invoice", "support", "token"
]

CRED_INTENT_WORDS = [
    "login", "signin", "sign-in", "verify", "verification", "password", "passcode",
    "account", "update", "secure", "security", "2fa", "otp", "token",
    "wallet", "billing", "invoice", "payment", "pay", "authorize",
    "recover", "reset", "unlock"
]

REDIRECT_PARAM_PAT = re.compile(r"(redirect|next|url|continue|dest|destination|return|callback)=", re.IGNORECASE)

RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"}

BRAND_KEYWORDS = [
    "google", "paypal", "microsoft", "apple", "amazon",
    "facebook", "instagram", "whatsapp", "youtube"
]

BRAND_DOMAINS = {
    "google.com", "paypal.com", "microsoft.com", "microsoftonline.com",
    "apple.com", "amazon.com", "facebook.com", "instagram.com",
    "whatsapp.com", "youtube.com"
}

INSTITUTION_SUFFIX_PREFIXES = ("edu.", "ac.", "gov.", "mil.")
INSTITUTION_SUFFIX_EXACT = {"edu", "ac", "gov", "mil"}

# ENHANCED: Expanded educational TLDs to include country-specific domains
EDUCATIONAL_TLDS = {
    "edu", "ac.uk", "edu.au", "ac.nz", "edu.jo", "edu.sa", "edu.eg", 
    "edu.ae", "ac.jp", "ac.kr", "edu.cn", "ac.in", "edu.my", "edu.sg",
    "edu.pk", "edu.bd", "ac.za", "edu.tr", "ac.il", "edu.br", "edu.mx",
    "edu.co", "edu.ar", "edu.pe", "edu.uy", "ac.th", "edu.ph"
}

# ENHANCED: Expanded government TLDs
GOVERNMENT_TLDS = {
    "gov", "gov.uk", "gov.au", "gov.jo", "gov.sa", "gov.ae", "gov.eg",
    "gov.cn", "gov.in", "gov.sg", "gov.my", "mil", "mil.jo",
    "go.jp", "go.kr", "gob.mx", "gouv.fr"
}

# Jordanian official domains (municipalities and government)
JORDANIAN_OFFICIAL = {
    "amman.jo", "zarqa.jo", "irbid.jo", "aqaba.jo", "madaba.jo",
    "salt.jo", "jerash.jo", "ajloun.jo", "karak.jo", "tafilah.jo",
    "maan.jo", "mafraq.jo"
}


# =========================================================
# PSL / tldextract
# =========================================================
EXTRACT = tldextract.TLDExtract()


# =========================================================
# ONLINE API KEYS
# =========================================================
GSB_API_KEY = os.getenv("SENTINURL_GSB_API_KEY", "").strip()
VT_API_KEY = os.getenv("SENTINURL_VT_API_KEY", "").strip()


# =========================================================
# HELPERS
# =========================================================
def utc_iso_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_date_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def normalize_url(u: str) -> str:
    u = str(u).strip()
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    return u


def safe_urlparse(u: str):
    try:
        return urlparse(u)
    except Exception:
        cleaned = re.sub(r"\[([^\]]+)\]", r"\1", u)
        try:
            return urlparse(cleaned)
        except Exception:
            return urlparse("http://invalid")


def _strip_www(host: str) -> str:
    host = (host or "").lower().strip().strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


@lru_cache(maxsize=2048)
def _cached_tld_extract(host: str):
    return EXTRACT(_strip_www(host))


@lru_cache(maxsize=2048)
def registrable_domain(host: str) -> str:
    host = _strip_www(host)
    if not host:
        return ""
    ext = _cached_tld_extract(host)
    if not ext.domain or not ext.suffix:
        return ""
    return f"{ext.domain}.{ext.suffix}"


@lru_cache(maxsize=2048)
def effective_suffix(host: str) -> str:
    host = _strip_www(host)
    if not host:
        return ""
    ext = _cached_tld_extract(host)
    return (ext.suffix or "").lower()


# ENHANCED: Better institution suffix detection
def is_institution_suffix(suffix: str) -> bool:
    suffix = (suffix or "").lower().strip().strip(".")
    if not suffix:
        return False
    # Check exact match in educational or government TLDs
    if suffix in EDUCATIONAL_TLDS or suffix in GOVERNMENT_TLDS:
        return True
    # Check if starts with known prefixes
    if suffix in INSTITUTION_SUFFIX_EXACT or suffix.startswith(INSTITUTION_SUFFIX_PREFIXES):
        return True
    return False


@lru_cache(maxsize=4096)
def get_host(url: str) -> str:
    p = safe_urlparse(normalize_url(url))
    host = (p.netloc or "").lower().split(":")[0].strip().strip(".")
    return _strip_www(host)


def find_brand_keyword(text: str):
    low = (text or "").lower()
    for b in BRAND_KEYWORDS:
        if b in low:
            return b
    return None


def entropy(s: str) -> float:
    if not s:
        return 0.0
    p = [c / len(s) for c in Counter(s).values()]
    return -sum(x * math.log2(x) for x in p if x > 0)


def has_ipv4(host: str) -> int:
    return 1 if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host or "") else 0


def safe_truncate(s: str, n: int = 60) -> str:
    s = s.replace("\n", " ").strip()
    return (s[:n] + "…") if len(s) > n else s


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


# =========================================================
# ENHANCED: WHOIS FUNCTIONALITY
# =========================================================
def get_whois_info(domain: str, debug: bool = False) -> dict:
    """Retrieve comprehensive WHOIS information for a domain"""
    info = {
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "registrar": None,
        "registrant_org": None,
        "registrant_country": None,
        "nameservers": [],
        "status": [],
        "age_days": None,
        "available": True  # Assume available if query fails
    }
    
    if not WHOIS_AVAILABLE or whois is None:
        if debug:
            print(f"[DEBUG] WHOIS module not available - install python-whois")
        return info
    
    try:
        if debug:
            print(f"[DEBUG] Attempting WHOIS lookup for: {domain}")
        
        # Try different API methods - python-whois has inconsistent APIs across versions
        w = None
        
        # Method 1: Try whois.whois() (most common)
        if hasattr(whois, 'whois'):
            try:
                w = whois.whois(domain)
                if debug:
                    print(f"[DEBUG] Used whois.whois() method")
            except:
                pass
        
        # Method 2: Try whois.query() (some versions)
        if w is None and hasattr(whois, 'query'):
            try:
                w = whois.query(domain)
                if debug:
                    print(f"[DEBUG] Used whois.query() method")
            except:
                pass
        
        # Method 3: Direct instantiation
        if w is None:
            try:
                from whois import WhoisEntry
                w = WhoisEntry.load(domain, domain)
                if debug:
                    print(f"[DEBUG] Used WhoisEntry.load() method")
            except:
                pass
        
        if w is None:
            if debug:
                print(f"[DEBUG] All WHOIS methods failed - no data available")
            return info
        
        if debug:
            print(f"[DEBUG] WHOIS response received")
            print(f"[DEBUG] Type: {type(w)}")
            print(f"[DEBUG] Attributes: {[a for a in dir(w) if not a.startswith('_')][:10]}")
        
        # Parse based on type
        # For dict-like responses (whois.whois() often returns dict)
        if isinstance(w, dict):
            if debug:
                print(f"[DEBUG] Processing dict response")
            
            # Creation date
            for key in ['creation_date', 'created']:
                if key in w and w[key]:
                    creation = w[key]
                    if isinstance(creation, list):
                        creation = creation[0]
                    try:
                        info["creation_date"] = creation.strftime("%Y-%m-%d") if hasattr(creation, 'strftime') else str(creation)
                        if hasattr(creation, 'year'):
                            info["age_days"] = (datetime.now() - creation).days
                    except:
                        pass
                    break
            
            # Expiration date
            for key in ['expiration_date', 'expires']:
                if key in w and w[key]:
                    expiration = w[key]
                    if isinstance(expiration, list):
                        expiration = expiration[0]
                    try:
                        info["expiration_date"] = expiration.strftime("%Y-%m-%d") if hasattr(expiration, 'strftime') else str(expiration)
                    except:
                        pass
                    break
            
            # Updated date
            for key in ['updated_date', 'updated', 'last_updated']:
                if key in w and w[key]:
                    updated = w[key]
                    if isinstance(updated, list):
                        updated = updated[0]
                    try:
                        info["updated_date"] = updated.strftime("%Y-%m-%d") if hasattr(updated, 'strftime') else str(updated)
                    except:
                        pass
                    break
            
            # Registrar
            if 'registrar' in w:
                reg = w['registrar']
                info["registrar"] = reg[0] if isinstance(reg, list) else reg
            
            # Organization
            for key in ['org', 'organization', 'registrant_organization']:
                if key in w and w[key]:
                    info["registrant_org"] = w[key]
                    break
            
            # Country
            if 'country' in w:
                info["registrant_country"] = w['country']
            
            # Nameservers
            for key in ['name_servers', 'nameservers']:
                if key in w and w[key]:
                    ns = w[key]
                    info["nameservers"] = [str(n).lower() for n in (ns if isinstance(ns, list) else [ns])]
                    break
            
            # Status
            if 'status' in w and w['status']:
                status = w['status']
                info["status"] = status if isinstance(status, list) else [status]
        
        # For object-like responses
        else:
            if debug:
                print(f"[DEBUG] Processing object response")
            
            # Creation date
            for attr in ['creation_date', 'created']:
                if hasattr(w, attr):
                    creation = getattr(w, attr)
                    if creation:
                        try:
                            info["creation_date"] = creation.strftime("%Y-%m-%d") if hasattr(creation, 'strftime') else str(creation)
                            if hasattr(creation, 'year'):
                                info["age_days"] = (datetime.now() - creation).days
                        except:
                            pass
                        break
            
            # Expiration date
            for attr in ['expiration_date', 'expires']:
                if hasattr(w, attr):
                    expiration = getattr(w, attr)
                    if expiration:
                        try:
                            info["expiration_date"] = expiration.strftime("%Y-%m-%d") if hasattr(expiration, 'strftime') else str(expiration)
                        except:
                            pass
                        break
            
            # Updated date
            for attr in ['updated_date', 'updated', 'last_updated']:
                if hasattr(w, attr):
                    updated = getattr(w, attr)
                    if updated:
                        try:
                            info["updated_date"] = updated.strftime("%Y-%m-%d") if hasattr(updated, 'strftime') else str(updated)
                        except:
                            pass
                        break
            
            # Registrar
            if hasattr(w, 'registrar'):
                info["registrar"] = w.registrar
            
            # Organization
            for attr in ['org', 'organization', 'name']:
                if hasattr(w, attr):
                    org = getattr(w, attr)
                    if org:
                        info["registrant_org"] = org
                        break
            
            # Nameservers
            if hasattr(w, 'name_servers'):
                ns = w.name_servers
                if ns:
                    info["nameservers"] = [str(n).lower() for n in (ns if isinstance(ns, list) else [ns])]
            
            # Status
            if hasattr(w, 'status'):
                status = w.status
                if status:
                    info["status"] = status if isinstance(status, list) else [status]
        
        if info["creation_date"] or info["registrar"] or info["nameservers"]:
            info["available"] = False  # Domain is registered
        
        if debug:
            print(f"[DEBUG] Successfully parsed WHOIS data")
            print(f"[DEBUG] Age: {info['age_days']} days" if info['age_days'] else "[DEBUG] No age data")
        
    except Exception as e:
        # Domain might not be registered or WHOIS lookup failed
        if debug:
            print(f"[DEBUG] WHOIS lookup failed: {type(e).__name__}: {str(e)}")
            import traceback
            print(f"[DEBUG] Traceback: {traceback.format_exc()}")
        pass
    
    return info


# =========================================================
# Daily log rotation
# =========================================================
def todays_log_path() -> str:
    name = f"{RESULTS_LOG_BASENAME}_{utc_date_str()}.json"
    return os.path.join(STAGE2_DIR, name)


def ensure_stage2_dir():
    os.makedirs(STAGE2_DIR, exist_ok=True)


# =========================================================
# Cache
# =========================================================
def cache_path() -> str:
    return os.path.join(STAGE2_DIR, "online_cache.json")


def _load_cache() -> dict:
    try:
        p = cache_path()
        if os.path.exists(p) and os.path.getsize(p) > 0:
            with open(p, "r", encoding="utf-8") as f:
                obj = json.load(f)
            if isinstance(obj, dict):
                return obj
    except Exception:
        pass
    return {"_meta": {"updated_utc": utc_iso_now()}, "items": {}}


def _save_cache(obj: dict):
    try:
        obj["_meta"] = {"updated_utc": utc_iso_now()}
        tmp = cache_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
        os.replace(tmp, cache_path())
    except Exception:
        pass


def cache_get(key: str):
    c = _load_cache()
    it = c.get("items", {}).get(key)
    if not it:
        return None
    ts = it.get("ts", 0)
    if (time.time() - ts) > CACHE_TTL_SECONDS:
        return None
    return it.get("val")


def cache_set(key: str, val):
    c = _load_cache()
    if "items" not in c or not isinstance(c["items"], dict):
        c["items"] = {}
    c["items"][key] = {"ts": time.time(), "val": val}
    _save_cache(c)


# =========================================================
# ALLOWLIST (keep small!)
# =========================================================
def _normalize_domain(d: str) -> str:
    d = (d or "").strip().lower().strip(".")
    return _strip_www(d)


BASE_ALLOW = {
    "google.com", "youtube.com", "github.com", "stackoverflow.com",
    "microsoftonline.com", "live.com", "apple.com", "amazon.com",
    "paypal.com", "wikipedia.org", "bbc.com", "cnn.com", "nytimes.com",
    "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
    "reddit.com", "example.com", "example.org", "example.net",
    "gamersfirst.com", "popcornmovies.org",
    # Financial services
    "americanexpress.com", "visa.com", "mastercard.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com",
    # Streaming & Communication
    "netflix.com", "zoom.us", "spotify.com", "slack.com", "discord.com",
    "twitch.tv", "hulu.com", "disney.com", "disneyplus.com",
    # E-commerce
    "ebay.com", "walmart.com", "target.com", "bestbuy.com", "etsy.com",
    # Tech companies
    "microsoft.com", "adobe.com", "oracle.com", "salesforce.com",
    "dropbox.com", "cloudflare.com",
    # Jordanian government/official domains
    "amman.jo", "jordan.gov.jo", "moi.gov.jo", "pm.gov.jo",
    "rta.jo", "cbj.gov.jo", "customs.gov.jo",
    # Other known safe .jo domains
    "sssd.gov.jo", "nitc.gov.jo"
}
POLICY_ALLOW = set(_normalize_domain(x) for x in policy.get("known_good_domains", []))
ALLOW_REG = set(_normalize_domain(x) for x in (BASE_ALLOW | POLICY_ALLOW))


def is_allowlisted_reg_domain(reg: str) -> bool:
    return _normalize_domain(reg) in ALLOW_REG


# =========================================================
# FEATURES
# =========================================================
def url_features(url: str) -> dict:
    decoded = unquote(str(url))
    low = decoded.lower()

    p = safe_urlparse(normalize_url(decoded))
    host_raw = (p.netloc or "").lower()
    path = p.path or ""
    query = p.query or ""
    host_no_port = host_raw.split(":")[0] if host_raw else ""
    host_no_port = _strip_www(host_no_port)

    digits = sum(c.isdigit() for c in decoded)
    specials = sum((not c.isalnum()) for c in decoded)

    host_tokens = [t for t in re.split(r"[.\-]", host_no_port) if t]
    path_tokens = [t for t in path.split("/") if t]
    query_params = [t for t in query.split("&") if t]

    tld = host_no_port.split(".")[-1] if "." in host_no_port else ""

    return {
        "url_len": len(decoded),
        "host_len": len(host_no_port),
        "path_len": len(path),
        "query_len": len(query),

        "dots": decoded.count("."),
        "hyphens": decoded.count("-"),
        "slashes": decoded.count("/"),
        "underscores": decoded.count("_"),
        "digits": digits,
        "specials": specials,

        "digit_ratio": digits / max(len(decoded), 1),
        "special_ratio": specials / max(len(decoded), 1),

        "subdomains": host_no_port.count("."),
        "host_tokens": len(host_tokens),
        "path_tokens": len(path_tokens),
        "query_params": len(query_params),

        "https": 1 if decoded.startswith("https") else 0,
        "has_ipv4": has_ipv4(host_no_port),
        "punycode": 1 if "xn--" in host_no_port else 0,
        "at_count": decoded.count("@"),
        "pct_count": decoded.count("%"),
        "eq_count": decoded.count("="),

        "suspicious_kw": sum(w in low for w in SUSPICIOUS_WORDS),
        "brand_hits": sum(1 for b in BRAND_KEYWORDS if b in low),
        "redirect_like": 1 if REDIRECT_PARAM_PAT.search(low) else 0,

        "entropy_url": entropy(decoded),
        "entropy_host": entropy(host_no_port),
        "entropy_path": entropy(path),

        "risky_tld": 1 if tld in RISKY_TLDS else 0,
    }


# =========================================================
# HARD RULES
# =========================================================
def hard_rules(url: str):
    host = get_host(url)
    if not host:
        return None

    raw = unquote(str(url))
    if "@" in raw:
        p = safe_urlparse(normalize_url(raw))
        if p.username or p.password:
            return ("PHISHING", 0.99, "rule_at_symbol", ["URL contains '@' (userinfo obfuscation)."], None, None, {})

    if has_ipv4(host):
        return ("PHISHING", 1.00, "rule_ip_host", ["URL uses an IP address host (high risk)."], None, None, {})

    if "xn--" in host:
        return ("PHISHING", 1.00, "rule_punycode", ["Punycode detected (possible look-alike domain)."], None, None, {})

    if host in SHORTENERS:
        return ("SUSPICIOUS_PHISHING", 0.85, "rule_shortener", ["URL shortener used (destination hidden)."], None, None, {})

    return None


def brand_deception_rule(url: str):
    host = get_host(url)
    if not host:
        return None

    reg = registrable_domain(host)
    if not reg:
        return None

    low = unquote(str(url)).lower()
    brand = find_brand_keyword(host)

    if brand and (reg not in BRAND_DOMAINS) and (not is_allowlisted_reg_domain(reg)):
        host_tokens = re.split(r"[.\-]", host)
        if brand in host_tokens:
            cred_intent = any(k in low for k in CRED_INTENT_WORDS)
            if cred_intent:
                return ("PHISHING", 0.99, "rule_brand_deception_login",
                        ["Brand impersonation + credential intent detected."], None, None, {})
            return ("SUSPICIOUS_PHISHING", 0.90, "rule_brand_deception",
                    ["Brand impersonation pattern detected."], None, None, {})

    return None


# =========================================================
# ONLINE UTILS
# =========================================================
def _need_requests():
    return requests is not None


def safe_requests_session():
    if not _need_requests():
        return None
    s = requests.Session()
    s.headers.update({"User-Agent": "SentinURLLinkEngine/2.2 (+security; headless)"})
    return s


def gsb_check(url: str):
    if not GSB_API_KEY or not _need_requests():
        return None

    cache_key = "gsb:" + sha256_hex(url)
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    body = {
        "client": {"clientId": "sentinurl", "clientVersion": ENGINE_VERSION},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": normalize_url(url)}],
        },
    }

    try:
        s = safe_requests_session()
        r = s.post(endpoint, json=body, timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            data = r.json() if r.text else {}
            matches = data.get("matches", [])
            out = {"hit": bool(matches), "threats": matches}
            cache_set(cache_key, out)
            return out
        out = {"error": f"GSB HTTP {r.status_code}"}
        cache_set(cache_key, out)
        return out
    except Exception as e:
        out = {"error": f"GSB error: {type(e).__name__}"}
        cache_set(cache_key, out)
        return out


def redirect_chain_check(url: str, max_redirects: int = 6):
    if not _need_requests():
        return None

    cache_key = "redir:" + sha256_hex(url)
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        s = safe_requests_session()
        r = s.head(normalize_url(url), allow_redirects=True, timeout=HTTP_TIMEOUT)
        chain = [x.url for x in r.history] + [r.url]
        out = {"ok": True, "final_url": r.url, "chain": chain[: max_redirects + 1], "status": r.status_code, "redirects": len(r.history)}
        cache_set(cache_key, out)
        return out
    except Exception:
        try:
            s = safe_requests_session()
            r = s.get(normalize_url(url), allow_redirects=True, timeout=HTTP_TIMEOUT, stream=True)
            chain = [x.url for x in r.history] + [r.url]
            out = {"ok": True, "final_url": r.url, "chain": chain[: max_redirects + 1], "status": r.status_code, "redirects": len(r.history)}
            cache_set(cache_key, out)
            return out
        except Exception as e:
            out = {"ok": False, "error": f"redirect_check: {type(e).__name__}"}
            cache_set(cache_key, out)
            return out


def tls_cert_check(host: str):
    host = _strip_www(host)
    if not host:
        return None

    cache_key = "tls:" + sha256_hex(host)
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TLS_TIMEOUT_S) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        not_after = cert.get("notAfter")
        days_left = None
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = int((exp - datetime.utcnow()).days)
            except Exception:
                days_left = None

        out = {"ok": True, "notAfter": not_after, "days_left": days_left}
        cache_set(cache_key, out)
        return out
    except Exception as e:
        out = {"ok": False, "error": f"tls: {type(e).__name__}"}
        cache_set(cache_key, out)
        return out


def content_snapshot(url: str):
    if not _need_requests():
        return None

    cache_key = "html:" + sha256_hex(url)
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        s = safe_requests_session()
        r = s.get(normalize_url(url), timeout=HTTP_TIMEOUT, allow_redirects=True, stream=True)
        ct = (r.headers.get("Content-Type") or "").lower()

        if "text/html" not in ct and "application/xhtml+xml" not in ct:
            out = {"ok": True, "html": False, "content_type": ct, "signals": {}}
            cache_set(cache_key, out)
            return out

        raw = b""
        for chunk in r.iter_content(chunk_size=4096):
            if not chunk:
                break
            raw += chunk
            if len(raw) >= MAX_HTML_BYTES:
                raw = raw[:MAX_HTML_BYTES]
                break

        html = raw.decode("utf-8", errors="ignore")
        low = html.lower()

        has_password = bool(re.search(r'type\s*=\s*["\']password["\']', low))
        has_form = "<form" in low
        has_login_words = any(w in low for w in ["sign in", "signin", "log in", "login", "verify your account", "update your account"])

        action_urls = re.findall(r'action\s*=\s*["\']([^"\']+)["\']', low)
        external_action = False
        action_reg = None

        page_host = get_host(r.url)
        page_reg = registrable_domain(page_host) if page_host else ""

        if action_urls:
            for a in action_urls[:5]:
                a = (a or "").strip()
                if not a:
                    continue

                if a.startswith("/") or a.startswith("./") or a.startswith("../"):
                    action_reg = page_reg
                    external_action = False
                    break

                a_norm = normalize_url(a) if not a.startswith(("http://", "https://")) else a
                ah = get_host(a_norm)
                if ah:
                    action_reg = registrable_domain(ah)
                    if page_reg and action_reg and page_reg != action_reg:
                        external_action = True
                        break

        out = {
            "ok": True,
            "html": True,
            "final_url": r.url,
            "content_type": ct,
            "signals": {
                "has_form": has_form,
                "has_password": has_password,
                "has_login_words": has_login_words,
                "external_form_action": external_action,
                "action_reg": action_reg,
                "page_reg": page_reg,
            }
        }
        cache_set(cache_key, out)
        return out

    except Exception as e:
        out = {"ok": False, "error": f"html: {type(e).__name__}"}
        cache_set(cache_key, out)
        return out


# =========================================================
# MODEL PROBABILITIES
# =========================================================
def stage1_prob(url: str) -> float:
    if tfidf is None or s1_model is None:
        return 0.5
    X = tfidf.transform([normalize_url(url)])
    return float(s1_model.predict_proba(X)[0, 1])


def stage2_prob(url: str) -> float:
    if s2_model is None or not STAGE2_COLS:
        return 0.5
    feats = url_features(url)
    row = {c: float(feats.get(c, 0.0)) for c in STAGE2_COLS}
    X = pd.DataFrame([row], columns=STAGE2_COLS).to_numpy(np.float32)
    return float(s2_model.predict_proba(X)[0, 1])


# =========================================================
# BANDS (policy + floors)
# =========================================================
def band(p: float) -> str:
    if MODE.upper() == "PROTECT":
        if p < max(SAFE_MAX, PROTECT_SAFE_FLOOR):
            return "SAFE"
        if p < max(SUSP_SAFE_MAX, PROTECT_SUSP_SAFE_FLOOR):
            return "SUSPICIOUS_SAFE"
        if p < min(PHISH_MIN, PROTECT_PHISH_FLOOR):
            return "SUSPICIOUS_PHISHING"
        return "PHISHING"

    if p < SAFE_MAX:
        return "SAFE"
    if p < SUSP_SAFE_MAX:
        return "SUSPICIOUS_SAFE"
    if p < PHISH_MIN:
        return "SUSPICIOUS_PHISHING"
    return "PHISHING"


# =========================================================
# Confidence
# =========================================================
def confidence_label(decision_by: str, score: float) -> str:
    if decision_by.startswith(("allowlist", "rule_", "trusted_institution", "online_")):
        return "High"
    if score <= 0.08:
        return "High"
    if 0.45 <= score <= 0.55:
        return "Low"
    return "Medium"


# =========================================================
# Presentation helpers
# =========================================================
def risk_percent(score: float) -> int:
    return int(round(max(0.0, min(1.0, score)) * 100))


def risk_label_from_percent(rp: int) -> str:
    if rp < 10:
        return "Very Low Risk"
    if rp < 30:
        return "Low Risk"
    if rp < 55:
        return "Medium Risk"
    if rp < 80:
        return "High Risk"
    return "Critical Risk"


def bar_meter(rp: int, width: int = 24) -> str:
    filled = int(round((rp / 100) * width))
    return "█" * filled + "░" * (width - filled)


def format_elapsed_ms(elapsed_ms: float) -> str:
    if elapsed_ms is None:
        return ""
    if elapsed_ms < 1:
        return "<1 ms"
    return f"{elapsed_ms:.2f} ms"


# =========================================================
# Trusted institution guard
# =========================================================
def trusted_institution_guard(url: str, p_ml: float, p1: float, p2: float, online: dict):
    host = get_host(url)
    if not host:
        return None

    suf = effective_suffix(host)
    if not is_institution_suffix(suf):
        return None

    feats = url_features(url)

    if feats.get("punycode") == 1 or feats.get("has_ipv4") == 1 or feats.get("at_count", 0) > 0:
        return None
    if feats.get("redirect_like") == 1:
        return None

    gsb = online.get("gsb")
    if isinstance(gsb, dict) and gsb.get("hit") is True:
        return None

    if isinstance(gsb, dict) and gsb.get("hit") is False:
        return ("SAFE", 0.02, f"trusted_institution_gsb_clean_{suf}",
                ["Institutional suffix detected and Google Safe Browsing is clean."])

    if p_ml < 0.45 and p1 < 0.65 and p2 < 0.75:
        return ("SAFE", min(0.05, p_ml), f"trusted_institution_low_ml_{suf}",
                ["Institutional suffix detected and ML risk is low."])

    return None


# =========================================================
# Online escalation
# =========================================================
def is_credentialish_url(u: str) -> bool:
    low = unquote(str(u)).lower()
    return any(k in low for k in CRED_INTENT_WORDS)


def should_escalate_online(ml_risk: float, feats: dict) -> bool:
    if not _need_requests():
        return False
    if UNCERTAIN_LOW <= ml_risk <= UNCERTAIN_HIGH:
        return True
    if feats.get("suspicious_kw", 0) >= 1:
        return True
    if feats.get("brand_hits", 0) >= 1:
        return True
    if feats.get("punycode", 0) == 1 or feats.get("has_ipv4", 0) == 1 or feats.get("at_count", 0) > 0:
        return True
    return False


# =========================================================
# Fuse evidence
# =========================================================
def fuse_evidence(url: str, p_ml: float, p1: float, p2: float, online: dict, whois_data: dict):
    reasons = []
    score = float(p_ml)

    gsb = online.get("gsb")
    if isinstance(gsb, dict) and gsb.get("hit") is True:
        reasons.append("Google Safe Browsing match (malicious).")
        return ("PHISHING", 0.99, "online_gsb_hit", reasons, p1, p2)

    # HARD SANITY CHECK: If GSB is clean and there are no hard signals, cap the risk
    if isinstance(gsb, dict) and gsb.get("hit") is False:
        reasons.append("Google Safe Browsing: no threats found (clean).")
        
        # ENHANCED: If Stage 1 is very safe, veto Stage 2's aggressiveness
        # This prevents false positives on legitimate sites
        if p1 < 0.10:
            score = min(score, 0.15)
            reasons.append("URL-based model is highly confident of safety; discounting feature-based risk.")
        elif p1 < 0.30:
            score = min(score, 0.35)
            reasons.append("URL patterns strongly suggest legitimate site; capping risk score.")
        elif p1 < 0.50:
            score = min(score, 0.45)
            reasons.append("Reputation and URL patterns suggest safety; capping risk score.")

    # ENHANCED: WHOIS-based risk adjustments with more nuance
    age = whois_data.get("age_days")
    if age is not None:
        if age < 7:
            reasons.append(f"Domain is extremely young ({age} days old) - critical risk.")
            score = max(score, 0.85)
        elif age < 30:
            reasons.append(f"Domain is very young ({age} days old) - higher risk.")
            score = max(score, 0.70)
        elif age < 90:
            reasons.append(f"Domain is relatively new ({age} days old).")
            # Don't increase score for domains 30-90 days old if Stage1 says safe
            if p1 > 0.50:
                score = max(score, 0.50)
        elif age > 365:
            years = age // 365
            reasons.append(f"Domain has established reputation ({years} year{'s' if years > 1 else ''} old).")
            score = min(score, 0.35)
        elif age > 180:
            reasons.append(f"Domain has moderate history ({age} days old).")
            score = min(score, 0.50)

    red = online.get("redir")
    if isinstance(red, dict) and red.get("ok"):
        redirects = int(red.get("redirects", 0) or 0)
        chain = red.get("chain") or []
        if redirects >= 3:
            reasons.append(f"Multiple redirects observed ({redirects}).")
            score = max(score, 0.80)
        try:
            if chain and len(chain) >= 2:
                first_reg = registrable_domain(get_host(chain[0]))
                last_reg = registrable_domain(get_host(chain[-1]))
                if first_reg and last_reg and first_reg != last_reg:
                    reasons.append(f"Redirected to different domain ({first_reg} → {last_reg}).")
                    score = max(score, 0.85)
        except Exception:
            pass

    tls = online.get("tls")
    if isinstance(tls, dict) and tls.get("ok") is False:
        reasons.append("TLS certificate check failed (risky host / misconfig).")
        score = max(score, 0.75)
    elif isinstance(tls, dict) and tls.get("ok") is True:
        days_left = tls.get("days_left")
        if days_left and days_left > 30:
            reasons.append("Valid TLS certificate detected (good sign).")
            score = min(score, max(score * 0.9, 0.20))  # Reduce by 10% but cap at 20%

    snap = online.get("html")
    if isinstance(snap, dict) and snap.get("ok") and snap.get("html"):
        sig = snap.get("signals") or {}
        has_pw = bool(sig.get("has_password"))
        has_form = bool(sig.get("has_form"))
        has_login_words = bool(sig.get("has_login_words"))
        external_action = bool(sig.get("external_form_action"))

        page_reg = (sig.get("page_reg") or "")
        action_reg = (sig.get("action_reg") or "")

        if has_pw and has_form and external_action:
            reasons.append("Password form posts to external domain (high confidence phishing).")
            return ("PHISHING", 0.97, "online_content_external_password_form", reasons, p1, p2)

        # ENHANCED: If login form is on same domain AND Stage1 says safe, trust it more
        if has_pw and has_form and has_login_words and (page_reg and action_reg and page_reg == action_reg):
            reasons.append("Login form detected on same domain (likely legitimate portal).")
            # If Stage1 says it's safe, really trust it
            if p1 < 0.10:
                score = min(score, 0.10)  # Very safe
            elif p1 < 0.30:
                score = min(score, 0.25)  # Quite safe
            else:
                score = min(score, 0.35)  # Moderately safe

        if has_pw and has_form and has_login_words and not action_reg:
            reasons.append("Login form detected but form target is unclear (uncertainty).")
            # Only increase if Stage1 also suspicious
            if p1 > 0.40:
                score = max(score, 0.60)

    host = get_host(url)
    suf = effective_suffix(host) if host else ""
    feats = url_features(url)
    
    # ENHANCED: Regional/Institutional/Government suffix bonus with stronger effect
    if is_institution_suffix(suf) and feats.get("redirect_like", 0) == 0 and feats.get("punycode", 0) == 0:
        reasons.append(f"Trusted institutional/government suffix (.{suf}) detected.")
        # Strong trust bonus for institutional domains
        if p1 < 0.10:
            score = min(score, 0.08)  # Very strong trust
        elif p1 < 0.30:
            score = min(score, 0.20)  # Strong trust
        else:
            score = min(score, 0.35)  # Moderate trust
    
    # ENHANCED: Country-code TLD trust (most ccTLDs are regulated)
    # Common legitimate ccTLDs
    trusted_cctlds = {
        "uk", "au", "ca", "de", "fr", "jp", "kr", "nl", "se", "ch", 
        "no", "dk", "fi", "it", "es", "be", "at", "nz", "sg", "hk",
        "jo", "ae", "sa", "eg", "il", "in", "br", "mx", "ar", "cl"
    }
    if suf in trusted_cctlds and p1 < 0.30:
        reasons.append(f"Regulated country-code TLD (.{suf}) with good reputation.")
        score = min(score, 0.40)

    # ENHANCED: Better model disagreement handling
    if abs(p1 - p2) > 0.6:
        # If Stage1 says very safe but Stage2 disagrees, trust Stage1 more
        if p1 < 0.20 and p2 > 0.60:
            score = 0.3 * p1 + 0.7 * p2  # Give more weight to Stage2 but still cap it
            reasons.append("Models disagree: URL analysis highly confident of safety; moderating feature-based concerns.")
        # If Stage2 says very safe but Stage1 disagrees, trust Stage2 more  
        elif p2 < 0.20 and p1 > 0.60:
            score = 0.7 * p1 + 0.3 * p2
            reasons.append("Models disagree: Feature analysis suggests safety; moderating URL-based concerns.")
        else:
            score = (p1 + p2) / 2
            reasons.append("Models disagree significantly; using averaged score for safety.")

    score = max(0.0, min(1.0, float(score)))
    return (band(score), score, "fusion_offline_online", reasons, p1, p2)


# =========================================================
# PREDICT
# =========================================================
def predict(url: str):
    u = normalize_url(url)
    host = get_host(u)
    reg = registrable_domain(host) if host else ""
    
    # ENHANCED: Get WHOIS info early for all domains
    whois_data = {}
    if reg:
        try:
            whois_data = get_whois_info(reg, debug=DEBUG_MODE)
        except Exception as e:
            if DEBUG_MODE:
                print(f"[DEBUG] Exception in predict() calling get_whois_info: {e}")
            whois_data = {"available": True}

    if reg and is_allowlisted_reg_domain(reg):
        return ("SAFE", 0.0, "allowlist_reg_domain", ["Registrable domain matches trusted allowlist."], 0.0, 0.0, whois_data)
    
    # ENHANCED: Check for Jordanian official domains (municipalities)
    if reg in JORDANIAN_OFFICIAL:
        return ("SAFE", 0.01, "allowlist_jordanian_official", 
                ["Jordanian official municipality/government domain."], 0.0, 0.0, whois_data)

    hr = hard_rules(u)
    if hr is not None:
        lbl, p, src, reasons, p1, p2, _ = hr
        return (lbl, p, src, reasons, p1, p2, whois_data)

    bd = brand_deception_rule(u)
    if bd is not None:
        lbl, p, src, reasons, p1, p2, _ = bd
        return (lbl, p, src, reasons, p1, p2, whois_data)

    p1 = stage1_prob(u)
    p2 = stage2_prob(u)
    
    # ENHANCED Dynamic Fusion: Give Stage 1 more weight when it's confident about safety
    # Stage 1 (URL-based) is better at recognizing legitimate domains
    # Stage 2 (features) can be overly aggressive on login pages
    
    if p1 < 0.02:
        # Stage1 is EXTREMELY confident it's safe - trust it almost entirely
        p_ml = (0.95 * p1 + 0.05 * p2)
    elif p1 < 0.05:
        # Stage1 is VERY confident it's safe - trust it heavily
        p_ml = (0.85 * p1 + 0.15 * p2)
    elif p1 < 0.15:
        # Stage1 is confident it's safe - trust it more
        p_ml = (0.7 * p1 + 0.3 * p2)
    elif p1 < 0.30:
        # Stage1 leans safe - give it more weight
        p_ml = (0.6 * p1 + 0.4 * p2)
    elif p1 > 0.80:
        # Stage1 is confident it's phishing - trust it more
        p_ml = (0.7 * p1 + 0.3 * p2)
    else:
        # Normal case - use policy weights
        p_ml = (W1 * p1 + W2 * p2)

    feats = url_features(u)
    suf = effective_suffix(host) if host else ""
    is_institution = is_institution_suffix(suf)

    online = {}

    if is_institution or suf == "jo":
        online["gsb"] = gsb_check(u)
        if host:
            online["tls"] = tls_cert_check(host)
        if is_credentialish_url(u) or feats.get("redirect_like", 0) == 1:
            online["redir"] = redirect_chain_check(u)
            online["html"] = content_snapshot(u)

    elif should_escalate_online(p_ml, feats):
        online["redir"] = redirect_chain_check(u)
        online["gsb"] = gsb_check(u)
        if host:
            online["tls"] = tls_cert_check(host)
        if is_credentialish_url(u) or (UNCERTAIN_LOW <= p_ml <= UNCERTAIN_HIGH) or feats.get("redirect_like", 0) == 1:
            online["html"] = content_snapshot(u)

    inst = trusted_institution_guard(u, p_ml, p1, p2, online)
    if inst is not None:
        lbl, p, src, reasons = inst
        return (lbl, p, src, reasons, p1, p2, whois_data)

    lbl, score, src, reasons, p1x, p2x = fuse_evidence(u, p_ml, p1, p2, online, whois_data)
    return (lbl, score, src, reasons, p1, p2, whois_data)


# =========================================================
# Output formatting
# =========================================================
def url_breakdown(url: str):
    u = normalize_url(url)
    decoded = unquote(str(u))
    p = safe_urlparse(u)
    host = get_host(u)
    reg = registrable_domain(host) if host else ""
    suf = effective_suffix(host) if host else ""
    return {
        "raw": str(url),
        "normalized": u,
        "decoded": decoded,
        "host": host,
        "registrable_domain": reg,
        "effective_suffix": suf,
        "path": p.path or "",
        "query": p.query or "",
    }


def category_from_decision(decision_by: str, url: str):
    low = unquote(str(url)).lower()
    if decision_by.startswith("trusted_institution"):
        return "Trusted institution (edu/gov/mil/ac)"
    if decision_by.startswith("allowlist"):
        return "Trusted domain"
    if decision_by.startswith("online_content_external_password_form"):
        return "Credential theft (external password form)"
    if decision_by.startswith("online_gsb_hit"):
        return "Reputation hit (Google Safe Browsing)"
    if any(k in low for k in ["login", "signin", "verify", "password", "otp"]):
        return "Possible credential phishing"
    return "Risk analysis (AI + online verification)"


def print_result_box(url: str, label: str, score: float, decision_by: str, reasons, p1=None, p2=None, whois_data=None, elapsed_ms=None):
    rp = risk_percent(score)
    tier = risk_label_from_percent(rp)
    conf = confidence_label(decision_by, score)
    info = url_breakdown(url)
    cat = category_from_decision(decision_by, url)

    status_icon = "✓ SAFE" if label == "SAFE" else ("⚠ WARNING" if "SUSPICIOUS" in label else "✗ DANGER")
    elapsed_str = format_elapsed_ms(elapsed_ms)

    print("\n" + "═" * 68)
    print(f"{status_icon}  |  {label}  |  {tier}  |  Confidence: {conf}")
    if elapsed_str:
        print(f"Analysis time: {elapsed_str}")
    print("─" * 68)

    print(f"Risk: {rp}%  [{bar_meter(rp)}]")
    print("─" * 68)

    print(f"Category      : {cat}")
    print(f"Domain checked : {info['registrable_domain'] or 'N/A'}")
    print(f"Public suffix : {info['effective_suffix'] or 'N/A'}")
    print(f"Host          : {info['host'] or 'N/A'}")
    if info["path"]:
        print(f"Path          : {safe_truncate(info['path'], 50)}")

    # ENHANCED: WHOIS Information Section
    if whois_data and not whois_data.get("available", True):
        print("─" * 68)
        print("WHOIS Domain Information:")
        
        if whois_data.get("creation_date"):
            print(f" 📅 Created       : {whois_data['creation_date']}")
            if whois_data.get("age_days"):
                years = whois_data["age_days"] // 365
                days = whois_data["age_days"] % 365
                age_str = f"{years} year(s), {days} day(s)" if years > 0 else f"{days} day(s)"
                print(f"    Age          : {age_str}")
        
        if whois_data.get("updated_date"):
            print(f" 🔄 Last Updated  : {whois_data['updated_date']}")
        
        if whois_data.get("expiration_date"):
            print(f" ⏰ Expires       : {whois_data['expiration_date']}")
        
        if whois_data.get("registrar"):
            print(f" 🏢 Registrar     : {whois_data['registrar']}")
        
        if whois_data.get("registrant_org"):
            print(f" 👤 Organization  : {whois_data['registrant_org']}")
        
        if whois_data.get("registrant_country"):
            print(f" 🌍 Country       : {whois_data['registrant_country']}")
        
        if whois_data.get("nameservers"):
            print(f" 🌐 Nameservers   :")
            for ns in whois_data["nameservers"][:3]:  # Show max 3
                print(f"    • {ns}")
            if len(whois_data["nameservers"]) > 3:
                print(f"    ... and {len(whois_data['nameservers']) - 3} more")
        
        if whois_data.get("status"):
            print(f" 📊 Status        : {whois_data['status'][0]}")
    else:
        print("─" * 68)
        print("WHOIS Domain Information:")
        print(" ℹ️  WHOIS lookup unavailable (domain may have privacy protection)")
        print("    or the WHOIS server did not respond in time.")

    print("─" * 68)
    print("Why:")
    for r in (reasons or [])[:10]:
        print(f" • {r}")
    if info["registrable_domain"] and not any("Domain checked is" in r for r in (reasons or [])):
        print(f" • Domain checked is '{info['registrable_domain']}' (registrable domain).")
    if info["effective_suffix"] and not any("Effective suffix is" in r for r in (reasons or [])):
        print(f" • Effective suffix is '{info['effective_suffix']}' (public suffix).")

    print("─" * 68)
    print("Technical details:")
    print(f" Decision By  : {decision_by}")
    print(f" Score        : {score*100:.4f}%")
    if p1 is not None:
        print(f" Stage1 Prob  : {p1 * 100:.2f}%")
    if p2 is not None:
        print(f" Stage2 Prob  : {p2 * 100:.2f}%")
    print("═" * 68 + "\n")


# =========================================================
# Logging
# =========================================================
def build_engine_meta():
    return {"engine_version": ENGINE_VERSION, "mode": MODE}


def load_or_init_log(path: str):
    if os.path.exists(path) and os.path.getsize(path) > 0:
        try:
            with open(path, "r", encoding="utf-8") as f:
                obj = json.load(f)
            if isinstance(obj, dict) and "scans" in obj and isinstance(obj["scans"], list):
                return obj
        except Exception:
            pass
    return {"engine": build_engine_meta(), "session": {"session_start_utc": utc_iso_now()}, "scans": []}


def append_scan(log_obj: dict, scan_obj: dict, path: str):
    if not isinstance(log_obj.get("scans"), list):
        log_obj["scans"] = []
    scan_obj["scan_id"] = len(log_obj["scans"]) + 1
    log_obj["scans"].append(scan_obj)

    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(log_obj, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def build_scan_object(url: str, label: str, score: float, decision_by: str, reasons, p1=None, p2=None, whois_data=None, elapsed_ms=None):
    info = url_breakdown(url)
    scan = {
        "timestamp_utc": utc_iso_now(),
        "url_sha256": sha256_hex(info["normalized"]),
        "url": info,
        "classification": {
            "label": label,
            "risk_percent": risk_percent(score),
            "category": category_from_decision(decision_by, url),
            "confidence": confidence_label(decision_by, score),
        },
        "engine": {"decision_by": decision_by, "score": float(score), "p1": p1, "p2": p2},
        "reasons": reasons,
        "analysis_time_ms": None if elapsed_ms is None else float(elapsed_ms),
    }
    
    # Add WHOIS data to log if available
    if whois_data and not whois_data.get("available", True):
        scan["whois"] = whois_data
    
    return scan


# =========================================================
# STARTUP BANNER
# =========================================================
def startup_banner(active_log_path: str):
    print("\n" + "=" * 68)
    print(f"SentinURL Link Risk Engine  |  v{ENGINE_VERSION}  |  MODE={MODE}")
    print("-" * 68)
    print("Models : Stage1 TF-IDF + Calibrated LR")
    if STAGE2_COLS:
        print(f"         Stage2 HistGradientBoosting ({len(STAGE2_COLS)} features)")
    else:
        print("         Stage2 HistGradientBoosting (Features not loaded)")
    print(
        f"Policy : SAFE < {SAFE_MAX*100:.2f}%  |  "
        f"SUSP_SAFE < {SUSP_SAFE_MAX*100:.2f}%  |  PHISH ≥ {PHISH_MIN*100:.2f}%"
    )
    if MODE.upper() == "PROTECT":
        print(
            f"Floors : SAFE < {PROTECT_SAFE_FLOOR*100:.0f}% | "
            f"SUSP_SAFE < {PROTECT_SUSP_SAFE_FLOOR*100:.0f}% | "
            f"PHISH ≥ {PROTECT_PHISH_FLOOR*100:.0f}%"
        )
    print(f"Fusion : Stage1 {W1*100:.0f}%  +  Stage2 {W2*100:.0f}%")
    print(f"Online : GSB={'ON' if bool(GSB_API_KEY) else 'OFF'} | VT={'ON' if bool(VT_API_KEY) else 'OFF'} | requests={'ON' if requests else 'OFF'}")
    print(f"WHOIS  : Enabled (domain age and reputation tracking)")
    print(f"Logging: {os.path.basename(active_log_path)}")
    print("=" * 68)
    print("Enter a URL to analyze")
    print("Type 'debug on' or 'debug off' to toggle WHOIS debug mode")
    print("Ctrl+C to exit\n")


# =========================================================
# CLI
# =========================================================
if __name__ == "__main__":
    ensure_stage2_dir()
    active_log_path = todays_log_path()
    startup_banner(active_log_path)
    log_obj = load_or_init_log(active_log_path)

    try:
        while True:
            u = input("URL> ").strip()
            if not u:
                continue
            
            # Handle debug command
            if u.lower() == "debug on":
                DEBUG_MODE = True
                print("✓ Debug mode enabled - WHOIS lookups will show detailed info\n")
                continue
            elif u.lower() == "debug off":
                DEBUG_MODE = False
                print("✓ Debug mode disabled\n")
                continue

            new_log_path = todays_log_path()
            if new_log_path != active_log_path:
                active_log_path = new_log_path
                log_obj = load_or_init_log(active_log_path)
                print(f"\n[Log rotation] Now logging to: {os.path.basename(active_log_path)}\n")

            t0 = time.perf_counter()
            lbl, p, src, reasons, p1, p2, whois_data = predict(u)
            elapsed_ms = (time.perf_counter() - t0) * 1000

            print_result_box(u, lbl, p, src, reasons, p1=p1, p2=p2, whois_data=whois_data, elapsed_ms=elapsed_ms)

            scan_obj = build_scan_object(u, lbl, p, src, reasons, p1=p1, p2=p2, whois_data=whois_data, elapsed_ms=elapsed_ms)
            append_scan(log_obj, scan_obj, active_log_path)

    except KeyboardInterrupt:
        print("\nExiting...")
