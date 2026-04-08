"""
SentinURL Dataset Feature Analyzer
===================================
Analyzes every URL in Master_SentinURL_Dataset.csv and extracts ALL features
used across Stage 1 (TF-IDF / NLP) and Stage 2 (Numeric / Heuristic) models.

Output: analyzed_dataset_features.csv
"""

import re
import csv
import math
import os
import sys
import io
from urllib.parse import urlparse, unquote

# Force UTF-8 on Windows terminals so progress bar renders correctly
if sys.stdout and hasattr(sys.stdout, 'buffer'):
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────
INPUT_CSV  = os.path.join(os.path.dirname(__file__), "Master_SentinURL_Dataset.csv")
OUTPUT_CSV = os.path.join(os.path.dirname(__file__), "analyzed_dataset_features.csv")
CHUNK_SIZE = 10_000   # report progress every N rows

# ─────────────────────────────────────────────────────────────
# CONSTANTS (mirrored from enhanced_original.py)
# ─────────────────────────────────────────────────────────────
BRAND_KEYWORDS = [
    "google", "paypal", "microsoft", "apple", "amazon", "facebook",
    "instagram", "whatsapp", "youtube", "netflix", "ebay", "twitter",
    "linkedin", "dropbox", "adobe", "office365", "outlook", "icloud",
    "steam", "roblox", "discord", "reddit", "spotify", "chase",
    "wellsfargo", "bankofamerica", "citibank", "visa", "mastercard",
    "amex", "usps", "fedex", "dhl", "ups", "irs", "gov",
]

SUSPICIOUS_PATHS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "banking", "webscr", "cmd=login", "redirect",
    "phishing", "malware", "payload", "click", "track",
]

CRED_INTENT_WORDS = [
    "login", "signin", "verify", "secure", "account", "auth",
    "password", "credential", "update", "confirm", "validate",
]

RISKY_TLDS = {
    "xyz", "top", "club", "online", "site", "info", "biz", "live",
    "click", "link", "win", "loan", "gq", "ml", "cf", "ga", "tk",
    "pw", "cc", "su", "ru", "cn", "icu", "vip", "buzz", "shop",
    "fun", "monster", "digital", "work", "world", "app", "mobi",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "tiny.cc", "url4.eu", "cutt.ly", "shorturl.at",
    "rb.gy", "t.ly", "s.id", "tr.ee", "go-link.ru", "rrrts.in",
}

IP_RE = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)

LOG_ODDS_FEATURES = [
    "login", "banking", "secure", "account", "confirm", "update",
    "verify", "paypal", "ebay", "amazon", "apple", "microsoft",
    "google", "facebook", "instagram", "netflix", "bitcoin", "crypto",
    "wallet", "password", "admin", "support", "access", "free",
    "bonus", "reward", "prize", "winner", "claim", "offer",
]


# ─────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────

def safe_urlparse(url: str):
    try:
        return urlparse(url)
    except Exception:
        return urlparse("")


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def has_ipv4(host: str) -> int:
    m = IP_RE.match(host)
    if not m:
        return 0
    return 1 if all(0 <= int(m.group(i)) <= 255 for i in range(1, 5)) else 0


def entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def get_vowel_consonant_ratio(s: str) -> float:
    if not s:
        return 0.0
    vowels    = sum(c in "aeiou" for c in s.lower())
    consonants = sum(c in "bcdfghjklmnpqrstvwxyz" for c in s.lower())
    if consonants == 0:
        return float(vowels)
    return vowels / consonants


def registrable_domain(host: str) -> str:
    """Very lightweight registrable-domain extractor (no tldextract needed)."""
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def levenshtein(s1: str, s2: str) -> int:
    """Compute edit distance between two strings."""
    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1, 1):
        curr = [i]
        for j, c2 in enumerate(s2, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1,
                            prev[j - 1] + (0 if c1 == c2 else 1)))
        prev = curr
    return prev[-1]


KNOWN_BRANDS_EXACT = [
    "google", "paypal", "microsoft", "apple", "amazon", "facebook",
    "instagram", "youtube", "netflix", "ebay", "twitter", "linkedin",
    "chase", "wellsfargo", "bankofamerica", "citibank", "dropbox", "adobe",
    "spotify", "discord", "steam", "roblox", "instagram",
]

def min_brand_edit_distance(domain_label: str) -> int:
    """Min Levenshtein distance from domain label (without TLD) to any known brand."""
    d = domain_label.lower()
    if not d:
        return 999
    return min(levenshtein(d, b) for b in KNOWN_BRANDS_EXACT)


# ─────────────────────────────────────────────────────────────
# CORE FEATURE EXTRACTION
# ─────────────────────────────────────────────────────────────

def extract_features(url: str) -> dict:
    """
    Extract every numeric / heuristic feature used across:
      - Stage 1  : TF-IDF (the NLP signals we deliberately encode)
      - Stage 2  : Histogram Gradient Boosting numeric features
      - Heuristic layers (adversarial hardening, hard rules, etc.)
    """
    try:
        decoded   = unquote(str(url))
        low       = decoded.lower()
        norm      = normalize_url(decoded)
        p         = safe_urlparse(norm)

        host_raw  = (p.netloc or "").lower()
        host      = host_raw.split(":")[0] if host_raw else ""
        path      = p.path or ""
        query_raw = p.query or ""

        # Clean ad/tracking params to avoid entropy spikes
        qclean = re.sub(
            r"(gclid|gad_source|gad|gclsrc|utm_source|utm_medium|utm_campaign)=[^&]+",
            "", query_raw
        ).strip("&")

        # ── derived tokens ────────────────────────────────────
        host_tokens = [t for t in re.split(r"[.\-]", host) if t]
        path_tokens = [t for t in path.split("/")           if t]
        query_parts = [t for t in qclean.split("&")         if t]

        tld = host.split(".")[-1] if "." in host else ""
        reg = registrable_domain(host)
        domain_label = reg.rsplit(".", 1)[0] if "." in reg else reg   # e.g. "paypal-secure"

        # ── character counts ──────────────────────────────────
        digits   = sum(c.isdigit() for c in decoded)
        specials = sum((not c.isalnum()) for c in decoded)
        letters  = sum(c.isalpha() for c in decoded)
        spaces   = decoded.count(" ")

        # ─────────────────────────────────────────────────────
        # SECTION A  – "Stage 2" numeric features
        #   (the exact dict returned by url_features() in enhanced_original.py)
        # ─────────────────────────────────────────────────────

        # Length features
        url_len            = len(decoded)
        host_len           = len(host)
        path_len           = len(path)
        query_len          = len(qclean)
        max_host_token_len = max((len(t) for t in host_tokens), default=0)
        max_path_token_len = max((len(t) for t in path_tokens), default=0)

        # Character frequency features
        dots        = decoded.count(".")
        hyphens     = decoded.count("-")
        slashes     = decoded.count("/")
        underscores = decoded.count("_")
        at_count    = decoded.count("@")
        pct_count   = decoded.count("%")  # percent-encoded chars
        eq_count    = decoded.count("=")
        amp_count   = decoded.count("&")
        ques_count  = decoded.count("?")
        tilde_count = decoded.count("~")
        hash_count  = decoded.count("#")
        excl_count  = decoded.count("!")
        plus_count  = decoded.count("+")
        colon_count = decoded.count(":")
        semi_count  = decoded.count(";")
        comma_count = decoded.count(",")
        star_count  = decoded.count("*")

        # Ratio features
        digit_ratio   = digits   / max(url_len, 1)
        special_ratio = specials / max(url_len, 1)
        letter_ratio  = letters  / max(url_len, 1)
        vc_ratio_host = get_vowel_consonant_ratio(host)

        # Structural features
        subdomains        = host.count(".")
        host_token_count  = len(host_tokens)
        path_token_count  = len(path_tokens)
        query_param_count = len(query_parts)
        path_depth        = path.count("/")
        port_present      = 1 if (":" in host_raw) else 0
        double_slash_path = 1 if ("//" in path) else 0

        # Protocol / encoding features
        is_https  = 1 if decoded.lower().startswith("https") else 0
        is_ipv4   = has_ipv4(host)
        punycode  = 1 if "xn--" in host else 0

        # Entropy features
        ent_url   = entropy(decoded)
        ent_host  = entropy(host)
        ent_path  = entropy(path)
        ent_query = entropy(qclean)

        # Keyword / intent features
        has_login   = 1 if any(w in low for w in ["login", "signin", "verify", "secure", "account", "auth"]) else 0
        has_finance = 1 if any(w in low for w in ["bank", "pay", "billing", "invoice", "crypto", "bitcoin", "wallet"]) else 0
        has_scam    = 1 if any(w in low for w in ["free", "bonus", "winner", "hack", "porn", "adware", "worm", "malware"]) else 0
        brand_hits  = sum(1 for b in BRAND_KEYWORDS if b in low)
        susp_path   = 1 if any(sp in low for sp in SUSPICIOUS_PATHS) else 0
        redirect_like = 1 if re.search(r"(redirect|next|url|continue|dest|destination)=", low) else 0

        # TLD / domain features
        risky_tld  = 1 if tld in RISKY_TLDS else 0
        is_shortener = 1 if any(s in host for s in SHORTENERS) else 0

        # ─────────────────────────────────────────────────────
        # SECTION B  – Extended / heuristic features
        # ─────────────────────────────────────────────────────

        # Digit-in-domain features
        digits_in_host = sum(c.isdigit() for c in host)
        digits_in_path = sum(c.isdigit() for c in path)

        # Hyphen analysis
        hyphens_in_host = host.count("-")
        hyphens_in_path = path.count("-")

        # Domain / TLD analysis
        tld_len = len(tld)
        num_dots_host = host.count(".")
        num_dots_path = path.count(".")

        # Suspicious keyword counts (granular)
        login_kw_count   = sum(low.count(w) for w in ["login", "signin", "logon"])
        verify_kw_count  = sum(low.count(w) for w in ["verify", "verification", "verif"])
        secure_kw_count  = sum(low.count(w) for w in ["secure", "security", "secur"])
        account_kw_count = sum(low.count(w) for w in ["account", "acct"])
        update_kw_count  = sum(low.count(w) for w in ["update", "updat"])
        confirm_kw_count = sum(low.count(w) for w in ["confirm", "confirmation"])
        pay_kw_count     = sum(low.count(w) for w in ["pay", "payment", "paypal", "paiement"])
        bank_kw_count    = sum(low.count(w) for w in ["bank", "banking"])
        free_kw_count    = low.count("free")
        win_kw_count     = sum(low.count(w) for w in ["winner", "win", "won", "prize", "reward", "bonus"])
        crypto_kw_count  = sum(low.count(w) for w in ["bitcoin", "crypto", "wallet", "ethereum", "nft", "defi", "dapp"])

        # Path file extension features
        path_lower = path.lower()
        has_php_ext   = 1 if path_lower.endswith(".php")  else 0
        has_html_ext  = 1 if path_lower.endswith(".html") or path_lower.endswith(".htm") else 0
        has_asp_ext   = 1 if path_lower.endswith(".asp")  or path_lower.endswith(".aspx") else 0
        has_js_ext    = 1 if path_lower.endswith(".js")   else 0
        has_exe_ext   = 1 if any(path_lower.endswith(e) for e in [".exe", ".bat", ".msi", ".scr", ".vbs", ".cmd"]) else 0
        has_zip_ext   = 1 if any(path_lower.endswith(e) for e in [".zip", ".rar", ".7z", ".gz", ".tar", ".tgz"]) else 0
        has_doc_ext   = 1 if any(path_lower.endswith(e) for e in [".doc", ".docx", ".xls", ".xlsx", ".pdf"]) else 0

        # WordPress / CMS indicators
        has_wp_path   = 1 if any(wp in path_lower for wp in ["wp-includes", "wp-content", "wp-admin", "wp-login"]) else 0

        # Known free-hosting platform in host
        free_hosts = [
            "weebly.com", "wixsite.com", "wordpress.com", "blogspot.com",
            "pages.dev", "workers.dev", "netlify.app", "vercel.app",
            "github.io", "glitch.me", "replit.app", "azurewebsites.net",
            "godaddysites.com", "weeblysite.com", "wix.com", "webflow.io",
            "squarespace.com", "simplybook.me", "hubside.fr", "brizy.site",
            "mystrikingly.com", "codeanyapp.com", "dreamwp.com",
            "wpenginepowered.com", "mybluehost.me", "cprapid.com",
        ]
        is_free_hosting = 1 if any(fh in host for fh in free_hosts) else 0

        # IPFS / decentralized hosting
        is_ipfs = 1 if any(s in host or s in path_lower for s in ["ipfs.io", "ipfs.dweb.link", "ipfs.w3s.link", "fleek.co", "moralisipfs"]) else 0

        # Credential intent in URL path
        cred_intent_path = 1 if any(w in path_lower for w in CRED_INTENT_WORDS) else 0

        # URL obfuscation indicators
        has_encoded_chars = 1 if pct_count > 3 else 0
        has_double_encoding = 1 if "%25" in decoded else 0
        has_suspicious_port = 1 if re.search(r":(8080|8443|4443|8888|9999|1337|31337)\b", decoded) else 0

        # Brand in non-standard position
        brand_in_path   = 1 if any(b in path.lower() for b in BRAND_KEYWORDS) else 0
        brand_in_query  = 1 if any(b in qclean.lower() for b in BRAND_KEYWORDS) else 0
        brand_in_domain = 1 if any(b in domain_label for b in BRAND_KEYWORDS) else 0

        # Typosquatting / visual deception proxies
        min_edit_dist = min_brand_edit_distance(domain_label)
        likely_typosquat = 1 if (min_edit_dist > 0 and min_edit_dist <= 2) else 0

        # Subdomain trickery
        subdomain_brand   = 1 if any(b in ".".join(host.split(".")[:-2]).lower() for b in BRAND_KEYWORDS) else 0
        many_subdomains   = 1 if subdomains > 3 else 0

        # Random-looking domain (high entropy domain label vs short label)
        ent_domain_label  = entropy(domain_label)
        looks_dga         = 1 if (ent_domain_label > 3.5 and len(domain_label) > 8) else 0

        # Combo squatting (brand + credential word in domain label)
        combo_squat = 1 if (
            any(b in domain_label for b in BRAND_KEYWORDS) and
            any(k in domain_label for k in CRED_INTENT_WORDS)
        ) else 0

        # Section C – Stage 1 token-level signals
        #  (These replicate what TF-IDF "sees" as raw boolean signals)
        stage1_token_has_login   = 1 if "login"    in decoded else 0
        stage1_token_has_verify  = 1 if "verify"   in decoded else 0
        stage1_token_has_secure  = 1 if "secure"   in decoded else 0
        stage1_token_has_account = 1 if "account"  in decoded else 0
        stage1_token_has_update  = 1 if "update"   in decoded else 0
        stage1_token_has_confirm = 1 if "confirm"  in decoded else 0
        stage1_token_has_payment = 1 if "payment"  in decoded else 0
        stage1_token_has_signin  = 1 if "signin"   in decoded else 0
        stage1_token_has_billing = 1 if "billing"  in decoded else 0
        stage1_token_has_recover = 1 if "recover"  in decoded else 0
        stage1_token_has_support = 1 if "support"  in decoded else 0
        stage1_token_has_helpdesk= 1 if "helpdesk" in decoded else 0
        stage1_token_has_webscr  = 1 if "webscr"   in decoded else 0
        stage1_token_has_php     = 1 if ".php"      in decoded else 0
        stage1_token_has_https   = 1 if decoded.lower().startswith("https") else 0
        stage1_token_has_http    = 1 if decoded.lower().startswith("http:") else 0

        # Log-odds keyword hits (counts of high-risk tokens that TF-IDF would weight)
        log_odds_hits = sum(1 for kw in LOG_ODDS_FEATURES if kw in low)

    except Exception as e:
        # Return all zeros for malformed URLs
        print(f"[WARN] Error processing URL: {url!r} → {e}", file=sys.stderr)
        return {k: 0 for k in _feature_keys()}

    return {
        # ── Core length features ────────────────────────────────
        "url_len":                url_len,
        "host_len":               host_len,
        "path_len":               path_len,
        "query_len":              query_len,
        "max_host_token_len":     max_host_token_len,
        "max_path_token_len":     max_path_token_len,

        # ── Character count features ────────────────────────────
        "dots":                   dots,
        "hyphens":                hyphens,
        "slashes":                slashes,
        "underscores":            underscores,
        "digits":                 digits,
        "letters":                letters,
        "specials":               specials,
        "at_count":               at_count,
        "pct_count":              pct_count,
        "eq_count":               eq_count,
        "amp_count":              amp_count,
        "ques_count":             ques_count,
        "tilde_count":            tilde_count,
        "hash_count":             hash_count,
        "excl_count":             excl_count,
        "plus_count":             plus_count,
        "colon_count":            colon_count,
        "semi_count":             semi_count,
        "comma_count":            comma_count,
        "star_count":             star_count,

        # ── Ratio features ─────────────────────────────────────
        "digit_ratio":            round(digit_ratio, 6),
        "special_ratio":          round(special_ratio, 6),
        "letter_ratio":           round(letter_ratio, 6),
        "vc_ratio_host":          round(vc_ratio_host, 6),

        # ── Structural features ────────────────────────────────
        "subdomains":             subdomains,
        "num_dots_host":          num_dots_host,
        "num_dots_path":          num_dots_path,
        "host_token_count":       host_token_count,
        "path_token_count":       path_token_count,
        "query_param_count":      query_param_count,
        "path_depth":             path_depth,
        "port_present":           port_present,
        "double_slash_path":      double_slash_path,
        "tld_len":                tld_len,

        # ── Protocol / encoding ────────────────────────────────
        "is_https":               is_https,
        "is_ipv4":                is_ipv4,
        "punycode":               punycode,
        "has_encoded_chars":      has_encoded_chars,
        "has_double_encoding":    has_double_encoding,
        "has_suspicious_port":    has_suspicious_port,

        # ── Entropy features ───────────────────────────────────
        "entropy_url":            round(ent_url,   6),
        "entropy_host":           round(ent_host,  6),
        "entropy_path":           round(ent_path,  6),
        "entropy_query":          round(ent_query, 6),
        "entropy_domain_label":   round(ent_domain_label, 6),

        # ── Keyword / intent features ──────────────────────────
        "has_login":              has_login,
        "has_finance":            has_finance,
        "has_scam":               has_scam,
        "brand_hits":             brand_hits,
        "suspicious_path":        susp_path,
        "redirect_like":          redirect_like,
        "cred_intent_path":       cred_intent_path,
        "log_odds_hits":          log_odds_hits,

        # ── Granular keyword counts ────────────────────────────
        "login_kw_count":         login_kw_count,
        "verify_kw_count":        verify_kw_count,
        "secure_kw_count":        secure_kw_count,
        "account_kw_count":       account_kw_count,
        "update_kw_count":        update_kw_count,
        "confirm_kw_count":       confirm_kw_count,
        "pay_kw_count":           pay_kw_count,
        "bank_kw_count":          bank_kw_count,
        "free_kw_count":          free_kw_count,
        "win_kw_count":           win_kw_count,
        "crypto_kw_count":        crypto_kw_count,

        # ── Domain features ────────────────────────────────────
        "risky_tld":              risky_tld,
        "is_shortener":           is_shortener,
        "is_free_hosting":        is_free_hosting,
        "is_ipfs":                is_ipfs,
        "digits_in_host":         digits_in_host,
        "digits_in_path":         digits_in_path,
        "hyphens_in_host":        hyphens_in_host,
        "hyphens_in_path":        hyphens_in_path,

        # ── Brand / impersonation features ────────────────────
        "brand_in_domain":        brand_in_domain,
        "brand_in_path":          brand_in_path,
        "brand_in_query":         brand_in_query,
        "subdomain_brand":        subdomain_brand,
        "many_subdomains":        many_subdomains,
        "combo_squat":            combo_squat,
        "likely_typosquat":       likely_typosquat,
        "min_edit_dist_to_brand": min_edit_dist if min_edit_dist < 999 else -1,

        # ── DGA / randomness features ──────────────────────────
        "looks_dga":              looks_dga,

        # ── File extension features ────────────────────────────
        "has_php_ext":            has_php_ext,
        "has_html_ext":           has_html_ext,
        "has_asp_ext":            has_asp_ext,
        "has_js_ext":             has_js_ext,
        "has_exe_ext":            has_exe_ext,
        "has_zip_ext":            has_zip_ext,
        "has_doc_ext":            has_doc_ext,
        "has_wp_path":            has_wp_path,

        # ── Stage 1 token-level signals ────────────────────────
        "tok_login":              stage1_token_has_login,
        "tok_verify":             stage1_token_has_verify,
        "tok_secure":             stage1_token_has_secure,
        "tok_account":            stage1_token_has_account,
        "tok_update":             stage1_token_has_update,
        "tok_confirm":            stage1_token_has_confirm,
        "tok_payment":            stage1_token_has_payment,
        "tok_signin":             stage1_token_has_signin,
        "tok_billing":            stage1_token_has_billing,
        "tok_recover":            stage1_token_has_recover,
        "tok_support":            stage1_token_has_support,
        "tok_helpdesk":           stage1_token_has_helpdesk,
        "tok_webscr":             stage1_token_has_webscr,
        "tok_php":                stage1_token_has_php,
        "tok_https":              stage1_token_has_https,
        "tok_http":               stage1_token_has_http,
    }


def _feature_keys():
    """Return the list of feature column names (used for zero-fill on error)."""
    # Build a dummy dict to get keys
    return list(extract_features("http://example.com").keys())


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    print("=" * 65)
    print("  SentinURL Dataset Feature Analyzer")
    print("=" * 65)
    print(f"  Input  : {INPUT_CSV}")
    print(f"  Output : {OUTPUT_CSV}")
    print("=" * 65)

    if not os.path.exists(INPUT_CSV):
        print(f"[ERROR] Input file not found: {INPUT_CSV}")
        sys.exit(1)

    # Pre-compute feature column names
    feature_keys = _feature_keys()
    print(f"  Features per URL : {len(feature_keys)}")

    # Count total rows for progress bar
    print("  Counting rows...", end="", flush=True)
    with open(INPUT_CSV, "r", encoding="utf-8", errors="ignore") as f:
        total_rows = sum(1 for _ in f) - 1   # minus header
    print(f" {total_rows:,} URLs found.")
    print()

    processed = 0
    skipped   = 0

    with open(INPUT_CSV, "r", encoding="utf-8", errors="ignore", newline="") as fin, \
         open(OUTPUT_CSV, "w", encoding="utf-8", newline="") as fout:

        reader = csv.DictReader(fin)
        fieldnames = ["URL", "Type"] + feature_keys
        writer = csv.DictWriter(fout, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            url  = (row.get("URL") or "").strip()
            typ  = (row.get("Type") or "").strip()

            if not url:
                skipped += 1
                continue

            feats = extract_features(url)
            out_row = {"URL": url, "Type": typ}
            out_row.update(feats)
            writer.writerow(out_row)
            processed += 1

            if processed % CHUNK_SIZE == 0:
                pct = processed / total_rows * 100
                bar = "█" * int(pct / 2) + "░" * (50 - int(pct / 2))
                print(f"\r  [{bar}] {pct:5.1f}%  ({processed:,}/{total_rows:,})", end="", flush=True)

    print(f"\r  [{'█'*50}] 100.0%  ({processed:,}/{total_rows:,})")
    print()
    print("=" * 65)
    print(f"  ✓ Done! Processed : {processed:,} URLs")
    if skipped:
        print(f"  ⚠ Skipped (empty) : {skipped:,} rows")
    print(f"  ✓ Output written  : {OUTPUT_CSV}")
    print(f"  ✓ Feature columns : {len(feature_keys)}")
    print("=" * 65)


if __name__ == "__main__":
    main()
