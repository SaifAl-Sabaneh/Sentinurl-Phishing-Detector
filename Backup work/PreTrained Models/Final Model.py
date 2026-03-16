import os
import re
import json
import math
import time
import joblib
import hashlib
from functools import lru_cache
from collections import Counter
from urllib.parse import urlparse, unquote
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import tldextract


# =========================================================
# Importing Both Pretrained Models into the Code 
# =========================================================
STAGE1_DIR = r"C:\Users\Asus\Desktop\Graduation Project\PreTrained Models\stage1"
STAGE2_DIR = r"C:\Users\Asus\Desktop\Graduation Project\PreTrained Models\stage2"

S1_TFIDF_PATH = os.path.join(STAGE1_DIR, "tfidf.joblib")
S1_MODEL_PATH = os.path.join(STAGE1_DIR, "calibrated_logreg.joblib")

S2_MODEL_PATH = os.path.join(STAGE2_DIR, "stage2_hgb.joblib")
S2_COLS_PATH = os.path.join(STAGE2_DIR, "stage2_feature_columns.joblib")
POLICY_PATH = os.path.join(STAGE2_DIR, "policy_meta.json")

# Base name only (rotation will generate scan_results_YYYY-MM-DD.json)
RESULTS_LOG_BASENAME = "scan_results"

ENGINE_VERSION = "1.0.1"


# =========================================================
# Loading the Models and The Policy 
# =========================================================
tfidf = joblib.load(S1_TFIDF_PATH)
s1_model = joblib.load(S1_MODEL_PATH)

s2_model = joblib.load(S2_MODEL_PATH)
STAGE2_COLS = joblib.load(S2_COLS_PATH)

with open(POLICY_PATH, "r", encoding="utf-8") as f:
    policy = json.load(f)

SAFE_MAX = float(policy["bands"]["SAFE_MAX"])
SUSP_SAFE_MAX = float(policy["bands"]["SUSP_SAFE_MAX"])
PHISH_MIN = float(policy["bands"]["PHISH_MIN"])

W1 = float(policy["fusion"]["w_stage1"])
W2 = float(policy["fusion"]["w_stage2"])

metrics = policy.get("metrics", {})  # optional


# =========================================================
# CONSTANTS
# =========================================================
SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "update", "secure", "account", "bank",
    "confirm", "password", "pay", "billing", "invoice", "support", "token"
]

RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co"}

BRAND_KEYWORDS = [
    "google", "paypal", "microsoft", "apple", "amazon",
    "facebook", "instagram", "whatsapp", "youtube"
]

BRAND_DOMAINS = {
    "google.com", "paypal.com", "microsoft.com", "microsoftonline.com",
    "apple.com", "amazon.com", "facebook.com", "instagram.com",
    "whatsapp.com", "youtube.com"
}

EXTRACT = tldextract.TLDExtract(suffix_list_urls=None)  # offline mode


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


@lru_cache(maxsize=1024)
def _cached_tld_extract(host: str):
    return EXTRACT(host)


@lru_cache(maxsize=2048)
def registrable_domain(host: str) -> str:
    host = (host or "").lower().strip().strip(".")
    if host.startswith("www."):
        host = host[4:]
    if not host:
        return ""
    ext = _cached_tld_extract(host)
    if not ext.domain or not ext.suffix:
        return ""  # explicit: parsing failed
    return f"{ext.domain}.{ext.suffix}"


def split_domain_tld(reg_domain: str):
    if not reg_domain or "." not in reg_domain:
        return reg_domain or "", ""
    parts = reg_domain.rsplit(".", 1)
    return parts[0], parts[1]


@lru_cache(maxsize=4096)
def get_host(url: str) -> str:
    p = safe_urlparse(normalize_url(url))
    host = (p.netloc or "").lower().split(":")[0].strip().strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


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


def _acc_to_percent(acc_value) -> float:
    if acc_value is None:
        return None
    if isinstance(acc_value, str):
        s = acc_value.strip().replace("%", "")
        if not s:
            return None
        try:
            v = float(s)
        except Exception:
            return None
    else:
        try:
            v = float(acc_value)
        except Exception:
            return None

    if v <= 1.0:
        v *= 100.0
    if v < 0:
        v = 0.0
    if v > 100:
        v = 100.0
    return v


# =========================================================
# Daily log rotation
# =========================================================
def todays_log_path() -> str:
    name = f"{RESULTS_LOG_BASENAME}_{utc_date_str()}.json"
    return os.path.join(STAGE2_DIR, name)


def ensure_stage2_dir():
    os.makedirs(STAGE2_DIR, exist_ok=True)


# =========================================================
# ALLOWLIST (SAFE: registrable-domain only)
# =========================================================
def _normalize_domain(d: str) -> str:
    d = (d or "").strip().lower().strip(".")
    if d.startswith("www."):
        d = d[4:]
    return d


BASE_ALLOW = {
    "google.com", "youtube.com", "github.com", "stackoverflow.com",
    "facebook.com", "instagram.com", "whatsapp.com",
    "microsoftonline.com", "live.com", "apple.com", "amazon.com",
    "paypal.com", "wikipedia.org", "bbc.com"
}
POLICY_ALLOW = set(_normalize_domain(x) for x in policy.get("known_good_domains", []))
ALLOW_REG = set(_normalize_domain(x) for x in (BASE_ALLOW | POLICY_ALLOW))


def is_allowlisted_reg_domain(reg: str) -> bool:
    reg = _normalize_domain(reg)
    return reg in ALLOW_REG


# =========================================================
# STARTUP BANNER
# =========================================================
def startup_banner(active_log_path: str):
    print("\n" + "=" * 68)
    print(f"SentinURL Link Risk Engine  |  v{ENGINE_VERSION}")
    print("-" * 68)
    print("Models : Stage1 TF-IDF + Calibrated LR")
    print(f"         Stage2 HistGradientBoosting ({len(STAGE2_COLS)} features)")

    # Accuracy & ROC-AUC (optional)
    try:
        m = metrics if isinstance(metrics, dict) else {}
        m1 = m.get("stage1", {}) if isinstance(m.get("stage1", {}), dict) else {}
        m2 = m.get("stage2", {}) if isinstance(m.get("stage2", {}), dict) else {}
        mf = m.get("fusion", {}) if isinstance(m.get("fusion", {}), dict) else {}

        s1_acc = _acc_to_percent(m1.get("accuracy"))
        s2_acc = _acc_to_percent(m2.get("accuracy"))
        fu_acc = _acc_to_percent(mf.get("accuracy"))

        s1_auc = m1.get("roc_auc")
        s2_auc = m2.get("roc_auc")
        fu_auc = mf.get("roc_auc")

        if s1_acc is not None or s2_acc is not None or fu_acc is not None:
            print(f"Accuracy: S1 {s1_acc:.2f}% | S2 {s2_acc:.2f}% | Fusion {fu_acc:.2f}%")

        def _auc(x):
            try:
                return f"{float(x):.4f}"
            except Exception:
                return "N/A"

        if s1_auc is not None or s2_auc is not None or fu_auc is not None:
            print(f"ROC-AUC : S1 {_auc(s1_auc)} | S2 {_auc(s2_auc)} | Fusion {_auc(fu_auc)}")
    except Exception:
        pass

    print(
        f"Policy : SAFE < {SAFE_MAX*100:.2f}%  |  "
        f"SUSP_SAFE < {SUSP_SAFE_MAX*100:.2f}%  |  "
        f"PHISH ≥ {PHISH_MIN*100:.2f}%"
    )
    print(f"Fusion : Stage1 {W1*100:.0f}%  +  Stage2 {W2*100:.0f}%")
    print(f"Logging: {os.path.basename(active_log_path)}")
    print("=" * 68)
    print("Enter a URL to analyze (Ctrl+C to exit)\n")


# =========================================================
# Extracting Features
# =========================================================
def url_features(url: str) -> dict:
    decoded = unquote(str(url))
    low = decoded.lower()

    p = safe_urlparse(normalize_url(decoded))
    host = (p.netloc or "").lower()
    path = p.path or ""
    query = p.query or ""
    host_no_port = host.split(":")[0] if host else ""

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
        "redirect_like": 1 if re.search(r"(redirect|next|url|continue|dest|destination)=", low) else 0,

        "entropy_url": entropy(decoded),
        "entropy_host": entropy(host_no_port),
        "entropy_path": entropy(path),

        "risky_tld": 1 if tld in RISKY_TLDS else 0,
    }


# =========================================================
# RULES (always return 5 values)
# =========================================================
def hard_rules(url: str):
    host = get_host(url)
    if not host:
        return None

    raw = unquote(str(url))

    if "@" in raw:
        return ("PHISHING", 0.99, "rule_at_symbol", None, None)

    if has_ipv4(host):
        return ("PHISHING", 1.00, "rule_ip_host", None, None)

    if "xn--" in host:
        return ("PHISHING", 1.00, "rule_punycode", None, None)

    if host in SHORTENERS:
        return ("SUSPICIOUS_PHISHING", 0.85, "rule_shortener", None, None)

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
        cred_intent = any(k in low for k in ["login", "signin", "verify", "password", "account", "update", "secure"])
        if cred_intent:
            return ("PHISHING", 0.99, "rule_brand_deception_login", None, None)
        return ("SUSPICIOUS_PHISHING", 0.90, "rule_brand_deception", None, None)

    return None


def domain_parse_fail_rule(url: str):
    host = get_host(url)
    if not host:
        return ("SUSPICIOUS_SAFE", 0.30, "rule_domain_parse_fail", None, None)
    reg = registrable_domain(host)
    if not reg:
        return ("SUSPICIOUS_SAFE", 0.30, "rule_domain_parse_fail", None, None)
    return None


# =========================================================
# MODEL PROBABILITIES
# =========================================================
def stage1_prob(url: str) -> float:
    X = tfidf.transform([normalize_url(url)])
    return float(s1_model.predict_proba(X)[0, 1])


def stage2_prob(url: str) -> float:
    feats = url_features(url)
    row = {c: float(feats.get(c, 0.0)) for c in STAGE2_COLS}
    X = pd.DataFrame([row], columns=STAGE2_COLS).to_numpy(np.float32)
    return float(s2_model.predict_proba(X)[0, 1])


# =========================================================
# BANDS + PREDICT
# =========================================================
def band(p: float) -> str:
    if p < SAFE_MAX:
        return "SAFE"
    if p < SUSP_SAFE_MAX:
        return "SUSPICIOUS_SAFE"
    if p < PHISH_MIN:
        return "SUSPICIOUS_PHISHING"
    return "PHISHING"


def fusion_safe_guard(url: str, p1: float, p2: float) -> bool:
    feats = url_features(url)

    if feats.get("has_ipv4", 0) == 1:
        return False
    if feats.get("punycode", 0) == 1:
        return False
    if feats.get("at_count", 0) > 0:
        return False
    if feats.get("redirect_like", 0) == 1:
        return False
    if feats.get("suspicious_kw", 0) >= 1:
        return False
    if feats.get("brand_hits", 0) >= 1:
        return False

    return (p1 <= 0.20 and p2 <= 0.20)


def predict(url: str):
    u = normalize_url(url)
    host = get_host(u)

    dpf = domain_parse_fail_rule(u)
    if dpf is not None:
        return dpf

    reg = registrable_domain(host)

    if reg and is_allowlisted_reg_domain(reg):
        return ("SAFE", 0.0, "allowlist_reg_domain", None, None)

    hr = hard_rules(u)
    if hr is not None:
        return hr

    bd = brand_deception_rule(u)
    if bd is not None:
        return bd

    p1 = stage1_prob(u)
    if p1 < SAFE_MAX:
        return ("SAFE", p1, "stage1_safe_exit", p1, None)

    p2 = stage2_prob(u)

    if fusion_safe_guard(u, p1, p2):
        return ("SAFE", min(p1, p2), "dual_low_risk_guard", p1, p2)

    p = W1 * p1 + W2 * p2
    return (band(p), p, "fusion", p1, p2)


# =========================================================
# PRESENTATION + JSON
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


def confidence_label(decision_by: str, score: float) -> str:
    if decision_by.startswith("allowlist"):
        return "High"
    if decision_by.startswith("rule_"):
        return "High"
    if decision_by in ("dual_low_risk_guard", "stage1_safe_exit"):
        return "High"
    margin = min(abs(score - SAFE_MAX), abs(score - SUSP_SAFE_MAX), abs(score - PHISH_MIN))
    if margin < 0.03:
        return "Low"
    if margin < 0.08:
        return "Medium"
    return "High"


def bar_meter(rp: int, width: int = 24) -> str:
    filled = int(round((rp / 100) * width))
    return "█" * filled + "░" * (width - filled)


def format_elapsed_ms(elapsed_ms: float) -> str:
    if elapsed_ms is None:
        return ""
    if elapsed_ms < 1:
        return "<1 ms"
    return f"{elapsed_ms:.2f} ms"


def url_breakdown(url: str):
    u = normalize_url(url)
    decoded = unquote(str(u))
    p = safe_urlparse(u)
    host = get_host(u)
    reg = registrable_domain(host) if host else ""
    dom, tld = split_domain_tld(reg) if reg else ("", "")
    path = p.path or ""
    query = p.query or ""
    brand = find_brand_keyword(host)
    return {
        "raw": str(url),
        "normalized": u,
        "decoded": decoded,
        "host": host,
        "registrable_domain": reg,
        "domain_name": dom,
        "tld": tld,
        "path": path,
        "query": query,
        "suspected_brand": brand
    }


def category_from_decision(decision_by: str, url: str):
    low = unquote(str(url)).lower()
    if decision_by.startswith("allowlist"):
        return "Trusted domain"
    if decision_by == "stage1_safe_exit":
        return "Low risk (AI)"
    if decision_by == "dual_low_risk_guard":
        return "Low risk (AI agreement)"
    if decision_by == "rule_brand_deception_login":
        return "Credential theft / Brand impersonation"
    if decision_by == "rule_brand_deception":
        return "Brand impersonation"
    if decision_by == "rule_at_symbol":
        return "URL obfuscation (userinfo '@')"
    if decision_by == "rule_shortener":
        return "Hidden destination (shortener)"
    if decision_by == "rule_punycode":
        return "Look-alike domain (punycode)"
    if decision_by == "rule_ip_host":
        return "Suspicious infrastructure (IP-based URL)"
    if decision_by == "rule_domain_parse_fail":
        return "Unclear domain parsing"
    if any(k in low for k in ["login", "signin", "verify", "password"]):
        return "Possible credential phishing"
    return "Risk analysis (AI + heuristics)"


def ai_hints(url: str):
    f = url_features(url)
    hints = []

    if f.get("url_len", 0) >= 120:
        hints.append("Unusually long URL.")
    if f.get("subdomains", 0) >= 3:
        hints.append("Many subdomains (can hide real domain).")
    if f.get("hyphens", 0) >= 3:
        hints.append("Many hyphens (common in fake domains).")
    if f.get("pct_count", 0) >= 5:
        hints.append("Heavy URL encoding (possible obfuscation).")
    if f.get("entropy_host", 0) >= 3.8:
        hints.append("High hostname entropy (random-looking host).")
    if f.get("suspicious_kw", 0) >= 1:
        hints.append("Contains credential-related keywords.")
    if f.get("risky_tld", 0) == 1:
        hints.append("Risky TLD observed.")
    if f.get("redirect_like", 0) == 1:
        hints.append("Possible redirect parameter detected.")

    return hints[:5]


def extract_ranked_reasons(url: str, decision_by: str):
    info = url_breakdown(url)
    reg = info["registrable_domain"] or ""
    brand = info["suspected_brand"]
    low = (info["decoded"] or "").lower()

    reasons = []
    primary_map = {
        "allowlist_reg_domain": "Registrable domain matches trusted allowlist.",
        "stage1_safe_exit": "Stage1 (calibrated) classified the URL as low risk.",
        "dual_low_risk_guard": "Both models agree on low risk and no phishing signals were found.",
        "rule_at_symbol": "URL contains '@' which can hide the real destination.",
        "rule_ip_host": "URL uses an IP address instead of a domain (high risk).",
        "rule_punycode": "Punycode detected (possible look-alike domain).",
        "rule_shortener": "URL shortener used (destination is hidden).",
        "rule_brand_deception": "Brand impersonation pattern detected (brand name inside untrusted domain).",
        "rule_brand_deception_login": "Brand impersonation + credential intent detected (high confidence phishing).",
        "rule_domain_parse_fail": "Could not reliably extract the registrable domain (treating as suspicious).",
        "fusion": "AI ensemble (Stage1 + Stage2) produced this risk score.",
    }
    if decision_by in primary_map:
        reasons.append(primary_map[decision_by])

    if reg:
        reasons.append(f"Domain checked is '{reg}' (effective registrable domain).")

    if decision_by in ("rule_brand_deception", "rule_brand_deception_login") and brand:
        reasons.append(f"Impersonated brand detected in hostname: {brand.title()}.")

    if any(k in low for k in ["login", "signin", "verify", "password", "account", "update", "secure"]):
        reasons.append("Credential-related keywords present (login/verify/update).")

    if decision_by in ("fusion", "dual_low_risk_guard"):
        for h in ai_hints(url):
            reasons.append(h)

    out, seen = [], set()
    for r in reasons:
        if r and r not in seen:
            out.append(r)
            seen.add(r)
    return out[:6]


def build_engine_meta():
    return {
        "engine_version": ENGINE_VERSION,
        "models": {
            "stage1_tfidf": os.path.basename(S1_TFIDF_PATH),
            "stage1_model": os.path.basename(S1_MODEL_PATH),
            "stage2_model": os.path.basename(S2_MODEL_PATH),
            "stage2_schema": os.path.basename(S2_COLS_PATH),
        },
        "policy": {
            "SAFE_MAX": SAFE_MAX,
            "SUSP_SAFE_MAX": SUSP_SAFE_MAX,
            "PHISH_MIN": PHISH_MIN,
            "w_stage1": W1,
            "w_stage2": W2,
        },
        "allowlist_reg_domains_count": len(ALLOW_REG),
    }


def load_or_init_log(path: str):
    if os.path.exists(path) and os.path.getsize(path) > 0:
        try:
            with open(path, "r", encoding="utf-8") as f:
                obj = json.load(f)
            if isinstance(obj, dict) and "scans" in obj and isinstance(obj["scans"], list):
                return obj
        except Exception:
            pass

    return {
        "engine": build_engine_meta(),
        "session": {
            "session_start_utc": utc_iso_now(),
        },
        "scans": []
    }


def append_scan(log_obj: dict, scan_obj: dict, path: str):
    if not isinstance(log_obj.get("scans"), list):
        log_obj["scans"] = []
    log_obj["engine"] = build_engine_meta()

    scan_id = len(log_obj["scans"]) + 1
    scan_obj["scan_id"] = scan_id

    log_obj["scans"].append(scan_obj)

    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(log_obj, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def print_result_box(url: str, label: str, score: float, decision_by: str, p1=None, p2=None, elapsed_ms=None):
    rp = risk_percent(score)
    tier = risk_label_from_percent(rp)
    conf = confidence_label(decision_by, score)

    info = url_breakdown(url)
    reasons = extract_ranked_reasons(url, decision_by)
    cat = category_from_decision(decision_by, url)

    status_icon = "SAFE" if label == "SAFE" else ("WARNING" if "SUSPICIOUS" in label else "DANGER")
    elapsed_str = format_elapsed_ms(elapsed_ms)

    print("\n" + "═" * 68)
    print(f"{status_icon}  |  {label}  |  {tier}  |  Confidence: {conf}")
    if elapsed_str:
        print(f"Analysis time: {elapsed_str}")
    print("─" * 68)

    print(f"Risk: {rp}%  [{bar_meter(rp)}]")
    print("─" * 68)

    print(f"Category      : {cat}")

    reg = info["registrable_domain"]
    if reg:
        print(f"Domain checked : {reg}")
        print(f" ├─ Domain name : {info['domain_name']}")
        print(f" └─ TLD         : .{info['tld']}")
    else:
        print("Domain checked : N/A")

    print(f"Host          : {info['host'] or 'N/A'}")

    if info["suspected_brand"] and decision_by in ("rule_brand_deception", "rule_brand_deception_login"):
        print(f"Impersonated  : {info['suspected_brand'].title()}")

    if info["path"]:
        print(f"Path          : {safe_truncate(info['path'], 50)}")

    print("─" * 68)

    print("Why:")
    for r in reasons:
        print(f" • {r}")

    print("─" * 68)
    print("Technical details:")
    print(f" Decision By  : {decision_by}")
    print(f" Score        : {score*100:.4f}%")
    if p1 is not None:
        print(f"Stage1 Prob  : {p1 * 100:.2f}%")

    if p2 is not None:
        print(f"Stage2 Prob  : {p2 * 100:.2f}%")


    print("═" * 68 + "\n")


def build_scan_object(url: str, label: str, score: float, decision_by: str, p1=None, p2=None, elapsed_ms=None):
    info = url_breakdown(url)
    rp = risk_percent(score)

    return {
        "timestamp_utc": utc_iso_now(),
        "url_sha256": sha256_hex(info["normalized"]),
        "input": {
            "raw": info["raw"],
            "normalized": info["normalized"],
            "decoded": info["decoded"]
        },
        "url_breakdown": {
            "host": info["host"],
            "registrable_domain": info["registrable_domain"],
            "domain_name": info["domain_name"],
            "tld": info["tld"],
            "path": info["path"],
            "query": info["query"]
        },
        "classification": {
            "label": label,
            "risk_percent": rp,
            "risk_tier": risk_label_from_percent(rp),
            "confidence": confidence_label(decision_by, score),
            "category": category_from_decision(decision_by, url)
        },
        "explanation": {
            "reasons": extract_ranked_reasons(url, decision_by)
        },
        "engine": {
            "decision_by": decision_by,
            "fusion_weights": {"stage1": W1, "stage2": W2},
            "thresholds": {"SAFE_MAX": SAFE_MAX, "SUSP_SAFE_MAX": SUSP_SAFE_MAX, "PHISH_MIN": PHISH_MIN},
            "scores": {
                "final": float(score),
                "stage1": None if p1 is None else float(p1),
                "stage2": None if p2 is None else float(p2)
            },
            "analysis_time_ms": None if elapsed_ms is None else float(elapsed_ms),
        }
    }


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

            # in case midnight passes while running
            new_log_path = todays_log_path()
            if new_log_path != active_log_path:
                active_log_path = new_log_path
                log_obj = load_or_init_log(active_log_path)
                print(f"\n[Log rotation] Now logging to: {os.path.basename(active_log_path)}\n")

            t0 = time.perf_counter()
            lbl, p, src, p1, p2 = predict(u)
            elapsed_ms = (time.perf_counter() - t0) * 1000

            print_result_box(u, lbl, p, src, p1=p1, p2=p2, elapsed_ms=elapsed_ms)

            scan_obj = build_scan_object(u, lbl, p, src, p1=p1, p2=p2, elapsed_ms=elapsed_ms)
            append_scan(log_obj, scan_obj, active_log_path)

    except KeyboardInterrupt:
        print("\nExiting...")
