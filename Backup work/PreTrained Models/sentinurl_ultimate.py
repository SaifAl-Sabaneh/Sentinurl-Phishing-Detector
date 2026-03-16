"""
SENTINURL ULTIMATE PHISHING DETECTION SYSTEM
Production-Grade with All Advanced Features
Version: 3.0.0-ultimate
"""

import os
import sys

# Add current directory and parent directories to path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, current_dir)
sys.path.insert(0, parent_dir)

# Import all components from enhanced_original
# First, try to import from the same directory
try:
    from enhanced_original import *
    print("[OK] Core engine loaded from local directory")
except ImportError:
    # If not found, try from parent directory
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("enhanced_original", 
            os.path.join(parent_dir, "enhanced_original.py"))
        if spec and spec.loader:
            enhanced = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(enhanced)
            # Import all from the module
            for name in dir(enhanced):
                if not name.startswith('_'):
                    globals()[name] = getattr(enhanced, name)
            print("[OK] Core engine loaded from parent directory")
        else:
            raise ImportError("enhanced_original.py not found")
    except Exception as e:
        print(f"[ERROR] Could not load enhanced_original.py: {e}")
        print("Please ensure enhanced_original.py is in the same directory or parent directory")
        sys.exit(1)

# Import advanced modules
try:
    from visual_similarity_detection import (
        check_visual_similarity, has_homograph_attack,
        detect_combo_squatting, detect_subdomain_tricks
    )
    VISUAL_SIMILARITY_AVAILABLE = True
except ImportError:
    VISUAL_SIMILARITY_AVAILABLE = False
    print("[WARNING] Visual similarity detection not available")

try:
    from threat_intelligence import check_threat_feeds, get_threat_intelligence
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False
    print("[WARNING] Threat intelligence feeds not available")

try:
    from certificate_analysis import analyze_url_certificate, get_cert_risk_level
    CERT_ANALYSIS_AVAILABLE = True
except ImportError:
    CERT_ANALYSIS_AVAILABLE = False
    print("[WARNING] Advanced certificate analysis not available")

# Update engine version
ENGINE_VERSION = "3.0.0-ultimate"

# =========================================================
# ADVANCED DETECTION LAYERS
# =========================================================

def advanced_brand_impersonation_check(url: str, host: str):
    """
    Advanced brand impersonation detection using visual similarity
    Returns: (is_threat, threat_type, details, score)
    """
    if not VISUAL_SIMILARITY_AVAILABLE:
        return (False, None, None, 0.0)
    
    threats = []
    max_score = 0.0
    
    # 1. Visual similarity check
    is_susp, brand, score, attack_type = check_visual_similarity(host)
    if is_susp:
        threats.append(f"Visual impersonation of '{brand}' detected ({attack_type})")
        max_score = max(max_score, score)
    
    # 2. Homograph attack check
    if has_homograph_attack(host):
        threats.append("IDN homograph attack detected (non-ASCII characters)")
        max_score = max(max_score, 0.95)
    
    # 3. Combo squatting check
    is_combo, combo_brand, combo_word = detect_combo_squatting(host)
    if is_combo:
        threats.append(f"Combo squatting detected: {combo_brand} + {combo_word}")
        max_score = max(max_score, 0.90)
    
    # 4. Subdomain tricks
    is_subdomain_trick, subdomain_brand, trick_type = detect_subdomain_tricks(host)
    if is_subdomain_trick:
        threats.append(f"Subdomain trick detected: fake {subdomain_brand} domain")
        max_score = max(max_score, 0.95)
    
    if threats:
        return (True, "brand_impersonation_advanced", threats, max_score)
    
    return (False, None, None, 0.0)

def check_advanced_threats(url: str):
    """
    Check URL against threat intelligence feeds
    Returns: (is_threat, feeds, details)
    """
    if not THREAT_INTEL_AVAILABLE:
        return (False, [], None)
    
    try:
        return check_threat_feeds(url)
    except Exception as e:
        if DEBUG_MODE:
            print(f"[DEBUG] Threat feed check failed: {e}")
        return (False, [], None)

def advanced_certificate_check(url: str):
    """
    Advanced certificate analysis beyond basic TLS check
    Returns: analysis dict with suspicion score
    """
    if not CERT_ANALYSIS_AVAILABLE:
        return None
    
    try:
        analysis = analyze_url_certificate(url)
        return analysis
    except Exception as e:
        if DEBUG_MODE:
            print(f"[DEBUG] Certificate analysis failed: {e}")
        return None

# =========================================================
# ENHANCED PREDICTION WITH ALL FEATURES
# =========================================================

def predict_ultimate(url: str):
    """
    Ultimate prediction with all advanced features integrated
    """
    u = normalize_url(url)
    host = get_host(u)
    reg = registrable_domain(host) if host else ""
    suf = effective_suffix(host) if host else ""
    reasons = []
    
    # WHOIS lookup
    whois_data = {}
    if reg:
        try:
            whois_data = get_whois_info(reg, debug=DEBUG_MODE)
        except Exception as e:
            if DEBUG_MODE:
                print(f"[DEBUG] Exception in predict_ultimate() calling get_whois_info: {e}")
            whois_data = {"available": True}
    
    # === LAYER 1: ALLOWLISTS ===
    if reg and is_allowlisted_reg_domain(reg):
        return ("SAFE", 0.0, "allowlist_reg_domain", ["Registrable domain matches trusted allowlist."], 0.0, 0.0, whois_data)
    
    if reg in JORDANIAN_OFFICIAL:
        return ("SAFE", 0.01, "allowlist_jordanian_official", 
                ["Jordanian official municipality/government domain."], 0.0, 0.0, whois_data)
    
    # === LAYER 2: THREAT INTELLIGENCE FEEDS ===
    is_threat, threat_feeds, threat_details = check_advanced_threats(u)
    if is_threat:
        return ("PHISHING", 0.99, "threat_intelligence_match",
                [f"URL found in threat intelligence feeds: {', '.join(threat_feeds)}",
                 threat_details or "Known malicious URL"], None, None, whois_data)
    
    # === LAYER 3: ADVANCED BRAND IMPERSONATION ===
    is_impersonation, imp_type, imp_threats, imp_score = advanced_brand_impersonation_check(u, host)
    if is_impersonation:
        return ("PHISHING", imp_score, "advanced_brand_impersonation",
                imp_threats, None, None, whois_data)
    
    # === LAYER 4: HARD RULES ===
    hr = hard_rules(u)
    if hr is not None:
        lbl, p, src, reasons, p1, p2, _ = hr
        return (lbl, p, src, reasons, p1, p2, whois_data)
    
    # === LAYER 5: ORIGINAL BRAND DECEPTION ===
    bd = brand_deception_rule(u)
    if bd is not None:
        lbl, p, src, reasons, p1, p2, _ = bd
        return (lbl, p, src, reasons, p1, p2, whois_data)
    
    # === LAYER 6: ML MODELS ===
    p1 = stage1_prob(u)
    p2 = stage2_prob(u)
    
    # Enhanced Dynamic Fusion
    if p1 < 0.02:
        p_ml = (0.95 * p1 + 0.05 * p2)
    elif p1 < 0.05:
        p_ml = (0.85 * p1 + 0.15 * p2)
    elif p1 < 0.15:
        p_ml = (0.7 * p1 + 0.3 * p2)
    elif p1 < 0.30:
        p_ml = (0.6 * p1 + 0.4 * p2)
    elif p1 > 0.80:
        p_ml = (0.7 * p1 + 0.3 * p2)
    else:
        p_ml = (W1 * p1 + W2 * p2)
    
    feats = url_features(u)
    is_institution = is_institution_suffix(suf)
    
    # === LAYER 7: ONLINE VERIFICATION ===
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
    
    # === LAYER 8: ADVANCED CERTIFICATE ANALYSIS ===
    cert_analysis = advanced_certificate_check(u)
    if cert_analysis and cert_analysis.get("valid"):
        cert_suspicion = cert_analysis.get("suspicion_score", 0)
        if cert_suspicion >= 50:
            reasons.append(f"Certificate analysis flags high risk (score: {cert_suspicion})")
            p_ml = max(p_ml, 0.70)
        elif cert_suspicion >= 30:
            reasons.append(f"Certificate analysis shows moderate concerns (score: {cert_suspicion})")
            p_ml = max(p_ml, 0.50)
        elif cert_analysis.get("uses_trusted_ca"):
            reasons.append("Valid certificate from trusted CA detected")
            p_ml = min(p_ml, p_ml * 0.9)  # 10% reduction
    
    # === LAYER 9: INSTITUTIONAL GUARD ===
    inst = trusted_institution_guard(u, p_ml, p1, p2, online)
    if inst is not None:
        lbl, p, src, inst_reasons = inst
        return (lbl, p, src, inst_reasons, p1, p2, whois_data)
    
    # === LAYER 10: EVIDENCE FUSION ===
    lbl, score, src, fusion_reasons, p1x, p2x = fuse_evidence(u, p_ml, p1, p2, online, whois_data)
    
    # Combine all reasons
    all_reasons = reasons + fusion_reasons
    
    return (lbl, score, src, all_reasons, p1, p2, whois_data)

# =========================================================
# ENHANCED OUTPUT WITH ADVANCED FEATURES
# =========================================================

def print_ultimate_result(url: str, label: str, score: float, decision_by: str, reasons, p1=None, p2=None, whois_data=None, elapsed_ms=None):
    """Enhanced output showing all analysis layers"""
    
    # Call original print function first
    print_result_box(url, label, score, decision_by, reasons, p1, p2, whois_data, elapsed_ms)
    
    # Add advanced features summary
    if VISUAL_SIMILARITY_AVAILABLE or THREAT_INTEL_AVAILABLE or CERT_ANALYSIS_AVAILABLE:
        print("─" * 68)
        print("Advanced Features Status:")
        
        if VISUAL_SIMILARITY_AVAILABLE:
            print(" ✓ Visual Similarity Detection: ACTIVE")
        else:
            print(" ✗ Visual Similarity Detection: UNAVAILABLE")
        
        if THREAT_INTEL_AVAILABLE:
            intel = get_threat_intelligence()
            stats = intel.get_stats()
            total_threats = sum(s['count'] for s in stats.values())
            print(f" ✓ Threat Intelligence: ACTIVE ({total_threats:,} known threats)")
        else:
            print(" ✗ Threat Intelligence: UNAVAILABLE")
        
        if CERT_ANALYSIS_AVAILABLE:
            print(" ✓ Advanced Certificate Analysis: ACTIVE")
        else:
            print(" ✗ Advanced Certificate Analysis: UNAVAILABLE")
        
        print("═" * 68 + "\n")

# =========================================================
# ENHANCED STARTUP
# =========================================================

def startup_banner_ultimate(active_log_path: str):
    """Enhanced startup banner with all features"""
    print("\n" + "=" * 68)
    print(f"SentinURL Ultimate Phishing Detection System")
    print(f"Version: {ENGINE_VERSION}  |  MODE={MODE}")
    print("-" * 68)
    print("Core Models:")
    print("  • Stage1: TF-IDF + Calibrated Logistic Regression")
    if STAGE2_COLS:
        print(f"  • Stage2: HistGradientBoosting ({len(STAGE2_COLS)} features)")
    print(f"  • Policy: SAFE<{SAFE_MAX*100:.2f}% | SUSP_SAFE<{SUSP_SAFE_MAX*100:.2f}% | PHISH≥{PHISH_MIN*100:.2f}%")
    
    print("-" * 68)
    print("Advanced Features:")
    if VISUAL_SIMILARITY_AVAILABLE:
        print("  ✓ Visual Similarity Detection (Homograph/Typosquatting)")
    if THREAT_INTEL_AVAILABLE:
        print("  ✓ Threat Intelligence Feeds (PhishTank, OpenPhish, URLhaus)")
    if CERT_ANALYSIS_AVAILABLE:
        print("  ✓ Advanced Certificate Analysis")
    print("  ✓ WHOIS Domain Intelligence")
    print("  ✓ Google Safe Browsing Integration" if GSB_API_KEY else "  ✗ Google Safe Browsing (no API key)")
    print("  ✓ Dynamic Content Analysis")
    
    print("-" * 68)
    print(f"Protection Layers: 10 | Logging: {os.path.basename(active_log_path)}")
    print("=" * 68)
    print("Commands: 'debug on/off' | Ctrl+C to exit\n")

# =========================================================
# MAIN LOOP
# =========================================================

if __name__ == "__main__":
    ensure_stage2_dir()
    active_log_path = todays_log_path()
    
    # Initialize threat feeds in background
    if THREAT_INTEL_AVAILABLE:
        print("[INFO] Initializing threat intelligence feeds...")
        try:
            intel = get_threat_intelligence()
            intel.update_all_feeds()
        except Exception as e:
            print(f"[WARNING] Threat feed initialization failed: {e}")
    
    startup_banner_ultimate(active_log_path)
    log_obj = load_or_init_log(active_log_path)
    
    try:
        while True:
            u = input("URL> ").strip()
            if not u:
                continue
            
            # Handle debug command
            if u.lower() == "debug on":
                DEBUG_MODE = True
                print("✓ Debug mode enabled\n")
                continue
            elif u.lower() == "debug off":
                DEBUG_MODE = False
                print("✓ Debug mode disabled\n")
                continue
            
            # Handle log rotation
            new_log_path = todays_log_path()
            if new_log_path != active_log_path:
                active_log_path = new_log_path
                log_obj = load_or_init_log(active_log_path)
                print(f"\n[Log rotation] Now logging to: {os.path.basename(active_log_path)}\n")
            
            # Run ultimate prediction
            t0 = time.perf_counter()
            lbl, p, src, reasons, p1, p2, whois_data = predict_ultimate(u)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            
            # Display results
            print_ultimate_result(u, lbl, p, src, reasons, p1=p1, p2=p2, whois_data=whois_data, elapsed_ms=elapsed_ms)
            
            # Log results
            scan_obj = build_scan_object(u, lbl, p, src, reasons, p1=p1, p2=p2, whois_data=whois_data, elapsed_ms=elapsed_ms)
            append_scan(log_obj, scan_obj, active_log_path)
    
    except KeyboardInterrupt:
        print("\n\nShutting down SentinURL Ultimate Phishing Detection System...")
        print("Stay safe! 🛡️\n")
