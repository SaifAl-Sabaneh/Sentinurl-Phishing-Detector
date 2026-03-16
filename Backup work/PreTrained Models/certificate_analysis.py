"""
Advanced TLS/SSL Certificate Analysis
Detects suspicious certificate patterns and misconfigurations
"""

import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

# Trusted Certificate Authorities (more trustworthy than others)
TRUSTED_CAs = [
    "DigiCert", "GlobalSign", "Entrust", "GeoTrust", "Thawte",
    "Comodo", "Sectigo", "GoDaddy", "VeriSign", "Symantec"
]

# Free CAs (more commonly used by phishers, but also legitimate)
FREE_CAs = [
    "Let's Encrypt", "ZeroSSL", "BuyPass", "SSL.com Free"
]

def parse_cert_date(date_str):
    """Parse certificate date string to datetime"""
    try:
        return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
    except:
        try:
            return datetime.strptime(date_str, "%Y%m%d%H%M%SZ")
        except:
            return None

def extract_issuer_info(cert):
    """Extract issuer information from certificate"""
    issuer = cert.get('issuer', ())
    issuer_dict = {}
    
    for item in issuer:
        for key, value in item:
            issuer_dict[key] = value
    
    return issuer_dict

def extract_subject_info(cert):
    """Extract subject information from certificate"""
    subject = cert.get('subject', ())
    subject_dict = {}
    
    for item in subject:
        for key, value in item:
            subject_dict[key] = value
    
    return subject_dict

def analyze_certificate(host, port=443, timeout=5):
    """
    Comprehensive certificate analysis
    Returns: dict with analysis results
    """
    result = {
        "valid": False,
        "error": None,
        "issuer": None,
        "issuer_org": None,
        "subject": None,
        "san": [],
        "not_before": None,
        "not_after": None,
        "days_until_expiry": None,
        "cert_age_days": None,
        "is_wildcard": False,
        "is_self_signed": False,
        "uses_free_ca": False,
        "uses_trusted_ca": False,
        "suspicion_score": 0,
        "warnings": [],
        "info": [],
    }
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect and get certificate
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        
        if not cert:
            result["error"] = "No certificate received"
            return result
        
        result["valid"] = True
        
        # Extract basic info
        issuer_info = extract_issuer_info(cert)
        subject_info = extract_subject_info(cert)
        
        result["issuer"] = issuer_info
        result["issuer_org"] = issuer_info.get('organizationName', issuer_info.get('commonName', 'Unknown'))
        result["subject"] = subject_info
        
        # Check for wildcards
        common_name = subject_info.get('commonName', '')
        if common_name.startswith('*.'):
            result["is_wildcard"] = True
            result["info"].append("Certificate uses wildcard domain")
        
        # Subject Alternative Names
        san = cert.get('subjectAltName', ())
        result["san"] = [name for typ, name in san if typ == 'DNS']
        
        # Dates
        not_before_str = cert.get('notBefore')
        not_after_str = cert.get('notAfter')
        
        if not_before_str:
            not_before = parse_cert_date(not_before_str)
            if not_before:
                result["not_before"] = not_before.strftime("%Y-%m-%d")
                cert_age = (datetime.utcnow() - not_before).days
                result["cert_age_days"] = cert_age
                
                # Suspicion: Very new certificate
                if cert_age < 7:
                    result["suspicion_score"] += 30
                    result["warnings"].append(f"Certificate is very new ({cert_age} days old)")
                elif cert_age < 30:
                    result["suspicion_score"] += 15
                    result["warnings"].append(f"Certificate is relatively new ({cert_age} days old)")
        
        if not_after_str:
            not_after = parse_cert_date(not_after_str)
            if not_after:
                result["not_after"] = not_after.strftime("%Y-%m-%d")
                days_left = (not_after - datetime.utcnow()).days
                result["days_until_expiry"] = days_left
                
                # Suspicion: Expiring soon (might indicate neglect)
                if days_left < 7:
                    result["suspicion_score"] += 20
                    result["warnings"].append(f"Certificate expires in {days_left} days")
                elif days_left < 30:
                    result["suspicion_score"] += 5
                    result["info"].append(f"Certificate expires in {days_left} days")
        
        # Check CA
        issuer_org = result["issuer_org"]
        
        # Self-signed check
        if issuer_info.get('commonName') == subject_info.get('commonName'):
            result["is_self_signed"] = True
            result["suspicion_score"] += 50
            result["warnings"].append("Certificate is self-signed")
        
        # Free CA check
        for free_ca in FREE_CAs:
            if free_ca.lower() in issuer_org.lower():
                result["uses_free_ca"] = True
                result["info"].append(f"Certificate from free CA: {issuer_org}")
                # Don't add suspicion - Let's Encrypt is legitimate
                break
        
        # Trusted CA check
        for trusted_ca in TRUSTED_CAs:
            if trusted_ca.lower() in issuer_org.lower():
                result["uses_trusted_ca"] = True
                result["info"].append(f"Certificate from trusted CA: {issuer_org}")
                result["suspicion_score"] = max(0, result["suspicion_score"] - 10)
                break
        
        # Wildcard on new domain = suspicious
        if result["is_wildcard"] and result["cert_age_days"] and result["cert_age_days"] < 30:
            result["suspicion_score"] += 20
            result["warnings"].append("New wildcard certificate (often used by phishers)")
        
        # Check SAN entries
        if len(result["san"]) > 100:
            result["suspicion_score"] += 15
            result["warnings"].append(f"Unusual number of SAN entries: {len(result['san'])}")
        
    except ssl.SSLError as e:
        result["error"] = f"SSL Error: {str(e)}"
        result["suspicion_score"] += 40
        result["warnings"].append("SSL/TLS connection failed")
    except socket.timeout:
        result["error"] = "Connection timeout"
        result["suspicion_score"] += 20
    except Exception as e:
        result["error"] = f"Connection error: {str(e)}"
        result["suspicion_score"] += 30
    
    return result

def get_cert_risk_level(analysis):
    """Convert suspicion score to risk level"""
    score = analysis.get("suspicion_score", 0)
    
    if score >= 80:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    elif score >= 10:
        return "LOW"
    else:
        return "MINIMAL"

def analyze_url_certificate(url):
    """Analyze certificate for a given URL"""
    try:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path
        host = host.split(':')[0]  # Remove port if present
        
        if not host:
            return {"valid": False, "error": "Invalid URL"}
        
        return analyze_certificate(host)
    except Exception as e:
        return {"valid": False, "error": str(e)}

# Testing
if __name__ == "__main__":
    test_domains = [
        "google.com",
        "github.com",
        "bankofamerica.com",
        "paypal.com",
    ]
    
    print("Certificate Analysis Tests:")
    print("=" * 100)
    
    for domain in test_domains:
        print(f"\nAnalyzing: {domain}")
        print("-" * 100)
        
        analysis = analyze_certificate(domain)
        
        if analysis["valid"]:
            print(f"  ✓ Valid Certificate")
            print(f"  Issuer: {analysis['issuer_org']}")
            print(f"  Age: {analysis['cert_age_days']} days")
            print(f"  Expires: {analysis['not_after']} ({analysis['days_until_expiry']} days left)")
            print(f"  Wildcard: {analysis['is_wildcard']}")
            print(f"  Self-Signed: {analysis['is_self_signed']}")
            print(f"  Free CA: {analysis['uses_free_ca']}")
            print(f"  Trusted CA: {analysis['uses_trusted_ca']}")
            print(f"  Suspicion Score: {analysis['suspicion_score']} ({get_cert_risk_level(analysis)})")
            
            if analysis['warnings']:
                print(f"  ⚠ Warnings:")
                for warning in analysis['warnings']:
                    print(f"    - {warning}")
            
            if analysis['info']:
                print(f"  ℹ Info:")
                for info in analysis['info']:
                    print(f"    - {info}")
        else:
            print(f"  ✗ Invalid: {analysis['error']}")
