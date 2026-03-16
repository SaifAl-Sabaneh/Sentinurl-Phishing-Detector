"""
Advanced Visual Similarity Detection Module
Catches homograph attacks, typosquatting, and brand impersonation
"""

import re
from difflib import SequenceMatcher

# Character substitution mappings for typosquatting
VISUAL_SUBSTITUTIONS = {
    '0': ['o', 'O'],
    '1': ['i', 'l', 'I', '|'],
    '3': ['e', 'E'],
    '4': ['a', 'A'],
    '5': ['s', 'S'],
    '6': ['g', 'G'],
    '7': ['t', 'T'],
    '8': ['b', 'B'],
    '9': ['g', 'q'],
    '@': ['a', 'A'],
    '$': ['s', 'S'],
    '!': ['i', 'l', '1'],
}

# Confusable Unicode characters (homoglyphs) - common in IDN homograph attacks
HOMOGLYPHS = {
    'a': ['а', 'ạ', 'ą', 'ά', 'α', 'ȧ', 'ä'],
    'c': ['с', 'ϲ', 'ċ', 'ç'],
    'e': ['е', 'ė', 'ę', 'έ', 'ē', 'ë'],
    'i': ['і', 'ı', 'í', 'ì', 'ï', 'ī'],
    'o': ['о', 'ο', 'ọ', 'ό', 'ö', 'ō', '0'],
    'p': ['р', 'ρ', 'þ'],
    'x': ['х', 'χ', '×'],
    'y': ['у', 'ý', 'ÿ', 'ү'],
    'n': ['п', 'ո', 'ñ'],
    'm': ['м', 'ṃ'],
    'h': ['һ', 'ḥ'],
    'k': ['κ', 'ķ'],
    'd': ['ԁ', 'ď'],
    'v': ['ν', 'ѵ'],
    'w': ['ԝ', 'ω'],
    'r': ['г', 'ř'],
}

# Top brands to protect against impersonation
PROTECTED_BRANDS = [
    # Tech Giants
    "google", "microsoft", "apple", "amazon", "meta", "facebook",
    "instagram", "whatsapp", "twitter", "linkedin", "youtube",
    "netflix", "spotify", "tiktok", "snapchat", "telegram",
    "github", "gitlab", "stackoverflow", "reddit", "discord",
    
    # E-commerce & Retail
    "ebay", "alibaba", "walmart", "target", "bestbuy", "etsy",
    "shopify", "aliexpress", "wayfair",
    
    # Financial Services
    "paypal", "stripe", "square", "venmo", "cashapp",
    "visa", "mastercard", "americanexpress", "discover",
    "chase", "wellsfargo", "bankofamerica", "citibank",
    "hsbc", "barclays", "capitalone",
    
    # Cloud & Enterprise
    "dropbox", "box", "onedrive", "icloud", "gdrive",
    "salesforce", "oracle", "sap", "adobe", "zoom",
    "slack", "teams", "webex", "atlassian", "jira",
    
    # Shipping & Logistics
    "fedex", "ups", "dhl", "usps",
    
    # Others
    "coinbase", "binance", "kraken", "metamask",
]

def normalize_for_similarity(text):
    """Normalize text by replacing visually similar characters"""
    text = text.lower().strip()
    
    # Replace numbers with letters they look like
    for num, letters in VISUAL_SUBSTITUTIONS.items():
        if num in text:
            # Use the most common letter substitution
            text = text.replace(num, letters[0])
    
    # Normalize homoglyphs to ASCII
    for ascii_char, confusables in HOMOGLYPHS.items():
        for confusable in confusables:
            if confusable in text:
                text = text.replace(confusable, ascii_char)
    
    # Remove common separators
    text = text.replace('-', '').replace('_', '').replace('.', '')
    
    return text

def levenshtein_distance(s1, s2):
    """Calculate edit distance between two strings"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
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

def check_visual_similarity(domain, protected_brands=PROTECTED_BRANDS):
    """
    Check if domain is visually similar to protected brands
    Returns: (is_suspicious, matched_brand, similarity_score, attack_type)
    """
    if not domain:
        return (False, None, 0.0, None)
    
    # Extract domain name without TLD
    domain_parts = domain.lower().split('.')
    if len(domain_parts) < 2:
        return (False, None, 0.0, None)
    
    domain_name = domain_parts[0]
    original_domain = domain_name
    normalized = normalize_for_similarity(domain_name)
    
    for brand in protected_brands:
        # 1. Exact match after normalization = homograph/typosquatting
        if normalized == brand and original_domain != brand:
            attack_type = "homograph" if has_homograph_attack(original_domain) else "typosquatting"
            return (True, brand, 1.0, attack_type)
        
        # 2. Levenshtein distance (1-2 char difference)
        if 0 < len(normalized) - len(brand) <= 2 or 0 < len(brand) - len(normalized) <= 2:
            distance = levenshtein_distance(normalized, brand)
            if 1 <= distance <= 2:
                similarity = 1.0 - (distance / max(len(brand), len(normalized)))
                if similarity >= 0.75:
                    return (True, brand, similarity, "typosquatting")
        
        # 3. Brand contained in domain with suspicious additions
        if brand in normalized and original_domain != brand:
            # Check for suspicious prefixes/suffixes
            suspicious_affixes = ['secure', 'login', 'account', 'verify', 'update', 
                                  'support', 'help', 'service', 'official', 'auth',
                                  'signin', 'wallet', 'portal', 'app', 'mail']
            
            for affix in suspicious_affixes:
                if affix in normalized:
                    return (True, brand, 0.9, "combo_squatting")
        
        # 4. Sequence matcher for overall similarity
        ratio = SequenceMatcher(None, normalized, brand).ratio()
        if ratio >= 0.85 and original_domain != brand:
            return (True, brand, ratio, "similar")
    
    return (False, None, 0.0, None)

def has_homograph_attack(text):
    """Detect if text contains non-ASCII homograph characters"""
    if not text:
        return False
    
    for char in text:
        # Check if character is non-ASCII (likely homoglyph)
        if ord(char) > 127:
            # Verify it's in our homoglyph list
            for ascii_char, confusables in HOMOGLYPHS.items():
                if char in confusables:
                    return True
    return False

def detect_combo_squatting(domain, brands=PROTECTED_BRANDS):
    """
    Detect combo squatting: brand + suspicious word
    Example: paypal-secure.com, google-verify.com
    """
    domain_lower = domain.lower()
    
    suspicious_combos = [
        'secure', 'verify', 'verification', 'login', 'signin',
        'account', 'update', 'support', 'help', 'service',
        'official', 'auth', 'authentication', 'portal', 'wallet'
    ]
    
    for brand in brands:
        if brand in domain_lower:
            for combo in suspicious_combos:
                if combo in domain_lower:
                    # Check if they're connected (not part of legitimate subdomain)
                    if f"{brand}-{combo}" in domain_lower or f"{brand}{combo}" in domain_lower or f"{combo}-{brand}" in domain_lower:
                        return (True, brand, combo)
    
    return (False, None, None)

def detect_subdomain_tricks(host):
    """
    Detect subdomain tricks like: paypal.com.evil.com, accounts-google.com.phish.ru
    """
    parts = host.lower().split('.')
    
    # Check for brand names in subdomains when main domain is suspicious
    if len(parts) >= 4:  # e.g., paypal.com.evil.com
        for i in range(len(parts) - 2):
            potential_fake = '.'.join(parts[i:i+2])
            # Check if it looks like a legitimate domain
            for brand in PROTECTED_BRANDS:
                if brand in potential_fake:
                    return (True, brand, "subdomain_trick")
    
    return (False, None, None)

# Testing
if __name__ == "__main__":
    test_cases = [
        ("g00gle.com", True),           # Number substitution
        ("paypa1.com", True),           # Number substitution
        ("micr0soft.com", True),        # Number substitution
        ("gοogle.com", True),           # Homoglyph (Greek omicron)
        ("аpple.com", True),            # Homoglyph (Cyrillic a)
        ("paypal-secure.com", True),    # Combo squatting
        ("google-verify.com", True),    # Combo squatting
        ("paypal.com.evil.com", True),  # Subdomain trick
        ("google.com", False),          # Legitimate
        ("amazon.com", False),          # Legitimate
        ("microsoft.com", False),       # Legitimate
    ]
    
    print("Visual Similarity Detection Tests:")
    print("=" * 80)
    
    for domain, should_detect in test_cases:
        is_susp, brand, score, attack_type = check_visual_similarity(domain)
        homograph = has_homograph_attack(domain)
        combo = detect_combo_squatting(domain)
        subdomain = detect_subdomain_tricks(domain)
        
        status = "✓" if (is_susp or combo[0] or subdomain[0]) == should_detect else "✗"
        
        print(f"{status} {domain:25} | Suspicious: {is_susp:5} | Brand: {str(brand):12} | "
              f"Score: {score:.2f} | Type: {attack_type or 'None':15} | Homograph: {homograph}")
