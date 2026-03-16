"""
Threat Intelligence Feed Integration
Aggregates multiple threat feeds for comprehensive protection
"""

import json
import time
import hashlib
from datetime import datetime, timedelta

try:
    import requests
except:
    requests = None

# Threat Feed URLs
THREAT_FEEDS = {
    "phishtank": {
        "url": "http://data.phishtank.com/data/online-valid.json",
        "format": "json",
        "ttl": 3600,  # 1 hour cache
    },
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "format": "txt",
        "ttl": 3600,
    },
    "urlhaus_recent": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "format": "csv",
        "ttl": 1800,  # 30 minutes
    },
}

class ThreatIntelligence:
    """Manages multiple threat intelligence feeds"""
    
    def __init__(self, cache_dir=None):
        self.cache_dir = cache_dir or "/tmp/threat_feeds"
        self.cache = {}
        self.last_update = {}
        
    def _cache_key(self, feed_name):
        """Generate cache key for feed"""
        return f"{feed_name}_cache"
    
    def _is_cache_valid(self, feed_name):
        """Check if cached feed is still valid"""
        if feed_name not in self.last_update:
            return False
        
        ttl = THREAT_FEEDS[feed_name]["ttl"]
        age = (datetime.now() - self.last_update[feed_name]).total_seconds()
        return age < ttl
    
    def _download_feed(self, feed_name, feed_config):
        """Download threat feed from source"""
        if not requests:
            return None
        
        try:
            response = requests.get(feed_config["url"], timeout=30)
            if response.status_code == 200:
                return response.text
        except Exception as e:
            print(f"[ThreatIntel] Failed to download {feed_name}: {e}")
        
        return None
    
    def _parse_phishtank(self, data):
        """Parse PhishTank JSON format"""
        try:
            entries = json.loads(data)
            urls = set()
            for entry in entries:
                if "url" in entry:
                    urls.add(entry["url"].lower().strip())
            return urls
        except:
            return set()
    
    def _parse_openphish(self, data):
        """Parse OpenPhish text format"""
        urls = set()
        for line in data.split('\n'):
            line = line.strip()
            if line and line.startswith('http'):
                urls.add(line.lower())
        return urls
    
    def _parse_urlhaus(self, data):
        """Parse URLhaus CSV format"""
        urls = set()
        for line in data.split('\n')[9:]:  # Skip header
            if line.strip():
                parts = line.split(',')
                if len(parts) > 2:
                    url = parts[2].strip('"').lower()
                    if url.startswith('http'):
                        urls.add(url)
        return urls
    
    def update_feed(self, feed_name):
        """Update a specific threat feed"""
        if feed_name not in THREAT_FEEDS:
            return False
        
        feed_config = THREAT_FEEDS[feed_name]
        
        # Check cache first
        if self._is_cache_valid(feed_name):
            return True
        
        # Download fresh data
        data = self._download_feed(feed_name, feed_config)
        if not data:
            return False
        
        # Parse based on format
        feed_format = feed_config["format"]
        if feed_format == "json" and feed_name == "phishtank":
            urls = self._parse_phishtank(data)
        elif feed_format == "txt" and feed_name == "openphish":
            urls = self._parse_openphish(data)
        elif feed_format == "csv" and feed_name == "urlhaus_recent":
            urls = self._parse_urlhaus(data)
        else:
            return False
        
        # Update cache
        self.cache[feed_name] = urls
        self.last_update[feed_name] = datetime.now()
        
        print(f"[ThreatIntel] Updated {feed_name}: {len(urls)} URLs")
        return True
    
    def update_all_feeds(self):
        """Update all threat feeds"""
        success_count = 0
        for feed_name in THREAT_FEEDS.keys():
            if self.update_feed(feed_name):
                success_count += 1
        return success_count
    
    def check_url(self, url):
        """
        Check if URL is in any threat feed
        Returns: (is_threat, matched_feeds, details)
        """
        url_lower = url.lower().strip()
        matched_feeds = []
        
        for feed_name, urls in self.cache.items():
            if url_lower in urls:
                matched_feeds.append(feed_name)
        
        if matched_feeds:
            return (True, matched_feeds, f"Found in {len(matched_feeds)} threat feed(s)")
        
        # Also check domain-level matches
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url_lower)
            domain = parsed.netloc
            
            for feed_name, urls in self.cache.items():
                for threat_url in urls:
                    if domain in threat_url:
                        matched_feeds.append(f"{feed_name}_domain")
                        break
        except:
            pass
        
        if matched_feeds:
            return (True, matched_feeds, "Domain matches known threat")
        
        return (False, [], None)
    
    def get_stats(self):
        """Get statistics about loaded feeds"""
        stats = {}
        for feed_name, urls in self.cache.items():
            stats[feed_name] = {
                "count": len(urls),
                "last_update": self.last_update.get(feed_name, "Never"),
                "age_minutes": (datetime.now() - self.last_update[feed_name]).total_seconds() / 60 if feed_name in self.last_update else None
            }
        return stats

# Singleton instance
_threat_intel = None

def get_threat_intelligence():
    """Get or create singleton threat intelligence instance"""
    global _threat_intel
    if _threat_intel is None:
        _threat_intel = ThreatIntelligence()
    return _threat_intel

def check_threat_feeds(url):
    """
    Convenience function to check URL against threat feeds
    Returns: (is_threat, feeds, details)
    """
    intel = get_threat_intelligence()
    
    # Auto-update if cache is empty
    if not intel.cache:
        print("[ThreatIntel] Initializing threat feeds...")
        intel.update_all_feeds()
    
    return intel.check_url(url)

# Testing
if __name__ == "__main__":
    intel = ThreatIntelligence()
    
    print("Updating threat feeds...")
    intel.update_all_feeds()
    
    print("\nFeed Statistics:")
    stats = intel.get_stats()
    for feed, info in stats.items():
        print(f"  {feed}: {info['count']} URLs (updated {info['age_minutes']:.1f} min ago)")
    
    # Test some URLs
    test_urls = [
        "http://google.com",  # Should be safe
        "http://paypal-verify.suspicious.com",  # Might be in feeds
    ]
    
    print("\nTesting URLs:")
    for url in test_urls:
        is_threat, feeds, details = intel.check_url(url)
        print(f"  {url}: Threat={is_threat}, Feeds={feeds}")
