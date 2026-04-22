import requests
import os
import time
import re

class URLHausFeed:
    def __init__(self, cache_file=None):
        if cache_file is None:
            # Try to put it in a 'stage2' or 'logs' directory if they exist
            if os.path.exists(os.path.join("models", "stage2")):
                self.cache_file = os.path.join(os.path.join("models", "stage2"), "urlhaus_cache.txt")
            elif os.path.exists("logs"):
                self.cache_file = os.path.join("logs", "urlhaus_cache.txt")
            else:
                self.cache_file = "urlhaus_cache.txt"
        else:
            self.cache_file = cache_file
            
        self.url = "https://urlhaus.abuse.ch/downloads/text/"
        self.malicious_urls = set()
        self.last_updated = 0
        self.ttl = 3600 * 6  # 6 hours TTL

    def _is_cache_valid(self):
        if not os.path.exists(self.cache_file):
            return False
        file_age = time.time() - os.path.getmtime(self.cache_file)
        return file_age < self.ttl

    def update_all_feeds(self):
        """Main entry point to ensure feed is loaded."""
        if self._is_cache_valid():
            return self.load_cache()
        else:
            return self.download_feed()

    def download_feed(self):
        """Downloads the URLHaus text feed and caches it locally."""
        try:
            response = requests.get(self.url, timeout=15)
            if response.status_code == 200:
                content = response.text
                urls = set()
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        urls.add(line)
                
                self.malicious_urls = urls
                self.last_updated = time.time()
                
                # Save to cache
                try:
                    os.makedirs(os.path.dirname(self.cache_file), exist_ok=True) if os.path.dirname(self.cache_file) else None
                    with open(self.cache_file, "w", encoding="utf-8") as f:
                        f.write(content)
                except Exception:
                    pass # Continue even if saving fails
                
                return True
        except Exception:
            # Fallback to cache if download fails
            return self.load_cache()
        return False

    def load_cache(self):
        """Loads the feed from the local cache if available."""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    content = f.read()
                    urls = set()
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            urls.add(line)
                    self.malicious_urls = urls
                    self.last_updated = os.path.getmtime(self.cache_file)
                    return True
            except Exception:
                pass
        return False

    def check_url(self, url):
        """Checks if a URL is in the malicious set."""
        if not self.malicious_urls:
            self.update_all_feeds()
        
        # Check exact and normalized versions
        search_urls = {url, url.rstrip('/'), url.lower(), url.lower().rstrip('/')}
        for u in search_urls:
            if u in self.malicious_urls:
                return True
        return False

    def get_stats(self):
        return {
            "urlhaus": {
                "count": len(self.malicious_urls),
                "last_updated": self.last_updated
            }
        }

# Singleton instance
_threat_intel_instance = None

def get_threat_intelligence():
    global _threat_intel_instance
    if _threat_intel_instance is None:
        _threat_intel_instance = URLHausFeed()
    return _threat_intel_instance

def check_threat_feeds(url):
    """
    Main interface for sentinurl.py
    Returns: (is_threat, feeds, details)
    """
    intel = get_threat_intelligence()
    if intel.check_url(url):
        return (True, ["URLHaus"], "URL found in abuse.ch URLHaus malicious feed (Known Malware/Distributor)")
    return (False, [], None)
