"""
VirusTotal API v3 client
"""

import time
from datetime import datetime
from typing import Dict, Any, Optional

from ids_suite.threat_intel.cache import ThreatIntelCache
from ids_suite.core.utils import is_private_ip
from ids_suite.core.dependencies import get_requests, REQUESTS_AVAILABLE


class VirusTotalClient:
    """VirusTotal API v3 client"""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.cache = ThreatIntelCache(ttl_hours=24)
        self.last_request: Optional[datetime] = None
        self.rate_limit_delay = 15  # seconds between requests for free API

    def _wait_for_rate_limit(self) -> None:
        """Ensure we don't exceed API rate limits"""
        if self.last_request:
            elapsed = (datetime.now() - self.last_request).total_seconds()
            if elapsed < self.rate_limit_delay:
                time.sleep(self.rate_limit_delay - elapsed)
        self.last_request = datetime.now()

    def _make_request(self, endpoint: str) -> Dict[str, Any]:
        """Make a request to VirusTotal API"""
        if not self.api_key or not REQUESTS_AVAILABLE:
            return {'error': 'API key not configured or requests not available'}

        self._wait_for_rate_limit()
        requests = get_requests()

        try:
            headers = {'x-apikey': self.api_key}
            response = requests.get(f"{self.BASE_URL}/{endpoint}", headers=headers, timeout=30)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                return {'error': 'Rate limit exceeded'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Look up IP address reputation"""
        # Never send private/LAN IPs to external APIs
        if is_private_ip(ip):
            return {
                'error': 'Private/LAN IP - not sent to API',
                'indicator': ip,
                'type': 'ip',
                'is_private': True
            }

        cached = self.cache.get(f"ip:{ip}")
        if cached:
            return cached

        result = self._make_request(f"ip_addresses/{ip}")
        if 'error' not in result:
            data = result.get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            parsed = {
                'indicator': ip,
                'type': 'ip',
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'reputation': data.get('reputation', 0),
                'country': data.get('country', 'Unknown'),
                'as_owner': data.get('as_owner', 'Unknown'),
            }
            self.cache.set(f"ip:{ip}", parsed)
            return parsed
        return result

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """Look up file hash"""
        cached = self.cache.get(f"hash:{file_hash}")
        if cached:
            return cached

        result = self._make_request(f"files/{file_hash}")
        if 'error' not in result:
            data = result.get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            parsed = {
                'indicator': file_hash,
                'type': 'hash',
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'type_description': data.get('type_description', 'Unknown'),
                'names': data.get('names', [])[:5],
            }
            self.cache.set(f"hash:{file_hash}", parsed)
            return parsed
        return result

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Look up domain reputation"""
        cached = self.cache.get(f"domain:{domain}")
        if cached:
            return cached

        result = self._make_request(f"domains/{domain}")
        if 'error' not in result:
            data = result.get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            parsed = {
                'indicator': domain,
                'type': 'domain',
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'reputation': data.get('reputation', 0),
                'categories': data.get('categories', {}),
            }
            self.cache.set(f"domain:{domain}", parsed)
            return parsed
        return result
