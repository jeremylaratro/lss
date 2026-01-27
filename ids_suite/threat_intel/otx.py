"""
AlienVault OTX (Open Threat Exchange) client
"""

from typing import Dict, Any, Optional

from ids_suite.threat_intel.cache import ThreatIntelCache
from ids_suite.core.dependencies import get_requests, REQUESTS_AVAILABLE


class OTXClient:
    """AlienVault OTX client"""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.cache = ThreatIntelCache(ttl_hours=24)

    def _make_request(self, endpoint: str) -> Dict[str, Any]:
        """Make a request to OTX API"""
        if not self.api_key or not REQUESTS_AVAILABLE:
            return {'error': 'API key not configured or requests not available'}

        requests = get_requests()
        try:
            headers = {'X-OTX-API-KEY': self.api_key}
            response = requests.get(f"{self.BASE_URL}/{endpoint}", headers=headers, timeout=30)
            if response.status_code == 200:
                return response.json()
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Look up IP address in OTX pulses"""
        cached = self.cache.get(f"otx:ip:{ip}")
        if cached:
            return cached

        result = self._make_request(f"indicators/IPv4/{ip}/general")
        if 'error' not in result:
            pulse_info = result.get('pulse_info', {})
            parsed = {
                'indicator': ip,
                'type': 'ip',
                'pulse_count': pulse_info.get('count', 0),
                'reputation': result.get('reputation', 0),
                'country': result.get('country_name', 'Unknown'),
                'pulses': [p.get('name', '') for p in pulse_info.get('pulses', [])[:5]]
            }
            self.cache.set(f"otx:ip:{ip}", parsed)
            return parsed
        return result

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Look up domain in OTX pulses"""
        cached = self.cache.get(f"otx:domain:{domain}")
        if cached:
            return cached

        result = self._make_request(f"indicators/domain/{domain}/general")
        if 'error' not in result:
            pulse_info = result.get('pulse_info', {})
            parsed = {
                'indicator': domain,
                'type': 'domain',
                'pulse_count': pulse_info.get('count', 0),
                'pulses': [p.get('name', '') for p in pulse_info.get('pulses', [])[:5]]
            }
            self.cache.set(f"otx:domain:{domain}", parsed)
            return parsed
        return result

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """Look up file hash in OTX pulses"""
        cached = self.cache.get(f"otx:hash:{file_hash}")
        if cached:
            return cached

        # Determine hash type by length
        hash_type = 'FileHash-MD5'
        if len(file_hash) == 40:
            hash_type = 'FileHash-SHA1'
        elif len(file_hash) == 64:
            hash_type = 'FileHash-SHA256'

        result = self._make_request(f"indicators/file/{file_hash}/general")
        if 'error' not in result:
            pulse_info = result.get('pulse_info', {})
            parsed = {
                'indicator': file_hash,
                'type': 'hash',
                'hash_type': hash_type,
                'pulse_count': pulse_info.get('count', 0),
                'pulses': [p.get('name', '') for p in pulse_info.get('pulses', [])[:5]]
            }
            self.cache.set(f"otx:hash:{file_hash}", parsed)
            return parsed
        return result
