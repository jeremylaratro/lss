"""
ThreatFox IOC lookup client (abuse.ch) - No API key required
"""

from typing import Dict, Any

from ids_suite.threat_intel.cache import ThreatIntelCache
from ids_suite.core.dependencies import get_requests, REQUESTS_AVAILABLE


class ThreatFoxClient:
    """ThreatFox IOC lookup client (abuse.ch) - No API key required"""

    BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(self):
        self.cache = ThreatIntelCache(ttl_hours=24)

    def lookup_ioc(self, ioc: str) -> Dict[str, Any]:
        """Look up any IOC (IP, domain, hash, URL) on ThreatFox"""
        if not REQUESTS_AVAILABLE:
            return {'error': 'requests library not available'}

        cached = self.cache.get(f"threatfox:{ioc}")
        if cached:
            return cached

        requests = get_requests()
        try:
            payload = {"query": "search_ioc", "search_term": ioc}
            response = requests.post(self.BASE_URL, json=payload, timeout=30)

            if response.status_code != 200:
                return {'error': f'HTTP {response.status_code}'}

            data = response.json()
            if data.get('query_status') == 'no_result':
                result = {
                    'indicator': ioc,
                    'found': False,
                    'message': 'Not found in ThreatFox database'
                }
            elif data.get('query_status') == 'ok' and data.get('data'):
                ioc_data = data['data'][0]  # First match
                result = {
                    'indicator': ioc,
                    'found': True,
                    'ioc_type': ioc_data.get('ioc_type', 'Unknown'),
                    'threat_type': ioc_data.get('threat_type', 'Unknown'),
                    'malware': ioc_data.get('malware', 'Unknown'),
                    'malware_alias': ioc_data.get('malware_alias', ''),
                    'confidence': ioc_data.get('confidence_level', 0),
                    'first_seen': ioc_data.get('first_seen', 'Unknown'),
                    'last_seen': ioc_data.get('last_seen', 'Unknown'),
                    'tags': ioc_data.get('tags', []),
                    'reference': ioc_data.get('reference', '')
                }
            else:
                result = {'error': data.get('query_status', 'Unknown error')}

            if 'error' not in result:
                self.cache.set(f"threatfox:{ioc}", result)
            return result

        except Exception as e:
            return {'error': str(e)}

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Look up IP address on ThreatFox"""
        return self.lookup_ioc(ip)

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Look up domain on ThreatFox"""
        return self.lookup_ioc(domain)

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """Look up file hash on ThreatFox"""
        return self.lookup_ioc(file_hash)
