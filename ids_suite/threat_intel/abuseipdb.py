"""
AbuseIPDB API client for IP reputation lookups
"""

from typing import Dict, Any, Optional

from ids_suite.threat_intel.cache import ThreatIntelCache
from ids_suite.core.utils import is_private_ip
from ids_suite.core.dependencies import get_requests, REQUESTS_AVAILABLE


class AbuseIPDBClient:
    """AbuseIPDB API client for IP reputation lookups"""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.cache = ThreatIntelCache(ttl_hours=24)

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Look up IP reputation on AbuseIPDB"""
        # Never send private/LAN IPs to external APIs
        if is_private_ip(ip):
            return {
                'error': 'Private/LAN IP - not sent to API',
                'indicator': ip,
                'type': 'ip',
                'is_private': True
            }

        if not self.api_key or not REQUESTS_AVAILABLE:
            return {'error': 'API key not configured or requests not available'}

        cached = self.cache.get(f"abuseipdb:{ip}")
        if cached:
            return cached

        requests = get_requests()
        try:
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            response = requests.get(
                f"{self.BASE_URL}/check",
                headers=headers,
                params=params,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json().get('data', {})
                result = {
                    'indicator': ip,
                    'type': 'ip',
                    'abuse_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'num_distinct_users': data.get('numDistinctUsers', 0),
                    'country': data.get('countryCode', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'domain': data.get('domain', ''),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'last_reported': data.get('lastReportedAt', 'Never'),
                    'usage_type': data.get('usageType', 'Unknown')
                }
                self.cache.set(f"abuseipdb:{ip}", result)
                return result
            elif response.status_code == 401:
                return {'error': 'Invalid API key'}
            elif response.status_code == 429:
                return {'error': 'Rate limit exceeded (1000/day for free tier)'}
            else:
                return {'error': f'HTTP {response.status_code}'}

        except Exception as e:
            return {'error': str(e)}
