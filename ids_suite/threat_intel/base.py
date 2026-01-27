"""
Base class for threat intelligence API clients
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

from ids_suite.threat_intel.cache import ThreatIntelCache
from ids_suite.core.dependencies import get_requests, REQUESTS_AVAILABLE


class ThreatIntelClient(ABC):
    """Abstract base class for threat intelligence API clients"""

    def __init__(self, api_key: Optional[str] = None, cache_ttl_hours: int = 24):
        self.api_key = api_key
        self.cache = ThreatIntelCache(ttl_hours=cache_ttl_hours)

    @property
    @abstractmethod
    def base_url(self) -> str:
        """Base URL for the API"""
        pass

    @property
    def requires_api_key(self) -> bool:
        """Whether this API requires an API key"""
        return True

    def _check_prerequisites(self) -> Optional[Dict[str, Any]]:
        """Check if prerequisites are met for making requests"""
        if not REQUESTS_AVAILABLE:
            return {'error': 'requests library not available'}
        if self.requires_api_key and not self.api_key:
            return {'error': 'API key not configured'}
        return None

    def _get_headers(self) -> Dict[str, str]:
        """Get headers for API requests - override in subclasses"""
        return {}

    def _make_request(
        self,
        endpoint: str,
        method: str = 'GET',
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """Make an HTTP request to the API"""
        error = self._check_prerequisites()
        if error:
            return error

        requests = get_requests()
        try:
            url = f"{self.base_url}/{endpoint}" if endpoint else self.base_url
            headers = self._get_headers()

            if method.upper() == 'GET':
                response = requests.get(url, headers=headers, params=params, timeout=timeout)
            elif method.upper() == 'POST':
                response = requests.post(url, headers=headers, json=json_data, timeout=timeout)
            else:
                return {'error': f'Unsupported method: {method}'}

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                return {'error': 'Invalid API key'}
            elif response.status_code == 429:
                return {'error': 'Rate limit exceeded'}
            else:
                return {'error': f'HTTP {response.status_code}'}

        except Exception as e:
            return {'error': str(e)}
