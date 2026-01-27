"""
Tests for ids_suite/threat_intel/abuseipdb.py - AbuseIPDB API client

Target: 75%+ coverage
"""

import pytest
from unittest.mock import patch, MagicMock

from ids_suite.threat_intel.abuseipdb import AbuseIPDBClient


class TestAbuseIPDBClientInit:
    """Test AbuseIPDBClient initialization"""

    def test_init_with_api_key(self):
        """AB-001: Client initializes with API key"""
        client = AbuseIPDBClient(api_key="test-key")
        assert client.api_key == "test-key"
        assert client.cache is not None

    def test_init_without_api_key(self):
        """AB-002: Client initializes without API key"""
        client = AbuseIPDBClient()
        assert client.api_key is None

    def test_base_url(self):
        """AB-003: Base URL is correct"""
        assert AbuseIPDBClient.BASE_URL == "https://api.abuseipdb.com/api/v2"


class TestAbuseIPDBLookupIP:
    """Test lookup_ip method"""

    def test_lookup_private_ip(self):
        """AB-004: Private IP returns error, not sent to API"""
        client = AbuseIPDBClient(api_key="key")
        result = client.lookup_ip("192.168.1.1")
        assert result['is_private'] is True
        assert 'Private' in result['error']
        assert result['indicator'] == '192.168.1.1'

    def test_lookup_loopback_ip(self):
        """AB-005: Loopback IP returns error"""
        client = AbuseIPDBClient(api_key="key")
        result = client.lookup_ip("127.0.0.1")
        assert result['is_private'] is True

    def test_lookup_link_local_ip(self):
        """AB-006: Link-local IP returns error"""
        client = AbuseIPDBClient(api_key="key")
        result = client.lookup_ip("169.254.1.1")
        assert result['is_private'] is True

    def test_lookup_no_api_key(self):
        """AB-007: Returns error when API key not set"""
        client = AbuseIPDBClient()
        result = client.lookup_ip("8.8.8.8")
        assert 'error' in result

    @patch('ids_suite.threat_intel.abuseipdb.REQUESTS_AVAILABLE', False)
    def test_lookup_no_requests(self):
        """AB-008: Returns error when requests not available"""
        client = AbuseIPDBClient(api_key="key")
        result = client.lookup_ip("8.8.8.8")
        assert 'error' in result

    @patch('ids_suite.threat_intel.abuseipdb.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.abuseipdb.get_requests')
    def test_lookup_cached(self, mock_get_requests):
        """AB-009: Cached IP returns cached result"""
        client = AbuseIPDBClient(api_key="key")
        cached_data = {'indicator': '8.8.8.8', 'abuse_score': 0}
        client.cache.set('abuseipdb:8.8.8.8', cached_data)

        result = client.lookup_ip("8.8.8.8")
        assert result == cached_data
        mock_get_requests.assert_not_called()

    @patch('ids_suite.threat_intel.abuseipdb.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.abuseipdb.get_requests')
    def test_lookup_success(self, mock_get_requests):
        """AB-010: Successful lookup returns parsed data"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                'abuseConfidenceScore': 85,
                'totalReports': 100,
                'numDistinctUsers': 50,
                'countryCode': 'RU',
                'isp': 'Evil ISP',
                'domain': 'evil.com',
                'isWhitelisted': False,
                'lastReportedAt': '2024-01-15T10:00:00Z',
                'usageType': 'Data Center'
            }
        }
        mock_requests.get.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = AbuseIPDBClient(api_key="key")
        result = client.lookup_ip("1.2.3.4")

        assert result['indicator'] == '1.2.3.4'
        assert result['type'] == 'ip'
        assert result['abuse_score'] == 85
        assert result['total_reports'] == 100
        assert result['num_distinct_users'] == 50
        assert result['country'] == 'RU'
        assert result['isp'] == 'Evil ISP'
        assert result['domain'] == 'evil.com'
        assert result['is_whitelisted'] is False
        assert result['usage_type'] == 'Data Center'

    @patch('ids_suite.threat_intel.abuseipdb.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.abuseipdb.get_requests')
    def test_lookup_401_error(self, mock_get_requests):
        """AB-011: Returns error on invalid API key"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_requests.get.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = AbuseIPDBClient(api_key="bad-key")
        result = client.lookup_ip("8.8.8.8")
        assert 'error' in result
        assert 'Invalid API key' in result['error']

    @patch('ids_suite.threat_intel.abuseipdb.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.abuseipdb.get_requests')
    def test_lookup_429_error(self, mock_get_requests):
        """AB-012: Returns error on rate limit"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_requests.get.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = AbuseIPDBClient(api_key="key")
        result = client.lookup_ip("8.8.8.8")
        assert 'error' in result
        assert 'Rate limit' in result['error']

    @patch('ids_suite.threat_intel.abuseipdb.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.abuseipdb.get_requests')
    def test_lookup_other_http_error(self, mock_get_requests):
        """AB-013: Returns HTTP error for other status codes"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_requests.get.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = AbuseIPDBClient(api_key="key")
        result = client.lookup_ip("8.8.8.8")
        assert 'error' in result
        assert 'HTTP 500' in result['error']

    @patch('ids_suite.threat_intel.abuseipdb.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.abuseipdb.get_requests')
    def test_lookup_exception(self, mock_get_requests):
        """AB-014: Returns error on exception"""
        mock_requests = MagicMock()
        mock_requests.get.side_effect = Exception("Network error")
        mock_get_requests.return_value = mock_requests

        client = AbuseIPDBClient(api_key="key")
        result = client.lookup_ip("8.8.8.8")
        assert 'error' in result
        assert 'Network error' in result['error']

    @patch('ids_suite.threat_intel.abuseipdb.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.abuseipdb.get_requests')
    def test_lookup_missing_fields(self, mock_get_requests):
        """AB-015: Handles missing fields with defaults"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': {}}
        mock_requests.get.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = AbuseIPDBClient(api_key="key")
        result = client.lookup_ip("5.6.7.8")

        assert result['abuse_score'] == 0
        assert result['total_reports'] == 0
        assert result['country'] == 'Unknown'
        assert result['isp'] == 'Unknown'
        assert result['is_whitelisted'] is False

    @patch('ids_suite.threat_intel.abuseipdb.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.abuseipdb.get_requests')
    def test_lookup_caches_result(self, mock_get_requests):
        """AB-016: Successful lookup caches the result"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                'abuseConfidenceScore': 0,
                'totalReports': 0
            }
        }
        mock_requests.get.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = AbuseIPDBClient(api_key="key")
        client.lookup_ip("9.9.9.9")

        # Verify it was cached
        cached = client.cache.get('abuseipdb:9.9.9.9')
        assert cached is not None
        assert cached['indicator'] == '9.9.9.9'

    def test_lookup_10_network(self):
        """AB-017: 10.x.x.x network returns private"""
        client = AbuseIPDBClient(api_key="key")
        result = client.lookup_ip("10.0.0.1")
        assert result['is_private'] is True

    def test_lookup_172_network(self):
        """AB-018: 172.16-31.x.x network returns private"""
        client = AbuseIPDBClient(api_key="key")
        result = client.lookup_ip("172.16.0.1")
        assert result['is_private'] is True
