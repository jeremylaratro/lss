"""
Tests for ids_suite/threat_intel/virustotal.py - VirusTotal API client

Target: 75%+ coverage
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

from ids_suite.threat_intel.virustotal import VirusTotalClient


class TestVirusTotalClientInit:
    """Test VirusTotalClient initialization"""

    def test_init_with_api_key(self):
        """VT-001: Client initializes with API key"""
        client = VirusTotalClient(api_key="test-key")
        assert client.api_key == "test-key"
        assert client.cache is not None
        assert client.last_request is None
        assert client.rate_limit_delay == 15

    def test_init_without_api_key(self):
        """VT-002: Client initializes without API key"""
        client = VirusTotalClient()
        assert client.api_key is None


class TestVirusTotalRateLimit:
    """Test rate limiting functionality"""

    def test_wait_for_rate_limit_first_request(self):
        """VT-003: First request doesn't wait"""
        client = VirusTotalClient(api_key="key")
        client._wait_for_rate_limit()
        assert client.last_request is not None

    @patch('time.sleep')
    def test_wait_for_rate_limit_within_window(self, mock_sleep):
        """VT-004: Waits when within rate limit window"""
        client = VirusTotalClient(api_key="key")
        client.last_request = datetime.now() - timedelta(seconds=5)
        client._wait_for_rate_limit()
        mock_sleep.assert_called_once()
        # Should sleep approximately 10 seconds (15 - 5)
        sleep_time = mock_sleep.call_args[0][0]
        assert 9 <= sleep_time <= 11

    @patch('time.sleep')
    def test_wait_for_rate_limit_past_window(self, mock_sleep):
        """VT-005: Doesn't wait when past rate limit window"""
        client = VirusTotalClient(api_key="key")
        client.last_request = datetime.now() - timedelta(seconds=20)
        client._wait_for_rate_limit()
        mock_sleep.assert_not_called()


class TestVirusTotalMakeRequest:
    """Test _make_request method"""

    def test_make_request_no_api_key(self):
        """VT-006: Returns error when API key not set"""
        client = VirusTotalClient()
        result = client._make_request("endpoint")
        assert 'error' in result

    @patch('ids_suite.threat_intel.virustotal.REQUESTS_AVAILABLE', False)
    def test_make_request_no_requests(self):
        """VT-007: Returns error when requests not available"""
        client = VirusTotalClient(api_key="key")
        result = client._make_request("endpoint")
        assert 'error' in result

    @patch('ids_suite.threat_intel.virustotal.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.virustotal.get_requests')
    @patch.object(VirusTotalClient, '_wait_for_rate_limit')
    def test_make_request_success(self, mock_wait, mock_get_requests):
        """VT-008: Returns JSON on successful request"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': 'value'}
        mock_requests.get.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = VirusTotalClient(api_key="key")
        result = client._make_request("endpoint")
        assert result == {'data': 'value'}
        mock_wait.assert_called_once()

    @patch('ids_suite.threat_intel.virustotal.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.virustotal.get_requests')
    @patch.object(VirusTotalClient, '_wait_for_rate_limit')
    def test_make_request_rate_limit(self, mock_wait, mock_get_requests):
        """VT-009: Returns error on 429 rate limit"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_requests.get.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = VirusTotalClient(api_key="key")
        result = client._make_request("endpoint")
        assert 'error' in result
        assert 'Rate limit' in result['error']

    @patch('ids_suite.threat_intel.virustotal.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.virustotal.get_requests')
    @patch.object(VirusTotalClient, '_wait_for_rate_limit')
    def test_make_request_exception(self, mock_wait, mock_get_requests):
        """VT-010: Returns error on exception"""
        mock_requests = MagicMock()
        mock_requests.get.side_effect = Exception("Connection error")
        mock_get_requests.return_value = mock_requests

        client = VirusTotalClient(api_key="key")
        result = client._make_request("endpoint")
        assert 'error' in result
        assert 'Connection error' in result['error']


class TestVirusTotalLookupIP:
    """Test lookup_ip method"""

    def test_lookup_ip_private(self):
        """VT-011: Private IP returns error, not sent to API"""
        client = VirusTotalClient(api_key="key")
        result = client.lookup_ip("192.168.1.1")
        assert result['is_private'] is True
        assert 'Private' in result['error']

    def test_lookup_ip_loopback(self):
        """VT-012: Loopback IP returns error"""
        client = VirusTotalClient(api_key="key")
        result = client.lookup_ip("127.0.0.1")
        assert result['is_private'] is True

    @patch.object(VirusTotalClient, '_make_request')
    def test_lookup_ip_cached(self, mock_request):
        """VT-013: Cached IP returns cached result"""
        client = VirusTotalClient(api_key="key")
        cached_data = {'indicator': '8.8.8.8', 'malicious': 0}
        client.cache.set('ip:8.8.8.8', cached_data)

        result = client.lookup_ip("8.8.8.8")
        assert result == cached_data
        mock_request.assert_not_called()

    @patch.object(VirusTotalClient, '_make_request')
    def test_lookup_ip_success(self, mock_request):
        """VT-014: Successful lookup returns parsed data"""
        mock_request.return_value = {
            'data': {
                'attributes': {
                    'last_analysis_stats': {
                        'malicious': 5,
                        'suspicious': 2,
                        'harmless': 90
                    },
                    'reputation': -10,
                    'country': 'US',
                    'as_owner': 'Google LLC'
                }
            }
        }

        client = VirusTotalClient(api_key="key")
        result = client.lookup_ip("8.8.8.8")

        assert result['indicator'] == '8.8.8.8'
        assert result['type'] == 'ip'
        assert result['malicious'] == 5
        assert result['suspicious'] == 2
        assert result['harmless'] == 90
        assert result['reputation'] == -10
        assert result['country'] == 'US'
        assert result['as_owner'] == 'Google LLC'

    @patch.object(VirusTotalClient, '_make_request')
    def test_lookup_ip_error(self, mock_request):
        """VT-015: Returns error on API failure"""
        mock_request.return_value = {'error': 'API error'}
        client = VirusTotalClient(api_key="key")
        result = client.lookup_ip("8.8.8.8")
        assert 'error' in result


class TestVirusTotalLookupHash:
    """Test lookup_hash method"""

    @patch.object(VirusTotalClient, '_make_request')
    def test_lookup_hash_cached(self, mock_request):
        """VT-016: Cached hash returns cached result"""
        client = VirusTotalClient(api_key="key")
        cached_data = {'indicator': 'abc123', 'malicious': 0}
        client.cache.set('hash:abc123', cached_data)

        result = client.lookup_hash("abc123")
        assert result == cached_data
        mock_request.assert_not_called()

    @patch.object(VirusTotalClient, '_make_request')
    def test_lookup_hash_success(self, mock_request):
        """VT-017: Successful lookup returns parsed data"""
        mock_request.return_value = {
            'data': {
                'attributes': {
                    'last_analysis_stats': {
                        'malicious': 45,
                        'suspicious': 5,
                        'harmless': 10
                    },
                    'type_description': 'Win32 EXE',
                    'names': ['malware.exe', 'trojan.exe', 'virus.exe']
                }
            }
        }

        client = VirusTotalClient(api_key="key")
        result = client.lookup_hash("abc123def456")

        assert result['indicator'] == 'abc123def456'
        assert result['type'] == 'hash'
        assert result['malicious'] == 45
        assert result['type_description'] == 'Win32 EXE'
        assert len(result['names']) <= 5

    @patch.object(VirusTotalClient, '_make_request')
    def test_lookup_hash_error(self, mock_request):
        """VT-018: Returns error on API failure"""
        mock_request.return_value = {'error': 'Not found'}
        client = VirusTotalClient(api_key="key")
        result = client.lookup_hash("badHash")
        assert 'error' in result


class TestVirusTotalLookupDomain:
    """Test lookup_domain method"""

    @patch.object(VirusTotalClient, '_make_request')
    def test_lookup_domain_cached(self, mock_request):
        """VT-019: Cached domain returns cached result"""
        client = VirusTotalClient(api_key="key")
        cached_data = {'indicator': 'example.com', 'malicious': 0}
        client.cache.set('domain:example.com', cached_data)

        result = client.lookup_domain("example.com")
        assert result == cached_data
        mock_request.assert_not_called()

    @patch.object(VirusTotalClient, '_make_request')
    def test_lookup_domain_success(self, mock_request):
        """VT-020: Successful lookup returns parsed data"""
        mock_request.return_value = {
            'data': {
                'attributes': {
                    'last_analysis_stats': {
                        'malicious': 3,
                        'suspicious': 1,
                        'harmless': 80
                    },
                    'reputation': 5,
                    'categories': {'Forcepoint ThreatSeeker': 'search engines'}
                }
            }
        }

        client = VirusTotalClient(api_key="key")
        result = client.lookup_domain("google.com")

        assert result['indicator'] == 'google.com'
        assert result['type'] == 'domain'
        assert result['malicious'] == 3
        assert result['reputation'] == 5
        assert 'categories' in result

    @patch.object(VirusTotalClient, '_make_request')
    def test_lookup_domain_error(self, mock_request):
        """VT-021: Returns error on API failure"""
        mock_request.return_value = {'error': 'Domain not found'}
        client = VirusTotalClient(api_key="key")
        result = client.lookup_domain("nonexistent.example")
        assert 'error' in result

    @patch.object(VirusTotalClient, '_make_request')
    def test_lookup_domain_missing_fields(self, mock_request):
        """VT-022: Handles missing fields with defaults"""
        mock_request.return_value = {
            'data': {
                'attributes': {
                    'last_analysis_stats': {}
                }
            }
        }

        client = VirusTotalClient(api_key="key")
        result = client.lookup_domain("sparse.example.com")

        assert result['malicious'] == 0
        assert result['suspicious'] == 0
        assert result['reputation'] == 0
