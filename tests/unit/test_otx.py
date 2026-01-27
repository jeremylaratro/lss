"""
Tests for ids_suite/threat_intel/otx.py - AlienVault OTX client

Target: 75%+ coverage
"""

import pytest
from unittest.mock import patch, MagicMock

from ids_suite.threat_intel.otx import OTXClient


class TestOTXClientInit:
    """Test OTXClient initialization"""

    def test_init_with_api_key(self):
        """OTX-001: Client initializes with API key"""
        client = OTXClient(api_key="test-key")
        assert client.api_key == "test-key"
        assert client.cache is not None

    def test_init_without_api_key(self):
        """OTX-002: Client initializes without API key"""
        client = OTXClient()
        assert client.api_key is None

    def test_base_url(self):
        """OTX-003: Base URL is correct"""
        assert OTXClient.BASE_URL == "https://otx.alienvault.com/api/v1"


class TestOTXMakeRequest:
    """Test _make_request method"""

    def test_make_request_no_api_key(self):
        """OTX-004: Returns error when API key not set"""
        client = OTXClient()
        result = client._make_request("endpoint")
        assert 'error' in result

    @patch('ids_suite.threat_intel.otx.REQUESTS_AVAILABLE', False)
    def test_make_request_no_requests(self):
        """OTX-005: Returns error when requests not available"""
        client = OTXClient(api_key="key")
        result = client._make_request("endpoint")
        assert 'error' in result

    @patch('ids_suite.threat_intel.otx.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.otx.get_requests')
    def test_make_request_success(self, mock_get_requests):
        """OTX-006: Returns JSON on successful request"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': 'value'}
        mock_requests.get.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = OTXClient(api_key="key")
        result = client._make_request("endpoint")
        assert result == {'data': 'value'}

    @patch('ids_suite.threat_intel.otx.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.otx.get_requests')
    def test_make_request_http_error(self, mock_get_requests):
        """OTX-007: Returns error on non-200 status"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_requests.get.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = OTXClient(api_key="key")
        result = client._make_request("endpoint")
        assert 'error' in result
        assert 'HTTP 403' in result['error']

    @patch('ids_suite.threat_intel.otx.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.otx.get_requests')
    def test_make_request_exception(self, mock_get_requests):
        """OTX-008: Returns error on exception"""
        mock_requests = MagicMock()
        mock_requests.get.side_effect = Exception("Connection timeout")
        mock_get_requests.return_value = mock_requests

        client = OTXClient(api_key="key")
        result = client._make_request("endpoint")
        assert 'error' in result
        assert 'Connection timeout' in result['error']


class TestOTXLookupIP:
    """Test lookup_ip method"""

    @patch.object(OTXClient, '_make_request')
    def test_lookup_ip_cached(self, mock_request):
        """OTX-009: Cached IP returns cached result"""
        client = OTXClient(api_key="key")
        cached_data = {'indicator': '8.8.8.8', 'pulse_count': 5}
        client.cache.set('otx:ip:8.8.8.8', cached_data)

        result = client.lookup_ip("8.8.8.8")
        assert result == cached_data
        mock_request.assert_not_called()

    @patch.object(OTXClient, '_make_request')
    def test_lookup_ip_success(self, mock_request):
        """OTX-010: Successful lookup returns parsed data"""
        mock_request.return_value = {
            'pulse_info': {
                'count': 10,
                'pulses': [
                    {'name': 'Pulse 1'},
                    {'name': 'Pulse 2'},
                    {'name': 'Pulse 3'}
                ]
            },
            'reputation': -5,
            'country_name': 'China'
        }

        client = OTXClient(api_key="key")
        result = client.lookup_ip("1.2.3.4")

        assert result['indicator'] == '1.2.3.4'
        assert result['type'] == 'ip'
        assert result['pulse_count'] == 10
        assert result['reputation'] == -5
        assert result['country'] == 'China'
        assert len(result['pulses']) == 3

    @patch.object(OTXClient, '_make_request')
    def test_lookup_ip_error(self, mock_request):
        """OTX-011: Returns error on API failure"""
        mock_request.return_value = {'error': 'API error'}
        client = OTXClient(api_key="key")
        result = client.lookup_ip("8.8.8.8")
        assert 'error' in result

    @patch.object(OTXClient, '_make_request')
    def test_lookup_ip_missing_fields(self, mock_request):
        """OTX-012: Handles missing fields with defaults"""
        mock_request.return_value = {
            'pulse_info': {}
        }

        client = OTXClient(api_key="key")
        result = client.lookup_ip("5.6.7.8")

        assert result['pulse_count'] == 0
        assert result['reputation'] == 0
        assert result['country'] == 'Unknown'
        assert result['pulses'] == []


class TestOTXLookupDomain:
    """Test lookup_domain method"""

    @patch.object(OTXClient, '_make_request')
    def test_lookup_domain_cached(self, mock_request):
        """OTX-013: Cached domain returns cached result"""
        client = OTXClient(api_key="key")
        cached_data = {'indicator': 'example.com', 'pulse_count': 2}
        client.cache.set('otx:domain:example.com', cached_data)

        result = client.lookup_domain("example.com")
        assert result == cached_data
        mock_request.assert_not_called()

    @patch.object(OTXClient, '_make_request')
    def test_lookup_domain_success(self, mock_request):
        """OTX-014: Successful lookup returns parsed data"""
        mock_request.return_value = {
            'pulse_info': {
                'count': 5,
                'pulses': [{'name': 'Malware Campaign'}]
            }
        }

        client = OTXClient(api_key="key")
        result = client.lookup_domain("evil.com")

        assert result['indicator'] == 'evil.com'
        assert result['type'] == 'domain'
        assert result['pulse_count'] == 5
        assert 'Malware Campaign' in result['pulses']

    @patch.object(OTXClient, '_make_request')
    def test_lookup_domain_error(self, mock_request):
        """OTX-015: Returns error on API failure"""
        mock_request.return_value = {'error': 'Not found'}
        client = OTXClient(api_key="key")
        result = client.lookup_domain("notfound.example")
        assert 'error' in result


class TestOTXLookupHash:
    """Test lookup_hash method"""

    @patch.object(OTXClient, '_make_request')
    def test_lookup_hash_cached(self, mock_request):
        """OTX-016: Cached hash returns cached result"""
        client = OTXClient(api_key="key")
        cached_data = {'indicator': 'abc123', 'pulse_count': 3}
        client.cache.set('otx:hash:abc123', cached_data)

        result = client.lookup_hash("abc123")
        assert result == cached_data
        mock_request.assert_not_called()

    @patch.object(OTXClient, '_make_request')
    def test_lookup_hash_md5(self, mock_request):
        """OTX-017: MD5 hash detected correctly"""
        mock_request.return_value = {
            'pulse_info': {'count': 1, 'pulses': []}
        }

        client = OTXClient(api_key="key")
        # MD5 is 32 chars
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        result = client.lookup_hash(md5_hash)

        assert result['hash_type'] == 'FileHash-MD5'

    @patch.object(OTXClient, '_make_request')
    def test_lookup_hash_sha1(self, mock_request):
        """OTX-018: SHA1 hash detected correctly"""
        mock_request.return_value = {
            'pulse_info': {'count': 1, 'pulses': []}
        }

        client = OTXClient(api_key="key")
        # SHA1 is 40 chars
        sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        result = client.lookup_hash(sha1_hash)

        assert result['hash_type'] == 'FileHash-SHA1'

    @patch.object(OTXClient, '_make_request')
    def test_lookup_hash_sha256(self, mock_request):
        """OTX-019: SHA256 hash detected correctly"""
        mock_request.return_value = {
            'pulse_info': {'count': 1, 'pulses': []}
        }

        client = OTXClient(api_key="key")
        # SHA256 is 64 chars
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = client.lookup_hash(sha256_hash)

        assert result['hash_type'] == 'FileHash-SHA256'

    @patch.object(OTXClient, '_make_request')
    def test_lookup_hash_success(self, mock_request):
        """OTX-020: Successful hash lookup returns parsed data"""
        mock_request.return_value = {
            'pulse_info': {
                'count': 15,
                'pulses': [
                    {'name': 'Ransomware Campaign'},
                    {'name': 'APT Group'}
                ]
            }
        }

        client = OTXClient(api_key="key")
        result = client.lookup_hash("abc123def456")

        assert result['indicator'] == 'abc123def456'
        assert result['type'] == 'hash'
        assert result['pulse_count'] == 15
        assert len(result['pulses']) == 2

    @patch.object(OTXClient, '_make_request')
    def test_lookup_hash_error(self, mock_request):
        """OTX-021: Returns error on API failure"""
        mock_request.return_value = {'error': 'Hash not found'}
        client = OTXClient(api_key="key")
        result = client.lookup_hash("badhash")
        assert 'error' in result

    @patch.object(OTXClient, '_make_request')
    def test_lookup_hash_limits_pulses(self, mock_request):
        """OTX-022: Limits pulses to 5 entries"""
        mock_request.return_value = {
            'pulse_info': {
                'count': 100,
                'pulses': [{'name': f'Pulse {i}'} for i in range(20)]
            }
        }

        client = OTXClient(api_key="key")
        result = client.lookup_hash("somehash")

        assert len(result['pulses']) <= 5
