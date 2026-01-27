"""
Tests for ids_suite/threat_intel/threatfox.py - ThreatFox IOC client

Target: 75%+ coverage
"""

import pytest
from unittest.mock import patch, MagicMock

from ids_suite.threat_intel.threatfox import ThreatFoxClient


class TestThreatFoxClientInit:
    """Test ThreatFoxClient initialization"""

    def test_init(self):
        """TF-001: Client initializes without API key (not required)"""
        client = ThreatFoxClient()
        assert client.cache is not None

    def test_base_url(self):
        """TF-002: Base URL is correct"""
        assert ThreatFoxClient.BASE_URL == "https://threatfox-api.abuse.ch/api/v1/"


class TestThreatFoxLookupIOC:
    """Test lookup_ioc method"""

    @patch('ids_suite.threat_intel.threatfox.REQUESTS_AVAILABLE', False)
    def test_lookup_no_requests(self):
        """TF-003: Returns error when requests not available"""
        client = ThreatFoxClient()
        result = client.lookup_ioc("8.8.8.8")
        assert 'error' in result

    @patch('ids_suite.threat_intel.threatfox.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.threatfox.get_requests')
    def test_lookup_cached(self, mock_get_requests):
        """TF-004: Cached IOC returns cached result"""
        client = ThreatFoxClient()
        cached_data = {'indicator': '8.8.8.8', 'found': False}
        client.cache.set('threatfox:8.8.8.8', cached_data)

        result = client.lookup_ioc("8.8.8.8")
        assert result == cached_data
        mock_get_requests.assert_not_called()

    @patch('ids_suite.threat_intel.threatfox.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.threatfox.get_requests')
    def test_lookup_not_found(self, mock_get_requests):
        """TF-005: Returns not found when IOC not in database"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'query_status': 'no_result'
        }
        mock_requests.post.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = ThreatFoxClient()
        result = client.lookup_ioc("clean.example.com")

        assert result['found'] is False
        assert 'Not found' in result['message']

    @patch('ids_suite.threat_intel.threatfox.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.threatfox.get_requests')
    def test_lookup_found(self, mock_get_requests):
        """TF-006: Returns IOC data when found"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'query_status': 'ok',
            'data': [{
                'ioc_type': 'ip:port',
                'threat_type': 'botnet_cc',
                'malware': 'Emotet',
                'malware_alias': 'Heodo',
                'confidence_level': 90,
                'first_seen': '2024-01-01 00:00:00',
                'last_seen': '2024-01-15 00:00:00',
                'tags': ['emotet', 'banking'],
                'reference': 'https://example.com/report'
            }]
        }
        mock_requests.post.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = ThreatFoxClient()
        result = client.lookup_ioc("1.2.3.4:443")

        assert result['found'] is True
        assert result['ioc_type'] == 'ip:port'
        assert result['threat_type'] == 'botnet_cc'
        assert result['malware'] == 'Emotet'
        assert result['malware_alias'] == 'Heodo'
        assert result['confidence'] == 90
        assert 'emotet' in result['tags']

    @patch('ids_suite.threat_intel.threatfox.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.threatfox.get_requests')
    def test_lookup_http_error(self, mock_get_requests):
        """TF-007: Returns error on non-200 status"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_requests.post.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = ThreatFoxClient()
        result = client.lookup_ioc("test")
        assert 'error' in result
        assert 'HTTP 500' in result['error']

    @patch('ids_suite.threat_intel.threatfox.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.threatfox.get_requests')
    def test_lookup_api_error(self, mock_get_requests):
        """TF-008: Returns error on API error status"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'query_status': 'illegal_search_term'
        }
        mock_requests.post.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = ThreatFoxClient()
        result = client.lookup_ioc("!invalid!")
        assert 'error' in result

    @patch('ids_suite.threat_intel.threatfox.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.threatfox.get_requests')
    def test_lookup_exception(self, mock_get_requests):
        """TF-009: Returns error on exception"""
        mock_requests = MagicMock()
        mock_requests.post.side_effect = Exception("Network error")
        mock_get_requests.return_value = mock_requests

        client = ThreatFoxClient()
        result = client.lookup_ioc("test.com")
        assert 'error' in result
        assert 'Network error' in result['error']

    @patch('ids_suite.threat_intel.threatfox.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.threatfox.get_requests')
    def test_lookup_caches_found_result(self, mock_get_requests):
        """TF-010: Caches successful lookup results"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'query_status': 'ok',
            'data': [{'ioc_type': 'domain', 'threat_type': 'payload', 'malware': 'Test'}]
        }
        mock_requests.post.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = ThreatFoxClient()
        client.lookup_ioc("evil.com")

        cached = client.cache.get('threatfox:evil.com')
        assert cached is not None
        assert cached['found'] is True

    @patch('ids_suite.threat_intel.threatfox.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.threatfox.get_requests')
    def test_lookup_caches_not_found(self, mock_get_requests):
        """TF-011: Caches not-found results"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'query_status': 'no_result'}
        mock_requests.post.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = ThreatFoxClient()
        client.lookup_ioc("clean.com")

        cached = client.cache.get('threatfox:clean.com')
        assert cached is not None
        assert cached['found'] is False

    @patch('ids_suite.threat_intel.threatfox.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.threatfox.get_requests')
    def test_lookup_does_not_cache_errors(self, mock_get_requests):
        """TF-012: Does not cache error results"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'query_status': 'illegal_search_term'}
        mock_requests.post.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = ThreatFoxClient()
        client.lookup_ioc("!bad!")

        cached = client.cache.get('threatfox:!bad!')
        assert cached is None


class TestThreatFoxConvenienceMethods:
    """Test convenience lookup methods"""

    @patch.object(ThreatFoxClient, 'lookup_ioc')
    def test_lookup_ip(self, mock_lookup):
        """TF-013: lookup_ip calls lookup_ioc"""
        mock_lookup.return_value = {'indicator': '1.2.3.4', 'found': False}
        client = ThreatFoxClient()
        result = client.lookup_ip("1.2.3.4")
        mock_lookup.assert_called_once_with("1.2.3.4")
        assert result['indicator'] == '1.2.3.4'

    @patch.object(ThreatFoxClient, 'lookup_ioc')
    def test_lookup_domain(self, mock_lookup):
        """TF-014: lookup_domain calls lookup_ioc"""
        mock_lookup.return_value = {'indicator': 'example.com', 'found': True}
        client = ThreatFoxClient()
        result = client.lookup_domain("example.com")
        mock_lookup.assert_called_once_with("example.com")
        assert result['indicator'] == 'example.com'

    @patch.object(ThreatFoxClient, 'lookup_ioc')
    def test_lookup_hash(self, mock_lookup):
        """TF-015: lookup_hash calls lookup_ioc"""
        mock_lookup.return_value = {'indicator': 'abc123', 'found': True}
        client = ThreatFoxClient()
        result = client.lookup_hash("abc123")
        mock_lookup.assert_called_once_with("abc123")
        assert result['indicator'] == 'abc123'

    @patch('ids_suite.threat_intel.threatfox.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.threatfox.get_requests')
    def test_lookup_missing_fields(self, mock_get_requests):
        """TF-016: Handles missing optional fields"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'query_status': 'ok',
            'data': [{}]  # Empty data object
        }
        mock_requests.post.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = ThreatFoxClient()
        result = client.lookup_ioc("sparse.ioc")

        assert result['found'] is True
        assert result['ioc_type'] == 'Unknown'
        assert result['threat_type'] == 'Unknown'
        assert result['malware'] == 'Unknown'
        assert result['malware_alias'] == ''
        assert result['confidence'] == 0
        assert result['tags'] == []
