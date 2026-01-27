"""
Tests for ids_suite/threat_intel/base.py - Base threat intel client

Target: 75%+ coverage
"""

import pytest
from unittest.mock import patch, MagicMock

from ids_suite.threat_intel.base import ThreatIntelClient


class ConcreteThreatIntelClient(ThreatIntelClient):
    """Concrete implementation for testing abstract base class"""

    @property
    def base_url(self) -> str:
        return "https://api.example.com/v1"


class NoKeyClient(ThreatIntelClient):
    """Client that doesn't require API key"""

    @property
    def base_url(self) -> str:
        return "https://api.public.com"

    @property
    def requires_api_key(self) -> bool:
        return False


class TestThreatIntelClientInit:
    """Test ThreatIntelClient initialization"""

    def test_init_with_api_key(self):
        """TI-001: Client initializes with API key"""
        client = ConcreteThreatIntelClient(api_key="test-key")
        assert client.api_key == "test-key"
        assert client.cache is not None

    def test_init_without_api_key(self):
        """TI-002: Client initializes without API key"""
        client = ConcreteThreatIntelClient()
        assert client.api_key is None

    def test_init_custom_cache_ttl(self):
        """TI-003: Client accepts custom cache TTL"""
        from datetime import timedelta
        client = ConcreteThreatIntelClient(api_key="key", cache_ttl_hours=48)
        assert client.cache.ttl == timedelta(hours=48)


class TestThreatIntelClientProperties:
    """Test client properties"""

    def test_base_url_abstract(self):
        """TI-004: base_url returns concrete value"""
        client = ConcreteThreatIntelClient(api_key="key")
        assert client.base_url == "https://api.example.com/v1"

    def test_requires_api_key_default(self):
        """TI-005: requires_api_key defaults to True"""
        client = ConcreteThreatIntelClient(api_key="key")
        assert client.requires_api_key is True

    def test_requires_api_key_override(self):
        """TI-006: requires_api_key can be overridden"""
        client = NoKeyClient()
        assert client.requires_api_key is False


class TestThreatIntelClientCheckPrerequisites:
    """Test _check_prerequisites method"""

    @patch('ids_suite.threat_intel.base.REQUESTS_AVAILABLE', False)
    def test_check_prerequisites_no_requests(self):
        """TI-007: Returns error when requests not available"""
        client = ConcreteThreatIntelClient(api_key="key")
        result = client._check_prerequisites()
        assert result is not None
        assert 'error' in result
        assert 'requests' in result['error'].lower()

    @patch('ids_suite.threat_intel.base.REQUESTS_AVAILABLE', True)
    def test_check_prerequisites_no_api_key(self):
        """TI-008: Returns error when API key not set but required"""
        client = ConcreteThreatIntelClient(api_key=None)
        result = client._check_prerequisites()
        assert result is not None
        assert 'error' in result
        assert 'api key' in result['error'].lower()

    @patch('ids_suite.threat_intel.base.REQUESTS_AVAILABLE', True)
    def test_check_prerequisites_success(self):
        """TI-009: Returns None when prerequisites met"""
        client = ConcreteThreatIntelClient(api_key="key")
        result = client._check_prerequisites()
        assert result is None

    @patch('ids_suite.threat_intel.base.REQUESTS_AVAILABLE', True)
    def test_check_prerequisites_no_key_not_required(self):
        """TI-010: Returns None when key not required"""
        client = NoKeyClient()
        result = client._check_prerequisites()
        assert result is None


class TestThreatIntelClientGetHeaders:
    """Test _get_headers method"""

    def test_get_headers_default(self):
        """TI-011: Default headers are empty"""
        client = ConcreteThreatIntelClient(api_key="key")
        headers = client._get_headers()
        assert headers == {}


class TestThreatIntelClientMakeRequest:
    """Test _make_request method"""

    @patch('ids_suite.threat_intel.base.REQUESTS_AVAILABLE', False)
    def test_make_request_no_requests(self):
        """TI-012: Returns error when requests not available"""
        client = ConcreteThreatIntelClient(api_key="key")
        result = client._make_request("endpoint")
        assert 'error' in result

    @patch('ids_suite.threat_intel.base.REQUESTS_AVAILABLE', True)
    def test_make_request_no_api_key(self):
        """TI-013: Returns error when API key missing"""
        client = ConcreteThreatIntelClient(api_key=None)
        result = client._make_request("endpoint")
        assert 'error' in result

    @patch('ids_suite.threat_intel.base.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.base.get_requests')
    def test_make_request_get_success(self, mock_get_requests):
        """TI-014: GET request returns JSON on success"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': 'value'}
        mock_requests.get.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = ConcreteThreatIntelClient(api_key="key")
        result = client._make_request("endpoint")
        assert result == {'data': 'value'}
        mock_requests.get.assert_called_once()

    @patch('ids_suite.threat_intel.base.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.base.get_requests')
    def test_make_request_post_success(self, mock_get_requests):
        """TI-015: POST request returns JSON on success"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'result': 'ok'}
        mock_requests.post.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = ConcreteThreatIntelClient(api_key="key")
        result = client._make_request("endpoint", method='POST', json_data={'query': 'test'})
        assert result == {'result': 'ok'}
        mock_requests.post.assert_called_once()

    @patch('ids_suite.threat_intel.base.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.base.get_requests')
    def test_make_request_401_error(self, mock_get_requests):
        """TI-016: Returns invalid API key error on 401"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_requests.get.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = ConcreteThreatIntelClient(api_key="bad-key")
        result = client._make_request("endpoint")
        assert 'error' in result
        assert 'Invalid API key' in result['error']

    @patch('ids_suite.threat_intel.base.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.base.get_requests')
    def test_make_request_429_error(self, mock_get_requests):
        """TI-017: Returns rate limit error on 429"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_requests.get.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = ConcreteThreatIntelClient(api_key="key")
        result = client._make_request("endpoint")
        assert 'error' in result
        assert 'Rate limit' in result['error']

    @patch('ids_suite.threat_intel.base.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.base.get_requests')
    def test_make_request_other_http_error(self, mock_get_requests):
        """TI-018: Returns HTTP error for other status codes"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_requests.get.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = ConcreteThreatIntelClient(api_key="key")
        result = client._make_request("endpoint")
        assert 'error' in result
        assert 'HTTP 500' in result['error']

    @patch('ids_suite.threat_intel.base.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.base.get_requests')
    def test_make_request_exception(self, mock_get_requests):
        """TI-019: Returns error on exception"""
        mock_requests = MagicMock()
        mock_requests.get.side_effect = Exception("Connection failed")
        mock_get_requests.return_value = mock_requests

        client = ConcreteThreatIntelClient(api_key="key")
        result = client._make_request("endpoint")
        assert 'error' in result
        assert 'Connection failed' in result['error']

    @patch('ids_suite.threat_intel.base.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.base.get_requests')
    def test_make_request_unsupported_method(self, mock_get_requests):
        """TI-020: Returns error for unsupported HTTP method"""
        mock_requests = MagicMock()
        mock_get_requests.return_value = mock_requests

        client = ConcreteThreatIntelClient(api_key="key")
        result = client._make_request("endpoint", method='DELETE')
        assert 'error' in result
        assert 'Unsupported method' in result['error']

    @patch('ids_suite.threat_intel.base.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.base.get_requests')
    def test_make_request_empty_endpoint(self, mock_get_requests):
        """TI-021: Empty endpoint uses base URL only"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_requests.get.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = ConcreteThreatIntelClient(api_key="key")
        client._make_request("")

        call_args = mock_requests.get.call_args
        assert call_args[0][0] == "https://api.example.com/v1"

    @patch('ids_suite.threat_intel.base.REQUESTS_AVAILABLE', True)
    @patch('ids_suite.threat_intel.base.get_requests')
    def test_make_request_with_params(self, mock_get_requests):
        """TI-022: GET request passes params correctly"""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_requests.get.return_value = mock_response
        mock_get_requests.return_value = mock_requests

        client = ConcreteThreatIntelClient(api_key="key")
        client._make_request("endpoint", params={'key': 'value'})

        call_args = mock_requests.get.call_args
        assert call_args[1]['params'] == {'key': 'value'}
