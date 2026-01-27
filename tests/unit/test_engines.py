"""
Tests for ids_suite/engines/ - IDS engine implementations

Target: 75%+ coverage for suricata.py and snort.py
"""

import pytest
import json
from unittest.mock import patch
from datetime import datetime

from ids_suite.engines.base import IDSEngine
from ids_suite.engines.suricata import SuricataEngine
from ids_suite.engines.snort import SnortEngine


# ============================================================================
# Base Engine Tests
# ============================================================================

class TestIDSEngineBase:
    """Test IDSEngine abstract base class"""

    def test_cannot_instantiate_abstract(self):
        """ENG-001: Cannot instantiate abstract IDSEngine"""
        with pytest.raises(TypeError):
            IDSEngine()


# ============================================================================
# Suricata Engine Tests
# ============================================================================

class TestSuricataEngine:
    """Test SuricataEngine implementation"""

    def test_get_name(self):
        """SUR-001: get_name returns 'Suricata'"""
        engine = SuricataEngine()
        assert engine.get_name() == "Suricata"

    def test_get_service_name(self):
        """SUR-002: get_service_name returns correct service"""
        engine = SuricataEngine()
        assert engine.get_service_name() == "suricata-laptop"

    def test_get_log_path(self):
        """SUR-003: get_log_path returns eve.json path"""
        engine = SuricataEngine()
        assert engine.get_log_path() == "/var/log/suricata/eve.json"

    def test_get_config_path(self):
        """SUR-004: get_config_path returns yaml config path"""
        engine = SuricataEngine()
        assert engine.get_config_path() == "/etc/suricata/suricata.yaml"

    @patch('os.path.exists')
    def test_is_installed_usr_bin(self, mock_exists):
        """SUR-005: is_installed returns True when in /usr/bin"""
        mock_exists.side_effect = lambda p: p == "/usr/bin/suricata"
        engine = SuricataEngine()
        assert engine.is_installed() is True

    @patch('os.path.exists')
    def test_is_installed_usr_local_bin(self, mock_exists):
        """SUR-006: is_installed returns True when in /usr/local/bin"""
        mock_exists.side_effect = lambda p: p == "/usr/local/bin/suricata"
        engine = SuricataEngine()
        assert engine.is_installed() is True

    @patch('os.path.exists')
    def test_is_installed_false(self, mock_exists):
        """SUR-007: is_installed returns False when not found"""
        mock_exists.return_value = False
        engine = SuricataEngine()
        assert engine.is_installed() is False


class TestSuricataParseAlert:
    """Test SuricataEngine.parse_alert method"""

    def test_parse_alert_valid(self):
        """SUR-008: parse_alert parses valid alert JSON"""
        engine = SuricataEngine()
        eve_line = json.dumps({
            'event_type': 'alert',
            'timestamp': '2024-01-15T10:30:45.123456+0000',
            'src_ip': '192.168.1.100',
            'src_port': 54321,
            'dest_ip': '8.8.8.8',
            'dest_port': 443,
            'proto': 'TCP',
            'alert': {
                'severity': 1,
                'signature': 'ET MALWARE Test',
                'category': 'A Network Trojan was Detected',
                'signature_id': 2024001
            }
        })
        result = engine.parse_alert(eve_line)

        assert result is not None
        assert result['engine'] == 'suricata'
        assert result['timestamp'] == '2024-01-15T10:30:45'  # Truncated
        assert result['severity'] == 1
        assert result['signature'] == 'ET MALWARE Test'
        assert result['src_ip'] == '192.168.1.100'
        assert result['src_port'] == 54321
        assert result['dest_ip'] == '8.8.8.8'
        assert result['dest_port'] == 443
        assert result['proto'] == 'TCP'
        assert result['category'] == 'A Network Trojan was Detected'
        assert result['sid'] == 2024001

    def test_parse_alert_non_alert_event(self):
        """SUR-009: parse_alert returns None for non-alert events"""
        engine = SuricataEngine()
        eve_line = json.dumps({
            'event_type': 'flow',
            'timestamp': '2024-01-15T10:30:45',
            'src_ip': '192.168.1.1'
        })
        result = engine.parse_alert(eve_line)
        assert result is None

    def test_parse_alert_invalid_json(self):
        """SUR-010: parse_alert returns None for invalid JSON"""
        engine = SuricataEngine()
        result = engine.parse_alert("not valid json{{{")
        assert result is None

    def test_parse_alert_missing_fields(self):
        """SUR-011: parse_alert handles missing fields with defaults"""
        engine = SuricataEngine()
        eve_line = json.dumps({
            'event_type': 'alert',
            'alert': {}
        })
        result = engine.parse_alert(eve_line)

        assert result is not None
        assert result['severity'] == 3  # Default
        assert result['signature'] == 'Unknown'  # Default
        assert result['category'] == 'Unknown'  # Default
        assert result['src_ip'] == ''
        assert result['dest_ip'] == ''

    def test_parse_alert_stores_raw(self):
        """SUR-012: parse_alert stores raw event data"""
        engine = SuricataEngine()
        original = {
            'event_type': 'alert',
            'custom_field': 'custom_value',
            'alert': {'severity': 2}
        }
        eve_line = json.dumps(original)
        result = engine.parse_alert(eve_line)

        assert result['raw'] == original
        assert result['raw']['custom_field'] == 'custom_value'

    def test_parse_alert_empty_string(self):
        """SUR-013: parse_alert returns None for empty string"""
        engine = SuricataEngine()
        result = engine.parse_alert("")
        assert result is None

    def test_parse_alert_stats_event(self):
        """SUR-014: parse_alert returns None for stats events"""
        engine = SuricataEngine()
        eve_line = json.dumps({
            'event_type': 'stats',
            'stats': {'uptime': 3600}
        })
        result = engine.parse_alert(eve_line)
        assert result is None


# ============================================================================
# Snort Engine Tests
# ============================================================================

class TestSnortEngine:
    """Test SnortEngine implementation"""

    def test_get_name(self):
        """SNO-001: get_name returns 'Snort'"""
        engine = SnortEngine()
        assert engine.get_name() == "Snort"

    def test_get_service_name(self):
        """SNO-002: get_service_name returns correct service"""
        engine = SnortEngine()
        assert engine.get_service_name() == "snort"

    def test_get_log_path(self):
        """SNO-003: get_log_path returns alert_json.txt path"""
        engine = SnortEngine()
        assert engine.get_log_path() == "/var/log/snort/alert_json.txt"

    def test_get_config_path(self):
        """SNO-004: get_config_path returns lua config path"""
        engine = SnortEngine()
        assert engine.get_config_path() == "/etc/snort/snort.lua"

    @patch('os.path.exists')
    def test_is_installed_usr_bin(self, mock_exists):
        """SNO-005: is_installed returns True when in /usr/bin"""
        mock_exists.side_effect = lambda p: p == "/usr/bin/snort"
        engine = SnortEngine()
        assert engine.is_installed() is True

    @patch('os.path.exists')
    def test_is_installed_usr_local_bin(self, mock_exists):
        """SNO-006: is_installed returns True when in /usr/local/bin"""
        mock_exists.side_effect = lambda p: p == "/usr/local/bin/snort"
        engine = SnortEngine()
        assert engine.is_installed() is True

    @patch('os.path.exists')
    def test_is_installed_false(self, mock_exists):
        """SNO-007: is_installed returns False when not found"""
        mock_exists.return_value = False
        engine = SnortEngine()
        assert engine.is_installed() is False


class TestSnortParseAlert:
    """Test SnortEngine.parse_alert method"""

    def test_parse_alert_valid(self):
        """SNO-008: parse_alert parses valid Snort 3 JSON"""
        engine = SnortEngine()
        # Snort 3 format
        snort_line = json.dumps({
            'timestamp': '01/15-10:30:45.123456',
            'src_ap': '192.168.1.100:54321',
            'dst_ap': '8.8.8.8:443',
            'proto': 'TCP',
            'priority': 1,
            'msg': 'MALWARE Test Alert',
            'class': 'trojan-activity',
            'sid': 1000001
        })
        result = engine.parse_alert(snort_line)

        assert result is not None
        assert result['engine'] == 'snort'
        assert result['severity'] == 1
        assert result['signature'] == 'MALWARE Test Alert'
        assert result['src_ip'] == '192.168.1.100'
        assert result['src_port'] == '54321'
        assert result['dest_ip'] == '8.8.8.8'
        assert result['dest_port'] == '443'
        assert result['proto'] == 'TCP'
        assert result['category'] == 'trojan-activity'
        assert result['sid'] == 1000001

    def test_parse_alert_invalid_json(self):
        """SNO-009: parse_alert returns None for invalid JSON"""
        engine = SnortEngine()
        result = engine.parse_alert("not valid json")
        assert result is None

    def test_parse_alert_missing_fields(self):
        """SNO-010: parse_alert handles missing fields with defaults"""
        engine = SnortEngine()
        snort_line = json.dumps({})
        result = engine.parse_alert(snort_line)

        assert result is not None
        assert result['severity'] == 3  # Default priority
        assert result['signature'] == 'Unknown'
        assert result['category'] == 'Unknown'

    def test_parse_alert_stores_raw(self):
        """SNO-011: parse_alert stores raw event data"""
        engine = SnortEngine()
        original = {
            'msg': 'Test',
            'custom': 'field'
        }
        snort_line = json.dumps(original)
        result = engine.parse_alert(snort_line)

        assert result['raw'] == original

    def test_parse_alert_empty_string(self):
        """SNO-012: parse_alert returns None for empty string"""
        engine = SnortEngine()
        result = engine.parse_alert("")
        assert result is None


class TestSnortParseAddressPort:
    """Test SnortEngine._parse_address_port static method"""

    def test_parse_address_port_ipv4(self):
        """SNO-013: Parses IPv4 address:port correctly"""
        ip, port = SnortEngine._parse_address_port("192.168.1.1:8080")
        assert ip == "192.168.1.1"
        assert port == "8080"

    def test_parse_address_port_empty(self):
        """SNO-014: Returns empty strings for empty input"""
        ip, port = SnortEngine._parse_address_port("")
        assert ip == ""
        assert port == ""

    def test_parse_address_port_no_port(self):
        """SNO-015: Handles address without port"""
        ip, port = SnortEngine._parse_address_port("192.168.1.1")
        assert ip == "192.168.1.1"
        assert port == ""

    def test_parse_address_port_ipv6(self):
        """SNO-016: Handles IPv6 address with port"""
        # IPv6 addresses have multiple colons, use rsplit to get port
        ip, port = SnortEngine._parse_address_port("::1:8080")
        assert port == "8080"

    def test_parse_address_port_ipv6_full(self):
        """SNO-017: Handles full IPv6 address with port"""
        ap = "2001:db8::1:443"
        ip, port = SnortEngine._parse_address_port(ap)
        assert port == "443"


class TestSnortTimestampNormalization:
    """Test Snort timestamp normalization"""

    def test_parse_alert_normalizes_timestamp(self):
        """SNO-018: Normalizes Snort timestamp format"""
        engine = SnortEngine()
        snort_line = json.dumps({
            'timestamp': '01/15-10:30:45.123456',
            'msg': 'Test'
        })
        result = engine.parse_alert(snort_line)

        # Should be normalized to ISO-like format with current year
        assert result['timestamp'].endswith('T10:30:45')
        assert '-01-15' in result['timestamp']

    def test_parse_alert_handles_bad_timestamp(self):
        """SNO-019: Handles malformed timestamp gracefully"""
        engine = SnortEngine()
        snort_line = json.dumps({
            'timestamp': 'invalid-timestamp',
            'msg': 'Test'
        })
        result = engine.parse_alert(snort_line)
        # Should still return result, timestamp may be original
        assert result is not None

    def test_parse_alert_empty_timestamp(self):
        """SNO-020: Handles empty timestamp"""
        engine = SnortEngine()
        snort_line = json.dumps({
            'timestamp': '',
            'msg': 'Test'
        })
        result = engine.parse_alert(snort_line)
        assert result is not None
        assert result['timestamp'] == ''

    def test_parse_alert_no_timestamp(self):
        """SNO-021: Handles missing timestamp"""
        engine = SnortEngine()
        snort_line = json.dumps({
            'msg': 'Test'
        })
        result = engine.parse_alert(snort_line)
        assert result is not None
        assert result['timestamp'] == ''


# ============================================================================
# Engine Interface Compliance Tests
# ============================================================================

class TestEngineInterfaceCompliance:
    """Test that both engines implement the interface correctly"""

    @pytest.mark.parametrize("engine_class", [SuricataEngine, SnortEngine])
    def test_engine_has_all_methods(self, engine_class):
        """ENG-002: Engine implements all abstract methods"""
        engine = engine_class()
        assert callable(engine.get_name)
        assert callable(engine.get_service_name)
        assert callable(engine.get_log_path)
        assert callable(engine.get_config_path)
        assert callable(engine.is_installed)
        assert callable(engine.parse_alert)

    @pytest.mark.parametrize("engine_class", [SuricataEngine, SnortEngine])
    def test_engine_returns_strings(self, engine_class):
        """ENG-003: Engine string methods return strings"""
        engine = engine_class()
        assert isinstance(engine.get_name(), str)
        assert isinstance(engine.get_service_name(), str)
        assert isinstance(engine.get_log_path(), str)
        assert isinstance(engine.get_config_path(), str)

    @pytest.mark.parametrize("engine_class", [SuricataEngine, SnortEngine])
    def test_engine_parse_alert_invalid_returns_none(self, engine_class):
        """ENG-004: parse_alert returns None for invalid input"""
        engine = engine_class()
        assert engine.parse_alert("invalid") is None
        assert engine.parse_alert("") is None
        assert engine.parse_alert("{not:json}") is None
