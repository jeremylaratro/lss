"""
Tests for ids_suite/models/alert.py - Alert data model

Target: 75%+ coverage
"""

import pytest
from ids_suite.models.alert import Alert


class TestAlertDataclass:
    """Test Alert dataclass basic functionality"""

    def test_alert_creation(self):
        """AL-001: Alert can be created with all fields"""
        alert = Alert(
            engine="suricata",
            timestamp="2024-01-15T10:30:45",
            severity=1,
            signature="ET MALWARE Test Signature",
            src_ip="192.168.1.100",
            src_port="45678",
            dest_ip="8.8.8.8",
            dest_port="443",
            proto="TCP",
            category="A Network Trojan was Detected",
            sid="2024001"
        )
        assert alert.engine == "suricata"
        assert alert.severity == 1
        assert alert.signature == "ET MALWARE Test Signature"

    def test_alert_default_raw(self):
        """AL-002: Alert has empty dict as default raw"""
        alert = Alert(
            engine="snort",
            timestamp="2024-01-15T10:30:45",
            severity=2,
            signature="Test",
            src_ip="1.2.3.4",
            src_port="80",
            dest_ip="5.6.7.8",
            dest_port="443",
            proto="TCP",
            category="Test",
            sid="12345"
        )
        assert alert.raw == {}

    def test_alert_with_raw(self):
        """AL-003: Alert stores raw data"""
        raw_data = {'full': 'json', 'event': 'data'}
        alert = Alert(
            engine="suricata",
            timestamp="",
            severity=3,
            signature="Test",
            src_ip="",
            src_port="",
            dest_ip="",
            dest_port="",
            proto="",
            category="",
            sid="",
            raw=raw_data
        )
        assert alert.raw == raw_data


class TestAlertFromDict:
    """Test Alert.from_dict class method"""

    def test_from_dict_none(self):
        """AL-004: from_dict returns None for None input"""
        assert Alert.from_dict(None) is None

    def test_from_dict_empty(self):
        """AL-005: from_dict returns None for empty dict"""
        assert Alert.from_dict({}) is None

    def test_from_dict_full_data(self):
        """AL-006: from_dict creates Alert with all fields"""
        data = {
            'engine': 'suricata',
            'timestamp': '2024-01-15T10:30:45',
            'severity': 1,
            'signature': 'Test Signature',
            'src_ip': '192.168.1.1',
            'src_port': 12345,
            'dest_ip': '8.8.8.8',
            'dest_port': 443,
            'proto': 'TCP',
            'category': 'Test Category',
            'sid': 2024001,
            'raw': {'key': 'value'}
        }
        alert = Alert.from_dict(data)
        assert alert is not None
        assert alert.engine == 'suricata'
        assert alert.severity == 1
        assert alert.src_port == '12345'  # Converted to string
        assert alert.dest_port == '443'
        assert alert.sid == '2024001'  # Converted to string

    def test_from_dict_missing_fields(self):
        """AL-007: from_dict uses defaults for missing fields"""
        data = {'engine': 'snort'}  # Minimal data
        alert = Alert.from_dict(data)
        assert alert is not None
        assert alert.engine == 'snort'
        assert alert.timestamp == ''
        assert alert.severity == 3  # Default
        assert alert.signature == 'Unknown'  # Default
        assert alert.category == 'Unknown'  # Default

    def test_from_dict_ports_as_int(self):
        """AL-008: from_dict converts port ints to strings"""
        data = {
            'engine': 'test',
            'src_port': 80,
            'dest_port': 443,
            'sid': 1001
        }
        alert = Alert.from_dict(data)
        assert alert.src_port == '80'
        assert alert.dest_port == '443'
        assert alert.sid == '1001'

    def test_from_dict_ports_as_string(self):
        """AL-009: from_dict handles string ports"""
        data = {
            'engine': 'test',
            'src_port': '8080',
            'dest_port': '443'
        }
        alert = Alert.from_dict(data)
        assert alert.src_port == '8080'
        assert alert.dest_port == '443'


class TestAlertToDict:
    """Test Alert.to_dict method"""

    def test_to_dict(self):
        """AL-010: to_dict returns correct dictionary"""
        alert = Alert(
            engine="suricata",
            timestamp="2024-01-15T10:30:45",
            severity=2,
            signature="Test",
            src_ip="1.1.1.1",
            src_port="1234",
            dest_ip="2.2.2.2",
            dest_port="5678",
            proto="UDP",
            category="Test Cat",
            sid="99999",
            raw={'original': 'data'}
        )
        d = alert.to_dict()
        assert d['engine'] == 'suricata'
        assert d['timestamp'] == '2024-01-15T10:30:45'
        assert d['severity'] == 2
        assert d['signature'] == 'Test'
        assert d['src_ip'] == '1.1.1.1'
        assert d['src_port'] == '1234'
        assert d['dest_ip'] == '2.2.2.2'
        assert d['dest_port'] == '5678'
        assert d['proto'] == 'UDP'
        assert d['category'] == 'Test Cat'
        assert d['sid'] == '99999'
        assert d['raw'] == {'original': 'data'}

    def test_to_dict_roundtrip(self):
        """AL-011: to_dict and from_dict are reversible"""
        original = Alert(
            engine="snort",
            timestamp="2024-01-01T00:00:00",
            severity=4,
            signature="Round Trip Test",
            src_ip="10.0.0.1",
            src_port="80",
            dest_ip="10.0.0.2",
            dest_port="443",
            proto="TCP",
            category="Testing",
            sid="1",
            raw={}
        )
        d = original.to_dict()
        restored = Alert.from_dict(d)
        assert restored.engine == original.engine
        assert restored.signature == original.signature
        assert restored.severity == original.severity


class TestAlertSeverityLabel:
    """Test Alert.severity_label property"""

    def test_severity_label_critical(self):
        """AL-012: Severity 1 is CRITICAL"""
        alert = Alert(
            engine="", timestamp="", severity=1, signature="",
            src_ip="", src_port="", dest_ip="", dest_port="",
            proto="", category="", sid=""
        )
        assert alert.severity_label == 'CRITICAL'

    def test_severity_label_high(self):
        """AL-013: Severity 2 is HIGH"""
        alert = Alert(
            engine="", timestamp="", severity=2, signature="",
            src_ip="", src_port="", dest_ip="", dest_port="",
            proto="", category="", sid=""
        )
        assert alert.severity_label == 'HIGH'

    def test_severity_label_medium(self):
        """AL-014: Severity 3 is MEDIUM"""
        alert = Alert(
            engine="", timestamp="", severity=3, signature="",
            src_ip="", src_port="", dest_ip="", dest_port="",
            proto="", category="", sid=""
        )
        assert alert.severity_label == 'MEDIUM'

    def test_severity_label_low(self):
        """AL-015: Severity 4 is LOW"""
        alert = Alert(
            engine="", timestamp="", severity=4, signature="",
            src_ip="", src_port="", dest_ip="", dest_port="",
            proto="", category="", sid=""
        )
        assert alert.severity_label == 'LOW'

    def test_severity_label_unknown(self):
        """AL-016: Unknown severity is INFO"""
        alert = Alert(
            engine="", timestamp="", severity=5, signature="",
            src_ip="", src_port="", dest_ip="", dest_port="",
            proto="", category="", sid=""
        )
        assert alert.severity_label == 'INFO'

    def test_severity_label_zero(self):
        """AL-017: Severity 0 is INFO"""
        alert = Alert(
            engine="", timestamp="", severity=0, signature="",
            src_ip="", src_port="", dest_ip="", dest_port="",
            proto="", category="", sid=""
        )
        assert alert.severity_label == 'INFO'


class TestAlertMatchesFilter:
    """Test Alert.matches_filter method"""

    def create_alert(self, **kwargs):
        """Helper to create test alerts"""
        defaults = {
            'engine': 'suricata',
            'timestamp': '2024-01-15T10:00:00',
            'severity': 2,
            'signature': 'Test Signature',
            'src_ip': '192.168.1.100',
            'src_port': '12345',
            'dest_ip': '8.8.8.8',
            'dest_port': '443',
            'proto': 'TCP',
            'category': 'Test Category',
            'sid': '1001'
        }
        defaults.update(kwargs)
        return Alert(**defaults)

    def test_matches_filter_no_filters(self):
        """AL-018: Alert matches when no filters applied"""
        alert = self.create_alert()
        assert alert.matches_filter() is True

    def test_matches_filter_engine_match(self):
        """AL-019: Alert matches when engine matches filter"""
        alert = self.create_alert(engine='suricata')
        assert alert.matches_filter(engine_filter='suricata') is True

    def test_matches_filter_engine_no_match(self):
        """AL-020: Alert doesn't match when engine differs"""
        alert = self.create_alert(engine='suricata')
        assert alert.matches_filter(engine_filter='snort') is False

    def test_matches_filter_engine_all(self):
        """AL-021: Alert matches with 'all' engine filter"""
        alert = self.create_alert(engine='snort')
        assert alert.matches_filter(engine_filter='all') is True

    def test_matches_filter_hidden_signature(self):
        """AL-022: Alert doesn't match when signature is hidden"""
        alert = self.create_alert(signature='Hidden Sig')
        assert alert.matches_filter(hidden_signatures={'Hidden Sig'}) is False

    def test_matches_filter_signature_not_hidden(self):
        """AL-023: Alert matches when signature is not in hidden set"""
        alert = self.create_alert(signature='Visible Sig')
        assert alert.matches_filter(hidden_signatures={'Other Sig'}) is True

    def test_matches_filter_hidden_src_ip(self):
        """AL-024: Alert doesn't match when src_ip is hidden"""
        alert = self.create_alert(src_ip='10.0.0.1')
        assert alert.matches_filter(hidden_src_ips={'10.0.0.1'}) is False

    def test_matches_filter_src_ip_not_hidden(self):
        """AL-025: Alert matches when src_ip is not in hidden set"""
        alert = self.create_alert(src_ip='10.0.0.1')
        assert alert.matches_filter(hidden_src_ips={'10.0.0.2'}) is True

    def test_matches_filter_hidden_dest_ip(self):
        """AL-026: Alert doesn't match when dest_ip is hidden"""
        alert = self.create_alert(dest_ip='8.8.8.8')
        assert alert.matches_filter(hidden_dest_ips={'8.8.8.8'}) is False

    def test_matches_filter_dest_ip_not_hidden(self):
        """AL-027: Alert matches when dest_ip is not in hidden set"""
        alert = self.create_alert(dest_ip='8.8.8.8')
        assert alert.matches_filter(hidden_dest_ips={'1.1.1.1'}) is True

    def test_matches_filter_hidden_category(self):
        """AL-028: Alert doesn't match when category is hidden"""
        alert = self.create_alert(category='Spam')
        assert alert.matches_filter(hidden_categories={'Spam'}) is False

    def test_matches_filter_category_not_hidden(self):
        """AL-029: Alert matches when category is not in hidden set"""
        alert = self.create_alert(category='Malware')
        assert alert.matches_filter(hidden_categories={'Spam'}) is True

    def test_matches_filter_multiple_filters(self):
        """AL-030: Alert matches when passing all filters"""
        alert = self.create_alert(
            engine='suricata',
            signature='Good Sig',
            src_ip='1.1.1.1',
            dest_ip='2.2.2.2',
            category='Good Cat'
        )
        assert alert.matches_filter(
            hidden_signatures={'Bad Sig'},
            hidden_src_ips={'3.3.3.3'},
            hidden_dest_ips={'4.4.4.4'},
            hidden_categories={'Bad Cat'},
            engine_filter='suricata'
        ) is True

    def test_matches_filter_fails_any_filter(self):
        """AL-031: Alert doesn't match if any filter fails"""
        alert = self.create_alert(
            engine='suricata',
            signature='Bad Sig'
        )
        assert alert.matches_filter(
            hidden_signatures={'Bad Sig'},
            engine_filter='suricata'
        ) is False

    def test_matches_filter_empty_sets(self):
        """AL-032: Alert matches with empty filter sets"""
        alert = self.create_alert()
        assert alert.matches_filter(
            hidden_signatures=set(),
            hidden_src_ips=set(),
            hidden_dest_ips=set(),
            hidden_categories=set()
        ) is True
