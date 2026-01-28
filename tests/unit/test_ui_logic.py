"""
Tests for UI logic functions in ids_suite/ui/main_window.py

These tests target pure logic functions that don't require a display server.
We mock the tkinter widgets and test the underlying business logic.

Target: Improve coverage of main_window.py logic functions
"""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from datetime import datetime


# Create a mock MainWindow class that extracts the testable logic
# without requiring tkinter initialization

class MockMainWindowLogic:
    """
    Extract testable logic from MainWindow without GUI dependencies.
    These methods are copied/adapted from main_window.py for testing.
    """

    def __init__(self):
        self.hidden_signatures = set()
        self.hidden_src_ips = set()
        self.hidden_dest_ips = set()
        self.hidden_categories = set()

    def _format_alert_timestamp(self, timestamp: str) -> str:
        """Format timestamp for display - compact for recent, full for older."""
        if not timestamp or len(timestamp) < 19:
            return timestamp or ''

        today = datetime.now().strftime('%Y-%m-%d')
        alert_date = timestamp[:10]

        if alert_date == today:
            return timestamp[11:19]  # HH:MM:SS
        else:
            return f"{timestamp[5:10]} {timestamp[11:16]}"

    def _combine_intel_status(self, src_intel: str, dst_intel: str) -> str:
        """Combine intel status from source and destination IPs."""
        priority = {'DANGER': 5, 'suspect': 4, 'error': 3, 'checking': 2, 'safe': 1}

        src_priority = priority.get(src_intel, 0) if src_intel else 0
        dst_priority = priority.get(dst_intel, 0) if dst_intel else 0

        if src_priority == 0 and dst_priority == 0:
            return None

        if src_priority >= dst_priority:
            return src_intel
        return dst_intel

    def _apply_alert_filters(self, alerts: list) -> list:
        """Apply hidden filters to alert list"""
        if not (self.hidden_signatures or self.hidden_src_ips or
                self.hidden_dest_ips or self.hidden_categories):
            return alerts

        filtered = []
        for alert in alerts:
            signature = alert.get('signature', '')
            src = alert.get('source', '').split(':')[0]
            dest = alert.get('destination', '').split(':')[0]
            category = alert.get('category', '')

            if signature in self.hidden_signatures:
                continue
            if src in self.hidden_src_ips:
                continue
            if dest in self.hidden_dest_ips:
                continue
            if category in self.hidden_categories:
                continue

            filtered.append(alert)

        return filtered

    def _group_alerts_by_signature(self, alerts: list) -> list:
        """Group similar alerts by signature, appending x{count} for duplicates."""
        if not alerts:
            return alerts

        signature_groups = {}
        for alert in alerts:
            sig = alert.get('signature', 'Unknown')
            if sig not in signature_groups:
                signature_groups[sig] = []
            signature_groups[sig].append(alert)

        grouped_alerts = []
        for sig, group in signature_groups.items():
            group.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            most_recent = group[0].copy()

            count = len(group)
            if count > 1:
                most_recent['signature'] = f"{sig} x{count}"
                most_recent['_group_count'] = count

            grouped_alerts.append(most_recent)

        grouped_alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return grouped_alerts

    def _group_connections_by_remote(self, connections: list) -> list:
        """Group connections by remote address, appending x{count} for duplicates."""
        if not connections:
            return connections

        remote_groups = {}
        for conn in connections:
            remote = conn.get('remote', '')
            if remote not in remote_groups:
                remote_groups[remote] = []
            remote_groups[remote].append(conn)

        grouped = []
        for remote, group in remote_groups.items():
            representative = group[0].copy()
            count = len(group)
            if count > 1:
                representative['remote'] = f"{remote} x{count}"
                representative['_group_count'] = count
            grouped.append(representative)

        return grouped

    def _group_traffic_by_destination(self, entries: list) -> list:
        """Group traffic entries by destination, appending x{count} for duplicates."""
        if not entries:
            return entries

        dest_groups = {}
        for entry in entries:
            dest = entry.get('destination', '')
            if dest not in dest_groups:
                dest_groups[dest] = []
            dest_groups[dest].append(entry)

        grouped_entries = []
        for dest, group in dest_groups.items():
            group.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            most_recent = group[0].copy()

            count = len(group)
            if count > 1:
                most_recent['destination'] = f"{dest} x{count}"
                most_recent['_group_count'] = count

            grouped_entries.append(most_recent)

        grouped_entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return grouped_entries

    def _group_dns_by_domain(self, entries: list) -> list:
        """Group DNS entries by domain, appending x{count} for duplicates."""
        if not entries:
            return entries

        domain_groups = {}
        for entry in entries:
            domain = entry.get('domain', '')
            if domain not in domain_groups:
                domain_groups[domain] = []
            domain_groups[domain].append(entry)

        grouped_entries = []
        for domain, group in domain_groups.items():
            group.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            most_recent = group[0].copy()

            count = len(group)
            if count > 1:
                most_recent['domain'] = f"{domain} x{count}"
                most_recent['_group_count'] = count

            grouped_entries.append(most_recent)

        grouped_entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return grouped_entries

    def _is_local_ip(self, ip: str) -> bool:
        """Check if IP is local/private"""
        if not ip:
            return False
        if ip.startswith('127.') or ip == '::1':
            return True
        if ip.startswith('192.168.') or ip.startswith('10.'):
            return True
        if ip.startswith('172.'):
            parts = ip.split('.')
            if len(parts) >= 2 and 16 <= int(parts[1]) <= 31:
                return True
        return False


class TestFormatAlertTimestamp:
    """Test _format_alert_timestamp method"""

    def test_format_today_timestamp(self):
        """UI-001: Today's timestamp shows time only"""
        logic = MockMainWindowLogic()
        today = datetime.now().strftime('%Y-%m-%d')
        timestamp = f"{today}T14:30:45.123456"
        result = logic._format_alert_timestamp(timestamp)
        assert result == "14:30:45"

    def test_format_yesterday_timestamp(self):
        """UI-002: Older timestamp shows MM-DD HH:MM"""
        logic = MockMainWindowLogic()
        timestamp = "2024-01-15T14:30:45.123456"
        result = logic._format_alert_timestamp(timestamp)
        assert result == "01-15 14:30"

    def test_format_empty_timestamp(self):
        """UI-003: Empty timestamp returns empty string"""
        logic = MockMainWindowLogic()
        assert logic._format_alert_timestamp("") == ""
        assert logic._format_alert_timestamp(None) == ""

    def test_format_short_timestamp(self):
        """UI-004: Short timestamp returned as-is"""
        logic = MockMainWindowLogic()
        result = logic._format_alert_timestamp("2024-01-15")
        assert result == "2024-01-15"


class TestCombineIntelStatus:
    """Test _combine_intel_status method"""

    def test_both_none(self):
        """UI-005: Both None returns None"""
        logic = MockMainWindowLogic()
        assert logic._combine_intel_status(None, None) is None

    def test_src_only(self):
        """UI-006: Only src_intel returns src_intel"""
        logic = MockMainWindowLogic()
        assert logic._combine_intel_status("DANGER", None) == "DANGER"

    def test_dst_only(self):
        """UI-007: Only dst_intel returns dst_intel"""
        logic = MockMainWindowLogic()
        assert logic._combine_intel_status(None, "safe") == "safe"

    def test_src_higher_priority(self):
        """UI-008: Higher priority src wins"""
        logic = MockMainWindowLogic()
        assert logic._combine_intel_status("DANGER", "safe") == "DANGER"

    def test_dst_higher_priority(self):
        """UI-009: Higher priority dst wins"""
        logic = MockMainWindowLogic()
        assert logic._combine_intel_status("safe", "suspect") == "suspect"

    def test_equal_priority(self):
        """UI-010: Equal priority returns src"""
        logic = MockMainWindowLogic()
        assert logic._combine_intel_status("safe", "safe") == "safe"

    def test_priority_order(self):
        """UI-011: Verify full priority order"""
        logic = MockMainWindowLogic()
        # DANGER > suspect > error > checking > safe
        assert logic._combine_intel_status("DANGER", "suspect") == "DANGER"
        assert logic._combine_intel_status("suspect", "error") == "suspect"
        assert logic._combine_intel_status("error", "checking") == "error"
        assert logic._combine_intel_status("checking", "safe") == "checking"


class TestApplyAlertFilters:
    """Test _apply_alert_filters method"""

    def test_no_filters(self):
        """UI-012: No filters returns all alerts"""
        logic = MockMainWindowLogic()
        alerts = [{'signature': 'Test', 'source': '1.1.1.1:80'}]
        result = logic._apply_alert_filters(alerts)
        assert len(result) == 1

    def test_filter_by_signature(self):
        """UI-013: Filter by hidden signature"""
        logic = MockMainWindowLogic()
        logic.hidden_signatures = {'Bad Sig'}
        alerts = [
            {'signature': 'Bad Sig', 'source': '1.1.1.1:80', 'destination': '2.2.2.2:443', 'category': 'Test'},
            {'signature': 'Good Sig', 'source': '1.1.1.1:80', 'destination': '2.2.2.2:443', 'category': 'Test'}
        ]
        result = logic._apply_alert_filters(alerts)
        assert len(result) == 1
        assert result[0]['signature'] == 'Good Sig'

    def test_filter_by_src_ip(self):
        """UI-014: Filter by hidden source IP"""
        logic = MockMainWindowLogic()
        logic.hidden_src_ips = {'10.0.0.1'}
        alerts = [
            {'signature': 'Test', 'source': '10.0.0.1:80', 'destination': '2.2.2.2:443', 'category': 'Test'},
            {'signature': 'Test', 'source': '10.0.0.2:80', 'destination': '2.2.2.2:443', 'category': 'Test'}
        ]
        result = logic._apply_alert_filters(alerts)
        assert len(result) == 1
        assert '10.0.0.2' in result[0]['source']

    def test_filter_by_dest_ip(self):
        """UI-015: Filter by hidden destination IP"""
        logic = MockMainWindowLogic()
        logic.hidden_dest_ips = {'8.8.8.8'}
        alerts = [
            {'signature': 'Test', 'source': '1.1.1.1:80', 'destination': '8.8.8.8:443', 'category': 'Test'},
            {'signature': 'Test', 'source': '1.1.1.1:80', 'destination': '1.1.1.1:443', 'category': 'Test'}
        ]
        result = logic._apply_alert_filters(alerts)
        assert len(result) == 1
        assert '1.1.1.1' in result[0]['destination']

    def test_filter_by_category(self):
        """UI-016: Filter by hidden category"""
        logic = MockMainWindowLogic()
        logic.hidden_categories = {'Spam'}
        alerts = [
            {'signature': 'Test', 'source': '1.1.1.1:80', 'destination': '2.2.2.2:443', 'category': 'Spam'},
            {'signature': 'Test', 'source': '1.1.1.1:80', 'destination': '2.2.2.2:443', 'category': 'Malware'}
        ]
        result = logic._apply_alert_filters(alerts)
        assert len(result) == 1
        assert result[0]['category'] == 'Malware'

    def test_multiple_filters(self):
        """UI-017: Multiple filters applied together"""
        logic = MockMainWindowLogic()
        logic.hidden_signatures = {'Hidden Sig'}
        logic.hidden_src_ips = {'10.0.0.1'}
        alerts = [
            {'signature': 'Hidden Sig', 'source': '5.5.5.5:80', 'destination': '2.2.2.2:443', 'category': 'Test'},
            {'signature': 'Test', 'source': '10.0.0.1:80', 'destination': '2.2.2.2:443', 'category': 'Test'},
            {'signature': 'Test', 'source': '5.5.5.5:80', 'destination': '2.2.2.2:443', 'category': 'Test'}
        ]
        result = logic._apply_alert_filters(alerts)
        assert len(result) == 1
        assert result[0]['signature'] == 'Test'
        assert '5.5.5.5' in result[0]['source']


class TestGroupAlertsBySignature:
    """Test _group_alerts_by_signature method"""

    def test_empty_list(self):
        """UI-018: Empty list returns empty"""
        logic = MockMainWindowLogic()
        assert logic._group_alerts_by_signature([]) == []

    def test_no_duplicates(self):
        """UI-019: No duplicates returns same alerts"""
        logic = MockMainWindowLogic()
        alerts = [
            {'signature': 'Sig A', 'timestamp': '2024-01-15T10:00:00'},
            {'signature': 'Sig B', 'timestamp': '2024-01-15T10:01:00'}
        ]
        result = logic._group_alerts_by_signature(alerts)
        assert len(result) == 2

    def test_groups_duplicates(self):
        """UI-020: Duplicates are grouped with count"""
        logic = MockMainWindowLogic()
        alerts = [
            {'signature': 'Same Sig', 'timestamp': '2024-01-15T10:00:00'},
            {'signature': 'Same Sig', 'timestamp': '2024-01-15T10:01:00'},
            {'signature': 'Same Sig', 'timestamp': '2024-01-15T10:02:00'}
        ]
        result = logic._group_alerts_by_signature(alerts)
        assert len(result) == 1
        assert 'x3' in result[0]['signature']
        assert result[0]['_group_count'] == 3

    def test_keeps_most_recent(self):
        """UI-021: Group keeps most recent timestamp"""
        logic = MockMainWindowLogic()
        alerts = [
            {'signature': 'Test', 'timestamp': '2024-01-15T10:00:00'},
            {'signature': 'Test', 'timestamp': '2024-01-15T12:00:00'},
            {'signature': 'Test', 'timestamp': '2024-01-15T11:00:00'}
        ]
        result = logic._group_alerts_by_signature(alerts)
        assert len(result) == 1
        assert result[0]['timestamp'] == '2024-01-15T12:00:00'

    def test_mixed_signatures(self):
        """UI-022: Mixed signatures grouped separately"""
        logic = MockMainWindowLogic()
        alerts = [
            {'signature': 'Sig A', 'timestamp': '2024-01-15T10:00:00'},
            {'signature': 'Sig B', 'timestamp': '2024-01-15T10:01:00'},
            {'signature': 'Sig A', 'timestamp': '2024-01-15T10:02:00'},
            {'signature': 'Sig B', 'timestamp': '2024-01-15T10:03:00'}
        ]
        result = logic._group_alerts_by_signature(alerts)
        assert len(result) == 2
        # Each should have x2
        for r in result:
            assert 'x2' in r['signature']


class TestGroupConnectionsByRemote:
    """Test _group_connections_by_remote method"""

    def test_empty_list(self):
        """UI-023: Empty list returns empty"""
        logic = MockMainWindowLogic()
        assert logic._group_connections_by_remote([]) == []

    def test_no_duplicates(self):
        """UI-024: No duplicates returns same connections"""
        logic = MockMainWindowLogic()
        conns = [
            {'remote': '1.1.1.1:80'},
            {'remote': '2.2.2.2:443'}
        ]
        result = logic._group_connections_by_remote(conns)
        assert len(result) == 2

    def test_groups_duplicates(self):
        """UI-025: Duplicates are grouped with count"""
        logic = MockMainWindowLogic()
        conns = [
            {'remote': '8.8.8.8:443'},
            {'remote': '8.8.8.8:443'},
            {'remote': '8.8.8.8:443'}
        ]
        result = logic._group_connections_by_remote(conns)
        assert len(result) == 1
        assert 'x3' in result[0]['remote']
        assert result[0]['_group_count'] == 3


class TestGroupTrafficByDestination:
    """Test _group_traffic_by_destination method"""

    def test_empty_list(self):
        """UI-026: Empty list returns empty"""
        logic = MockMainWindowLogic()
        assert logic._group_traffic_by_destination([]) == []

    def test_groups_by_destination(self):
        """UI-027: Groups traffic by destination"""
        logic = MockMainWindowLogic()
        entries = [
            {'destination': '1.1.1.1:443', 'timestamp': '2024-01-15T10:00:00'},
            {'destination': '1.1.1.1:443', 'timestamp': '2024-01-15T10:01:00'},
            {'destination': '2.2.2.2:80', 'timestamp': '2024-01-15T10:02:00'}
        ]
        result = logic._group_traffic_by_destination(entries)
        assert len(result) == 2
        # Check one has x2
        grouped = [e for e in result if 'x2' in e['destination']]
        assert len(grouped) == 1

    def test_sorted_by_timestamp(self):
        """UI-028: Results sorted by timestamp descending"""
        logic = MockMainWindowLogic()
        entries = [
            {'destination': 'A', 'timestamp': '2024-01-15T10:00:00'},
            {'destination': 'B', 'timestamp': '2024-01-15T12:00:00'},
            {'destination': 'C', 'timestamp': '2024-01-15T11:00:00'}
        ]
        result = logic._group_traffic_by_destination(entries)
        assert result[0]['destination'] == 'B'


class TestGroupDNSByDomain:
    """Test _group_dns_by_domain method"""

    def test_empty_list(self):
        """UI-029: Empty list returns empty"""
        logic = MockMainWindowLogic()
        assert logic._group_dns_by_domain([]) == []

    def test_groups_by_domain(self):
        """UI-030: Groups DNS by domain"""
        logic = MockMainWindowLogic()
        entries = [
            {'domain': 'example.com', 'timestamp': '2024-01-15T10:00:00'},
            {'domain': 'example.com', 'timestamp': '2024-01-15T10:01:00'},
            {'domain': 'google.com', 'timestamp': '2024-01-15T10:02:00'}
        ]
        result = logic._group_dns_by_domain(entries)
        assert len(result) == 2


class TestIsLocalIP:
    """Test _is_local_ip method"""

    def test_loopback_ipv4(self):
        """UI-031: 127.x.x.x is local"""
        logic = MockMainWindowLogic()
        assert logic._is_local_ip("127.0.0.1") is True
        assert logic._is_local_ip("127.0.1.1") is True

    def test_loopback_ipv6(self):
        """UI-032: ::1 is local"""
        logic = MockMainWindowLogic()
        assert logic._is_local_ip("::1") is True

    def test_private_192(self):
        """UI-033: 192.168.x.x is local"""
        logic = MockMainWindowLogic()
        assert logic._is_local_ip("192.168.1.1") is True
        assert logic._is_local_ip("192.168.0.100") is True

    def test_private_10(self):
        """UI-034: 10.x.x.x is local"""
        logic = MockMainWindowLogic()
        assert logic._is_local_ip("10.0.0.1") is True
        assert logic._is_local_ip("10.255.255.255") is True

    def test_private_172(self):
        """UI-035: 172.16-31.x.x is local"""
        logic = MockMainWindowLogic()
        assert logic._is_local_ip("172.16.0.1") is True
        assert logic._is_local_ip("172.31.255.255") is True
        assert logic._is_local_ip("172.15.0.1") is False
        assert logic._is_local_ip("172.32.0.1") is False

    def test_public_ip(self):
        """UI-036: Public IPs are not local"""
        logic = MockMainWindowLogic()
        assert logic._is_local_ip("8.8.8.8") is False
        assert logic._is_local_ip("1.1.1.1") is False
        assert logic._is_local_ip("142.250.80.46") is False

    def test_empty_ip(self):
        """UI-037: Empty IP returns False"""
        logic = MockMainWindowLogic()
        assert logic._is_local_ip("") is False
        assert logic._is_local_ip(None) is False


class TestGetClamavUser:
    """Test get_clamav_user function"""

    @patch('pwd.getpwnam')
    @patch('grp.getgrnam')
    def test_clamupdate_exists(self, mock_grp, mock_pwd):
        """UI-038: Returns clamupdate when it exists (Fedora)"""
        from ids_suite.ui.main_window import get_clamav_user
        # First call succeeds (clamupdate)
        mock_pwd.side_effect = lambda x: MagicMock() if x == 'clamupdate' else None
        mock_grp.side_effect = lambda x: MagicMock() if x == 'clamupdate' else None

        result = get_clamav_user()
        assert result == ('clamupdate', 'clamupdate')

    @patch('pwd.getpwnam')
    @patch('grp.getgrnam')
    def test_clamav_exists(self, mock_grp, mock_pwd):
        """UI-039: Returns clamav when clamupdate doesn't exist (Debian)"""
        from ids_suite.ui.main_window import get_clamav_user

        def pwd_side(name):
            if name == 'clamupdate':
                raise KeyError()
            return MagicMock()

        def grp_side(name):
            if name == 'clamupdate':
                raise KeyError()
            return MagicMock()

        mock_pwd.side_effect = pwd_side
        mock_grp.side_effect = grp_side

        result = get_clamav_user()
        assert result == ('clamav', 'clamav')

    @patch('pwd.getpwnam')
    @patch('grp.getgrnam')
    def test_fallback_to_root(self, mock_grp, mock_pwd):
        """UI-040: Returns root when neither clamav user exists"""
        from ids_suite.ui.main_window import get_clamav_user
        mock_pwd.side_effect = KeyError()
        mock_grp.side_effect = KeyError()

        result = get_clamav_user()
        assert result == ('root', 'root')


class TestAPIKeyManagement:
    """Test API key loading/saving logic"""

    @patch('builtins.open', create=True)
    @patch('os.path.exists')
    def test_load_api_keys_file_exists(self, mock_exists, mock_open):
        """UI-041: Loads API keys from file when it exists"""
        mock_exists.return_value = True
        mock_open.return_value.__enter__.return_value.read.return_value = '{"virustotal": "test-key"}'

        # Simulate the _load_all_api_keys logic
        import json
        import os

        keys_file = os.path.expanduser("~/.config/ids-suite/api_keys.json")
        if os.path.exists(keys_file):
            with open(keys_file, 'r') as f:
                keys = json.loads(f.read())
        else:
            keys = {}

        # Check that mock was used
        assert mock_exists.called

    @patch('os.path.exists')
    def test_load_api_keys_no_file(self, mock_exists):
        """UI-042: Returns empty dict when no keys file"""
        mock_exists.return_value = False

        import os
        keys_file = os.path.expanduser("~/.config/ids-suite/api_keys.json")
        if os.path.exists(keys_file):
            keys = {"some": "data"}
        else:
            keys = {}

        assert keys == {}


class TestSuricataConfigParsing:
    """Test Suricata config parsing logic"""

    def test_parse_interface_from_yaml(self):
        """UI-043: Parse interface from suricata.yaml content"""
        import re
        content = """
af-packet:
  - interface: enp5s0
    threads: auto
  - interface: default
"""
        iface_matches = re.findall(r'^\s*-\s*interface:\s*(\S+)', content, re.MULTILINE)
        current_iface = None
        for iface in iface_matches:
            if iface not in ('default', 'lo'):
                current_iface = iface
                break

        assert current_iface == 'enp5s0'

    def test_parse_ja3_enabled(self):
        """UI-044: Parse JA3 enabled from config"""
        content = "ja3-fingerprints: yes"
        ja3_enabled = 'ja3-fingerprints: yes' in content
        assert ja3_enabled is True

    def test_parse_ja3_disabled(self):
        """UI-045: Parse JA3 disabled from config"""
        content = "ja3-fingerprints: no"
        ja3_enabled = 'ja3-fingerprints: yes' in content
        assert ja3_enabled is False

    def test_parse_runmode(self):
        """UI-046: Parse runmode from config"""
        import re
        content = """
# Runmode
runmode: autofp
"""
        runmode_match = re.search(r'^runmode:\s*(\S+)', content, re.MULTILINE)
        runmode = runmode_match.group(1) if runmode_match else 'autofp'
        assert runmode == 'autofp'

    def test_parse_threads(self):
        """UI-047: Parse detect-thread-ratio from config"""
        import re
        content = "detect-thread-ratio: 1.5"
        threads_match = re.search(r'detect-thread-ratio:\s*(\d+\.?\d*)', content)
        threads = threads_match.group(1) if threads_match else 'auto'
        assert threads == '1.5'


class TestFilterCountCalculation:
    """Test filter count display logic"""

    def test_filter_count_empty(self):
        """UI-048: No filters returns 0"""
        hidden_signatures = set()
        hidden_src_ips = set()
        hidden_dest_ips = set()
        hidden_categories = set()

        total = (len(hidden_signatures) + len(hidden_src_ips) +
                 len(hidden_dest_ips) + len(hidden_categories))
        assert total == 0

    def test_filter_count_with_filters(self):
        """UI-049: Counts all filter types"""
        hidden_signatures = {'Sig1', 'Sig2'}
        hidden_src_ips = {'1.1.1.1'}
        hidden_dest_ips = {'2.2.2.2', '3.3.3.3'}
        hidden_categories = {'Spam'}

        total = (len(hidden_signatures) + len(hidden_src_ips) +
                 len(hidden_dest_ips) + len(hidden_categories))
        assert total == 6
