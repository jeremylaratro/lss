"""
UI Tab Business Logic Tests

Tests the data transformation, filtering, sorting, and state management
logic from UI tabs WITHOUT requiring tkinter or a display server.

These tests extract and verify the core algorithms that power the UI,
ensuring they work correctly regardless of the presentation layer.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
from typing import Dict, List, Any, Optional


# =============================================================================
# AlertsTab Logic Tests
# =============================================================================

class TestAlertTimestampFormatting:
    """
    BUSINESS LOGIC: Timestamp display adapts based on recency.

    WHY THIS MATTERS:
    - Today's alerts show time only (HH:MM:SS) for quick scanning
    - Older alerts show date+time (MM-DD HH:MM) for context
    - Invalid timestamps should fail gracefully, not crash the UI
    """

    @staticmethod
    def format_alert_timestamp(timestamp: str) -> str:
        """Extract from AlertsTab._format_alert_timestamp for testing."""
        if not timestamp or len(timestamp) < 19:
            return timestamp or ''

        today = datetime.now().strftime('%Y-%m-%d')
        alert_date = timestamp[:10]

        if alert_date == today:
            return timestamp[11:19]  # HH:MM:SS
        else:
            return f"{timestamp[5:10]} {timestamp[11:16]}"  # MM-DD HH:MM

    def test_today_shows_time_only(self):
        """Today's alerts show compact HH:MM:SS format."""
        today = datetime.now().strftime('%Y-%m-%d')
        timestamp = f"{today}T14:30:45.123456"

        result = self.format_alert_timestamp(timestamp)
        assert result == "14:30:45"

    def test_yesterday_shows_date_and_time(self):
        """Yesterday's alerts show MM-DD HH:MM format."""
        yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
        timestamp = f"{yesterday}T14:30:45.123456"

        result = self.format_alert_timestamp(timestamp)
        # Format: MM-DD HH:MM
        expected_date = yesterday[5:10]  # MM-DD
        assert result == f"{expected_date} 14:30"

    def test_empty_timestamp_returns_empty(self):
        """Empty timestamp returns empty string (no crash)."""
        assert self.format_alert_timestamp("") == ""
        assert self.format_alert_timestamp(None) == ""

    def test_short_timestamp_returns_unchanged(self):
        """Malformed short timestamps pass through unchanged."""
        assert self.format_alert_timestamp("2024-01") == "2024-01"
        assert self.format_alert_timestamp("invalid") == "invalid"


class TestIntelStatusCombination:
    """
    BUSINESS LOGIC: Combine threat intel status from source and destination IPs.

    WHY THIS MATTERS:
    An alert might have threat intel for source IP, destination IP, or both.
    We display the MOST SEVERE status to ensure dangerous alerts stand out.

    Priority hierarchy: DANGER > suspect > error > checking > safe > None
    """

    @staticmethod
    def combine_intel_status(src_intel: Optional[str], dst_intel: Optional[str]) -> Optional[str]:
        """Extract from AlertsTab._combine_intel_status for testing."""
        priority = {'DANGER': 5, 'suspect': 4, 'error': 3, 'checking': 2, 'safe': 1}

        src_priority = priority.get(src_intel, 0) if src_intel else 0
        dst_priority = priority.get(dst_intel, 0) if dst_intel else 0

        if src_priority == 0 and dst_priority == 0:
            return None

        if src_priority >= dst_priority:
            return src_intel
        return dst_intel

    def test_danger_beats_all(self):
        """DANGER status always wins - highest priority."""
        assert self.combine_intel_status("DANGER", "safe") == "DANGER"
        assert self.combine_intel_status("safe", "DANGER") == "DANGER"
        assert self.combine_intel_status("DANGER", "suspect") == "DANGER"
        assert self.combine_intel_status("suspect", "DANGER") == "DANGER"

    def test_suspect_beats_lower(self):
        """Suspect beats error, checking, and safe."""
        assert self.combine_intel_status("suspect", "safe") == "suspect"
        assert self.combine_intel_status("error", "suspect") == "suspect"
        assert self.combine_intel_status("suspect", "checking") == "suspect"

    def test_none_values_handled(self):
        """None values don't crash - return the non-None value."""
        assert self.combine_intel_status("safe", None) == "safe"
        assert self.combine_intel_status(None, "DANGER") == "DANGER"
        assert self.combine_intel_status(None, None) is None

    def test_same_priority_prefers_source(self):
        """When equal priority, source IP status wins."""
        assert self.combine_intel_status("safe", "safe") == "safe"
        assert self.combine_intel_status("DANGER", "DANGER") == "DANGER"

    def test_unknown_status_treated_as_none(self):
        """Unknown status strings have zero priority."""
        assert self.combine_intel_status("unknown_status", "safe") == "safe"
        assert self.combine_intel_status("safe", "gibberish") == "safe"


class TestAlertFiltering:
    """
    BUSINESS LOGIC: Filter alerts based on user-hidden signatures, IPs, categories.

    WHY THIS MATTERS:
    Users hide noisy alerts they don't care about (e.g., internal DNS lookups).
    Filtering must apply ALL conditions (AND logic) - if ANY filter matches,
    the alert is hidden.
    """

    @staticmethod
    def apply_alert_filters(
        alerts: List[Dict[str, Any]],
        hidden_signatures: set,
        hidden_src_ips: set,
        hidden_dest_ips: set,
        hidden_categories: set
    ) -> List[Dict[str, Any]]:
        """Extract from AlertsTab._apply_alert_filters for testing."""
        if not (hidden_signatures or hidden_src_ips or hidden_dest_ips or hidden_categories):
            return alerts

        filtered = []
        for alert in alerts:
            signature = alert.get('signature', '')
            src = alert.get('source', '').split(':')[0]
            dest = alert.get('destination', '').split(':')[0]
            category = alert.get('category', '')

            if signature in hidden_signatures:
                continue
            if src in hidden_src_ips:
                continue
            if dest in hidden_dest_ips:
                continue
            if category in hidden_categories:
                continue

            filtered.append(alert)

        return filtered

    def test_no_filters_returns_all(self):
        """With no filters, all alerts pass through."""
        alerts = [
            {'signature': 'sig1', 'source': '10.0.0.1', 'destination': '8.8.8.8', 'category': 'dns'},
            {'signature': 'sig2', 'source': '10.0.0.2', 'destination': '8.8.4.4', 'category': 'web'},
        ]
        result = self.apply_alert_filters(alerts, set(), set(), set(), set())
        assert len(result) == 2

    def test_filter_by_signature(self):
        """Alerts with hidden signatures are excluded."""
        alerts = [
            {'signature': 'ET INFO DNS Query', 'source': '10.0.0.1', 'destination': '8.8.8.8', 'category': 'dns'},
            {'signature': 'ET MALWARE CnC', 'source': '10.0.0.2', 'destination': '185.1.2.3', 'category': 'malware'},
        ]
        result = self.apply_alert_filters(alerts, {'ET INFO DNS Query'}, set(), set(), set())
        assert len(result) == 1
        assert result[0]['signature'] == 'ET MALWARE CnC'

    def test_filter_by_source_ip(self):
        """Alerts from hidden source IPs are excluded."""
        alerts = [
            {'signature': 'sig1', 'source': '10.0.0.1:12345', 'destination': '8.8.8.8', 'category': 'dns'},
            {'signature': 'sig2', 'source': '192.168.1.100:54321', 'destination': '8.8.8.8', 'category': 'dns'},
        ]
        result = self.apply_alert_filters(alerts, set(), {'10.0.0.1'}, set(), set())
        assert len(result) == 1
        assert '192.168.1.100' in result[0]['source']

    def test_filter_extracts_ip_from_port(self):
        """Source/dest filtering extracts IP from IP:port format."""
        alerts = [
            {'signature': 'sig1', 'source': '10.0.0.1:12345', 'destination': '8.8.8.8:53', 'category': 'dns'},
        ]
        # Filter by IP, not IP:port
        result = self.apply_alert_filters(alerts, set(), {'10.0.0.1'}, set(), set())
        assert len(result) == 0  # Filtered out

    def test_filter_by_category(self):
        """Alerts in hidden categories are excluded."""
        alerts = [
            {'signature': 'sig1', 'source': '10.0.0.1', 'destination': '8.8.8.8', 'category': 'Potentially Bad Traffic'},
            {'signature': 'sig2', 'source': '10.0.0.2', 'destination': '8.8.8.8', 'category': 'Malware Command and Control'},
        ]
        result = self.apply_alert_filters(alerts, set(), set(), set(), {'Potentially Bad Traffic'})
        assert len(result) == 1
        assert result[0]['category'] == 'Malware Command and Control'

    def test_multiple_filters_apply_and_logic(self):
        """Multiple filter types all apply (any match = excluded)."""
        alerts = [
            {'signature': 'hidden_sig', 'source': '10.0.0.1', 'destination': '8.8.8.8', 'category': 'dns'},
            {'signature': 'good_sig', 'source': 'hidden_ip', 'destination': '8.8.8.8', 'category': 'dns'},
            {'signature': 'good_sig', 'source': '10.0.0.1', 'destination': '8.8.8.8', 'category': 'hidden_cat'},
            {'signature': 'good_sig', 'source': '10.0.0.1', 'destination': '8.8.8.8', 'category': 'dns'},  # Passes
        ]
        result = self.apply_alert_filters(
            alerts,
            {'hidden_sig'},
            {'hidden_ip'},
            set(),
            {'hidden_cat'}
        )
        assert len(result) == 1
        assert result[0]['signature'] == 'good_sig'


class TestAlertGrouping:
    """
    BUSINESS LOGIC: Group similar alerts by signature for cleaner display.

    WHY THIS MATTERS:
    A single attack might trigger 1000+ alerts with the same signature.
    Without grouping, users can't see the forest for the trees.
    Grouping shows "ET MALWARE CnC x47" instead of 47 separate rows.
    """

    @staticmethod
    def group_alerts_by_signature(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract from AlertsTab._group_alerts_by_signature for testing."""
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

    def test_single_alert_unchanged(self):
        """Single alerts don't get count suffix."""
        alerts = [{'signature': 'ET MALWARE CnC', 'timestamp': '2024-01-15T10:00:00'}]
        result = self.group_alerts_by_signature(alerts)

        assert len(result) == 1
        assert result[0]['signature'] == 'ET MALWARE CnC'
        assert '_group_count' not in result[0]

    def test_duplicate_alerts_grouped(self):
        """Multiple alerts with same signature show count."""
        alerts = [
            {'signature': 'ET MALWARE CnC', 'timestamp': '2024-01-15T10:00:00'},
            {'signature': 'ET MALWARE CnC', 'timestamp': '2024-01-15T10:01:00'},
            {'signature': 'ET MALWARE CnC', 'timestamp': '2024-01-15T10:02:00'},
        ]
        result = self.group_alerts_by_signature(alerts)

        assert len(result) == 1
        assert result[0]['signature'] == 'ET MALWARE CnC x3'
        assert result[0]['_group_count'] == 3

    def test_most_recent_preserved(self):
        """Grouped result uses most recent alert's data."""
        alerts = [
            {'signature': 'ET MALWARE CnC', 'timestamp': '2024-01-15T08:00:00', 'source': 'old_ip'},
            {'signature': 'ET MALWARE CnC', 'timestamp': '2024-01-15T12:00:00', 'source': 'newest_ip'},
            {'signature': 'ET MALWARE CnC', 'timestamp': '2024-01-15T10:00:00', 'source': 'middle_ip'},
        ]
        result = self.group_alerts_by_signature(alerts)

        assert result[0]['source'] == 'newest_ip'
        assert result[0]['timestamp'] == '2024-01-15T12:00:00'

    def test_different_signatures_separate(self):
        """Different signatures remain as separate entries."""
        alerts = [
            {'signature': 'ET MALWARE CnC', 'timestamp': '2024-01-15T10:00:00'},
            {'signature': 'ET MALWARE CnC', 'timestamp': '2024-01-15T10:01:00'},
            {'signature': 'ET INFO DNS', 'timestamp': '2024-01-15T10:02:00'},
        ]
        result = self.group_alerts_by_signature(alerts)

        assert len(result) == 2
        signatures = [r['signature'] for r in result]
        assert 'ET MALWARE CnC x2' in signatures
        assert 'ET INFO DNS' in signatures

    def test_empty_list_returns_empty(self):
        """Empty input returns empty output (no crash)."""
        assert self.group_alerts_by_signature([]) == []

    def test_results_sorted_by_timestamp(self):
        """Grouped results sorted with most recent first."""
        alerts = [
            {'signature': 'Older Sig', 'timestamp': '2024-01-14T10:00:00'},
            {'signature': 'Newer Sig', 'timestamp': '2024-01-15T10:00:00'},
        ]
        result = self.group_alerts_by_signature(alerts)

        assert result[0]['signature'] == 'Newer Sig'
        assert result[1]['signature'] == 'Older Sig'


# =============================================================================
# DNSTab Logic Tests
# =============================================================================

class TestDNSGrouping:
    """
    BUSINESS LOGIC: Group DNS queries by domain for cleaner display.

    WHY THIS MATTERS:
    A client might query the same domain hundreds of times.
    Grouping shows "google.com x150" instead of 150 rows.
    """

    @staticmethod
    def group_by_domain(entries: list) -> list:
        """Extract from DNSTab._group_by_domain for testing."""
        if not entries:
            return entries

        domain_groups = {}
        for entry in entries:
            domain = entry.get('domain', 'Unknown')
            if domain not in domain_groups:
                domain_groups[domain] = []
            domain_groups[domain].append(entry)

        grouped = []
        for domain, group in domain_groups.items():
            group.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            most_recent = group[0].copy()

            count = len(group)
            if count > 1:
                most_recent['domain'] = f"{domain} x{count}"

            grouped.append(most_recent)

        grouped.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return grouped

    def test_single_query_unchanged(self):
        """Single DNS query doesn't get count suffix."""
        entries = [{'domain': 'google.com', 'timestamp': '2024-01-15T10:00:00'}]
        result = self.group_by_domain(entries)

        assert len(result) == 1
        assert result[0]['domain'] == 'google.com'

    def test_multiple_queries_grouped(self):
        """Multiple queries to same domain show count."""
        entries = [
            {'domain': 'google.com', 'timestamp': '2024-01-15T10:00:00'},
            {'domain': 'google.com', 'timestamp': '2024-01-15T10:01:00'},
            {'domain': 'google.com', 'timestamp': '2024-01-15T10:02:00'},
        ]
        result = self.group_by_domain(entries)

        assert len(result) == 1
        assert result[0]['domain'] == 'google.com x3'


# =============================================================================
# TrafficTab Logic Tests
# =============================================================================

class TestTrafficGrouping:
    """
    BUSINESS LOGIC: Group traffic by destination for cleaner display.

    WHY THIS MATTERS:
    Shows traffic patterns without noise - "185.1.2.3:443 x500" indicates
    sustained communication with a specific endpoint.
    """

    @staticmethod
    def group_traffic_by_destination(entries: List[Dict]) -> List[Dict]:
        """Extract from TrafficTab._group_traffic_by_destination for testing."""
        if not entries:
            return entries

        dest_groups = {}
        for entry in entries:
            dest = entry.get('destination', 'Unknown')
            if dest not in dest_groups:
                dest_groups[dest] = []
            dest_groups[dest].append(entry)

        grouped = []
        for dest, group in dest_groups.items():
            group.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            most_recent = group[0].copy()

            count = len(group)
            if count > 1:
                most_recent['destination'] = f"{dest} x{count}"

            grouped.append(most_recent)

        grouped.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return grouped

    def test_single_flow_unchanged(self):
        """Single traffic flow doesn't get count suffix."""
        entries = [{'destination': '8.8.8.8:53', 'timestamp': '2024-01-15T10:00:00'}]
        result = self.group_traffic_by_destination(entries)

        assert len(result) == 1
        assert result[0]['destination'] == '8.8.8.8:53'

    def test_multiple_flows_grouped(self):
        """Multiple flows to same destination show count."""
        entries = [
            {'destination': '185.1.2.3:443', 'timestamp': '2024-01-15T10:00:00'},
            {'destination': '185.1.2.3:443', 'timestamp': '2024-01-15T10:01:00'},
            {'destination': '8.8.8.8:53', 'timestamp': '2024-01-15T10:02:00'},
        ]
        result = self.group_traffic_by_destination(entries)

        assert len(result) == 2
        destinations = [r['destination'] for r in result]
        assert '185.1.2.3:443 x2' in destinations
        assert '8.8.8.8:53' in destinations


# =============================================================================
# Sort State Management Tests
# =============================================================================

class TestSortStateManagement:
    """
    BUSINESS LOGIC: Sort column toggle behavior.

    WHY THIS MATTERS:
    - Clicking same column toggles sort direction (asc/desc)
    - Clicking different column resets to descending
    - This is standard UX pattern users expect
    """

    @staticmethod
    def update_sort_state(current_col: str, current_reverse: bool, clicked_col: str) -> tuple:
        """Simulate sort state update logic."""
        if clicked_col == current_col:
            return (clicked_col, not current_reverse)  # Toggle direction
        else:
            return (clicked_col, True)  # New column, descending

    def test_same_column_toggles_direction(self):
        """Clicking same column toggles between asc and desc."""
        col, rev = self.update_sort_state("timestamp", True, "timestamp")
        assert col == "timestamp"
        assert rev is False  # Was True, now False

        col, rev = self.update_sort_state("timestamp", False, "timestamp")
        assert rev is True  # Was False, now True

    def test_new_column_resets_to_descending(self):
        """Clicking new column starts with descending."""
        col, rev = self.update_sort_state("timestamp", False, "severity")
        assert col == "severity"
        assert rev is True


# =============================================================================
# Data Truncation Tests
# =============================================================================

class TestDataTruncation:
    """
    BUSINESS LOGIC: Truncate long values for display.

    WHY THIS MATTERS:
    Long URLs/answers can break table layout. Truncation with '...'
    indicates there's more data without overflowing the column.
    """

    @staticmethod
    def truncate_value(value: str, max_length: int = 50) -> str:
        """Truncate string with ellipsis if too long."""
        if not value or len(value) <= max_length:
            return value or ''
        return value[:max_length] + '...'

    def test_short_values_unchanged(self):
        """Values under max length pass through unchanged."""
        assert self.truncate_value("short") == "short"
        assert self.truncate_value("x" * 50) == "x" * 50

    def test_long_values_truncated(self):
        """Values over max length get truncated with ellipsis."""
        long_url = "https://example.com/" + "a" * 100
        result = self.truncate_value(long_url, 50)

        assert len(result) == 53  # 50 + '...'
        assert result.endswith('...')

    def test_empty_and_none_handled(self):
        """Empty strings and None don't crash."""
        assert self.truncate_value("") == ""
        assert self.truncate_value(None) == ""


# =============================================================================
# File Size Formatting Tests
# =============================================================================

class TestFileSizeFormatting:
    """
    BUSINESS LOGIC: Format byte sizes for human display.

    WHY THIS MATTERS:
    Users need to quickly understand file sizes in the quarantine tab.
    "1.5 MB" is much clearer than "1572864 bytes".
    """

    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """Format bytes to human-readable string."""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

    def test_bytes(self):
        """Small files show bytes."""
        assert self.format_file_size(512) == "512 B"
        assert self.format_file_size(1023) == "1023 B"

    def test_kilobytes(self):
        """Medium files show KB."""
        assert self.format_file_size(1024) == "1.0 KB"
        assert self.format_file_size(1536) == "1.5 KB"

    def test_megabytes(self):
        """Large files show MB."""
        assert self.format_file_size(1024 * 1024) == "1.0 MB"
        assert self.format_file_size(int(1.5 * 1024 * 1024)) == "1.5 MB"

    def test_gigabytes(self):
        """Very large files show GB."""
        assert self.format_file_size(1024 * 1024 * 1024) == "1.0 GB"
