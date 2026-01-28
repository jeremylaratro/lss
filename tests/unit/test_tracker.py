"""
Tests for ids_suite/threat_intel/tracker.py - IP Lookup Tracker

Target: 75%+ coverage
"""

import pytest
import json
import tempfile
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from pathlib import Path

from ids_suite.threat_intel.tracker import IPLookupTracker


class TestIPLookupTrackerInit:
    """Test IPLookupTracker initialization"""

    def test_init_default_window(self):
        """TR-001: Default window is 12 hours"""
        tracker = IPLookupTracker()
        assert tracker.window == timedelta(hours=12)

    def test_init_custom_window(self):
        """TR-002: Custom window is respected"""
        tracker = IPLookupTracker(window_hours=6)
        assert tracker.window == timedelta(hours=6)

    def test_init_loads_empty_lookups(self):
        """TR-003: Starts with empty lookups when file doesn't exist"""
        with patch.object(Path, 'exists', return_value=False):
            tracker = IPLookupTracker()
            assert tracker.lookups == {}


class TestIPLookupTrackerLoad:
    """Test _load method"""

    def test_load_nonexistent_file(self):
        """TR-004: Handles nonexistent file gracefully"""
        with patch.object(Path, 'exists', return_value=False):
            tracker = IPLookupTracker()
            assert tracker.lookups == {}

    def test_load_valid_file(self):
        """TR-005: Loads valid data from file"""
        recent_time = datetime.now().isoformat()
        mock_data = {
            '8.8.8.8': {
                'timestamp': recent_time,
                'result': 'safe',
                'source': 'AbuseIPDB'
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(mock_data, f)
            temp_path = Path(f.name)

        try:
            with patch.object(IPLookupTracker, 'TRACKER_FILE', temp_path):
                tracker = IPLookupTracker()
                assert '8.8.8.8' in tracker.lookups
                assert tracker.lookups['8.8.8.8']['result'] == 'safe'
        finally:
            temp_path.unlink()

    def test_load_filters_expired(self):
        """TR-006: Filters out expired entries on load"""
        old_time = (datetime.now() - timedelta(hours=24)).isoformat()
        recent_time = datetime.now().isoformat()
        mock_data = {
            '1.1.1.1': {'timestamp': old_time, 'result': 'safe', 'source': 'Test'},
            '8.8.8.8': {'timestamp': recent_time, 'result': 'safe', 'source': 'Test'}
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(mock_data, f)
            temp_path = Path(f.name)

        try:
            with patch.object(IPLookupTracker, 'TRACKER_FILE', temp_path):
                tracker = IPLookupTracker()
                assert '8.8.8.8' in tracker.lookups
                assert '1.1.1.1' not in tracker.lookups
        finally:
            temp_path.unlink()

    def test_load_handles_error(self):
        """TR-007: Handles JSON parse error gracefully"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json{{{")
            temp_path = Path(f.name)

        try:
            with patch.object(IPLookupTracker, 'TRACKER_FILE', temp_path):
                tracker = IPLookupTracker()
                assert tracker.lookups == {}
        finally:
            temp_path.unlink()


class TestIPLookupTrackerSave:
    """Test _save method"""

    def test_save_creates_directory(self):
        """TR-008: Creates parent directory if needed"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker_file = Path(tmpdir) / "subdir" / "lookups.json"
            with patch.object(IPLookupTracker, 'TRACKER_FILE', tracker_file):
                tracker = IPLookupTracker()
                tracker.lookups = {'1.2.3.4': {'timestamp': datetime.now().isoformat()}}
                tracker._save()
                assert tracker_file.exists()

    def test_save_writes_json(self):
        """TR-009: Saves lookups as JSON"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker_file = Path(tmpdir) / "lookups.json"
            with patch.object(IPLookupTracker, 'TRACKER_FILE', tracker_file):
                tracker = IPLookupTracker()
                tracker.lookups = {'5.5.5.5': {
                    'timestamp': datetime.now().isoformat(),
                    'result': 'DANGER',
                    'source': 'Test'
                }}
                tracker._save()

                with open(tracker_file) as f:
                    saved = json.load(f)
                assert '5.5.5.5' in saved
                assert saved['5.5.5.5']['result'] == 'DANGER'


class TestIPLookupTrackerShouldLookup:
    """Test should_lookup method"""

    def test_should_lookup_private_ip(self):
        """TR-010: Returns False for private IPs"""
        tracker = IPLookupTracker()
        assert tracker.should_lookup("192.168.1.1") is False
        assert tracker.should_lookup("10.0.0.1") is False
        assert tracker.should_lookup("172.16.0.1") is False
        assert tracker.should_lookup("127.0.0.1") is False

    def test_should_lookup_new_ip(self):
        """TR-011: Returns True for new public IPs"""
        tracker = IPLookupTracker()
        tracker.lookups = {}
        assert tracker.should_lookup("8.8.8.8") is True

    def test_should_lookup_recent_ip(self):
        """TR-012: Returns False for recently looked up IPs"""
        tracker = IPLookupTracker()
        tracker.lookups = {
            '8.8.8.8': {
                'timestamp': datetime.now().isoformat(),
                'result': 'safe'
            }
        }
        assert tracker.should_lookup("8.8.8.8") is False

    def test_should_lookup_expired_ip(self):
        """TR-013: Returns True for expired lookups"""
        tracker = IPLookupTracker()
        old_time = (datetime.now() - timedelta(hours=24)).isoformat()
        tracker.lookups = {
            '8.8.8.8': {
                'timestamp': old_time,
                'result': 'safe'
            }
        }
        assert tracker.should_lookup("8.8.8.8") is True
        # Should have removed expired entry
        assert '8.8.8.8' not in tracker.lookups


class TestIPLookupTrackerRecordLookup:
    """Test record_lookup method"""

    def test_record_lookup_basic(self):
        """TR-014: Records basic lookup info"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker_file = Path(tmpdir) / "lookups.json"
            with patch.object(IPLookupTracker, 'TRACKER_FILE', tracker_file):
                tracker = IPLookupTracker()
                tracker.record_lookup("1.2.3.4", "DANGER", "AbuseIPDB")

                assert '1.2.3.4' in tracker.lookups
                assert tracker.lookups['1.2.3.4']['result'] == 'DANGER'
                assert tracker.lookups['1.2.3.4']['source'] == 'AbuseIPDB'

    def test_record_lookup_with_details(self):
        """TR-015: Records lookup with full details"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker_file = Path(tmpdir) / "lookups.json"
            with patch.object(IPLookupTracker, 'TRACKER_FILE', tracker_file):
                tracker = IPLookupTracker()
                details = {'abuse_score': 95, 'reports': 100}
                tracker.record_lookup("5.6.7.8", "suspect", "VirusTotal", details)

                assert tracker.lookups['5.6.7.8']['details'] == details

    def test_record_lookup_default_details(self):
        """TR-016: Default details is empty dict"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker_file = Path(tmpdir) / "lookups.json"
            with patch.object(IPLookupTracker, 'TRACKER_FILE', tracker_file):
                tracker = IPLookupTracker()
                tracker.record_lookup("9.9.9.9", "safe", "Test")

                assert tracker.lookups['9.9.9.9']['details'] == {}


class TestIPLookupTrackerGetResult:
    """Test get_result method"""

    def test_get_result_found(self):
        """TR-017: Returns result for active lookup"""
        tracker = IPLookupTracker()
        tracker.lookups = {
            '8.8.8.8': {
                'timestamp': datetime.now().isoformat(),
                'result': 'safe'
            }
        }
        assert tracker.get_result("8.8.8.8") == 'safe'

    def test_get_result_not_found(self):
        """TR-018: Returns None for unknown IP"""
        tracker = IPLookupTracker()
        assert tracker.get_result("1.2.3.4") is None

    def test_get_result_expired(self):
        """TR-019: Returns None for expired lookup"""
        tracker = IPLookupTracker()
        old_time = (datetime.now() - timedelta(hours=24)).isoformat()
        tracker.lookups = {
            '8.8.8.8': {
                'timestamp': old_time,
                'result': 'safe'
            }
        }
        assert tracker.get_result("8.8.8.8") is None


class TestIPLookupTrackerGetLookupInfo:
    """Test get_lookup_info method"""

    def test_get_lookup_info_found(self):
        """TR-020: Returns full info for active lookup"""
        tracker = IPLookupTracker()
        tracker.lookups = {
            '8.8.8.8': {
                'timestamp': datetime.now().isoformat(),
                'result': 'DANGER',
                'source': 'Test',
                'details': {'score': 100}
            }
        }
        info = tracker.get_lookup_info("8.8.8.8")
        assert info is not None
        assert info['result'] == 'DANGER'
        assert info['source'] == 'Test'
        assert info['details']['score'] == 100

    def test_get_lookup_info_not_found(self):
        """TR-021: Returns None for unknown IP"""
        tracker = IPLookupTracker()
        assert tracker.get_lookup_info("1.2.3.4") is None

    def test_get_lookup_info_expired(self):
        """TR-022: Returns None for expired lookup"""
        tracker = IPLookupTracker()
        old_time = (datetime.now() - timedelta(hours=24)).isoformat()
        tracker.lookups = {
            '8.8.8.8': {
                'timestamp': old_time,
                'result': 'safe'
            }
        }
        assert tracker.get_lookup_info("8.8.8.8") is None


class TestIPLookupTrackerGetAllLookups:
    """Test get_all_lookups method"""

    def test_get_all_lookups_empty(self):
        """TR-023: Returns empty list when no lookups"""
        tracker = IPLookupTracker()
        tracker.lookups = {}
        assert tracker.get_all_lookups() == []

    def test_get_all_lookups_filters_expired(self):
        """TR-024: Filters expired lookups"""
        tracker = IPLookupTracker()
        old_time = (datetime.now() - timedelta(hours=24)).isoformat()
        recent_time = datetime.now().isoformat()
        tracker.lookups = {
            '1.1.1.1': {'timestamp': old_time, 'result': 'safe', 'source': 'Test'},
            '8.8.8.8': {'timestamp': recent_time, 'result': 'DANGER', 'source': 'Test'}
        }

        results = tracker.get_all_lookups()
        assert len(results) == 1
        assert results[0]['ip'] == '8.8.8.8'

    def test_get_all_lookups_sorted_by_time(self):
        """TR-025: Returns lookups sorted newest first"""
        tracker = IPLookupTracker()
        time1 = (datetime.now() - timedelta(hours=1)).isoformat()
        time2 = datetime.now().isoformat()
        tracker.lookups = {
            '1.1.1.1': {'timestamp': time1, 'result': 'safe', 'source': 'Test'},
            '2.2.2.2': {'timestamp': time2, 'result': 'DANGER', 'source': 'Test'}
        }

        results = tracker.get_all_lookups()
        assert results[0]['ip'] == '2.2.2.2'
        assert results[1]['ip'] == '1.1.1.1'

    def test_get_all_lookups_includes_all_fields(self):
        """TR-026: Includes all expected fields"""
        tracker = IPLookupTracker()
        tracker.lookups = {
            '8.8.8.8': {
                'timestamp': datetime.now().isoformat(),
                'result': 'safe',
                'source': 'AbuseIPDB',
                'details': {'score': 0}
            }
        }

        results = tracker.get_all_lookups()
        assert 'ip' in results[0]
        assert 'timestamp' in results[0]
        assert 'result' in results[0]
        assert 'source' in results[0]
        assert 'details' in results[0]


class TestIPLookupTrackerGetStats:
    """Test get_stats method"""

    def test_get_stats_empty(self):
        """TR-027: Returns zero stats when empty"""
        tracker = IPLookupTracker()
        tracker.lookups = {}
        stats = tracker.get_stats()
        assert stats['active'] == 0
        assert stats['dangerous'] == 0
        assert stats['suspect'] == 0

    def test_get_stats_counts_active(self):
        """TR-028: Counts active lookups correctly"""
        tracker = IPLookupTracker()
        now = datetime.now().isoformat()
        tracker.lookups = {
            '1.1.1.1': {'timestamp': now, 'result': 'safe'},
            '2.2.2.2': {'timestamp': now, 'result': 'DANGER'},
            '3.3.3.3': {'timestamp': now, 'result': 'suspect'}
        }

        stats = tracker.get_stats()
        assert stats['active'] == 3
        assert stats['dangerous'] == 1
        assert stats['suspect'] == 1

    def test_get_stats_filters_expired(self):
        """TR-029: Doesn't count expired lookups"""
        tracker = IPLookupTracker()
        old_time = (datetime.now() - timedelta(hours=24)).isoformat()
        now = datetime.now().isoformat()
        tracker.lookups = {
            '1.1.1.1': {'timestamp': old_time, 'result': 'DANGER'},
            '2.2.2.2': {'timestamp': now, 'result': 'safe'}
        }

        stats = tracker.get_stats()
        assert stats['active'] == 1
        assert stats['dangerous'] == 0


class TestTrackerBusinessLogic:
    """
    Test real-world business logic for IP lookup tracking.

    These tests verify the tracker behaves correctly in actual
    security monitoring scenarios, not just basic functionality.
    """

    # --- API Rate Limiting Protection ---

    def test_prevents_duplicate_api_calls(self):
        """
        BUSINESS LOGIC: Prevent burning API credits on duplicate lookups.

        AbuseIPDB/VirusTotal have daily limits. Looking up same IP
        repeatedly would waste quota. Window-based caching prevents this.
        """
        with patch.object(Path, 'exists', return_value=False):
            tracker = IPLookupTracker(window_hours=12)

        # First lookup should be allowed (fresh tracker with no history)
        assert tracker.should_lookup("185.234.123.45") is True

        # Record the lookup (mock save to avoid file ops)
        with patch.object(tracker, '_save'):
            tracker.record_lookup("185.234.123.45", "DANGER", "AbuseIPDB")

        # Second lookup within window should be blocked
        assert tracker.should_lookup("185.234.123.45") is False

        # Different IP should still be allowed
        assert tracker.should_lookup("185.234.123.46") is True

    def test_window_expiration_allows_fresh_lookup(self):
        """
        BUSINESS LOGIC: After window expires, allow fresh lookup.

        Threat intel changes over time. An IP safe yesterday might
        be compromised today. Window expiration enables re-checking.
        """
        tracker = IPLookupTracker(window_hours=1)  # Short window for testing

        # Simulate lookup from 2 hours ago
        old_time = (datetime.now() - timedelta(hours=2)).isoformat()
        tracker.lookups = {
            '8.8.8.8': {
                'timestamp': old_time,
                'result': 'safe',
                'source': 'AbuseIPDB',
                'details': {}
            }
        }

        # Expired lookup should allow re-lookup
        assert tracker.should_lookup("8.8.8.8") is True

        # And the old entry should be removed
        assert '8.8.8.8' not in tracker.lookups

    # --- Private IP Protection ---

    def test_never_sends_private_ips_to_apis(self):
        """
        BUSINESS LOGIC: Private IPs must NEVER be sent to threat intel APIs.

        1. Privacy: Reveals internal network structure
        2. Useless: Private IPs have no threat intel value
        3. Rate limit: Would waste API quota on meaningless lookups
        """
        tracker = IPLookupTracker()

        # RFC1918 private ranges
        assert tracker.should_lookup("10.0.0.1") is False
        assert tracker.should_lookup("10.255.255.255") is False
        assert tracker.should_lookup("172.16.0.1") is False
        assert tracker.should_lookup("172.31.255.255") is False
        assert tracker.should_lookup("192.168.0.1") is False
        assert tracker.should_lookup("192.168.255.255") is False

        # Loopback
        assert tracker.should_lookup("127.0.0.1") is False
        assert tracker.should_lookup("127.255.255.255") is False

        # Link-local
        assert tracker.should_lookup("169.254.1.1") is False

        # But public IPs should be allowed
        assert tracker.should_lookup("8.8.8.8") is True
        assert tracker.should_lookup("1.1.1.1") is True

    # --- Threat Classification ---

    def test_threat_levels_for_dashboard_display(self):
        """
        BUSINESS LOGIC: Stats categorize threats for dashboard summary.

        Dashboard shows: "5 active lookups (2 DANGER, 1 suspect)"
        Correct categorization is critical for security awareness.
        """
        tracker = IPLookupTracker()
        now = datetime.now().isoformat()

        tracker.lookups = {
            '1.1.1.1': {'timestamp': now, 'result': 'safe', 'source': 'Test'},
            '2.2.2.2': {'timestamp': now, 'result': 'safe', 'source': 'Test'},
            '3.3.3.3': {'timestamp': now, 'result': 'suspect', 'source': 'Test'},
            '4.4.4.4': {'timestamp': now, 'result': 'DANGER', 'source': 'Test'},
            '5.5.5.5': {'timestamp': now, 'result': 'DANGER', 'source': 'Test'},
        }

        stats = tracker.get_stats()

        assert stats['active'] == 5
        assert stats['dangerous'] == 2
        assert stats['suspect'] == 1
        # 'safe' not tracked separately (active - dangerous - suspect = safe)

    def test_result_status_case_sensitivity(self):
        """
        BUSINESS LOGIC: Result status matching is CASE SENSITIVE.

        'DANGER' != 'danger' - must use exact strings from API normalization.
        Inconsistent casing would cause incorrect threat counts.
        """
        tracker = IPLookupTracker()
        now = datetime.now().isoformat()

        tracker.lookups = {
            '1.1.1.1': {'timestamp': now, 'result': 'DANGER', 'source': 'Test'},
            '2.2.2.2': {'timestamp': now, 'result': 'danger', 'source': 'Test'},  # Wrong case
            '3.3.3.3': {'timestamp': now, 'result': 'Danger', 'source': 'Test'},  # Wrong case
        }

        stats = tracker.get_stats()

        # Only exact 'DANGER' match counts
        assert stats['dangerous'] == 1

    # --- Data Persistence ---

    def test_lookup_survives_restart(self):
        """
        BUSINESS LOGIC: Lookups must persist across application restarts.

        User closes app, reopens next day - recent lookups should
        still be cached to avoid re-querying APIs.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker_file = Path(tmpdir) / "lookups.json"

            # First session: record a lookup
            with patch.object(IPLookupTracker, 'TRACKER_FILE', tracker_file):
                tracker1 = IPLookupTracker()
                tracker1.record_lookup(
                    "185.234.123.45",
                    "DANGER",
                    "AbuseIPDB",
                    {'abuse_confidence_score': 95}
                )

            # Second session: lookup should still be cached
            with patch.object(IPLookupTracker, 'TRACKER_FILE', tracker_file):
                tracker2 = IPLookupTracker()
                assert tracker2.should_lookup("185.234.123.45") is False
                assert tracker2.get_result("185.234.123.45") == "DANGER"

    def test_corrupted_file_recovery(self):
        """
        BUSINESS LOGIC: Corrupted tracker file shouldn't crash the app.

        File could be corrupted by crash, disk error, manual edit.
        App must start fresh rather than crashing.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker_file = Path(tmpdir) / "lookups.json"

            # Create corrupted file
            with open(tracker_file, 'w') as f:
                f.write("{invalid json[[[")

            # Should start with empty lookups, not crash
            with patch.object(IPLookupTracker, 'TRACKER_FILE', tracker_file):
                tracker = IPLookupTracker()
                assert tracker.lookups == {}

                # Should still be functional
                assert tracker.should_lookup("8.8.8.8") is True

    # --- Sorting and Display ---

    def test_recent_lookups_shown_first(self):
        """
        BUSINESS LOGIC: Most recent lookups appear at top of Intel tab.

        Users want to see latest threat intel first, not scroll through
        hours of old lookups to find recent activity.
        """
        tracker = IPLookupTracker()

        # Create lookups at different times
        time_3h_ago = (datetime.now() - timedelta(hours=3)).isoformat()
        time_2h_ago = (datetime.now() - timedelta(hours=2)).isoformat()
        time_1h_ago = (datetime.now() - timedelta(hours=1)).isoformat()
        time_now = datetime.now().isoformat()

        tracker.lookups = {
            '1.1.1.1': {'timestamp': time_3h_ago, 'result': 'safe', 'source': 'A'},
            '2.2.2.2': {'timestamp': time_1h_ago, 'result': 'safe', 'source': 'B'},
            '3.3.3.3': {'timestamp': time_now, 'result': 'DANGER', 'source': 'C'},
            '4.4.4.4': {'timestamp': time_2h_ago, 'result': 'suspect', 'source': 'D'},
        }

        results = tracker.get_all_lookups()

        # Should be sorted newest first
        assert results[0]['ip'] == '3.3.3.3'  # Most recent
        assert results[1]['ip'] == '2.2.2.2'
        assert results[2]['ip'] == '4.4.4.4'
        assert results[3]['ip'] == '1.1.1.1'  # Oldest

    def test_full_lookup_info_available_for_display(self):
        """
        BUSINESS LOGIC: All API response details must be preserved.

        Intel tab shows: IP, timestamp, result, source, AND detailed
        info like abuse score, country, ISP from API response.
        """
        tracker = IPLookupTracker()

        api_details = {
            'abuseConfidenceScore': 95,
            'countryCode': 'RU',
            'isp': 'Evil Corp ISP',
            'domain': 'evil.com',
            'totalReports': 1234,
            'lastReportedAt': '2024-01-15T10:00:00'
        }

        tracker.record_lookup(
            "185.234.123.45",
            "DANGER",
            "AbuseIPDB",
            api_details
        )

        info = tracker.get_lookup_info("185.234.123.45")

        # All details preserved
        assert info['details']['abuseConfidenceScore'] == 95
        assert info['details']['countryCode'] == 'RU'
        assert info['details']['isp'] == 'Evil Corp ISP'
        assert info['details']['totalReports'] == 1234

    # --- Edge Cases ---

    def test_rapid_consecutive_lookups_same_ip(self):
        """
        BUSINESS LOGIC: Rapid clicks shouldn't cause multiple API calls.

        User double-clicks "Lookup" button - only one API call should happen.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker_file = Path(tmpdir) / "lookups.json"
            with patch.object(IPLookupTracker, 'TRACKER_FILE', tracker_file):
                tracker = IPLookupTracker()

                # First check allows lookup
                assert tracker.should_lookup("8.8.8.8") is True

                # Record immediately
                tracker.record_lookup("8.8.8.8", "safe", "Test")

                # Immediate second check should be blocked
                assert tracker.should_lookup("8.8.8.8") is False

                # Even after a millisecond delay
                import time
                time.sleep(0.001)
                assert tracker.should_lookup("8.8.8.8") is False

    def test_overwrite_existing_lookup_updates_timestamp(self):
        """
        BUSINESS LOGIC: Re-lookup after expiration updates the entry.

        If IP was looked up yesterday, re-lookup today should
        replace old data with fresh data, not append.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker_file = Path(tmpdir) / "lookups.json"
            with patch.object(IPLookupTracker, 'TRACKER_FILE', tracker_file):
                tracker = IPLookupTracker()

                # First lookup says 'safe'
                old_time = (datetime.now() - timedelta(hours=1)).isoformat()
                tracker.lookups = {
                    '8.8.8.8': {
                        'timestamp': old_time,
                        'result': 'safe',
                        'source': 'OldSource',
                        'details': {'old': 'data'}
                    }
                }

                # Re-lookup says 'suspect'
                tracker.record_lookup("8.8.8.8", "suspect", "NewSource", {'new': 'data'})

                # Should have new data, not old
                info = tracker.get_lookup_info("8.8.8.8")
                assert info['result'] == 'suspect'
                assert info['source'] == 'NewSource'
                assert info['details'] == {'new': 'data'}

                # Only one entry for this IP
                assert len([k for k in tracker.lookups if k == '8.8.8.8']) == 1

    def test_empty_details_doesnt_crash(self):
        """
        BUSINESS LOGIC: Missing details field shouldn't crash display.

        Older lookups might not have details field.
        get_all_lookups() must handle gracefully.
        """
        tracker = IPLookupTracker()
        now = datetime.now().isoformat()

        # Entry without details field (legacy data)
        tracker.lookups = {
            '8.8.8.8': {
                'timestamp': now,
                'result': 'safe',
                'source': 'Test'
                # No 'details' key
            }
        }

        results = tracker.get_all_lookups()

        # Should not crash, should have empty details
        assert len(results) == 1
        assert results[0]['details'] == {}

    def test_missing_source_uses_unknown(self):
        """
        BUSINESS LOGIC: Missing source field shows 'Unknown'.

        Older lookups might not have source field.
        UI should show something rather than crash.
        """
        tracker = IPLookupTracker()
        now = datetime.now().isoformat()

        # Entry without source field (legacy data)
        tracker.lookups = {
            '8.8.8.8': {
                'timestamp': now,
                'result': 'safe'
                # No 'source' key
            }
        }

        results = tracker.get_all_lookups()

        assert results[0]['source'] == 'Unknown'
