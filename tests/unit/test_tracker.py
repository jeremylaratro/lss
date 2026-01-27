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
