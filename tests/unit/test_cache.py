"""
Unit tests for ids_suite.threat_intel.cache module
"""

import pytest
from datetime import datetime, timedelta
from time import sleep
from ids_suite.threat_intel.cache import ThreatIntelCache


class TestThreatIntelCache:
    """Test suite for ThreatIntelCache class"""

    def test_cache_initialization_default_ttl(self):
        """Test cache initializes with default TTL of 24 hours"""
        cache = ThreatIntelCache()
        assert cache.ttl == timedelta(hours=24)
        assert cache.cache == {}

    def test_cache_initialization_custom_ttl(self):
        """Test cache initializes with custom TTL"""
        cache = ThreatIntelCache(ttl_hours=12)
        assert cache.ttl == timedelta(hours=12)

        cache2 = ThreatIntelCache(ttl_hours=1)
        assert cache2.ttl == timedelta(hours=1)

    def test_set_and_get_basic(self):
        """Test basic set and get operations"""
        cache = ThreatIntelCache()
        result = {"is_malicious": True, "score": 85}

        cache.set("192.168.1.1", result)
        retrieved = cache.get("192.168.1.1")

        assert retrieved == result

    def test_get_nonexistent_key(self):
        """Test getting a key that doesn't exist returns None"""
        cache = ThreatIntelCache()
        assert cache.get("nonexistent.ip") is None

    def test_get_expired_entry(self):
        """Test that expired entries return None and are removed"""
        # Use very short TTL for testing
        cache = ThreatIntelCache(ttl_hours=0)  # 0 hours = immediate expiry
        result = {"is_malicious": False, "score": 0}

        cache.set("8.8.8.8", result)

        # Even with 0 hours, need to ensure time has passed
        sleep(0.01)  # Small delay to ensure timestamp difference

        # Should be expired
        retrieved = cache.get("8.8.8.8")
        assert retrieved is None

        # Entry should be removed from cache
        assert "8.8.8.8" not in cache.cache

    def test_get_non_expired_entry(self):
        """Test that non-expired entries are returned"""
        cache = ThreatIntelCache(ttl_hours=24)
        result = {"is_malicious": True, "score": 95, "details": {"country": "US"}}

        cache.set("malicious.example.com", result)

        # Should still be valid
        retrieved = cache.get("malicious.example.com")
        assert retrieved == result
        assert "malicious.example.com" in cache.cache

    def test_multiple_entries(self):
        """Test caching multiple entries"""
        cache = ThreatIntelCache()

        entries = {
            "ip1.example.com": {"score": 10},
            "ip2.example.com": {"score": 20},
            "ip3.example.com": {"score": 30},
        }

        for indicator, result in entries.items():
            cache.set(indicator, result)

        for indicator, expected_result in entries.items():
            assert cache.get(indicator) == expected_result

    def test_overwrite_existing_entry(self):
        """Test that setting an existing key updates the value"""
        cache = ThreatIntelCache()

        cache.set("test.ip", {"score": 50})
        assert cache.get("test.ip") == {"score": 50}

        # Overwrite
        cache.set("test.ip", {"score": 75, "updated": True})
        assert cache.get("test.ip") == {"score": 75, "updated": True}

    def test_clear_cache(self):
        """Test clearing all cache entries"""
        cache = ThreatIntelCache()

        cache.set("entry1", {"data": 1})
        cache.set("entry2", {"data": 2})
        cache.set("entry3", {"data": 3})

        assert len(cache.cache) == 3

        cache.clear()

        assert len(cache.cache) == 0
        assert cache.get("entry1") is None
        assert cache.get("entry2") is None
        assert cache.get("entry3") is None

    def test_remove_existing_entry(self):
        """Test removing a specific entry returns True"""
        cache = ThreatIntelCache()

        cache.set("to_remove", {"data": "test"})
        assert cache.get("to_remove") is not None

        result = cache.remove("to_remove")

        assert result is True
        assert cache.get("to_remove") is None
        assert "to_remove" not in cache.cache

    def test_remove_nonexistent_entry(self):
        """Test removing a nonexistent entry returns False"""
        cache = ThreatIntelCache()

        result = cache.remove("does_not_exist")

        assert result is False

    def test_cleanup_expired_no_expired(self):
        """Test cleanup_expired returns 0 when no entries are expired"""
        cache = ThreatIntelCache(ttl_hours=24)

        cache.set("fresh1", {"data": 1})
        cache.set("fresh2", {"data": 2})
        cache.set("fresh3", {"data": 3})

        removed_count = cache.cleanup_expired()

        assert removed_count == 0
        assert len(cache.cache) == 3

    def test_cleanup_expired_with_expired(self):
        """Test cleanup_expired removes expired entries"""
        cache = ThreatIntelCache(ttl_hours=0)

        # Add entries that will expire immediately
        cache.set("expired1", {"data": 1})
        cache.set("expired2", {"data": 2})
        cache.set("expired3", {"data": 3})

        # Wait to ensure expiration
        sleep(0.01)

        removed_count = cache.cleanup_expired()

        assert removed_count == 3
        assert len(cache.cache) == 0

    def test_cleanup_expired_mixed(self):
        """Test cleanup_expired with mix of expired and fresh entries"""
        cache = ThreatIntelCache(ttl_hours=1)

        # Manually set some entries with old timestamps
        old_time = datetime.now() - timedelta(hours=2)
        cache.cache["old1"] = ({"data": 1}, old_time)
        cache.cache["old2"] = ({"data": 2}, old_time)

        # Add fresh entries
        cache.set("fresh1", {"data": 3})
        cache.set("fresh2", {"data": 4})

        assert len(cache.cache) == 4

        removed_count = cache.cleanup_expired()

        assert removed_count == 2
        assert len(cache.cache) == 2
        assert cache.get("fresh1") == {"data": 3}
        assert cache.get("fresh2") == {"data": 4}
        assert cache.get("old1") is None
        assert cache.get("old2") is None

    def test_ttl_expiration_boundary(self):
        """Test expiration at exact TTL boundary"""
        cache = ThreatIntelCache(ttl_hours=1)

        # Manually set entry with timestamp exactly at TTL boundary
        boundary_time = datetime.now() - timedelta(hours=1)
        cache.cache["boundary"] = ({"data": "test"}, boundary_time)

        # At exact boundary, should be expired (>= check)
        result = cache.get("boundary")
        assert result is None

    def test_cache_stores_complex_results(self):
        """Test that cache can store complex nested result structures"""
        cache = ThreatIntelCache()

        complex_result = {
            "indicator": "203.0.113.50",
            "is_malicious": True,
            "score": 88,
            "services": {
                "virustotal": {
                    "positives": 45,
                    "total": 70,
                    "scans": {
                        "scanner1": "malware",
                        "scanner2": "clean"
                    }
                },
                "abuseipdb": {
                    "abuse_score": 95,
                    "reports": [1, 2, 3, 4, 5]
                }
            },
            "metadata": {
                "country": "Unknown",
                "asn": None,
                "tags": ["botnet", "malware", "c2"]
            }
        }

        cache.set("complex_ip", complex_result)
        retrieved = cache.get("complex_ip")

        assert retrieved == complex_result
        assert retrieved["services"]["virustotal"]["positives"] == 45
        assert retrieved["metadata"]["tags"] == ["botnet", "malware", "c2"]

    def test_cache_thread_safety_awareness(self):
        """Test that cache operations work correctly in sequence (basic sanity)"""
        cache = ThreatIntelCache()

        # Simulate multiple operations in sequence
        for i in range(100):
            cache.set(f"ip_{i}", {"score": i})

        # Verify all entries
        for i in range(100):
            result = cache.get(f"ip_{i}")
            assert result == {"score": i}

        # Cleanup some
        for i in range(0, 100, 2):
            cache.remove(f"ip_{i}")

        # Verify odd entries remain
        for i in range(1, 100, 2):
            assert cache.get(f"ip_{i}") == {"score": i}

        # Verify even entries removed
        for i in range(0, 100, 2):
            assert cache.get(f"ip_{i}") is None

    def test_timestamp_stored_correctly(self):
        """Test that timestamps are stored with entries"""
        cache = ThreatIntelCache()

        before_time = datetime.now()
        cache.set("test_timestamp", {"data": "test"})
        after_time = datetime.now()

        # Access internal cache structure to verify timestamp
        assert "test_timestamp" in cache.cache
        result, timestamp = cache.cache["test_timestamp"]

        assert result == {"data": "test"}
        assert before_time <= timestamp <= after_time

    def test_empty_result_caching(self):
        """Test that empty results can be cached"""
        cache = ThreatIntelCache()

        empty_result = {}
        cache.set("empty_indicator", empty_result)

        retrieved = cache.get("empty_indicator")
        assert retrieved == empty_result
        assert retrieved == {}

    def test_cache_size_tracking(self):
        """Test tracking number of cached entries"""
        cache = ThreatIntelCache()

        assert len(cache.cache) == 0

        for i in range(10):
            cache.set(f"entry_{i}", {"num": i})
            assert len(cache.cache) == i + 1

        cache.remove("entry_5")
        assert len(cache.cache) == 9

        cache.clear()
        assert len(cache.cache) == 0
