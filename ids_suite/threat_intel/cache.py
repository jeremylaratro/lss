"""
Threat Intelligence caching with TTL
"""

from datetime import datetime, timedelta
from typing import Dict, Any, Optional


class ThreatIntelCache:
    """Cache for threat intelligence lookups with TTL"""

    def __init__(self, ttl_hours: int = 24):
        self.cache: Dict[str, tuple] = {}
        self.ttl = timedelta(hours=ttl_hours)

    def get(self, indicator: str) -> Optional[Dict[str, Any]]:
        """Get cached result if not expired"""
        if indicator in self.cache:
            result, timestamp = self.cache[indicator]
            if datetime.now() - timestamp < self.ttl:
                return result
            del self.cache[indicator]
        return None

    def set(self, indicator: str, result: Dict[str, Any]) -> None:
        """Cache a result with current timestamp"""
        self.cache[indicator] = (result, datetime.now())

    def clear(self) -> None:
        """Clear all cached entries"""
        self.cache.clear()

    def remove(self, indicator: str) -> bool:
        """Remove a specific cached entry"""
        if indicator in self.cache:
            del self.cache[indicator]
            return True
        return False

    def cleanup_expired(self) -> int:
        """Remove all expired entries and return count removed"""
        now = datetime.now()
        expired = [
            key for key, (_, timestamp) in self.cache.items()
            if now - timestamp >= self.ttl
        ]
        for key in expired:
            del self.cache[key]
        return len(expired)
