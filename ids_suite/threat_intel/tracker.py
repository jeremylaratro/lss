"""
IP Lookup Tracker to avoid duplicate API queries
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, List, Any

from ids_suite.core.utils import is_private_ip


class IPLookupTracker:
    """Track IP lookups to avoid duplicate queries within a time window.

    Default window is 12 hours to prevent burning API credits on repeated lookups.
    Stores detailed results for display in Intel tab.
    """

    TRACKER_FILE = Path.home() / ".config" / "ids-suite" / "ip_lookups.json"

    def __init__(self, window_hours: int = 12):
        self.window = timedelta(hours=window_hours)
        # {ip: {'timestamp': str, 'result': str, 'source': str, 'details': dict}}
        self.lookups: Dict[str, Dict] = {}
        self._load()

    def _load(self) -> None:
        """Load tracked lookups from file"""
        try:
            if self.TRACKER_FILE.exists():
                with open(self.TRACKER_FILE, 'r') as f:
                    data = json.load(f)
                    # Clean expired entries on load
                    now = datetime.now()
                    for ip, info in list(data.items()):
                        lookup_time = datetime.fromisoformat(info['timestamp'])
                        if now - lookup_time < self.window:
                            self.lookups[ip] = info
        except Exception as e:
            print(f"Error loading IP tracker: {e}")
            self.lookups = {}

    def _save(self) -> None:
        """Save tracked lookups to file"""
        try:
            self.TRACKER_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(self.TRACKER_FILE, 'w') as f:
                json.dump(self.lookups, f, indent=2)
        except Exception as e:
            print(f"Error saving IP tracker: {e}")

    def should_lookup(self, ip: str) -> bool:
        """Check if IP should be looked up (not in window and not private)"""
        # Never lookup private/LAN IPs
        if is_private_ip(ip):
            return False

        if ip in self.lookups:
            lookup_time = datetime.fromisoformat(self.lookups[ip]['timestamp'])
            if datetime.now() - lookup_time < self.window:
                return False
            # Expired, remove it
            del self.lookups[ip]
        return True

    def record_lookup(self, ip: str, result: str, source: str = 'AbuseIPDB',
                      details: Optional[Dict[str, Any]] = None) -> None:
        """Record an IP lookup result with full details.

        Args:
            ip: The IP address looked up
            result: Status string ('safe', 'suspect', 'DANGER', 'error')
            source: The threat intel source (e.g., 'AbuseIPDB', 'VirusTotal')
            details: Full API response details for display
        """
        self.lookups[ip] = {
            'timestamp': datetime.now().isoformat(),
            'result': result,
            'source': source,
            'details': details or {}
        }
        self._save()

    def get_result(self, ip: str) -> Optional[str]:
        """Get cached result status for an IP if within window"""
        if ip in self.lookups:
            lookup_time = datetime.fromisoformat(self.lookups[ip]['timestamp'])
            if datetime.now() - lookup_time < self.window:
                return self.lookups[ip]['result']
        return None

    def get_lookup_info(self, ip: str) -> Optional[Dict]:
        """Get full lookup info for an IP if within window"""
        if ip in self.lookups:
            lookup_time = datetime.fromisoformat(self.lookups[ip]['timestamp'])
            if datetime.now() - lookup_time < self.window:
                return self.lookups[ip]
        return None

    def get_all_lookups(self) -> List[Dict]:
        """Get all active lookups sorted by timestamp (newest first).

        Returns list of dicts with: ip, timestamp, result, source, details
        """
        now = datetime.now()
        active = []
        for ip, info in self.lookups.items():
            lookup_time = datetime.fromisoformat(info['timestamp'])
            if now - lookup_time < self.window:
                active.append({
                    'ip': ip,
                    'timestamp': info['timestamp'],
                    'result': info['result'],
                    'source': info.get('source', 'Unknown'),
                    'details': info.get('details', {})
                })
        # Sort by timestamp descending
        active.sort(key=lambda x: x['timestamp'], reverse=True)
        return active

    def get_stats(self) -> Dict[str, int]:
        """Get statistics about tracked IPs"""
        now = datetime.now()
        active = 0
        dangerous = 0
        suspect = 0
        for ip, info in self.lookups.items():
            lookup_time = datetime.fromisoformat(info['timestamp'])
            if now - lookup_time < self.window:
                active += 1
                if info['result'] == 'DANGER':
                    dangerous += 1
                elif info['result'] == 'suspect':
                    suspect += 1
        return {'active': active, 'dangerous': dangerous, 'suspect': suspect}
