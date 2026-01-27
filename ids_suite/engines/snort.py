"""
Snort 3 IDS engine implementation
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, Optional

from ids_suite.engines.base import IDSEngine


class SnortEngine(IDSEngine):
    """Snort 3 IDS engine implementation"""

    def get_name(self) -> str:
        return "Snort"

    def get_service_name(self) -> str:
        return "snort"

    def get_log_path(self) -> str:
        return "/var/log/snort/alert_json.txt"

    def get_config_path(self) -> str:
        return "/etc/snort/snort.lua"

    def is_installed(self) -> bool:
        return os.path.exists("/usr/bin/snort") or os.path.exists("/usr/local/bin/snort")

    def parse_alert(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a Snort 3 JSON alert line.

        Returns alert dict if parsing succeeds, None otherwise.
        """
        try:
            data = json.loads(line)
            timestamp = data.get('timestamp', '')

            # Normalize timestamp format
            if timestamp and '-' in timestamp:
                try:
                    parts = timestamp.split('-')
                    date_part = parts[0]
                    time_part = parts[1].split('.')[0] if '.' in parts[1] else parts[1]
                    year = datetime.now().year
                    month, day = date_part.split('/')
                    timestamp = f"{year}-{month.zfill(2)}-{day.zfill(2)}T{time_part}"
                except Exception:
                    pass

            # Parse source and destination address:port pairs
            src_ap = data.get('src_ap', '')
            dst_ap = data.get('dst_ap', '')

            src_ip, src_port = self._parse_address_port(src_ap)
            dest_ip, dest_port = self._parse_address_port(dst_ap)

            return {
                'engine': 'snort',
                'timestamp': timestamp,
                'severity': data.get('priority', 3),
                'signature': data.get('msg', 'Unknown'),
                'src_ip': src_ip,
                'src_port': src_port,
                'dest_ip': dest_ip,
                'dest_port': dest_port,
                'proto': data.get('proto', ''),
                'category': data.get('class', 'Unknown'),
                'sid': data.get('sid', ''),
                'raw': data
            }
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _parse_address_port(ap: str) -> tuple:
        """Parse address:port string, handling both IPv4 and IPv6"""
        if not ap:
            return ('', '')
        if ':' in ap:
            parts = ap.rsplit(':', 1)
            if len(parts) == 2:
                return (parts[0], parts[1])
            return (ap, '')
        return (ap, '')
