"""
Suricata IDS engine implementation
"""

import json
import os
from typing import Dict, Any, Optional

from ids_suite.engines.base import IDSEngine


class SuricataEngine(IDSEngine):
    """Suricata IDS engine implementation"""

    def get_name(self) -> str:
        return "Suricata"

    def get_service_name(self) -> str:
        return "suricata-laptop"

    def get_log_path(self) -> str:
        return "/var/log/suricata/eve.json"

    def get_config_path(self) -> str:
        return "/etc/suricata/suricata.yaml"

    def is_installed(self) -> bool:
        return os.path.exists("/usr/bin/suricata") or os.path.exists("/usr/local/bin/suricata")

    def parse_alert(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a Suricata EVE JSON log line.

        Returns alert dict if line is an alert event, None otherwise.
        """
        try:
            data = json.loads(line)
            if data.get('event_type') != 'alert':
                return None
            alert = data.get('alert', {})
            return {
                'engine': 'suricata',
                'timestamp': data.get('timestamp', '')[:19],
                'severity': alert.get('severity', 3),
                'signature': alert.get('signature', 'Unknown'),
                'src_ip': data.get('src_ip', ''),
                'src_port': data.get('src_port', ''),
                'dest_ip': data.get('dest_ip', ''),
                'dest_port': data.get('dest_port', ''),
                'proto': data.get('proto', ''),
                'category': alert.get('category', 'Unknown'),
                'sid': alert.get('signature_id', ''),
                'raw': data
            }
        except json.JSONDecodeError:
            return None
