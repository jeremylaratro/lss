"""
Alert data model
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional


@dataclass
class Alert:
    """Represents a parsed IDS alert from Suricata or Snort"""

    engine: str
    timestamp: str
    severity: int
    signature: str
    src_ip: str
    src_port: str
    dest_ip: str
    dest_port: str
    proto: str
    category: str
    sid: str
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Optional['Alert']:
        """Create an Alert from a dictionary"""
        if not data:
            return None
        return cls(
            engine=data.get('engine', ''),
            timestamp=data.get('timestamp', ''),
            severity=data.get('severity', 3),
            signature=data.get('signature', 'Unknown'),
            src_ip=data.get('src_ip', ''),
            src_port=str(data.get('src_port', '')),
            dest_ip=data.get('dest_ip', ''),
            dest_port=str(data.get('dest_port', '')),
            proto=data.get('proto', ''),
            category=data.get('category', 'Unknown'),
            sid=str(data.get('sid', '')),
            raw=data.get('raw', {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary"""
        return {
            'engine': self.engine,
            'timestamp': self.timestamp,
            'severity': self.severity,
            'signature': self.signature,
            'src_ip': self.src_ip,
            'src_port': self.src_port,
            'dest_ip': self.dest_ip,
            'dest_port': self.dest_port,
            'proto': self.proto,
            'category': self.category,
            'sid': self.sid,
            'raw': self.raw,
        }

    @property
    def severity_label(self) -> str:
        """Get human-readable severity label"""
        labels = {1: 'CRITICAL', 2: 'HIGH', 3: 'MEDIUM', 4: 'LOW'}
        return labels.get(self.severity, 'INFO')

    def matches_filter(
        self,
        hidden_signatures: set = None,
        hidden_src_ips: set = None,
        hidden_dest_ips: set = None,
        hidden_categories: set = None,
        engine_filter: str = 'all'
    ) -> bool:
        """Check if this alert should be displayed based on filter criteria"""
        # Engine filter
        if engine_filter != 'all' and self.engine != engine_filter:
            return False

        # Hidden signature filter
        if hidden_signatures and self.signature in hidden_signatures:
            return False

        # Hidden IP filters
        if hidden_src_ips and self.src_ip in hidden_src_ips:
            return False
        if hidden_dest_ips and self.dest_ip in hidden_dest_ips:
            return False

        # Hidden category filter
        if hidden_categories and self.category in hidden_categories:
            return False

        return True
