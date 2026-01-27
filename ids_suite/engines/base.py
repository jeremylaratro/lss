"""
Abstract base class for IDS engines
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class IDSEngine(ABC):
    """Abstract base class for IDS engines (Suricata, Snort)"""

    @abstractmethod
    def get_name(self) -> str:
        """Get display name of the IDS engine"""
        pass

    @abstractmethod
    def get_service_name(self) -> str:
        """Get systemd service name"""
        pass

    @abstractmethod
    def get_log_path(self) -> str:
        """Get path to the log file"""
        pass

    @abstractmethod
    def get_config_path(self) -> str:
        """Get path to the configuration file"""
        pass

    @abstractmethod
    def is_installed(self) -> bool:
        """Check if the IDS engine is installed"""
        pass

    @abstractmethod
    def parse_alert(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a log line and return alert dict if it's an alert, None otherwise"""
        pass
