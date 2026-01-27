"""
Application configuration management
"""

import json
import os
from pathlib import Path
from typing import Optional, Dict, Any

from ids_suite.core.constants import Paths, Limits, Timeouts


class Config:
    """Centralized configuration management for the Security Suite"""

    _instance: Optional['Config'] = None
    _settings: Dict[str, Any] = {}

    def __new__(cls):
        """Singleton pattern to ensure single configuration instance"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_settings()
        return cls._instance

    @property
    def settings_path(self) -> Path:
        """Get the settings file path, expanding user directory"""
        return Path(os.path.expanduser(Paths.SETTINGS_FILE))

    def _load_settings(self) -> None:
        """Load settings from disk"""
        settings_file = self.settings_path
        if settings_file.exists():
            try:
                with open(settings_file, 'r') as f:
                    self._settings = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._settings = self._get_defaults()
        else:
            self._settings = self._get_defaults()

    def _get_defaults(self) -> Dict[str, Any]:
        """Get default settings"""
        return {
            'auto_refresh': True,
            'refresh_interval': Timeouts.AUTO_REFRESH,
            'data_retention_minutes': Limits.DATA_RETENTION_MINUTES,
            'hidden_signatures': [],
            'hidden_src_ips': [],
            'hidden_dest_ips': [],
            'hidden_categories': [],
            'engine_filter': 'all',
            'selected_time_range': 'live',
        }

    def save(self) -> bool:
        """Save settings to disk"""
        settings_file = self.settings_path
        try:
            settings_file.parent.mkdir(parents=True, exist_ok=True)
            with open(settings_file, 'w') as f:
                json.dump(self._settings, f, indent=2)
            return True
        except IOError:
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """Get a setting value"""
        return self._settings.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a setting value"""
        self._settings[key] = value

    def reset(self) -> None:
        """Reset all settings to defaults"""
        self._settings = self._get_defaults()

    @property
    def auto_refresh(self) -> bool:
        return self.get('auto_refresh', True)

    @auto_refresh.setter
    def auto_refresh(self, value: bool) -> None:
        self.set('auto_refresh', value)

    @property
    def refresh_interval(self) -> int:
        return self.get('refresh_interval', Timeouts.AUTO_REFRESH)

    @refresh_interval.setter
    def refresh_interval(self, value: int) -> None:
        self.set('refresh_interval', value)

    @property
    def data_retention_minutes(self) -> int:
        return self.get('data_retention_minutes', Limits.DATA_RETENTION_MINUTES)

    @data_retention_minutes.setter
    def data_retention_minutes(self, value: int) -> None:
        self.set('data_retention_minutes', value)

    @property
    def engine_filter(self) -> str:
        return self.get('engine_filter', 'all')

    @engine_filter.setter
    def engine_filter(self, value: str) -> None:
        self.set('engine_filter', value)

    @property
    def hidden_signatures(self) -> set:
        return set(self.get('hidden_signatures', []))

    @hidden_signatures.setter
    def hidden_signatures(self, value: set) -> None:
        self.set('hidden_signatures', list(value))

    @property
    def hidden_src_ips(self) -> set:
        return set(self.get('hidden_src_ips', []))

    @hidden_src_ips.setter
    def hidden_src_ips(self, value: set) -> None:
        self.set('hidden_src_ips', list(value))

    @property
    def hidden_dest_ips(self) -> set:
        return set(self.get('hidden_dest_ips', []))

    @hidden_dest_ips.setter
    def hidden_dest_ips(self, value: set) -> None:
        self.set('hidden_dest_ips', list(value))

    @property
    def hidden_categories(self) -> set:
        return set(self.get('hidden_categories', []))

    @hidden_categories.setter
    def hidden_categories(self, value: set) -> None:
        self.set('hidden_categories', list(value))
