"""
Tests for ids_suite/core/config.py - Configuration management

Sprint 1.1: Configuration & Validators
Target: 95% coverage of Config class
"""

import json
import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
import threading


class TestConfigSingleton:
    """Test singleton pattern for Config class"""

    def test_singleton_pattern(self, temp_dir):
        """CFG-001: Verify only one Config instance exists"""
        # Reset singleton for clean test
        from ids_suite.core.config import Config
        Config._instance = None

        tmp_path = Path(temp_dir)
        with patch.object(Config, 'settings_path', new_callable=lambda: property(
            lambda self: tmp_path / 'settings.json'
        )):
            config1 = Config()
            config2 = Config()

            assert config1 is config2
            assert id(config1) == id(config2)

    def test_singleton_thread_safety(self, temp_dir):
        """CFG-002: Multiple threads should get the same instance"""
        from ids_suite.core.config import Config
        Config._instance = None

        tmp_path = Path(temp_dir)
        instances = []

        def get_instance():
            with patch.object(Config, 'settings_path', new_callable=lambda: property(
                lambda self: tmp_path / 'settings.json'
            )):
                instances.append(Config())

        threads = [threading.Thread(target=get_instance) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All instances should be the same object
        assert len(set(id(inst) for inst in instances)) == 1


class TestConfigLoading:
    """Test configuration loading functionality"""

    def test_load_default_settings(self, temp_dir):
        """CFG-003: Defaults load when no config file exists"""
        from ids_suite.core.config import Config
        Config._instance = None

        tmp_path = Path(temp_dir)
        settings_path = tmp_path / 'nonexistent' / 'settings.json'

        with patch.object(Config, 'settings_path', new_callable=lambda: property(
            lambda self: settings_path
        )):
            config = Config()

            # Verify defaults are loaded
            assert config.auto_refresh is True
            assert config.engine_filter == 'all'
            assert isinstance(config.hidden_signatures, set)
            assert len(config.hidden_signatures) == 0

    def test_load_existing_settings(self, temp_dir):
        """CFG-004: Load settings from existing config file"""
        from ids_suite.core.config import Config
        Config._instance = None

        tmp_path = Path(temp_dir)
        settings_path = tmp_path / 'settings.json'
        custom_settings = {
            'auto_refresh': False,
            'refresh_interval': 10000,
            'data_retention_minutes': 60,
            'hidden_signatures': ['sig1', 'sig2'],
            'engine_filter': 'suricata'
        }
        with open(settings_path, 'w') as f:
            json.dump(custom_settings, f)

        with patch.object(Config, 'settings_path', new_callable=lambda: property(
            lambda self: settings_path
        )):
            config = Config()

            assert config.auto_refresh is False
            assert config.refresh_interval == 10000
            assert config.data_retention_minutes == 60
            assert 'sig1' in config.hidden_signatures
            assert config.engine_filter == 'suricata'

    def test_load_corrupted_file(self, temp_dir):
        """CFG-005: Graceful handling of invalid JSON in config file"""
        from ids_suite.core.config import Config
        Config._instance = None

        tmp_path = Path(temp_dir)
        settings_path = tmp_path / 'settings.json'
        with open(settings_path, 'w') as f:
            f.write("{ invalid json }")

        with patch.object(Config, 'settings_path', new_callable=lambda: property(
            lambda self: settings_path
        )):
            config = Config()

            # Should fall back to defaults
            assert config.auto_refresh is True
            assert config.engine_filter == 'all'


class TestConfigSaving:
    """Test configuration saving functionality"""

    def test_save_settings(self, temp_dir):
        """CFG-006: Save creates valid JSON file"""
        from ids_suite.core.config import Config
        Config._instance = None

        tmp_path = Path(temp_dir)
        settings_path = tmp_path / 'settings.json'

        with patch.object(Config, 'settings_path', new_callable=lambda: property(
            lambda self: settings_path
        )):
            config = Config()
            config.auto_refresh = False
            config.refresh_interval = 15000
            result = config.save()

            assert result is True
            assert settings_path.exists()

            # Verify saved content
            with open(settings_path) as f:
                saved = json.load(f)
            assert saved['auto_refresh'] is False
            assert saved['refresh_interval'] == 15000

    def test_save_creates_directory(self, temp_dir):
        """CFG-007: Parent directories are created if missing"""
        from ids_suite.core.config import Config
        Config._instance = None

        tmp_path = Path(temp_dir)
        settings_path = tmp_path / 'nested' / 'dir' / 'settings.json'

        with patch.object(Config, 'settings_path', new_callable=lambda: property(
            lambda self: settings_path
        )):
            config = Config()
            result = config.save()

            assert result is True
            assert settings_path.parent.exists()
            assert settings_path.exists()


class TestConfigGetSet:
    """Test get/set functionality"""

    def test_get_existing_key(self, temp_dir):
        """CFG-008: Get returns stored value"""
        from ids_suite.core.config import Config
        Config._instance = None

        tmp_path = Path(temp_dir)
        with patch.object(Config, 'settings_path', new_callable=lambda: property(
            lambda self: tmp_path / 'settings.json'
        )):
            config = Config()
            config.set('test_key', 'test_value')

            assert config.get('test_key') == 'test_value'

    def test_get_missing_key_with_default(self, temp_dir):
        """CFG-009: Get returns default for missing key"""
        from ids_suite.core.config import Config
        Config._instance = None

        tmp_path = Path(temp_dir)
        with patch.object(Config, 'settings_path', new_callable=lambda: property(
            lambda self: tmp_path / 'settings.json'
        )):
            config = Config()

            assert config.get('nonexistent_key', 'fallback') == 'fallback'
            assert config.get('another_missing') is None

    def test_set_and_persist(self, temp_dir):
        """CFG-010: Set updates in-memory and can be persisted"""
        from ids_suite.core.config import Config
        Config._instance = None

        tmp_path = Path(temp_dir)
        settings_path = tmp_path / 'settings.json'

        with patch.object(Config, 'settings_path', new_callable=lambda: property(
            lambda self: settings_path
        )):
            config = Config()
            config.set('custom_setting', 42)
            config.save()

            # Verify in-memory
            assert config.get('custom_setting') == 42

            # Verify on disk
            with open(settings_path) as f:
                saved = json.load(f)
            assert saved['custom_setting'] == 42


class TestConfigReset:
    """Test configuration reset"""

    def test_reset_to_defaults(self, temp_dir):
        """CFG-011: Reset clears all custom values"""
        from ids_suite.core.config import Config
        Config._instance = None

        tmp_path = Path(temp_dir)
        with patch.object(Config, 'settings_path', new_callable=lambda: property(
            lambda self: tmp_path / 'settings.json'
        )):
            config = Config()

            # Set custom values
            config.auto_refresh = False
            config.refresh_interval = 99999
            config.hidden_signatures = {'sig1', 'sig2'}

            # Reset
            config.reset()

            # Verify defaults restored
            assert config.auto_refresh is True
            assert config.engine_filter == 'all'
            assert len(config.hidden_signatures) == 0


class TestConfigProperties:
    """Test property getters and setters"""

    def test_auto_refresh_property(self, temp_dir):
        """CFG-012: Bool property getter/setter"""
        from ids_suite.core.config import Config
        Config._instance = None

        tmp_path = Path(temp_dir)
        with patch.object(Config, 'settings_path', new_callable=lambda: property(
            lambda self: tmp_path / 'settings.json'
        )):
            config = Config()

            config.auto_refresh = False
            assert config.auto_refresh is False

            config.auto_refresh = True
            assert config.auto_refresh is True

    def test_refresh_interval_property(self, temp_dir):
        """CFG-013: Int property for refresh interval"""
        from ids_suite.core.config import Config
        Config._instance = None

        tmp_path = Path(temp_dir)
        with patch.object(Config, 'settings_path', new_callable=lambda: property(
            lambda self: tmp_path / 'settings.json'
        )):
            config = Config()

            config.refresh_interval = 10000
            assert config.refresh_interval == 10000

            config.refresh_interval = 5000
            assert config.refresh_interval == 5000

    def test_data_retention_property(self, temp_dir):
        """CFG-014: Int property for data retention"""
        from ids_suite.core.config import Config
        Config._instance = None

        tmp_path = Path(temp_dir)
        with patch.object(Config, 'settings_path', new_callable=lambda: property(
            lambda self: tmp_path / 'settings.json'
        )):
            config = Config()

            config.data_retention_minutes = 240
            assert config.data_retention_minutes == 240

    def test_hidden_signatures_list_to_set(self, temp_dir):
        """CFG-015: List converts to set properly"""
        from ids_suite.core.config import Config
        Config._instance = None

        tmp_path = Path(temp_dir)
        settings_path = tmp_path / 'settings.json'
        with open(settings_path, 'w') as f:
            json.dump({'hidden_signatures': ['sig1', 'sig2', 'sig1']}, f)

        with patch.object(Config, 'settings_path', new_callable=lambda: property(
            lambda self: settings_path
        )):
            config = Config()

            sigs = config.hidden_signatures
            assert isinstance(sigs, set)
            assert len(sigs) == 2  # Duplicates removed
            assert 'sig1' in sigs
            assert 'sig2' in sigs

    def test_hidden_ips_persistence(self, temp_dir):
        """CFG-016: IP sets roundtrip correctly"""
        from ids_suite.core.config import Config
        Config._instance = None

        tmp_path = Path(temp_dir)
        settings_path = tmp_path / 'settings.json'

        with patch.object(Config, 'settings_path', new_callable=lambda: property(
            lambda self: settings_path
        )):
            config = Config()

            # Set IPs
            config.hidden_src_ips = {'192.168.1.1', '10.0.0.1'}
            config.hidden_dest_ips = {'8.8.8.8'}
            config.save()

            # Reload and verify
            Config._instance = None
            config2 = Config()

            assert '192.168.1.1' in config2.hidden_src_ips
            assert '10.0.0.1' in config2.hidden_src_ips
            assert '8.8.8.8' in config2.hidden_dest_ips

    def test_engine_filter_values(self, temp_dir):
        """CFG-017: Engine filter accepts valid values"""
        from ids_suite.core.config import Config
        Config._instance = None

        tmp_path = Path(temp_dir)
        with patch.object(Config, 'settings_path', new_callable=lambda: property(
            lambda self: tmp_path / 'settings.json'
        )):
            config = Config()

            for value in ['all', 'suricata', 'snort']:
                config.engine_filter = value
                assert config.engine_filter == value


class TestConfigRoundtrip:
    """Test full save/load cycles"""

    def test_settings_roundtrip(self, temp_dir):
        """CFG-020: Full save/load roundtrip preserves all settings"""
        from ids_suite.core.config import Config
        Config._instance = None

        tmp_path = Path(temp_dir)
        settings_path = tmp_path / 'settings.json'

        with patch.object(Config, 'settings_path', new_callable=lambda: property(
            lambda self: settings_path
        )):
            # Create and configure
            config1 = Config()
            config1.auto_refresh = False
            config1.refresh_interval = 7500
            config1.data_retention_minutes = 180
            config1.engine_filter = 'suricata'
            config1.hidden_signatures = {'ET SCAN', 'GPL ATTACK'}
            config1.hidden_src_ips = {'192.168.1.100'}
            config1.hidden_dest_ips = {'1.2.3.4'}
            config1.hidden_categories = {'scan', 'attack'}
            config1.save()

            # Reset singleton and reload
            Config._instance = None
            config2 = Config()

            # Verify all values preserved
            assert config2.auto_refresh is False
            assert config2.refresh_interval == 7500
            assert config2.data_retention_minutes == 180
            assert config2.engine_filter == 'suricata'
            assert 'ET SCAN' in config2.hidden_signatures
            assert 'GPL ATTACK' in config2.hidden_signatures
            assert '192.168.1.100' in config2.hidden_src_ips
            assert '1.2.3.4' in config2.hidden_dest_ips
            assert 'scan' in config2.hidden_categories
