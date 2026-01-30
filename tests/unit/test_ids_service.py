"""
Tests for ids_suite/services/ids_service.py - IDS Service manager

Target: 75%+ coverage
"""

import pytest
from unittest.mock import patch, MagicMock, PropertyMock, mock_open
import os
import subprocess

from ids_suite.services.ids_service import IDSService
from ids_suite.services.systemd import ServiceResult


class MockEngine:
    """Mock IDS engine for testing"""

    def __init__(self, name="Suricata", service_name="suricata",
                 config_path="/etc/suricata/suricata.yaml",
                 log_path="/var/log/suricata/eve.json",
                 installed=True):
        self._name = name
        self._service_name = service_name
        self._config_path = config_path
        self._log_path = log_path
        self._installed = installed

    def get_name(self):
        return self._name

    def get_service_name(self):
        return self._service_name

    def get_config_path(self):
        return self._config_path

    def get_log_path(self):
        return self._log_path

    def is_installed(self):
        return self._installed


class TestIDSServiceInit:
    """Test IDSService initialization"""

    def test_init_with_suricata(self):
        """IDS-001: IDSService initializes with Suricata engine"""
        engine = MockEngine(name="Suricata", service_name="suricata")
        svc = IDSService(engine)
        assert svc.engine == engine
        assert svc.service.service_name == "suricata"

    def test_init_with_snort(self):
        """IDS-002: IDSService initializes with Snort engine"""
        engine = MockEngine(name="Snort", service_name="snort")
        svc = IDSService(engine)
        assert svc.engine == engine
        assert svc.service.service_name == "snort"


class TestIDSServiceStartStop:
    """Test start/stop/restart methods"""

    @patch('ids_suite.services.systemd.SystemdService.start')
    def test_start_no_callback(self, mock_start):
        """IDS-003: start() without callback"""
        mock_start.return_value = ServiceResult(True, "OK", 0)
        engine = MockEngine()
        svc = IDSService(engine)
        svc.start()
        mock_start.assert_called_once()

    @patch('ids_suite.services.systemd.SystemdService.start')
    def test_start_with_callback(self, mock_start):
        """IDS-004: start() invokes callback with result"""
        result = ServiceResult(True, "Started", 0)
        mock_start.return_value = result
        engine = MockEngine()
        svc = IDSService(engine)

        callback_result = None
        def callback(r):
            nonlocal callback_result
            callback_result = r

        svc.start(callback=callback)
        assert callback_result == result

    @patch('ids_suite.services.systemd.SystemdService.stop')
    def test_stop_no_callback(self, mock_stop):
        """IDS-005: stop() without callback"""
        mock_stop.return_value = ServiceResult(True, "OK", 0)
        engine = MockEngine()
        svc = IDSService(engine)
        svc.stop()
        mock_stop.assert_called_once()

    @patch('ids_suite.services.systemd.SystemdService.stop')
    def test_stop_with_callback(self, mock_stop):
        """IDS-006: stop() invokes callback with result"""
        result = ServiceResult(True, "Stopped", 0)
        mock_stop.return_value = result
        engine = MockEngine()
        svc = IDSService(engine)

        callback_result = None
        def callback(r):
            nonlocal callback_result
            callback_result = r

        svc.stop(callback=callback)
        assert callback_result == result

    @patch('ids_suite.services.systemd.SystemdService.restart')
    def test_restart_no_callback(self, mock_restart):
        """IDS-007: restart() without callback"""
        mock_restart.return_value = ServiceResult(True, "OK", 0)
        engine = MockEngine()
        svc = IDSService(engine)
        svc.restart()
        mock_restart.assert_called_once()

    @patch('ids_suite.services.systemd.SystemdService.restart')
    def test_restart_with_callback(self, mock_restart):
        """IDS-008: restart() invokes callback with result"""
        result = ServiceResult(True, "Restarted", 0)
        mock_restart.return_value = result
        engine = MockEngine()
        svc = IDSService(engine)

        callback_result = None
        def callback(r):
            nonlocal callback_result
            callback_result = r

        svc.restart(callback=callback)
        assert callback_result == result


class TestIDSServiceIsRunning:
    """Test is_running method"""

    @patch('ids_suite.services.systemd.SystemdService.is_active')
    def test_is_running_true(self, mock_active):
        """IDS-009: is_running() returns True when active"""
        mock_active.return_value = True
        engine = MockEngine()
        svc = IDSService(engine)
        assert svc.is_running() is True

    @patch('ids_suite.services.systemd.SystemdService.is_active')
    def test_is_running_false(self, mock_active):
        """IDS-010: is_running() returns False when inactive"""
        mock_active.return_value = False
        engine = MockEngine()
        svc = IDSService(engine)
        assert svc.is_running() is False


class TestIDSServiceUpdateRules:
    """Test update_rules method"""

    @patch('ids_suite.services.ids_service.run_privileged_command')
    def test_update_rules_suricata(self, mock_cmd):
        """IDS-011: update_rules() runs suricata-update for Suricata"""
        mock_cmd.return_value = ServiceResult(True, "Updated", 0)
        engine = MockEngine(name="Suricata")
        svc = IDSService(engine)

        callback_called = False
        def callback(r):
            nonlocal callback_called
            callback_called = True
            assert r.success is True

        svc.update_rules(callback=callback)
        mock_cmd.assert_called_once_with("suricata-update --no-test")
        assert callback_called

    def test_update_rules_snort(self):
        """IDS-012: update_rules() returns not implemented for Snort"""
        engine = MockEngine(name="Snort")
        svc = IDSService(engine)

        callback_result = None
        def callback(r):
            nonlocal callback_result
            callback_result = r

        svc.update_rules(callback=callback)
        assert callback_result.success is False
        assert "not implemented" in callback_result.message.lower()

    @patch('ids_suite.services.ids_service.run_privileged_command')
    def test_update_rules_no_callback(self, mock_cmd):
        """IDS-013: update_rules() works without callback"""
        mock_cmd.return_value = ServiceResult(True, "OK", 0)
        engine = MockEngine(name="Suricata")
        svc = IDSService(engine)
        svc.update_rules()  # Should not raise
        mock_cmd.assert_called_once()


class TestIDSServiceReloadRules:
    """Test reload_rules method"""

    @patch('ids_suite.services.ids_service.run_privileged_command')
    def test_reload_rules_suricata(self, mock_cmd):
        """IDS-014: reload_rules() uses suricatasc for Suricata"""
        mock_cmd.return_value = ServiceResult(True, "Reloaded", 0)
        engine = MockEngine(name="Suricata")
        svc = IDSService(engine)

        callback_result = None
        def callback(r):
            nonlocal callback_result
            callback_result = r

        svc.reload_rules(callback=callback)
        mock_cmd.assert_called_once_with("suricatasc -c reload-rules")
        assert callback_result.success is True

    @patch('ids_suite.services.systemd.SystemdService.reload')
    def test_reload_rules_snort(self, mock_reload):
        """IDS-015: reload_rules() uses systemctl reload for Snort"""
        mock_reload.return_value = ServiceResult(True, "Reloaded", 0)
        engine = MockEngine(name="Snort")
        svc = IDSService(engine)

        callback_result = None
        def callback(r):
            nonlocal callback_result
            callback_result = r

        svc.reload_rules(callback=callback)
        mock_reload.assert_called_once()
        assert callback_result.success is True

    @patch('ids_suite.services.ids_service.run_privileged_command')
    def test_reload_rules_no_callback(self, mock_cmd):
        """IDS-016: reload_rules() works without callback"""
        mock_cmd.return_value = ServiceResult(True, "OK", 0)
        engine = MockEngine(name="Suricata")
        svc = IDSService(engine)
        svc.reload_rules()  # Should not raise


class TestIDSServiceUpdateAndReload:
    """Test update_and_reload method"""

    @patch('ids_suite.services.ids_service.run_privileged_batch')
    def test_update_and_reload_suricata_success(self, mock_batch):
        """IDS-017: update_and_reload() batches commands for Suricata"""
        mock_batch.return_value = MagicMock(
            success=True, message="OK", returncode=0, stdout="", stderr=""
        )
        engine = MockEngine(name="Suricata")
        svc = IDSService(engine)

        callback_result = None
        def callback(r):
            nonlocal callback_result
            callback_result = r

        svc.update_and_reload(callback=callback)
        mock_batch.assert_called_once_with([
            "suricata-update --no-test",
            "suricatasc -c reload-rules",
        ])
        assert callback_result.success is True
        assert "updated and reloaded" in callback_result.message.lower()

    @patch('ids_suite.services.ids_service.run_privileged_batch')
    def test_update_and_reload_suricata_failure(self, mock_batch):
        """IDS-018: update_and_reload() reports failure correctly"""
        mock_batch.return_value = MagicMock(
            success=False, message="Command failed", returncode=1, stdout="", stderr="error"
        )
        engine = MockEngine(name="Suricata")
        svc = IDSService(engine)

        callback_result = None
        def callback(r):
            nonlocal callback_result
            callback_result = r

        svc.update_and_reload(callback=callback)
        assert callback_result.success is False
        assert "Command failed" in callback_result.message

    def test_update_and_reload_snort(self):
        """IDS-019: update_and_reload() not implemented for Snort"""
        engine = MockEngine(name="Snort")
        svc = IDSService(engine)

        callback_result = None
        def callback(r):
            nonlocal callback_result
            callback_result = r

        svc.update_and_reload(callback=callback)
        assert callback_result.success is False
        assert "not implemented" in callback_result.message.lower()

    @patch('ids_suite.services.ids_service.run_privileged_batch')
    def test_update_and_reload_no_callback(self, mock_batch):
        """IDS-020: update_and_reload() works without callback"""
        mock_batch.return_value = MagicMock(
            success=True, message="OK", returncode=0, stdout="", stderr=""
        )
        engine = MockEngine(name="Suricata")
        svc = IDSService(engine)
        svc.update_and_reload()  # Should not raise


class TestIDSServiceCleanLogs:
    """Test clean_logs method"""

    @patch('ids_suite.services.ids_service.run_privileged_command')
    def test_clean_logs_with_callback(self, mock_cmd):
        """IDS-021: clean_logs() runs cleanup script"""
        mock_cmd.return_value = ServiceResult(True, "Cleaned", 0)
        engine = MockEngine()
        svc = IDSService(engine)

        callback_result = None
        def callback(r):
            nonlocal callback_result
            callback_result = r

        svc.clean_logs(callback=callback)
        mock_cmd.assert_called_once_with("/usr/local/bin/ids-cleanup")
        assert callback_result.success is True

    @patch('ids_suite.services.ids_service.run_privileged_command')
    def test_clean_logs_no_callback(self, mock_cmd):
        """IDS-022: clean_logs() works without callback"""
        mock_cmd.return_value = ServiceResult(True, "OK", 0)
        engine = MockEngine()
        svc = IDSService(engine)
        svc.clean_logs()  # Should not raise


class TestIDSServiceOpenConfig:
    """Test open_config method"""

    @patch('os.path.exists')
    @patch('subprocess.Popen')
    def test_open_config_exists(self, mock_popen, mock_exists):
        """IDS-023: open_config() opens config when it exists"""
        mock_exists.return_value = True
        engine = MockEngine(config_path="/etc/suricata/suricata.yaml")
        svc = IDSService(engine)

        svc.open_config()
        mock_popen.assert_called_once_with(["xdg-open", "/etc/suricata/suricata.yaml"])

    @patch('os.path.exists')
    @patch('subprocess.Popen')
    def test_open_config_not_exists(self, mock_popen, mock_exists):
        """IDS-024: open_config() does nothing when config doesn't exist"""
        mock_exists.return_value = False
        engine = MockEngine(config_path="/etc/suricata/suricata.yaml")
        svc = IDSService(engine)

        svc.open_config()
        mock_popen.assert_not_called()


class TestIDSServiceOpenLogs:
    """Test open_logs method"""

    @patch('os.path.exists')
    @patch('subprocess.Popen')
    def test_open_logs_exists(self, mock_popen, mock_exists):
        """IDS-025: open_logs() opens log directory when it exists"""
        mock_exists.return_value = True
        engine = MockEngine(log_path="/var/log/suricata/eve.json")
        svc = IDSService(engine)

        svc.open_logs()
        mock_popen.assert_called_once_with(["xdg-open", "/var/log/suricata"])

    @patch('os.path.exists')
    @patch('subprocess.Popen')
    def test_open_logs_not_exists(self, mock_popen, mock_exists):
        """IDS-026: open_logs() does nothing when log dir doesn't exist"""
        mock_exists.return_value = False
        engine = MockEngine(log_path="/var/log/suricata/eve.json")
        svc = IDSService(engine)

        svc.open_logs()
        mock_popen.assert_not_called()


class TestIDSServiceGetRuleCount:
    """Test get_rule_count method - uses pure Python file reading"""

    @patch('builtins.open', mock_open(read_data="alert tcp any any -> any any (msg:\"Test1\"; sid:1;)\nalert udp any any -> any any (msg:\"Test2\"; sid:2;)\n# comment\n"))
    @patch('ids_suite.services.ids_service.glob.glob')
    @patch('os.path.exists')
    def test_get_rule_count_suricata_success(self, mock_exists, mock_glob):
        """IDS-027: get_rule_count() returns count for Suricata via file reading"""
        mock_exists.return_value = True
        mock_glob.return_value = ['/var/lib/suricata/rules/test.rules']
        engine = MockEngine(name="Suricata")
        svc = IDSService(engine)

        count = svc.get_rule_count()
        assert count == 2  # Two alert lines in mock file

    @patch('os.path.exists')
    def test_get_rule_count_suricata_no_rules_dir(self, mock_exists):
        """IDS-028: get_rule_count() returns 0 when rules dir doesn't exist"""
        mock_exists.return_value = False
        engine = MockEngine(name="Suricata")
        svc = IDSService(engine)

        count = svc.get_rule_count()
        assert count == 0

    @patch('builtins.open')
    @patch('ids_suite.services.ids_service.glob.glob')
    @patch('os.path.exists')
    def test_get_rule_count_suricata_error(self, mock_exists, mock_glob, mock_file):
        """IDS-029: get_rule_count() returns 0 on IO error"""
        mock_exists.return_value = True
        mock_glob.return_value = ['/var/lib/suricata/rules/test.rules']
        mock_file.side_effect = IOError("Permission denied")
        engine = MockEngine(name="Suricata")
        svc = IDSService(engine)

        count = svc.get_rule_count()
        assert count == 0

    @patch('ids_suite.services.ids_service.glob.glob')
    @patch('os.path.exists')
    def test_get_rule_count_suricata_exception(self, mock_exists, mock_glob):
        """IDS-030: get_rule_count() returns 0 on exception"""
        mock_exists.return_value = True
        mock_glob.side_effect = Exception("Failed")
        engine = MockEngine(name="Suricata")
        svc = IDSService(engine)

        count = svc.get_rule_count()
        assert count == 0

    def test_get_rule_count_snort(self):
        """IDS-031: get_rule_count() returns 0 for Snort"""
        engine = MockEngine(name="Snort")
        svc = IDSService(engine)

        count = svc.get_rule_count()
        assert count == 0


class TestIDSServiceGetStatusInfo:
    """Test get_status_info method"""

    @patch('ids_suite.services.systemd.SystemdService.is_active')
    @patch('builtins.open', mock_open(read_data="alert tcp any any -> any any (msg:\"Test\"; sid:1;)\n" * 500))
    @patch('ids_suite.services.ids_service.glob.glob')
    @patch('os.path.exists')
    def test_get_status_info(self, mock_exists, mock_glob, mock_active):
        """IDS-032: get_status_info() returns complete status dict"""
        mock_exists.return_value = True
        mock_glob.return_value = ['/var/lib/suricata/rules/test.rules']
        mock_active.return_value = True

        engine = MockEngine(
            name="Suricata",
            service_name="suricata",
            config_path="/etc/suricata/suricata.yaml",
            log_path="/var/log/suricata/eve.json",
            installed=True
        )
        svc = IDSService(engine)

        info = svc.get_status_info()
        assert info['name'] == "Suricata"
        assert info['service'] == "suricata"
        assert info['running'] is True
        assert info['installed'] is True
        assert info['config_path'] == "/etc/suricata/suricata.yaml"
        assert info['log_path'] == "/var/log/suricata/eve.json"
        assert info['rule_count'] == 500

    @patch('ids_suite.services.systemd.SystemdService.is_active')
    def test_get_status_info_not_running(self, mock_active):
        """IDS-033: get_status_info() reports not running"""
        mock_active.return_value = False
        engine = MockEngine(name="Snort", installed=False)
        svc = IDSService(engine)

        info = svc.get_status_info()
        assert info['running'] is False
        assert info['installed'] is False
