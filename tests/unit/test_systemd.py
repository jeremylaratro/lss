"""
Tests for ids_suite/services/systemd.py - Systemd service wrapper

Target: 75%+ coverage
"""

import pytest
from unittest.mock import patch, MagicMock
import subprocess

from ids_suite.services.systemd import SystemdService, ServiceResult, run_privileged_command


class TestServiceResult:
    """Test ServiceResult dataclass"""

    def test_service_result_basic(self):
        """SYS-001: ServiceResult stores success state"""
        result = ServiceResult(success=True, message="OK", returncode=0)
        assert result.success is True
        assert result.message == "OK"
        assert result.returncode == 0

    def test_service_result_with_output(self):
        """SYS-002: ServiceResult stores stdout/stderr"""
        result = ServiceResult(
            success=False, message="Failed", returncode=1,
            stdout="output", stderr="error"
        )
        assert result.stdout == "output"
        assert result.stderr == "error"

    def test_service_result_defaults(self):
        """SYS-003: ServiceResult has empty string defaults"""
        result = ServiceResult(success=True, message="OK", returncode=0)
        assert result.stdout == ""
        assert result.stderr == ""


class TestSystemdServiceValidation:
    """Test service name and action validation"""

    def test_valid_service_name(self):
        """SYS-004: Valid service names are accepted"""
        svc = SystemdService("nginx")
        assert svc.service_name == "nginx"

    def test_valid_service_name_with_hyphen(self):
        """SYS-005: Service names with hyphens are valid"""
        svc = SystemdService("clamav-daemon")
        assert svc.service_name == "clamav-daemon"

    def test_valid_service_name_with_at(self):
        """SYS-006: Templated service names with @ are valid"""
        svc = SystemdService("clamd@scan")
        assert svc.service_name == "clamd@scan"

    def test_valid_service_name_with_dot(self):
        """SYS-007: Service names with dots are valid"""
        svc = SystemdService("dnf-automatic.timer")
        assert svc.service_name == "dnf-automatic.timer"

    def test_valid_service_name_with_underscore(self):
        """SYS-008: Service names with underscores are valid"""
        svc = SystemdService("my_service")
        assert svc.service_name == "my_service"

    def test_invalid_service_name_empty(self):
        """SYS-009: Empty service name is rejected"""
        with pytest.raises(ValueError) as exc_info:
            SystemdService("")
        assert "Invalid service name" in str(exc_info.value)

    def test_invalid_service_name_spaces(self):
        """SYS-010: Service names with spaces are rejected"""
        with pytest.raises(ValueError) as exc_info:
            SystemdService("my service")
        assert "Invalid service name" in str(exc_info.value)

    def test_invalid_service_name_shell_chars(self):
        """SYS-011: Service names with shell chars are rejected"""
        with pytest.raises(ValueError) as exc_info:
            SystemdService("nginx;rm -rf /")
        assert "Invalid service name" in str(exc_info.value)

    def test_invalid_service_name_too_long(self):
        """SYS-012: Service names over 256 chars are rejected"""
        long_name = "a" * 257
        with pytest.raises(ValueError) as exc_info:
            SystemdService(long_name)
        assert "Invalid service name" in str(exc_info.value)

    def test_is_valid_action_allowed(self):
        """SYS-013: Allowed actions return True"""
        assert SystemdService._is_valid_action("start") is True
        assert SystemdService._is_valid_action("stop") is True
        assert SystemdService._is_valid_action("restart") is True
        assert SystemdService._is_valid_action("reload") is True
        assert SystemdService._is_valid_action("status") is True
        assert SystemdService._is_valid_action("is-active") is True
        assert SystemdService._is_valid_action("is-enabled") is True
        assert SystemdService._is_valid_action("enable") is True
        assert SystemdService._is_valid_action("disable") is True

    def test_is_valid_action_rejected(self):
        """SYS-014: Invalid actions return False"""
        assert SystemdService._is_valid_action("kill") is False
        assert SystemdService._is_valid_action("mask") is False
        assert SystemdService._is_valid_action("daemon-reload") is False
        assert SystemdService._is_valid_action("") is False


class TestSystemdServiceRunSystemctl:
    """Test _run_systemctl method"""

    def test_run_systemctl_invalid_action(self):
        """SYS-015: Invalid action returns error result"""
        svc = SystemdService("nginx")
        result = svc._run_systemctl("invalid-action")
        assert result.success is False
        assert "Invalid action" in result.message
        assert result.returncode == -1

    @patch('subprocess.run')
    def test_run_systemctl_success_with_pkexec(self, mock_run):
        """SYS-016: Successful command with pkexec"""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="success", stderr=""
        )
        svc = SystemdService("nginx")
        result = svc._run_systemctl("start", use_pkexec=True)

        assert result.success is True
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert call_args == ["pkexec", "systemctl", "start", "nginx"]

    @patch('subprocess.run')
    def test_run_systemctl_success_without_pkexec(self, mock_run):
        """SYS-017: Successful command without pkexec"""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="active", stderr=""
        )
        svc = SystemdService("nginx")
        result = svc._run_systemctl("is-active", use_pkexec=False)

        assert result.success is True
        call_args = mock_run.call_args[0][0]
        assert call_args == ["systemctl", "is-active", "nginx"]

    @patch('subprocess.run')
    def test_run_systemctl_failure(self, mock_run):
        """SYS-018: Failed command returns error result"""
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="Failed to start"
        )
        svc = SystemdService("nginx")
        result = svc._run_systemctl("start")

        assert result.success is False
        assert result.returncode == 1

    @patch('subprocess.run')
    def test_run_systemctl_timeout(self, mock_run):
        """SYS-019: Timeout returns error result"""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["systemctl"], timeout=30)
        svc = SystemdService("nginx")
        result = svc._run_systemctl("start")

        assert result.success is False
        assert "timed out" in result.message.lower()
        assert result.returncode == -1

    @patch('subprocess.run')
    def test_run_systemctl_command_not_found(self, mock_run):
        """SYS-020: FileNotFoundError returns error result"""
        mock_run.side_effect = FileNotFoundError("pkexec not found")
        svc = SystemdService("nginx")
        result = svc._run_systemctl("start")

        assert result.success is False
        assert "not found" in result.message.lower()
        assert result.returncode == -1

    @patch('subprocess.run')
    def test_run_systemctl_generic_exception(self, mock_run):
        """SYS-021: Generic exception returns error result"""
        mock_run.side_effect = Exception("Something went wrong")
        svc = SystemdService("nginx")
        result = svc._run_systemctl("start")

        assert result.success is False
        assert "Something went wrong" in result.message
        assert result.returncode == -1


class TestSystemdServiceMethods:
    """Test convenience methods (start, stop, etc.)"""

    @patch.object(SystemdService, '_run_systemctl')
    def test_start(self, mock_run):
        """SYS-022: start() calls _run_systemctl with 'start'"""
        mock_run.return_value = ServiceResult(True, "OK", 0)
        svc = SystemdService("nginx")
        result = svc.start()
        mock_run.assert_called_once_with("start")
        assert result.success is True

    @patch.object(SystemdService, '_run_systemctl')
    def test_stop(self, mock_run):
        """SYS-023: stop() calls _run_systemctl with 'stop'"""
        mock_run.return_value = ServiceResult(True, "OK", 0)
        svc = SystemdService("nginx")
        result = svc.stop()
        mock_run.assert_called_once_with("stop")

    @patch.object(SystemdService, '_run_systemctl')
    def test_restart(self, mock_run):
        """SYS-024: restart() calls _run_systemctl with 'restart'"""
        mock_run.return_value = ServiceResult(True, "OK", 0)
        svc = SystemdService("nginx")
        result = svc.restart()
        mock_run.assert_called_once_with("restart")

    @patch.object(SystemdService, '_run_systemctl')
    def test_reload(self, mock_run):
        """SYS-025: reload() calls _run_systemctl with 'reload'"""
        mock_run.return_value = ServiceResult(True, "OK", 0)
        svc = SystemdService("nginx")
        result = svc.reload()
        mock_run.assert_called_once_with("reload")

    @patch.object(SystemdService, '_run_systemctl')
    def test_is_active_true(self, mock_run):
        """SYS-026: is_active() returns True when service is active"""
        mock_run.return_value = ServiceResult(True, "active", 0, stdout="active")
        svc = SystemdService("nginx")
        assert svc.is_active() is True
        mock_run.assert_called_once_with("is-active", use_pkexec=False)

    @patch.object(SystemdService, '_run_systemctl')
    def test_is_active_false(self, mock_run):
        """SYS-027: is_active() returns False when service is inactive"""
        mock_run.return_value = ServiceResult(False, "inactive", 3, stdout="inactive")
        svc = SystemdService("nginx")
        assert svc.is_active() is False

    @patch.object(SystemdService, '_run_systemctl')
    def test_is_enabled_true(self, mock_run):
        """SYS-028: is_enabled() returns True when service is enabled"""
        mock_run.return_value = ServiceResult(True, "enabled", 0, stdout="enabled")
        svc = SystemdService("nginx")
        assert svc.is_enabled() is True
        mock_run.assert_called_once_with("is-enabled", use_pkexec=False)

    @patch.object(SystemdService, '_run_systemctl')
    def test_is_enabled_false(self, mock_run):
        """SYS-029: is_enabled() returns False when service is disabled"""
        mock_run.return_value = ServiceResult(False, "disabled", 1, stdout="disabled")
        svc = SystemdService("nginx")
        assert svc.is_enabled() is False

    @patch.object(SystemdService, '_run_systemctl')
    def test_status(self, mock_run):
        """SYS-030: status() calls without pkexec"""
        mock_run.return_value = ServiceResult(True, "OK", 0)
        svc = SystemdService("nginx")
        svc.status()
        mock_run.assert_called_once_with("status", use_pkexec=False)

    @patch.object(SystemdService, '_run_systemctl')
    def test_enable(self, mock_run):
        """SYS-031: enable() calls _run_systemctl with 'enable'"""
        mock_run.return_value = ServiceResult(True, "OK", 0)
        svc = SystemdService("nginx")
        result = svc.enable()
        mock_run.assert_called_once_with("enable")

    @patch.object(SystemdService, '_run_systemctl')
    def test_disable(self, mock_run):
        """SYS-032: disable() calls _run_systemctl with 'disable'"""
        mock_run.return_value = ServiceResult(True, "OK", 0)
        svc = SystemdService("nginx")
        result = svc.disable()
        mock_run.assert_called_once_with("disable")


class TestRunPrivilegedCommand:
    """Test run_privileged_command function"""

    def test_empty_command_rejected(self):
        """SYS-033: Empty command list is rejected"""
        result = run_privileged_command([])
        assert result.success is False
        assert "non-empty list" in result.message.lower()

    def test_non_list_rejected(self):
        """SYS-034: Non-list command is rejected"""
        result = run_privileged_command("systemctl start nginx")  # type: ignore
        assert result.success is False
        assert "non-empty list" in result.message.lower()

    def test_non_string_args_rejected(self):
        """SYS-035: Non-string arguments are rejected"""
        result = run_privileged_command(["systemctl", 123, "nginx"])  # type: ignore
        assert result.success is False
        assert "strings" in result.message.lower()

    @patch('subprocess.run')
    def test_success(self, mock_run):
        """SYS-036: Successful command execution"""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="success", stderr=""
        )
        result = run_privileged_command(["systemctl", "start", "nginx"])

        assert result.success is True
        call_args = mock_run.call_args[0][0]
        assert call_args == ["pkexec", "systemctl", "start", "nginx"]

    @patch('subprocess.run')
    def test_failure(self, mock_run):
        """SYS-037: Failed command returns error result"""
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="permission denied"
        )
        result = run_privileged_command(["systemctl", "start", "nginx"])

        assert result.success is False
        assert result.returncode == 1

    @patch('subprocess.run')
    def test_timeout(self, mock_run):
        """SYS-038: Timeout handling"""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["pkexec"], timeout=30)
        result = run_privileged_command(["systemctl", "start", "nginx"])

        assert result.success is False
        assert "timed out" in result.message.lower()

    @patch('subprocess.run')
    def test_file_not_found(self, mock_run):
        """SYS-039: FileNotFoundError handling"""
        mock_run.side_effect = FileNotFoundError()
        result = run_privileged_command(["systemctl", "start", "nginx"])

        assert result.success is False
        assert "not found" in result.message.lower()

    @patch('subprocess.run')
    def test_generic_exception(self, mock_run):
        """SYS-040: Generic exception handling"""
        mock_run.side_effect = Exception("unexpected error")
        result = run_privileged_command(["systemctl", "start", "nginx"])

        assert result.success is False
        assert "unexpected error" in result.message.lower()

    @patch('subprocess.run')
    def test_custom_timeout(self, mock_run):
        """SYS-041: Custom timeout is passed to subprocess"""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        run_privileged_command(["test"], timeout=60)

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs['timeout'] == 60
