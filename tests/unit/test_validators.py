"""
Tests for ids_suite/core/validators.py - Input validation functions

Sprint 1.1: Configuration & Validators
Target: 95% coverage of all validation functions
"""

import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from ids_suite.core.validators import (
    validate_port,
    validate_sid,
    validate_service_name,
    validate_systemctl_action,
    validate_ufw_action,
    validate_protocol,
    validate_ip_address,
    validate_file_path,
    sanitize_for_shell,
    validate_command_whitelist,
    ValidationError,
    PORT_PATTERN,
    SID_PATTERN,
    SERVICE_NAME_PATTERN,
    IP_PATTERN,
    ALLOWED_SYSTEMCTL_ACTIONS,
    ALLOWED_UFW_ACTIONS,
    ALLOWED_PROTOCOLS,
)


class TestValidatePort:
    """Test port validation function"""

    def test_valid_single_port(self):
        """VAL-001: Valid single port returns success"""
        valid, error = validate_port("80")
        assert valid is True
        assert error is None

    def test_valid_high_port(self):
        """VAL-002: Valid high port number"""
        valid, error = validate_port("65535")
        assert valid is True
        assert error is None

    def test_valid_low_port(self):
        """VAL-003: Valid low port number"""
        valid, error = validate_port("1")
        assert valid is True
        assert error is None

    def test_valid_port_range(self):
        """VAL-004: Valid port range"""
        valid, error = validate_port("8080-8090")
        assert valid is True
        assert error is None

    def test_empty_port_rejected(self):
        """VAL-005: Empty port string rejected"""
        valid, error = validate_port("")
        assert valid is False
        assert "cannot be empty" in error

    def test_zero_port_rejected(self):
        """VAL-006: Port 0 rejected"""
        valid, error = validate_port("0")
        assert valid is False
        assert "out of range" in error

    def test_port_above_max_rejected(self):
        """VAL-007: Port above 65535 rejected"""
        valid, error = validate_port("65536")
        assert valid is False
        assert "out of range" in error

    def test_negative_port_rejected(self):
        """VAL-008: Negative port format rejected"""
        valid, error = validate_port("-1")
        assert valid is False
        assert "Invalid port format" in error

    def test_non_numeric_port_rejected(self):
        """VAL-009: Non-numeric port rejected"""
        valid, error = validate_port("http")
        assert valid is False
        assert "Invalid port format" in error

    def test_port_with_spaces_rejected(self):
        """VAL-010: Port with spaces rejected"""
        valid, error = validate_port("80 ")
        assert valid is False

    def test_inverted_port_range_rejected(self):
        """VAL-011: Inverted port range (start > end) rejected"""
        valid, error = validate_port("9000-8000")
        assert valid is False
        assert "start" in error and "end" in error

    def test_port_range_with_invalid_end(self):
        """VAL-012: Port range with out-of-range end rejected"""
        valid, error = validate_port("80-70000")
        assert valid is False
        assert "out of range" in error

    def test_common_ports(self):
        """VAL-013: Common service ports valid"""
        common_ports = ["22", "80", "443", "3306", "5432", "8080"]
        for port in common_ports:
            valid, error = validate_port(port)
            assert valid is True, f"Port {port} should be valid"


class TestValidateSID:
    """Test Suricata/Snort SID validation"""

    def test_valid_sid(self):
        """VAL-014: Valid SID returns success"""
        valid, error = validate_sid("2000001")
        assert valid is True
        assert error is None

    def test_valid_small_sid(self):
        """VAL-015: Valid small SID"""
        valid, error = validate_sid("1")
        assert valid is True
        assert error is None

    def test_valid_large_sid(self):
        """VAL-016: Valid large SID"""
        valid, error = validate_sid("999999999")
        assert valid is True
        assert error is None

    def test_empty_sid_rejected(self):
        """VAL-017: Empty SID rejected"""
        valid, error = validate_sid("")
        assert valid is False
        assert "cannot be empty" in error

    def test_zero_sid_rejected(self):
        """VAL-018: Zero SID rejected"""
        valid, error = validate_sid("0")
        assert valid is False
        assert "must be positive" in error

    def test_negative_sid_rejected(self):
        """VAL-019: Negative SID rejected"""
        valid, error = validate_sid("-1")
        assert valid is False
        assert "Invalid SID format" in error

    def test_non_numeric_sid_rejected(self):
        """VAL-020: Non-numeric SID rejected"""
        valid, error = validate_sid("abc123")
        assert valid is False
        assert "Invalid SID format" in error

    def test_sid_with_spaces_rejected(self):
        """VAL-021: SID with spaces rejected"""
        valid, error = validate_sid("2000 001")
        assert valid is False

    def test_sid_with_leading_zeros(self):
        """VAL-022: SID with leading zeros valid"""
        valid, error = validate_sid("0000123")
        assert valid is True  # Leading zeros are valid numeric format


class TestValidateServiceName:
    """Test systemd service name validation"""

    def test_valid_simple_name(self):
        """VAL-023: Valid simple service name"""
        valid, error = validate_service_name("suricata")
        assert valid is True
        assert error is None

    def test_valid_name_with_hyphen(self):
        """VAL-024: Valid name with hyphen"""
        valid, error = validate_service_name("clamav-daemon")
        assert valid is True
        assert error is None

    def test_valid_name_with_at_symbol(self):
        """VAL-025: Valid template instance name with @"""
        valid, error = validate_service_name("getty@tty1")
        assert valid is True
        assert error is None

    def test_valid_name_with_dot(self):
        """VAL-026: Valid name with dot"""
        valid, error = validate_service_name("system.slice")
        assert valid is True
        assert error is None

    def test_valid_name_with_underscore(self):
        """VAL-027: Valid name with underscore"""
        valid, error = validate_service_name("my_service")
        assert valid is True
        assert error is None

    def test_empty_name_rejected(self):
        """VAL-028: Empty service name rejected"""
        valid, error = validate_service_name("")
        assert valid is False
        assert "cannot be empty" in error

    def test_name_too_long_rejected(self):
        """VAL-029: Service name over 256 chars rejected"""
        long_name = "a" * 257
        valid, error = validate_service_name(long_name)
        assert valid is False
        assert "too long" in error

    def test_name_with_spaces_rejected(self):
        """VAL-030: Service name with spaces rejected"""
        valid, error = validate_service_name("my service")
        assert valid is False
        assert "Invalid service name format" in error

    def test_name_with_special_chars_rejected(self):
        """VAL-031: Service name with special chars rejected"""
        invalid_names = ["test;echo", "test|cat", "test&bg", "test$(cmd)"]
        for name in invalid_names:
            valid, error = validate_service_name(name)
            assert valid is False, f"Name '{name}' should be invalid"

    def test_valid_common_services(self):
        """VAL-032: Common service names valid"""
        services = ["suricata-laptop", "clamav-daemon", "freshclam", "sshd", "nginx"]
        for svc in services:
            valid, error = validate_service_name(svc)
            assert valid is True, f"Service '{svc}' should be valid"


class TestValidateSystemctlAction:
    """Test systemctl action validation"""

    def test_valid_start_action(self):
        """VAL-033: 'start' action valid"""
        valid, error = validate_systemctl_action("start")
        assert valid is True
        assert error is None

    def test_valid_stop_action(self):
        """VAL-034: 'stop' action valid"""
        valid, error = validate_systemctl_action("stop")
        assert valid is True

    def test_valid_restart_action(self):
        """VAL-035: 'restart' action valid"""
        valid, error = validate_systemctl_action("restart")
        assert valid is True

    def test_valid_reload_action(self):
        """VAL-036: 'reload' action valid"""
        valid, error = validate_systemctl_action("reload")
        assert valid is True

    def test_valid_status_action(self):
        """VAL-037: 'status' action valid"""
        valid, error = validate_systemctl_action("status")
        assert valid is True

    def test_valid_is_active_action(self):
        """VAL-038: 'is-active' action valid"""
        valid, error = validate_systemctl_action("is-active")
        assert valid is True

    def test_valid_is_enabled_action(self):
        """VAL-039: 'is-enabled' action valid"""
        valid, error = validate_systemctl_action("is-enabled")
        assert valid is True

    def test_valid_enable_action(self):
        """VAL-040: 'enable' action valid"""
        valid, error = validate_systemctl_action("enable")
        assert valid is True

    def test_valid_disable_action(self):
        """VAL-041: 'disable' action valid"""
        valid, error = validate_systemctl_action("disable")
        assert valid is True

    def test_empty_action_rejected(self):
        """VAL-042: Empty action rejected"""
        valid, error = validate_systemctl_action("")
        assert valid is False
        assert "cannot be empty" in error

    def test_invalid_action_rejected(self):
        """VAL-043: Invalid action rejected"""
        valid, error = validate_systemctl_action("kill")
        assert valid is False
        assert "Invalid action" in error
        assert "Allowed:" in error

    def test_dangerous_action_rejected(self):
        """VAL-044: Dangerous actions not in whitelist"""
        dangerous = ["mask", "unmask", "daemon-reload", "reset-failed"]
        for action in dangerous:
            valid, error = validate_systemctl_action(action)
            assert valid is False, f"Action '{action}' should be rejected"


class TestValidateUfwAction:
    """Test UFW firewall action validation"""

    def test_valid_allow_action(self):
        """VAL-045: 'allow' action valid"""
        valid, error = validate_ufw_action("allow")
        assert valid is True
        assert error is None

    def test_valid_deny_action(self):
        """VAL-046: 'deny' action valid"""
        valid, error = validate_ufw_action("deny")
        assert valid is True

    def test_valid_reject_action(self):
        """VAL-047: 'reject' action valid"""
        valid, error = validate_ufw_action("reject")
        assert valid is True

    def test_valid_limit_action(self):
        """VAL-048: 'limit' action valid"""
        valid, error = validate_ufw_action("limit")
        assert valid is True

    def test_valid_delete_action(self):
        """VAL-049: 'delete' action valid"""
        valid, error = validate_ufw_action("delete")
        assert valid is True

    def test_empty_action_rejected(self):
        """VAL-050: Empty action rejected"""
        valid, error = validate_ufw_action("")
        assert valid is False
        assert "cannot be empty" in error

    def test_invalid_action_rejected(self):
        """VAL-051: Invalid UFW action rejected"""
        valid, error = validate_ufw_action("enable")
        assert valid is False
        assert "Invalid UFW action" in error

    def test_dangerous_action_rejected(self):
        """VAL-052: Potentially dangerous actions rejected"""
        dangerous = ["reset", "disable", "--force"]
        for action in dangerous:
            valid, error = validate_ufw_action(action)
            assert valid is False, f"Action '{action}' should be rejected"


class TestValidateProtocol:
    """Test network protocol validation"""

    def test_valid_tcp(self):
        """VAL-053: 'tcp' protocol valid"""
        valid, error = validate_protocol("tcp")
        assert valid is True
        assert error is None

    def test_valid_udp(self):
        """VAL-054: 'udp' protocol valid"""
        valid, error = validate_protocol("udp")
        assert valid is True

    def test_valid_both(self):
        """VAL-055: 'both' protocol valid"""
        valid, error = validate_protocol("both")
        assert valid is True

    def test_case_insensitive_tcp(self):
        """VAL-056: Protocol validation is case-insensitive"""
        valid, error = validate_protocol("TCP")
        assert valid is True

    def test_case_insensitive_udp(self):
        """VAL-057: UDP uppercase valid"""
        valid, error = validate_protocol("UDP")
        assert valid is True

    def test_mixed_case_both(self):
        """VAL-058: Mixed case 'Both' valid"""
        valid, error = validate_protocol("Both")
        assert valid is True

    def test_empty_protocol_rejected(self):
        """VAL-059: Empty protocol rejected"""
        valid, error = validate_protocol("")
        assert valid is False
        assert "cannot be empty" in error

    def test_invalid_protocol_rejected(self):
        """VAL-060: Invalid protocol rejected"""
        valid, error = validate_protocol("icmp")
        assert valid is False
        assert "Invalid protocol" in error

    def test_sctp_protocol_rejected(self):
        """VAL-061: SCTP not in allowed protocols"""
        valid, error = validate_protocol("sctp")
        assert valid is False


class TestValidateIPAddress:
    """Test IPv4 address validation"""

    def test_valid_ip(self):
        """VAL-062: Valid IPv4 address"""
        valid, error = validate_ip_address("192.168.1.1")
        assert valid is True
        assert error is None

    def test_valid_localhost(self):
        """VAL-063: Localhost IP valid"""
        valid, error = validate_ip_address("127.0.0.1")
        assert valid is True

    def test_valid_all_zeros(self):
        """VAL-064: 0.0.0.0 valid"""
        valid, error = validate_ip_address("0.0.0.0")
        assert valid is True

    def test_valid_broadcast(self):
        """VAL-065: 255.255.255.255 valid"""
        valid, error = validate_ip_address("255.255.255.255")
        assert valid is True

    def test_valid_public_ip(self):
        """VAL-066: Public IP valid"""
        valid, error = validate_ip_address("8.8.8.8")
        assert valid is True

    def test_empty_ip_rejected(self):
        """VAL-067: Empty IP rejected"""
        valid, error = validate_ip_address("")
        assert valid is False
        assert "cannot be empty" in error

    def test_invalid_format_rejected(self):
        """VAL-068: Invalid format rejected"""
        valid, error = validate_ip_address("192.168.1")
        assert valid is False
        assert "Invalid IP address format" in error

    def test_octet_too_high_rejected(self):
        """VAL-069: Octet > 255 rejected"""
        valid, error = validate_ip_address("192.168.1.256")
        assert valid is False

    def test_too_many_octets_rejected(self):
        """VAL-070: Too many octets rejected"""
        valid, error = validate_ip_address("192.168.1.1.1")
        assert valid is False

    def test_negative_octet_rejected(self):
        """VAL-071: Negative octet rejected"""
        valid, error = validate_ip_address("192.168.-1.1")
        assert valid is False

    def test_hostname_rejected(self):
        """VAL-072: Hostname rejected"""
        valid, error = validate_ip_address("localhost")
        assert valid is False

    def test_ipv6_rejected(self):
        """VAL-073: IPv6 address rejected (only IPv4 supported)"""
        valid, error = validate_ip_address("::1")
        assert valid is False

    def test_cidr_notation_rejected(self):
        """VAL-074: CIDR notation rejected"""
        valid, error = validate_ip_address("192.168.1.0/24")
        assert valid is False


class TestValidateFilePath:
    """Test file path validation"""

    def test_valid_absolute_path(self, temp_dir):
        """VAL-075: Valid absolute path"""
        tmp_path = Path(temp_dir)
        test_file = tmp_path / "test.txt"
        test_file.touch()
        valid, error = validate_file_path(str(test_file))
        assert valid is True
        assert error is None

    def test_empty_path_rejected(self):
        """VAL-076: Empty path rejected"""
        valid, error = validate_file_path("")
        assert valid is False
        assert "cannot be empty" in error

    def test_must_exist_fails_for_missing(self, temp_dir):
        """VAL-077: must_exist=True fails for missing file"""
        tmp_path = Path(temp_dir)
        missing = tmp_path / "nonexistent.txt"
        valid, error = validate_file_path(str(missing), must_exist=True)
        assert valid is False
        assert "does not exist" in error

    def test_must_exist_passes_for_existing(self, temp_dir):
        """VAL-078: must_exist=True passes for existing file"""
        tmp_path = Path(temp_dir)
        test_file = tmp_path / "exists.txt"
        test_file.touch()
        valid, error = validate_file_path(str(test_file), must_exist=True)
        assert valid is True

    def test_allowed_dirs_accepts_valid(self, temp_dir):
        """VAL-079: File in allowed directory accepted"""
        tmp_path = Path(temp_dir)
        test_file = tmp_path / "config.json"
        test_file.touch()
        valid, error = validate_file_path(
            str(test_file),
            allowed_dirs=[str(tmp_path)]
        )
        assert valid is True

    def test_allowed_dirs_rejects_outside(self, temp_dir):
        """VAL-080: File outside allowed directories rejected"""
        valid, error = validate_file_path(
            "/etc/passwd",
            allowed_dirs=[temp_dir]
        )
        assert valid is False
        assert "not in allowed directories" in error

    def test_relative_path_resolved(self, temp_dir):
        """VAL-081: Relative paths are resolved"""
        tmp_path = Path(temp_dir)
        # Create subdirectory
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        test_file = subdir / "file.txt"
        test_file.touch()

        # Use path with ..
        rel_path = str(subdir / ".." / "subdir" / "file.txt")
        valid, error = validate_file_path(rel_path, must_exist=True)
        assert valid is True

    def test_symlink_resolved(self, temp_dir):
        """VAL-082: Symlinks are resolved"""
        tmp_path = Path(temp_dir)
        target = tmp_path / "target.txt"
        target.touch()
        link = tmp_path / "link.txt"
        link.symlink_to(target)

        valid, error = validate_file_path(str(link), must_exist=True)
        assert valid is True


class TestSanitizeForShell:
    """Test shell sanitization"""

    def test_simple_string_quoted(self):
        """VAL-083: Simple string gets quoted"""
        result = sanitize_for_shell("hello")
        assert result == "'hello'" or result == "hello"  # shlex may not quote simple

    def test_string_with_spaces_quoted(self):
        """VAL-084: String with spaces properly quoted"""
        result = sanitize_for_shell("hello world")
        assert " " not in result or result.startswith("'") or result.startswith('"')

    def test_dangerous_chars_escaped(self):
        """VAL-085: Shell metacharacters escaped"""
        dangerous = "test; rm -rf /"
        result = sanitize_for_shell(dangerous)
        # The semicolon should be escaped/quoted
        assert result != dangerous
        assert "'" in result or "\\" in result

    def test_quotes_escaped(self):
        """VAL-086: Quotes in string escaped"""
        result = sanitize_for_shell("test'quote")
        # Should handle the embedded quote
        assert "'" in result

    def test_dollar_sign_escaped(self):
        """VAL-087: Dollar sign escaped"""
        result = sanitize_for_shell("$HOME")
        # Should prevent variable expansion
        assert result != "$HOME"

    def test_backticks_escaped(self):
        """VAL-088: Backticks escaped"""
        result = sanitize_for_shell("`whoami`")
        # Should prevent command substitution
        assert "`" not in result or "'" in result


class TestValidateCommandWhitelist:
    """Test command whitelist validation"""

    def test_valid_whitelisted_command(self):
        """VAL-089: Whitelisted command passes"""
        whitelist = {"systemctl": ["start", "stop", "restart"]}
        valid, error = validate_command_whitelist("systemctl start nginx", whitelist)
        assert valid is True
        assert error is None

    def test_program_not_in_whitelist(self):
        """VAL-090: Non-whitelisted program rejected"""
        whitelist = {"systemctl": None}
        valid, error = validate_command_whitelist("rm -rf /", whitelist)
        assert valid is False
        assert "not in whitelist" in error

    def test_empty_command_rejected(self):
        """VAL-091: Empty command rejected"""
        whitelist = {"test": None}
        valid, error = validate_command_whitelist("", whitelist)
        assert valid is False
        assert "cannot be empty" in error

    def test_null_args_allows_any(self):
        """VAL-092: None in whitelist allows any arguments"""
        whitelist = {"suricata-update": None}
        valid, error = validate_command_whitelist(
            "suricata-update --reload-command=/bin/true", whitelist
        )
        assert valid is True

    def test_invalid_arg_rejected(self):
        """VAL-093: Argument not in whitelist rejected"""
        whitelist = {"ufw": ["allow", "deny"]}
        valid, error = validate_command_whitelist("ufw --force reset", whitelist)
        assert valid is False
        assert "not allowed" in error

    def test_command_with_path(self):
        """VAL-094: Command with full path uses basename"""
        whitelist = {"systemctl": None}
        valid, error = validate_command_whitelist("/usr/bin/systemctl status", whitelist)
        assert valid is True

    def test_invalid_shell_syntax_rejected(self):
        """VAL-095: Invalid shell syntax rejected"""
        whitelist = {"echo": None}
        valid, error = validate_command_whitelist('echo "unterminated', whitelist)
        assert valid is False
        assert "Invalid command syntax" in error

    def test_multiple_commands_only_first_checked(self):
        """VAL-096: Multiple commands - only first validated"""
        whitelist = {"echo": None}
        # shlex.split handles this as arguments, not separate commands
        valid, error = validate_command_whitelist("echo hello; rm -rf /", whitelist)
        # This passes because shlex sees "hello;" and "rm" as arguments to echo
        assert valid is True


class TestPatternConstants:
    """Test regex pattern constants"""

    def test_port_pattern_matches_single(self):
        """VAL-097: PORT_PATTERN matches single port"""
        assert PORT_PATTERN.match("8080")

    def test_port_pattern_matches_range(self):
        """VAL-098: PORT_PATTERN matches port range"""
        assert PORT_PATTERN.match("8000-9000")

    def test_sid_pattern_matches_numeric(self):
        """VAL-099: SID_PATTERN matches numeric"""
        assert SID_PATTERN.match("2000001")

    def test_service_pattern_matches_complex(self):
        """VAL-100: SERVICE_NAME_PATTERN matches complex names"""
        assert SERVICE_NAME_PATTERN.match("clamav-daemon@server1")

    def test_ip_pattern_matches_valid(self):
        """VAL-101: IP_PATTERN matches valid IPs"""
        assert IP_PATTERN.match("192.168.1.1")
        assert IP_PATTERN.match("0.0.0.0")
        assert IP_PATTERN.match("255.255.255.255")


class TestAllowedSets:
    """Test allowed value sets"""

    def test_systemctl_actions_complete(self):
        """VAL-102: All expected systemctl actions present"""
        expected = {'start', 'stop', 'restart', 'reload', 'status',
                    'is-active', 'is-enabled', 'enable', 'disable'}
        assert ALLOWED_SYSTEMCTL_ACTIONS == expected

    def test_ufw_actions_complete(self):
        """VAL-103: All expected UFW actions present"""
        expected = {'allow', 'deny', 'reject', 'limit', 'delete'}
        assert ALLOWED_UFW_ACTIONS == expected

    def test_protocols_complete(self):
        """VAL-104: All expected protocols present"""
        expected = {'tcp', 'udp', 'both'}
        assert ALLOWED_PROTOCOLS == expected


class TestValidationError:
    """Test ValidationError exception"""

    def test_validation_error_is_exception(self):
        """VAL-105: ValidationError is an Exception"""
        assert issubclass(ValidationError, Exception)

    def test_validation_error_message(self):
        """VAL-106: ValidationError preserves message"""
        err = ValidationError("test error")
        assert str(err) == "test error"

    def test_validation_error_raise(self):
        """VAL-107: ValidationError can be raised and caught"""
        with pytest.raises(ValidationError) as exc_info:
            raise ValidationError("invalid input")
        assert "invalid input" in str(exc_info.value)
