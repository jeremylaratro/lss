#!/usr/bin/env python3
"""
Fuzzing-based test suite for IDS Suite
Date: 30 January 2026

This test suite contains test cases derived from fuzzing research
to validate security and robustness of the IDS Suite.

Run with:
    pytest tests/test_fuzzing.py -v
"""

import pytest
import json
import os
import tempfile
import sys

# Add project to path
sys.path.insert(0, '/home/jay/Documents/cyber/dev/lss2')

from ids_suite.engines.suricata import SuricataEngine
from ids_suite.models.eve_reader import EVEFileReader
from ids_suite.core.utils import is_private_ip
from ids_suite.core.validators import (
    validate_port, validate_ip_address, validate_file_path,
    validate_sid, validate_service_name, validate_systemctl_action,
    validate_protocol, sanitize_for_shell, validate_command_whitelist
)


# ============================================================================
# FILE PARSING TESTS
# ============================================================================

class TestEVEJSONParsing:
    """Tests for EVE JSON log parsing robustness"""

    def test_malformed_json_truncated(self):
        """EVE parser should handle truncated JSON gracefully"""
        engine = SuricataEngine()

        test_cases = [
            '{"event_type": "alert", "alert": {"severity"',  # Truncated
            '{"event_type": "alert"',
            '{',
            '',
        ]

        for line in test_cases:
            result = engine.parse_alert(line)
            assert result is None, f"Should return None for malformed JSON: {line[:50]}"

    def test_malformed_json_type_confusion(self):
        """EVE parser should handle type confusion"""
        engine = SuricataEngine()

        test_cases = [
            '{"event_type": "alert", "severity": "not_an_int", "alert": {}}',
            '{"event_type": "alert", "src_port": [1, 2, 3], "alert": {}}',
            '{"event_type": "alert", "timestamp": null, "alert": {}}',
            '{"event_type": null}',
            '{"event_type": ""}',
        ]

        for line in test_cases:
            # Should not crash
            result = engine.parse_alert(line)
            # If it returns something, verify type
            if result is not None:
                assert isinstance(result, dict)

    def test_malformed_json_integer_overflow(self):
        """EVE parser should handle integer overflow"""
        engine = SuricataEngine()

        test_cases = [
            '{"event_type": "alert", "src_port": 999999999999999999999, "alert": {}}',
            '{"event_type": "alert", "severity": -2147483649, "alert": {}}',
        ]

        for line in test_cases:
            # Should not crash
            result = engine.parse_alert(line)

    def test_malformed_json_control_characters(self):
        """EVE parser should handle control characters"""
        engine = SuricataEngine()

        test_cases = [
            '{"event_type": "alert\x00", "alert": {}}',
            '{"event_type": "alert\n\r\t", "alert": {}}',
        ]

        for line in test_cases:
            # Should not crash
            result = engine.parse_alert(line)

    def test_valid_alert_parsing(self):
        """EVE parser should correctly parse valid alerts"""
        engine = SuricataEngine()

        valid_alert = json.dumps({
            "event_type": "alert",
            "timestamp": "2026-01-30T12:00:00.000000+0000",
            "src_ip": "192.168.1.100",
            "src_port": 54321,
            "dest_ip": "8.8.8.8",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "severity": 2,
                "signature": "TEST ALERT",
                "category": "Test Category",
                "signature_id": 12345
            }
        })

        result = engine.parse_alert(valid_alert)
        assert result is not None
        assert result['engine'] == 'suricata'
        assert result['severity'] == 2
        assert result['signature'] == "TEST ALERT"


# ============================================================================
# IP ADDRESS HANDLING TESTS
# ============================================================================

class TestIPAddressHandling:
    """Tests for IP address validation and private IP detection"""

    def test_is_private_ip_type_confusion(self):
        """is_private_ip should handle non-string types safely"""
        test_cases = [
            (None, True),           # Should return True (invalid)
            (123, True),
            (12.34, True),
            (['192', '168', '1', '1'], True),
            ({'ip': '192.168.1.1'}, True),
            (b'192.168.1.1', True),
            (True, True),
        ]

        for test_input, expected in test_cases:
            result = is_private_ip(test_input)
            assert result == expected, f"Failed for input: {test_input}"

    def test_is_private_ip_octet_count(self):
        """is_private_ip should reject invalid octet counts"""
        test_cases = [
            '192.168.1',       # 3 octets
            '192.168.1.1.1',   # 5 octets
            '192.168',         # 2 octets
            '192',             # 1 octet
            '.....',           # Only dots
        ]

        for ip in test_cases:
            result = is_private_ip(ip)
            assert result == True, f"Should treat {ip} as invalid (return True)"

    def test_is_private_ip_integer_overflow(self):
        """is_private_ip should handle integer overflow gracefully"""
        test_cases = [
            '256.168.1.1',
            '192.999999999999.1.1',
            '192.-1.1.1',
            '999999999.1.1.1',
        ]

        for ip in test_cases:
            # Should not crash, should return True (invalid)
            result = is_private_ip(ip)
            assert result == True

    def test_is_private_ip_valid_private_ranges(self):
        """is_private_ip should correctly identify private IPs"""
        test_cases = [
            ('10.0.0.1', True),          # Class A private
            ('172.16.0.1', True),        # Class B private
            ('172.31.255.255', True),    # Class B private edge
            ('192.168.1.1', True),       # Class C private
            ('127.0.0.1', True),         # Loopback
            ('169.254.1.1', True),       # Link-local
            ('224.0.0.1', True),         # Multicast
            ('240.0.0.1', True),         # Reserved
            ('8.8.8.8', False),          # Public (Google DNS)
            ('1.1.1.1', False),          # Public (Cloudflare DNS)
        ]

        for ip, expected_private in test_cases:
            result = is_private_ip(ip)
            assert result == expected_private, f"Failed for {ip}"

    def test_is_private_ip_ipv6(self):
        """is_private_ip should correctly identify IPv6 addresses"""
        test_cases = [
            ('::1', True),               # Loopback
            ('fe80::1', True),           # Link-local
            ('fc00::1', True),           # ULA
            ('fd00::1', True),           # ULA
            ('ff00::1', True),           # Multicast
            ('fed0::1', False),          # Public (not fc/fd prefix)
            ('2001:db8::1', False),      # Public
            ('::ffff:192.168.1.1', False),  # IPv4-mapped (not handled specially)
        ]

        for ip, expected_private in test_cases:
            result = is_private_ip(ip)
            assert result == expected_private, f"Failed for {ip}"

    def test_validate_ip_address_basic(self):
        """validate_ip_address should validate basic IPv4 addresses"""
        test_cases = [
            ('192.168.1.1', True),
            ('256.0.0.0', False),
            ('192.168.1.1\n', False),
            ('192.168.001.001', True),  # Leading zeros - valid in regex
            ('', False),
            ('not_an_ip', False),
        ]

        for ip, expected_valid in test_cases:
            is_valid, error = validate_ip_address(ip)
            assert is_valid == expected_valid, f"Failed for {ip}: {error}"


# ============================================================================
# PATH HANDLING TESTS
# ============================================================================

class TestPathHandling:
    """Tests for file path validation and traversal prevention"""

    def test_validate_file_path_traversal(self):
        """validate_file_path should prevent path traversal"""
        test_cases = [
            '../../../etc/passwd',
            '/var/log/../../etc/passwd',
            '/var/log/suricata/../../../etc/passwd',
        ]

        allowed_dirs = ['/var/log/suricata']

        for path in test_cases:
            is_valid, error = validate_file_path(path, allowed_dirs=allowed_dirs)
            assert not is_valid, f"Traversal not prevented for: {path}"

    def test_validate_file_path_null_byte(self):
        """validate_file_path should handle null bytes"""
        path_with_null = '/var/log/suricata/eve.json\x00../../etc/passwd'

        # Should either fail validation or safely truncate at null
        try:
            is_valid, error = validate_file_path(path_with_null)
            # Just shouldn't crash
        except (ValueError, OSError):
            # Expected for some systems
            pass

    def test_validate_file_path_allowed_directory_bypass(self):
        """validate_file_path should not be bypassed via prefix matching"""
        allowed_dirs = ['/var/log']

        # Should FAIL - not actually in /var/log
        is_valid, error = validate_file_path('/var/log_fake/file', allowed_dirs=allowed_dirs)
        assert not is_valid, "Prefix bypass should be prevented"

    def test_validate_file_path_symlink(self):
        """validate_file_path should resolve symlinks correctly"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create safe dir and file
            safe_dir = os.path.join(tmpdir, 'safe')
            os.makedirs(safe_dir)
            safe_file = os.path.join(safe_dir, 'file.txt')
            open(safe_file, 'w').close()

            # Validate safe file - should pass
            is_valid, error = validate_file_path(safe_file, allowed_dirs=[safe_dir])
            assert is_valid, f"Safe file should be valid: {error}"

            # Create symlink pointing to /etc/passwd
            if os.path.exists('/etc/passwd'):
                symlink = os.path.join(safe_dir, 'link_to_etc')
                try:
                    os.symlink('/etc/passwd', symlink)

                    # Should reject symlink pointing outside allowed dir
                    is_valid, error = validate_file_path(symlink, allowed_dirs=[safe_dir])
                    assert not is_valid, "Symlink escape should be prevented"
                except OSError:
                    # Symlink creation failed, skip test
                    pass

    def test_validate_file_path_empty(self):
        """validate_file_path should reject empty paths"""
        is_valid, error = validate_file_path('')
        assert not is_valid
        assert 'empty' in error.lower()


# ============================================================================
# PORT AND SID VALIDATION TESTS
# ============================================================================

class TestPortValidation:
    """Tests for port number validation"""

    def test_validate_port_boundaries(self):
        """validate_port should enforce correct boundaries"""
        test_cases = [
            ('0', False),           # Below range
            ('1', True),            # Minimum
            ('80', True),           # Valid
            ('65535', True),        # Maximum
            ('65536', False),       # Above range
            ('-1', False),          # Negative
            ('99999', False),       # Way above
        ]

        for port, expected_valid in test_cases:
            is_valid, error = validate_port(port)
            assert is_valid == expected_valid, f"Failed for port {port}: {error}"

    def test_validate_port_injection(self):
        """validate_port should prevent command injection"""
        test_cases = [
            '80; echo pwned',
            '80 && rm -rf /',
            '80`whoami`',
            '80$(id)',
            '80|cat /etc/passwd',
        ]

        for port in test_cases:
            is_valid, error = validate_port(port)
            assert not is_valid, f"Injection not prevented: {port}"

    def test_validate_port_ranges(self):
        """validate_port should handle port ranges"""
        test_cases = [
            ('80-90', True),
            ('8080-8090', True),
            ('90-80', False),       # Reversed
            ('1-65535', True),      # Full range
            ('80-', False),         # Missing end
            ('-80', False),         # Missing start
        ]

        for port, expected_valid in test_cases:
            is_valid, error = validate_port(port)
            assert is_valid == expected_valid, f"Failed for port range {port}: {error}"

    def test_validate_port_empty(self):
        """validate_port should reject empty input"""
        is_valid, error = validate_port('')
        assert not is_valid
        assert 'empty' in error.lower()


class TestSIDValidation:
    """Tests for SID (Signature ID) validation"""

    def test_validate_sid_basic(self):
        """validate_sid should validate basic SIDs"""
        test_cases = [
            ('123', True),
            ('1', True),
            ('999999', True),
            ('0', False),           # Below minimum
            ('-1', False),          # Negative
            ('abc', False),         # Non-numeric
            ('123abc', False),      # Mixed
            ('', False),            # Empty
        ]

        for sid, expected_valid in test_cases:
            is_valid, error = validate_sid(sid)
            assert is_valid == expected_valid, f"Failed for SID {sid}: {error}"

    def test_validate_sid_injection(self):
        """validate_sid should prevent command injection"""
        test_cases = [
            '123; rm -rf /',
            '123`whoami`',
            '123$(id)',
        ]

        for sid in test_cases:
            is_valid, error = validate_sid(sid)
            assert not is_valid, f"Injection not prevented: {sid}"


# ============================================================================
# SERVICE NAME AND COMMAND VALIDATION TESTS
# ============================================================================

class TestServiceNameValidation:
    """Tests for systemd service name validation"""

    def test_validate_service_name_length(self):
        """validate_service_name should enforce length limit"""
        # Exactly 256 chars (should pass)
        is_valid, _ = validate_service_name('A' * 256)
        assert is_valid

        # 257 chars (should fail)
        is_valid, error = validate_service_name('A' * 257)
        assert not is_valid
        assert 'long' in error.lower()

    def test_validate_service_name_injection(self):
        """validate_service_name should prevent injection"""
        test_cases = [
            'suricata; rm -rf /',
            'suricata`whoami`',
            'suricata$(id)',
            'suricata|cat /etc/passwd',
            'suricata&& echo pwned',
        ]

        for name in test_cases:
            is_valid, error = validate_service_name(name)
            assert not is_valid, f"Injection not prevented: {name}"

    def test_validate_service_name_valid(self):
        """validate_service_name should accept valid names"""
        test_cases = [
            'suricata-laptop',
            'clamav-daemon',
            'clamd@scan',
            'clamav-freshclam.service',
        ]

        for name in test_cases:
            is_valid, error = validate_service_name(name)
            assert is_valid, f"Valid name rejected: {name} - {error}"

    def test_validate_systemctl_action(self):
        """validate_systemctl_action should enforce whitelist"""
        valid_actions = ['start', 'stop', 'restart', 'reload', 'status']
        invalid_actions = ['', 'invalid', 'start; echo pwned', 'start && rm']

        for action in valid_actions:
            is_valid, error = validate_systemctl_action(action)
            assert is_valid, f"Valid action rejected: {action}"

        for action in invalid_actions:
            is_valid, error = validate_systemctl_action(action)
            assert not is_valid, f"Invalid action accepted: {action}"


class TestCommandWhitelist:
    """Tests for command whitelist validation"""

    def test_validate_command_whitelist_basic(self):
        """validate_command_whitelist should validate against whitelist"""
        whitelist = {'systemctl': ['start', 'stop']}

        # Valid command
        is_valid, error = validate_command_whitelist('systemctl start suricata', whitelist)
        # Current implementation may not fully validate args, just program

        # Invalid program
        is_valid, error = validate_command_whitelist('rm -rf /', whitelist)
        assert not is_valid

    def test_validate_command_whitelist_shlex_errors(self):
        """validate_command_whitelist should handle shlex errors"""
        whitelist = {'systemctl': []}

        # Unmatched quotes cause ValueError in shlex.split
        test_cases = [
            "systemctl 'unmatched",
            'systemctl "unmatched',
        ]

        for command in test_cases:
            is_valid, error = validate_command_whitelist(command, whitelist)
            assert not is_valid, "Should handle shlex errors gracefully"


class TestShellSanitization:
    """Tests for shell command sanitization"""

    def test_sanitize_for_shell_basic(self):
        """sanitize_for_shell should handle basic strings"""
        test_cases = [
            'simple',
            "it's a test",
            'path/to/file',
            '',
        ]

        for test_input in test_cases:
            result = sanitize_for_shell(test_input)
            assert isinstance(result, str)
            # Result should be safely quoted
            assert result  # Non-empty result

    def test_sanitize_for_shell_special_chars(self):
        """sanitize_for_shell should escape special characters"""
        test_cases = [
            'test; echo pwned',
            'test && rm -rf /',
            'test`whoami`',
            'test$(id)',
            'test|cat /etc/passwd',
        ]

        for test_input in test_cases:
            result = sanitize_for_shell(test_input)
            # Should be safely escaped by shlex.quote
            assert ';' not in result or result.startswith("'")


# ============================================================================
# PROTOCOL VALIDATION TESTS
# ============================================================================

class TestProtocolValidation:
    """Tests for network protocol validation"""

    def test_validate_protocol_basic(self):
        """validate_protocol should validate protocol names"""
        test_cases = [
            ('tcp', True),
            ('udp', True),
            ('both', True),
            ('TCP', True),          # Should handle case
            ('UDP', True),
            ('icmp', False),        # Not in whitelist
            ('', False),            # Empty
            ('tcp; echo pwned', False),
        ]

        for proto, expected_valid in test_cases:
            is_valid, error = validate_protocol(proto)
            assert is_valid == expected_valid, f"Failed for protocol {proto}: {error}"


# ============================================================================
# PROPERTY-BASED TESTS (if hypothesis is available)
# ============================================================================

try:
    from hypothesis import given, strategies as st

    class TestPropertyBased:
        """Property-based tests using Hypothesis"""

        @given(st.text())
        def test_is_private_ip_never_crashes(self, ip):
            """is_private_ip should never crash regardless of input"""
            try:
                result = is_private_ip(ip)
                assert isinstance(result, bool)
            except Exception as e:
                pytest.fail(f"Crashed on input {repr(ip)}: {e}")

        @given(st.text(min_size=0, max_size=100))
        def test_validate_port_never_crashes(self, port):
            """validate_port should never crash"""
            try:
                is_valid, error = validate_port(port)
                assert isinstance(is_valid, bool)
                assert error is None or isinstance(error, str)
            except Exception as e:
                pytest.fail(f"Crashed on input {repr(port)}: {e}")

        @given(st.integers(min_value=0, max_value=255),
               st.integers(min_value=0, max_value=255),
               st.integers(min_value=0, max_value=255),
               st.integers(min_value=0, max_value=255))
        def test_is_private_ip_valid_ipv4(self, a, b, c, d):
            """Property: Valid IPv4 addresses should never crash"""
            ip = f"{a}.{b}.{c}.{d}"
            result = is_private_ip(ip)
            assert isinstance(result, bool)

except ImportError:
    print("Hypothesis not available - skipping property-based tests")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
