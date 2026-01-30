#!/usr/bin/env python3
"""
Fuzzing harness for IDS Suite - Security Testing
Author: Security Testing Team
Date: 30 January 2026

This harness uses Atheris (libFuzzer for Python) to discover crashes
and undefined behavior in the IDS Suite codebase.

Usage:
    # Install atheris first
    pip install atheris

    # Run fuzzer
    python3 fuzzing_harness.py

    # Run with corpus directory
    mkdir -p /tmp/fuzzing_corpus
    python3 fuzzing_harness.py /tmp/fuzzing_corpus

    # Run for specific duration (1 hour)
    timeout 3600 python3 fuzzing_harness.py
"""

import sys
import os

# Add project to path
sys.path.insert(0, '/home/jay/Documents/cyber/dev/lss2')

try:
    import atheris
    ATHERIS_AVAILABLE = True
except ImportError:
    print("WARNING: atheris not available. Install with: pip install atheris")
    ATHERIS_AVAILABLE = False

# Import target functions
from ids_suite.models.eve_reader import EVEFileReader
from ids_suite.engines.suricata import SuricataEngine
from ids_suite.core.utils import is_private_ip
from ids_suite.core.validators import (
    validate_port, validate_ip_address, validate_file_path,
    validate_sid, validate_service_name, validate_systemctl_action,
    validate_protocol, sanitize_for_shell, validate_command_whitelist
)


# ============================================================================
# FUZZING TARGETS
# ============================================================================

def fuzz_eve_json_parsing(data):
    """
    Fuzz EVE JSON log parsing (Suricata alert format)

    Targets:
        - SuricataEngine.parse_alert()
        - JSON parsing with malformed input
        - Type confusion in dictionary access

    Expected behavior:
        - Should never crash
        - Should return None for invalid JSON
        - Should handle type confusion gracefully
    """
    engine = SuricataEngine()
    try:
        line = data.decode('utf-8', errors='ignore')
        result = engine.parse_alert(line)

        # If result is returned, verify it's the expected type
        if result is not None:
            assert isinstance(result, dict), "parse_alert should return dict or None"

    except (ValueError, KeyError, AttributeError, TypeError) as e:
        # These are expected for malformed input
        pass
    except Exception as e:
        # Any other exception is a potential bug
        print(f"[!] UNEXPECTED EXCEPTION: {type(e).__name__}: {e}")
        print(f"[!] Input: {repr(data[:100])}")
        raise


def fuzz_ip_validation(data):
    """
    Fuzz IP address validation and private IP detection

    Targets:
        - is_private_ip() - IPv4 and IPv6 handling
        - validate_ip_address() - Regex validation

    Expected behavior:
        - Should never crash regardless of input
        - Should return boolean for is_private_ip()
        - Should return (bool, str/None) tuple for validate_ip_address()
    """
    try:
        ip = data.decode('utf-8', errors='ignore').strip()

        # Test is_private_ip - should never crash
        result1 = is_private_ip(ip)
        assert isinstance(result1, bool), "is_private_ip should return bool"

        # Test validate_ip_address - should never crash
        is_valid, error = validate_ip_address(ip)
        assert isinstance(is_valid, bool), "validate_ip_address should return bool"
        assert error is None or isinstance(error, str), "error should be None or str"

    except (ValueError, AttributeError, TypeError) as e:
        # Expected for some malformed inputs
        pass
    except Exception as e:
        print(f"[!] UNEXPECTED EXCEPTION: {type(e).__name__}: {e}")
        print(f"[!] Input: {repr(data[:100])}")
        raise


def fuzz_path_validation(data):
    """
    Fuzz file path validation

    Targets:
        - validate_file_path() - Path traversal prevention
        - os.path.realpath() - Symlink resolution
        - Directory whitelist validation

    Expected behavior:
        - Should never crash
        - Should prevent path traversal
        - Should correctly validate against allowed directories
    """
    try:
        path = data.decode('utf-8', errors='ignore')

        # Test without allowed directories
        is_valid1, error1 = validate_file_path(path)
        assert isinstance(is_valid1, bool)
        assert error1 is None or isinstance(error1, str)

        # Test with allowed directories
        is_valid2, error2 = validate_file_path(
            path,
            allowed_dirs=['/var/log', '/tmp']
        )
        assert isinstance(is_valid2, bool)
        assert error2 is None or isinstance(error2, str)

    except (OSError, ValueError, TypeError) as e:
        # Expected for some invalid paths
        pass
    except Exception as e:
        print(f"[!] UNEXPECTED EXCEPTION: {type(e).__name__}: {e}")
        print(f"[!] Input: {repr(data[:100])}")
        raise


def fuzz_port_validation(data):
    """
    Fuzz port number validation

    Targets:
        - validate_port() - Port range validation
        - Integer conversion
        - Range validation (1-65535)

    Expected behavior:
        - Should never crash
        - Should reject invalid ports
        - Should prevent command injection
    """
    try:
        port = data.decode('utf-8', errors='ignore')

        is_valid, error = validate_port(port)
        assert isinstance(is_valid, bool)
        assert error is None or isinstance(error, str)

    except (ValueError, TypeError) as e:
        # Expected for some inputs
        pass
    except Exception as e:
        print(f"[!] UNEXPECTED EXCEPTION: {type(e).__name__}: {e}")
        print(f"[!] Input: {repr(data[:100])}")
        raise


def fuzz_service_name_validation(data):
    """
    Fuzz systemd service name validation

    Targets:
        - validate_service_name() - Service name format validation
        - validate_systemctl_action() - Action whitelist

    Expected behavior:
        - Should never crash
        - Should reject invalid service names
        - Should prevent command injection
    """
    try:
        name = data.decode('utf-8', errors='ignore')

        # Test service name
        is_valid1, error1 = validate_service_name(name)
        assert isinstance(is_valid1, bool)
        assert error1 is None or isinstance(error1, str)

        # Test systemctl action
        is_valid2, error2 = validate_systemctl_action(name)
        assert isinstance(is_valid2, bool)
        assert error2 is None or isinstance(error2, str)

    except (ValueError, TypeError) as e:
        pass
    except Exception as e:
        print(f"[!] UNEXPECTED EXCEPTION: {type(e).__name__}: {e}")
        print(f"[!] Input: {repr(data[:100])}")
        raise


def fuzz_shell_sanitization(data):
    """
    Fuzz shell command sanitization

    Targets:
        - sanitize_for_shell() - Shell escaping
        - validate_command_whitelist() - Command whitelist validation

    Expected behavior:
        - Should never crash
        - Should properly escape all special characters
        - Should prevent command injection
    """
    try:
        text = data.decode('utf-8', errors='ignore')

        # Test sanitization
        sanitized = sanitize_for_shell(text)
        assert isinstance(sanitized, str)

        # Test command whitelist
        whitelist = {
            'systemctl': ['start', 'stop', 'restart'],
            'suricatasc': ['-c']
        }

        is_valid, error = validate_command_whitelist(text, whitelist)
        assert isinstance(is_valid, bool)
        assert error is None or isinstance(error, str)

    except (ValueError, TypeError) as e:
        pass
    except Exception as e:
        print(f"[!] UNEXPECTED EXCEPTION: {type(e).__name__}: {e}")
        print(f"[!] Input: {repr(data[:100])}")
        raise


def fuzz_all_validators(data):
    """
    Fuzz all validators with the same input

    Tests all validation functions to find common crash vectors
    """
    try:
        text = data.decode('utf-8', errors='ignore')

        # Run all validators
        _ = validate_port(text)
        _ = validate_sid(text)
        _ = validate_service_name(text)
        _ = validate_systemctl_action(text)
        _ = validate_protocol(text)
        _ = validate_ip_address(text)
        _ = is_private_ip(text)

    except Exception as e:
        # Log unexpected exceptions
        if not isinstance(e, (ValueError, TypeError, AttributeError, KeyError)):
            print(f"[!] UNEXPECTED EXCEPTION: {type(e).__name__}: {e}")
            print(f"[!] Input: {repr(data[:100])}")
            raise


# ============================================================================
# MAIN FUZZING ENTRY POINT
# ============================================================================

if ATHERIS_AVAILABLE:
    @atheris.instrument_func
    def TestOneInput(data):
        """
        Main fuzzing entry point for Atheris

        Uses first byte as selector to route to different fuzz targets
        """
        if len(data) < 2:
            return

        # Use first byte to select fuzzing target
        selector = data[0] % 7
        payload = data[1:]

        if selector == 0:
            fuzz_eve_json_parsing(payload)
        elif selector == 1:
            fuzz_ip_validation(payload)
        elif selector == 2:
            fuzz_path_validation(payload)
        elif selector == 3:
            fuzz_port_validation(payload)
        elif selector == 4:
            fuzz_service_name_validation(payload)
        elif selector == 5:
            fuzz_shell_sanitization(payload)
        elif selector == 6:
            fuzz_all_validators(payload)


def main():
    """Main entry point"""
    if not ATHERIS_AVAILABLE:
        print("ERROR: Atheris is required for fuzzing")
        print("Install with: pip install atheris")
        return 1

    print("=" * 70)
    print("IDS Suite Fuzzing Harness")
    print("=" * 70)
    print()
    print("Fuzzing targets:")
    print("  1. EVE JSON parsing")
    print("  2. IP address validation")
    print("  3. Path validation")
    print("  4. Port validation")
    print("  5. Service name validation")
    print("  6. Shell sanitization")
    print("  7. All validators")
    print()
    print("Starting fuzzer... (Ctrl+C to stop)")
    print("=" * 70)
    print()

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    sys.exit(main())
