"""
Input validators for security-sensitive operations.

This module provides validation functions for user inputs that will be
used in privileged operations (subprocess calls, file operations, etc.).
"""

import re
import os
from typing import Optional, Tuple


# Validation patterns
PORT_PATTERN = re.compile(r'^[0-9]+(-[0-9]+)?$')
SID_PATTERN = re.compile(r'^[0-9]+$')
SERVICE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9@._-]+$')
IP_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

# Allowed systemctl actions
ALLOWED_SYSTEMCTL_ACTIONS = frozenset([
    'start', 'stop', 'restart', 'reload', 'status',
    'is-active', 'is-enabled', 'enable', 'disable'
])

# Allowed firewall actions
ALLOWED_UFW_ACTIONS = frozenset(['allow', 'deny', 'reject', 'limit', 'delete'])
ALLOWED_FIREWALLD_ACTIONS = frozenset(['--add-port', '--remove-port', '--reload'])

# Allowed protocols
ALLOWED_PROTOCOLS = frozenset(['tcp', 'udp', 'both'])


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


def validate_port(port: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a port or port range string.

    Args:
        port: Port number or range (e.g., "80", "8080-8090")

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not port:
        return False, "Port cannot be empty"

    if not PORT_PATTERN.match(port):
        return False, f"Invalid port format: {port}"

    # Check numeric range
    parts = port.split('-')
    for part in parts:
        try:
            port_num = int(part)
            if not (1 <= port_num <= 65535):
                return False, f"Port {port_num} out of range (1-65535)"
        except ValueError:
            return False, f"Invalid port number: {part}"

    # For ranges, ensure start <= end
    if len(parts) == 2:
        if int(parts[0]) > int(parts[1]):
            return False, f"Invalid port range: start ({parts[0]}) > end ({parts[1]})"

    return True, None


def validate_sid(sid: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a Suricata/Snort rule SID.

    Args:
        sid: Rule signature ID (numeric string)

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not sid:
        return False, "SID cannot be empty"

    if not SID_PATTERN.match(sid):
        return False, f"Invalid SID format: {sid}"

    try:
        sid_num = int(sid)
        if sid_num < 1:
            return False, f"SID must be positive: {sid}"
    except ValueError:
        return False, f"Invalid SID: {sid}"

    return True, None


def validate_service_name(name: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a systemd service name.

    Args:
        name: Service name (e.g., "suricata-laptop", "clamav-daemon")

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not name:
        return False, "Service name cannot be empty"

    if len(name) > 256:
        return False, "Service name too long (max 256 chars)"

    if not SERVICE_NAME_PATTERN.match(name):
        return False, f"Invalid service name format: {name}"

    return True, None


def validate_systemctl_action(action: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a systemctl action.

    Args:
        action: The systemctl action (e.g., "start", "stop")

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not action:
        return False, "Action cannot be empty"

    if action not in ALLOWED_SYSTEMCTL_ACTIONS:
        allowed = ', '.join(sorted(ALLOWED_SYSTEMCTL_ACTIONS))
        return False, f"Invalid action '{action}'. Allowed: {allowed}"

    return True, None


def validate_ufw_action(action: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a UFW firewall action.

    Args:
        action: The UFW action (e.g., "allow", "deny")

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not action:
        return False, "Action cannot be empty"

    if action not in ALLOWED_UFW_ACTIONS:
        allowed = ', '.join(sorted(ALLOWED_UFW_ACTIONS))
        return False, f"Invalid UFW action '{action}'. Allowed: {allowed}"

    return True, None


def validate_protocol(proto: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a network protocol.

    Args:
        proto: Protocol name (tcp, udp, or both)

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not proto:
        return False, "Protocol cannot be empty"

    proto_lower = proto.lower()
    if proto_lower not in ALLOWED_PROTOCOLS:
        allowed = ', '.join(sorted(ALLOWED_PROTOCOLS))
        return False, f"Invalid protocol '{proto}'. Allowed: {allowed}"

    return True, None


def validate_ip_address(ip: str) -> Tuple[bool, Optional[str]]:
    """
    Validate an IPv4 address.

    Args:
        ip: IPv4 address string

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not ip:
        return False, "IP address cannot be empty"

    if not IP_PATTERN.match(ip):
        return False, f"Invalid IP address format: {ip}"

    return True, None


def validate_file_path(path: str, must_exist: bool = False,
                       allowed_dirs: Optional[list] = None) -> Tuple[bool, Optional[str]]:
    """
    Validate and canonicalize a file path.

    Args:
        path: File path to validate
        must_exist: If True, path must exist
        allowed_dirs: If provided, path must be within one of these directories

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not path:
        return False, "Path cannot be empty"

    # Canonicalize to resolve symlinks and relative paths
    try:
        canonical = os.path.realpath(path)
    except (OSError, ValueError) as e:
        return False, f"Invalid path: {e}"

    # Check existence if required
    if must_exist and not os.path.exists(canonical):
        return False, f"Path does not exist: {path}"

    # Check against allowed directories
    if allowed_dirs:
        in_allowed = False
        for allowed in allowed_dirs:
            allowed_canonical = os.path.realpath(allowed)
            if canonical.startswith(allowed_canonical + os.sep) or canonical == allowed_canonical:
                in_allowed = True
                break

        if not in_allowed:
            return False, f"Path not in allowed directories: {path}"

    return True, None


def sanitize_for_shell(value: str) -> str:
    """
    Sanitize a value for safe shell use.

    This should be used sparingly - prefer list-based subprocess calls.
    Only use when shell=True is absolutely necessary.

    Args:
        value: String to sanitize

    Returns:
        Sanitized string safe for shell use
    """
    import shlex
    return shlex.quote(value)


def validate_command_whitelist(command: str, whitelist: dict) -> Tuple[bool, Optional[str]]:
    """
    Validate a command against a whitelist of allowed commands.

    Args:
        command: Full command string
        whitelist: Dict of {program: [allowed_args]} or {program: None} for any args

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not command:
        return False, "Command cannot be empty"

    import shlex
    try:
        parts = shlex.split(command)
    except ValueError as e:
        return False, f"Invalid command syntax: {e}"

    if not parts:
        return False, "Empty command"

    program = os.path.basename(parts[0])

    if program not in whitelist:
        allowed = ', '.join(sorted(whitelist.keys()))
        return False, f"Program '{program}' not in whitelist. Allowed: {allowed}"

    allowed_args = whitelist.get(program)

    # None means any args are allowed for this program
    if allowed_args is None:
        return True, None

    # Check that all provided args are in the allowed list
    for arg in parts[1:]:
        # Skip values that follow flags (like "-c reload-rules")
        if arg.startswith('-'):
            if arg not in allowed_args:
                return False, f"Argument '{arg}' not allowed for {program}"

    return True, None
