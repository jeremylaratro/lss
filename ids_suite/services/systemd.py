"""
Systemd service wrapper for privileged operations
"""

import re
import subprocess
from typing import Tuple, Optional, List
from dataclasses import dataclass


@dataclass
class ServiceResult:
    """Result of a service operation"""
    success: bool
    message: str
    returncode: int
    stdout: str = ""
    stderr: str = ""


class SystemdService:
    """Wrapper for systemd service control with pkexec for privilege escalation"""

    # Whitelist of allowed systemctl actions
    ALLOWED_ACTIONS = {
        'start', 'stop', 'restart', 'reload', 'status',
        'is-active', 'is-enabled', 'enable', 'disable'
    }

    # Valid service name pattern (alphanumeric, @, ., _, -)
    SERVICE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9@._-]+$')

    def __init__(self, service_name: str):
        if not self._is_valid_service_name(service_name):
            raise ValueError(
                f"Invalid service name: {service_name}. "
                f"Service names must match pattern: {self.SERVICE_NAME_PATTERN.pattern}"
            )
        self.service_name = service_name

    @classmethod
    def _is_valid_service_name(cls, service_name: str) -> bool:
        """Validate service name against allowed pattern"""
        if not service_name or len(service_name) > 256:
            return False
        return cls.SERVICE_NAME_PATTERN.match(service_name) is not None

    @classmethod
    def _is_valid_action(cls, action: str) -> bool:
        """Validate action against whitelist"""
        return action in cls.ALLOWED_ACTIONS

    def _run_systemctl(self, action: str, use_pkexec: bool = True) -> ServiceResult:
        """Run a systemctl command with proper input validation"""
        # Validate action against whitelist
        if not self._is_valid_action(action):
            return ServiceResult(
                success=False,
                message=f"Invalid action: {action}. Allowed actions: {', '.join(sorted(self.ALLOWED_ACTIONS))}",
                returncode=-1
            )

        # Build command as list (no shell=True)
        if use_pkexec:
            cmd = ["pkexec", "systemctl", action, self.service_name]
        else:
            cmd = ["systemctl", action, self.service_name]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                shell=False  # Explicit: never use shell
            )
            return ServiceResult(
                success=result.returncode == 0,
                message=result.stdout or result.stderr,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr
            )
        except subprocess.TimeoutExpired:
            return ServiceResult(
                success=False,
                message=f"Command timed out: {' '.join(cmd)}",
                returncode=-1
            )
        except FileNotFoundError:
            return ServiceResult(
                success=False,
                message=f"Command not found: {cmd[0]}",
                returncode=-1
            )
        except Exception as e:
            return ServiceResult(
                success=False,
                message=f"Command execution error: {str(e)}",
                returncode=-1
            )

    def start(self) -> ServiceResult:
        """Start the service"""
        return self._run_systemctl("start")

    def stop(self) -> ServiceResult:
        """Stop the service"""
        return self._run_systemctl("stop")

    def restart(self) -> ServiceResult:
        """Restart the service"""
        return self._run_systemctl("restart")

    def reload(self) -> ServiceResult:
        """Reload the service configuration"""
        return self._run_systemctl("reload")

    def is_active(self) -> bool:
        """Check if service is active (running)"""
        result = self._run_systemctl("is-active", use_pkexec=False)
        return result.stdout.strip() == "active"

    def is_enabled(self) -> bool:
        """Check if service is enabled (starts at boot)"""
        result = self._run_systemctl("is-enabled", use_pkexec=False)
        return result.stdout.strip() == "enabled"

    def status(self) -> ServiceResult:
        """Get service status"""
        return self._run_systemctl("status", use_pkexec=False)

    def enable(self) -> ServiceResult:
        """Enable the service to start at boot"""
        return self._run_systemctl("enable")

    def disable(self) -> ServiceResult:
        """Disable the service from starting at boot"""
        return self._run_systemctl("disable")


def run_privileged_command(command: List[str], timeout: int = 30) -> ServiceResult:
    """
    Run a privileged command with pkexec

    Args:
        command: List of command arguments (e.g., ['systemctl', 'restart', 'nginx'])
        timeout: Command timeout in seconds

    Returns:
        ServiceResult with command execution details

    Security:
        - Requires command as list (no shell injection possible)
        - Caller is responsible for validating command arguments
        - No shell=True usage
    """
    if not isinstance(command, list) or not command:
        return ServiceResult(
            success=False,
            message="Command must be a non-empty list of arguments",
            returncode=-1
        )

    # Validate that command elements are strings
    if not all(isinstance(arg, str) for arg in command):
        return ServiceResult(
            success=False,
            message="All command arguments must be strings",
            returncode=-1
        )

    # Build full command with pkexec
    full_cmd = ["pkexec"] + command

    try:
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False  # Explicit: never use shell
        )
        return ServiceResult(
            success=result.returncode == 0,
            message=result.stdout or result.stderr,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr
        )
    except subprocess.TimeoutExpired:
        return ServiceResult(
            success=False,
            message=f"Command timed out after {timeout} seconds",
            returncode=-1
        )
    except FileNotFoundError:
        return ServiceResult(
            success=False,
            message=f"Command not found: {full_cmd[0]}",
            returncode=-1
        )
    except Exception as e:
        return ServiceResult(
            success=False,
            message=f"Command execution error: {str(e)}",
            returncode=-1
        )
