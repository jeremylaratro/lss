"""
Privilege Helper - Batched privileged command execution

This module provides mechanisms to run multiple privileged commands with
a single authentication prompt, which is essential for polybar/taskbar usage.

Three strategies are provided:
1. Batch script execution - combines commands into a single pkexec call
2. Sudo timestamp caching - uses sudo's built-in credential caching
3. PolicyKit rules - allows passwordless execution for specific commands
"""

import subprocess
import os
import re
import tempfile
import shlex
from typing import List, Tuple, Optional, Callable, Dict
from dataclasses import dataclass
from pathlib import Path


# Command whitelist - only these commands with these arguments are allowed
# firewall-cmd and ufw are whitelisted for firewall control (reload/add-port/
# remove-port and enable/disable/reset/allow/deny respectively); dynamic
# port/protocol values are validated via regex in validate_command() below.
ALLOWED_COMMANDS = {
    'systemctl': {
        'allowed_args': ['start', 'stop', 'restart', 'reload', 'status', 'enable', 'disable', 'daemon-reload', '--now'],
        # NOTE: keep in sync with main_window._UNIT_CANDIDATES — the GUI
        # auto-detects the active unit name per host and any name it may pick
        # MUST be whitelisted here, or privileged control of that unit fails.
        'allowed_services': [
            'suricata-laptop',
            'suricata',
            'snort',
            'clamav-daemon',
            'clamav-freshclam',
            'clamav-clamonacc',
            'clamd@scan',
            'clamd',
            'freshclam',
            'clamonacc',
            'clamav-scheduled-scan.timer',
            'firewalld'
        ]
    },
    'mkdir': {
        'allowed_args': ['-p'],
        'validate_paths': True
    },
    'chown': {
        'allowed_args': [],  # format: user:group path
        'validate_paths': True,
        'allowed_owners': ['clamav:clamav', 'clamupdate:clamupdate', 'root:root']  # Fedora uses clamupdate
    },
    'suricata-update': {
        'allowed_args': ['--no-test', '--reload-command', '--help'],
        'max_args': 2
    },
    'suricatasc': {
        'allowed_args': ['-c', '--command', '--help'],
        'allowed_commands': ['reload-rules', 'uptime', 'shutdown']
    },
    'freshclam': {
        'allowed_args': ['--help', '--version'],
        'max_args': 0
    },
    'clamscan': {
        'allowed_args': ['-r', '--recursive', '--infected', '--remove', '--help'],
        'max_args': 3
    },
    'cp': {
        'allowed_args': [],
        'validate_paths': True
    },
    'chmod': {
        'allowed_args': ['644', '755', '700', '600', '+x'],
        'validate_paths': True
    },
    'rm': {
        'allowed_args': ['-f'],
        'validate_paths': True,
        'max_args': 2
    },
    'firewall-cmd': {
        # --add-port=/--remove-port= carry a dynamic PORT[-PORT]/tcp|udp value
        # that is validated separately (see validate_command)
        'allowed_args': ['--complete-reload', '--reload', '--permanent']
    },
    'ufw': {
        # allow/deny carry a dynamic port (optionally with /tcp|/udp) that is
        # validated separately (see validate_command)
        'allowed_args': ['enable', 'disable', 'reset', 'allow', 'deny']
    }
}


class CommandValidationError(Exception):
    """Raised when a command fails validation against the whitelist."""
    pass


@dataclass
class CommandResult:
    """Result of a privileged command execution"""
    success: bool
    message: str
    returncode: int
    stdout: str = ""
    stderr: str = ""
    commands_run: int = 0


def validate_command(command: str) -> List[str]:
    """Validate a command against the whitelist and return parsed command list.

    Args:
        command: The command string to validate

    Returns:
        List of command parts that have been validated

    Raises:
        CommandValidationError: If the command is not allowed
    """
    # Parse the command safely
    try:
        parts = shlex.split(command)
    except ValueError as e:
        raise CommandValidationError(f"Invalid command syntax: {e}")

    if not parts:
        raise CommandValidationError("Empty command")

    binary = parts[0]
    args = parts[1:]

    # Check if binary is in whitelist
    if binary not in ALLOWED_COMMANDS:
        raise CommandValidationError(
            f"Command '{binary}' is not in the allowed command list. "
            f"Allowed commands: {', '.join(ALLOWED_COMMANDS.keys())}"
        )

    config = ALLOWED_COMMANDS[binary]

    # Validate systemctl commands
    if binary == 'systemctl':
        if len(args) < 1:
            raise CommandValidationError(f"systemctl requires at least an action")

        action = args[0]

        # daemon-reload doesn't need a service name
        if action == 'daemon-reload':
            if len(args) > 1:
                raise CommandValidationError("daemon-reload takes no additional arguments")
            return parts

        if len(args) < 2:
            raise CommandValidationError(f"systemctl {action} requires a service name")

        # Handle --now flag (can appear before or after service name)
        remaining_args = [a for a in args[1:] if a != '--now']
        has_now_flag = '--now' in args

        if has_now_flag and action not in ['enable', 'disable']:
            raise CommandValidationError("--now flag only valid with enable/disable")

        if len(remaining_args) != 1:
            raise CommandValidationError(f"systemctl {action} requires exactly one service name")

        service = remaining_args[0]

        if action not in config['allowed_args']:
            raise CommandValidationError(
                f"systemctl action '{action}' not allowed. "
                f"Allowed: {', '.join(config['allowed_args'])}"
            )

        if service not in config['allowed_services']:
            raise CommandValidationError(
                f"Service '{service}' not allowed. "
                f"Allowed services: {', '.join(config['allowed_services'])}"
            )

    # Validate suricatasc commands
    elif binary == 'suricatasc':
        if '-c' in args or '--command' in args:
            cmd_index = args.index('-c') if '-c' in args else args.index('--command')
            if cmd_index + 1 >= len(args):
                raise CommandValidationError("suricatasc -c requires a command argument")

            suricata_cmd = args[cmd_index + 1]
            if suricata_cmd not in config['allowed_commands']:
                raise CommandValidationError(
                    f"suricatasc command '{suricata_cmd}' not allowed. "
                    f"Allowed: {', '.join(config['allowed_commands'])}"
                )

    # Validate firewall-cmd commands
    elif binary == 'firewall-cmd':
        if not args:
            raise CommandValidationError("firewall-cmd requires at least one argument")

        port_action_prefixes = ('--add-port=', '--remove-port=')

        for arg in args:
            if arg in config['allowed_args']:
                continue
            if arg.startswith(port_action_prefixes):
                _, _, value = arg.partition('=')
                if not _is_valid_port_spec(value, allow_range=True, require_proto=True):
                    raise CommandValidationError(
                        f"firewall-cmd port spec '{value}' is not valid "
                        f"(expected PORT[-PORT]/tcp or PORT[-PORT]/udp, ports 1-65535)"
                    )
                continue
            raise CommandValidationError(
                f"Argument '{arg}' not allowed for firewall-cmd. "
                f"Allowed: {', '.join(config['allowed_args'])}, "
                f"--add-port=PORT[-PORT]/tcp|udp, --remove-port=PORT[-PORT]/tcp|udp"
            )

    # Validate ufw commands
    elif binary == 'ufw':
        if not args:
            raise CommandValidationError("ufw requires at least one argument")

        # Allow an optional leading --force (needed for non-interactive
        # `ufw --force enable` / `ufw --force reset`, which would otherwise
        # block on an interactive y/n prompt under pkexec).
        if args[0] == '--force':
            args = args[1:]
            if not args:
                raise CommandValidationError("ufw --force requires an action")

        action = args[0]
        if action not in config['allowed_args']:
            raise CommandValidationError(
                f"ufw action '{action}' not allowed. "
                f"Allowed: {', '.join(config['allowed_args'])}"
            )

        if action in ('enable', 'disable', 'reset'):
            if len(args) != 1:
                raise CommandValidationError(f"ufw {action} takes no additional arguments")
        elif action in ('allow', 'deny'):
            if len(args) != 2:
                raise CommandValidationError(f"ufw {action} requires exactly one port argument")

            if not _is_valid_port_spec(args[1], allow_range=False):
                raise CommandValidationError(
                    f"ufw port '{args[1]}' is not valid "
                    f"(expected PORT or PORT/tcp or PORT/udp, ports 1-65535)"
                )

    # Validate commands with path restrictions (cp, chmod, rm)
    elif config.get('validate_paths'):
        if binary == 'cp':
            # cp requires exactly 2 path arguments
            if len(args) != 2:
                raise CommandValidationError("cp requires exactly 2 arguments (source and destination)")

            # Validate paths point to allowed locations
            for path in args:
                if not _is_safe_path(path):
                    raise CommandValidationError(f"Path '{path}' is not in allowed locations")

        elif binary == 'chmod':
            if len(args) < 2:
                raise CommandValidationError("chmod requires mode and path")

            mode = args[0]
            if mode not in config['allowed_args']:
                raise CommandValidationError(
                    f"chmod mode '{mode}' not allowed. "
                    f"Allowed modes: {', '.join(config['allowed_args'])}"
                )

            path = args[1]
            if not _is_safe_path(path):
                raise CommandValidationError(f"Path '{path}' is not in allowed locations")

        elif binary == 'rm':
            if not args:
                raise CommandValidationError("rm requires at least one argument")

            # Validate each path
            for arg in args:
                if arg.startswith('-'):
                    if arg not in config['allowed_args']:
                        raise CommandValidationError(f"rm flag '{arg}' not allowed")
                else:
                    if not _is_safe_path(arg):
                        raise CommandValidationError(f"Path '{arg}' is not in allowed locations")

        elif binary == 'mkdir':
            if not args:
                raise CommandValidationError("mkdir requires at least one argument")

            # Validate flags and path
            for arg in args:
                if arg.startswith('-'):
                    if arg not in config['allowed_args']:
                        raise CommandValidationError(f"mkdir flag '{arg}' not allowed")
                else:
                    if not _is_safe_path(arg):
                        raise CommandValidationError(f"Path '{arg}' is not in allowed locations")

        elif binary == 'chown':
            if len(args) < 2:
                raise CommandValidationError("chown requires owner:group and path")

            owner = args[0]
            path = args[1]

            if owner not in config.get('allowed_owners', []):
                raise CommandValidationError(
                    f"Owner '{owner}' not allowed. "
                    f"Allowed: {', '.join(config.get('allowed_owners', []))}"
                )

            if not _is_safe_path(path):
                raise CommandValidationError(f"Path '{path}' is not in allowed locations")

    # Validate argument count limits
    if 'max_args' in config:
        if len(args) > config['max_args']:
            raise CommandValidationError(
                f"{binary} accepts maximum {config['max_args']} arguments, got {len(args)}"
            )

    # Validate allowed arguments for commands with strict argument lists
    # Skip commands that have their own validation logic above
    path_validated_commands = ['systemctl', 'suricatasc', 'cp', 'chmod', 'rm', 'mkdir', 'chown', 'firewall-cmd', 'ufw']
    if 'allowed_args' in config and binary not in path_validated_commands:
        for arg in args:
            if arg not in config['allowed_args']:
                raise CommandValidationError(
                    f"Argument '{arg}' not allowed for {binary}. "
                    f"Allowed: {', '.join(config['allowed_args'])}"
                )

    return parts


def _is_safe_path(path: str) -> bool:
    """Check if a path is in allowed locations."""
    # Only allow specific safe directories
    allowed_prefixes = [
        '/tmp/',
        '/var/tmp/',
        '/etc/polkit-1/rules.d/',
        '/usr/local/bin/',
        '/etc/systemd/system/',
        '/var/lib/clamav/',
        '/etc/suricata/',
        '/etc/clamav/',
    ]

    # Resolve the path to prevent directory traversal
    try:
        resolved = os.path.realpath(path)
    except (OSError, ValueError):
        return False

    # Check if resolved path starts with any allowed prefix
    for prefix in allowed_prefixes:
        if resolved.startswith(prefix):
            return True

    return False


_PORT_SPEC_RE = re.compile(r'^(\d{1,5})(?:-(\d{1,5}))?(?:/(tcp|udp))?$')


def _is_valid_port_spec(spec: str, allow_range: bool = False, require_proto: bool = False) -> bool:
    """Check if a firewall port spec (e.g. '8080', '8080/tcp', '8000-8010/udp')
    is well-formed, with each port number in the valid 1-65535 range.

    Args:
        spec: The port spec to validate.
        allow_range: Whether a PORT-PORT range is permitted (firewall-cmd
            supports ranges; ufw's `allow`/`deny` do not).
        require_proto: Whether the /tcp|/udp suffix is mandatory (firewalld's
            --add-port/--remove-port require it; ufw's allow/deny do not).
    """
    match = _PORT_SPEC_RE.match(spec)
    if not match:
        return False

    start_str, end_str, proto = match.groups()

    if end_str is not None and not allow_range:
        return False

    if require_proto and proto is None:
        return False

    for port_str in (start_str, end_str):
        if port_str is None:
            continue
        port = int(port_str)
        if not (1 <= port <= 65535):
            return False

    if end_str is not None and int(start_str) > int(end_str):
        return False

    return True


class PrivilegeHelper:
    """Helper for executing privileged commands with minimal auth prompts.

    Strategies:
    - batch: Combine commands into a single script, run with one pkexec
    - sudo_cache: Use sudo with credential caching (requires sudoers config)
    - direct: Use pkexec for each command (fallback, multiple prompts)
    """

    def __init__(self, strategy: str = "batch"):
        """
        Initialize the privilege helper.

        Args:
            strategy: "batch" (recommended), "sudo_cache", or "direct"
        """
        self.strategy = strategy
        self._pending_commands: List[str] = []

    def add_command(self, command: str) -> None:
        """Add a command to the pending batch.

        Args:
            command: Command string to add

        Raises:
            CommandValidationError: If command fails validation
        """
        # Validate command before adding
        validate_command(command)
        self._pending_commands.append(command)

    def clear_pending(self) -> None:
        """Clear all pending commands."""
        self._pending_commands.clear()

    def execute_batch(
        self,
        commands: Optional[List[str]] = None,
        on_output: Optional[Callable[[str], None]] = None
    ) -> CommandResult:
        """Execute a batch of commands with a single authentication.

        Args:
            commands: List of commands to run. If None, uses pending commands.
            on_output: Optional callback for real-time output.

        Returns:
            CommandResult with aggregated results.
        """
        cmds = commands if commands is not None else self._pending_commands

        if not cmds:
            return CommandResult(
                success=True,
                message="No commands to execute",
                returncode=0,
                commands_run=0
            )

        if self.strategy == "batch":
            return self._execute_batch_script(cmds, on_output)
        elif self.strategy == "sudo_cache":
            return self._execute_sudo_cached(cmds, on_output)
        else:
            return self._execute_direct(cmds, on_output)

    def _execute_batch_script(
        self,
        commands: List[str],
        on_output: Optional[Callable[[str], None]] = None
    ) -> CommandResult:
        """Execute commands via a single batch script with pkexec."""

        # Validate all commands first
        validated_commands = []
        try:
            for cmd in commands:
                validated_parts = validate_command(cmd)
                validated_commands.append(validated_parts)
        except CommandValidationError as e:
            return CommandResult(
                success=False,
                message=f"Command validation failed: {e}",
                returncode=-1,
                commands_run=0
            )

        # Create a temporary script with all validated commands
        # Don't use set -e; track failures manually so we can see all command results
        script_content = "#!/bin/bash\n\n"
        script_content += "FAILED=0\n\n"

        for i, cmd_parts in enumerate(validated_commands, 1):
            script_content += f'echo ">>> Executing command {i}/{len(validated_commands)}..."\n'
            # Use properly quoted command parts
            script_content += shlex.join(cmd_parts) + '\n'
            script_content += 'EXIT_CODE=$?\n'
            script_content += f'if [ $EXIT_CODE -ne 0 ]; then\n'
            script_content += f'    echo ">>> Command {i} FAILED with exit code $EXIT_CODE"\n'
            script_content += f'    FAILED=1\n'
            script_content += f'else\n'
            script_content += f'    echo ">>> Command {i} completed successfully"\n'
            script_content += f'fi\n\n'

        # Exit with failure if any command failed
        script_content += 'exit $FAILED\n'

        script_path = None
        try:
            # Write script to temp file
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.sh', delete=False
            ) as f:
                f.write(script_content)
                script_path = f.name

            os.chmod(script_path, 0o700)

            # Execute with pkexec using list-based invocation (no shell injection)
            result = subprocess.run(
                ["pkexec", "bash", script_path],
                capture_output=True,
                text=True,
                timeout=300
            )

            if on_output and result.stdout:
                for line in result.stdout.split('\n'):
                    on_output(line)

            self.clear_pending()

            return CommandResult(
                success=result.returncode == 0,
                message=result.stdout or result.stderr,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                commands_run=len(commands)
            )

        except subprocess.TimeoutExpired:
            return CommandResult(
                success=False,
                message="Command batch timed out",
                returncode=-1,
                commands_run=0
            )
        except Exception as e:
            return CommandResult(
                success=False,
                message=str(e),
                returncode=-1,
                commands_run=0
            )
        finally:
            # Ensure cleanup in all cases
            if script_path and os.path.exists(script_path):
                try:
                    os.unlink(script_path)
                except OSError:
                    pass

    def _execute_sudo_cached(
        self,
        commands: List[str],
        on_output: Optional[Callable[[str], None]] = None
    ) -> CommandResult:
        """Execute commands using sudo with timestamp caching.

        This requires the user to have sudo access and relies on sudo's
        built-in credential caching (default 15 minutes).
        """
        # Validate all commands first
        validated_commands = []
        try:
            for cmd in commands:
                validated_parts = validate_command(cmd)
                validated_commands.append(validated_parts)
        except CommandValidationError as e:
            return CommandResult(
                success=False,
                message=f"Command validation failed: {e}",
                returncode=-1,
                commands_run=0
            )

        # First, validate sudo access (this prompts once)
        validate = subprocess.run(
            ["sudo", "-v"],
            capture_output=True,
            text=True
        )

        if validate.returncode != 0:
            return CommandResult(
                success=False,
                message="Sudo authentication failed",
                returncode=validate.returncode,
                commands_run=0
            )

        # Now execute each command (no more prompts within timeout)
        all_stdout = []
        all_stderr = []
        success = True
        last_returncode = 0

        for cmd_parts in validated_commands:
            # Use list-based execution to prevent shell injection
            result = subprocess.run(
                ["sudo"] + cmd_parts,
                capture_output=True,
                text=True
            )

            all_stdout.append(result.stdout)
            all_stderr.append(result.stderr)

            if on_output and result.stdout:
                for line in result.stdout.split('\n'):
                    on_output(line)

            if result.returncode != 0:
                success = False
                last_returncode = result.returncode
                break

        self.clear_pending()

        return CommandResult(
            success=success,
            message='\n'.join(all_stdout),
            returncode=last_returncode,
            stdout='\n'.join(all_stdout),
            stderr='\n'.join(all_stderr),
            commands_run=len(commands)
        )

    def _execute_direct(
        self,
        commands: List[str],
        on_output: Optional[Callable[[str], None]] = None
    ) -> CommandResult:
        """Execute each command with pkexec (multiple prompts - fallback)."""
        # Validate all commands first
        validated_commands = []
        try:
            for cmd in commands:
                validated_parts = validate_command(cmd)
                validated_commands.append(validated_parts)
        except CommandValidationError as e:
            return CommandResult(
                success=False,
                message=f"Command validation failed: {e}",
                returncode=-1,
                commands_run=0
            )

        all_stdout = []
        all_stderr = []
        success = True
        last_returncode = 0

        for cmd_parts in validated_commands:
            # Use list-based execution to prevent shell injection
            result = subprocess.run(
                ["pkexec"] + cmd_parts,
                capture_output=True,
                text=True
            )

            all_stdout.append(result.stdout)
            all_stderr.append(result.stderr)

            if on_output and result.stdout:
                for line in result.stdout.split('\n'):
                    on_output(line)

            if result.returncode != 0:
                success = False
                last_returncode = result.returncode
                break

        self.clear_pending()

        return CommandResult(
            success=success,
            message='\n'.join(all_stdout),
            returncode=last_returncode,
            stdout='\n'.join(all_stdout),
            stderr='\n'.join(all_stderr),
            commands_run=len(commands)
        )


# Convenience functions for common operations

def run_privileged_batch(commands: List[str]) -> CommandResult:
    """Run a batch of privileged commands with single auth."""
    helper = PrivilegeHelper(strategy="batch")
    return helper.execute_batch(commands)


def restart_ids_services() -> CommandResult:
    """Restart IDS services with single auth."""
    return run_privileged_batch([
        "systemctl restart suricata-laptop",
    ])


def restart_clamav_services() -> CommandResult:
    """Restart all ClamAV services with single auth."""
    return run_privileged_batch([
        "systemctl restart clamav-daemon",
        "systemctl restart clamav-freshclam",
        "systemctl restart clamav-clamonacc",
    ])


def start_clamav_services() -> CommandResult:
    """Start all ClamAV services with single auth."""
    return run_privileged_batch([
        "systemctl start clamav-daemon",
        "systemctl start clamav-freshclam",
        "systemctl start clamav-clamonacc",
    ])


def stop_clamav_services() -> CommandResult:
    """Stop all ClamAV services with single auth."""
    return run_privileged_batch([
        "systemctl stop clamav-clamonacc",
        "systemctl stop clamav-freshclam",
        "systemctl stop clamav-daemon",
    ])


def update_and_reload_suricata() -> CommandResult:
    """Update rules and reload Suricata with single auth."""
    return run_privileged_batch([
        "suricata-update --no-test",
        "suricatasc -c reload-rules",
    ])


def update_clamav_signatures() -> CommandResult:
    """Update ClamAV signatures with single auth."""
    return run_privileged_batch([
        "systemctl stop clamav-freshclam",
        "freshclam",
        "systemctl start clamav-freshclam",
    ])


# PolicyKit rule generator

def generate_polkit_rules() -> str:
    """Generate PolicyKit rules for passwordless operation.

    Install to: /etc/polkit-1/rules.d/50-ids-suite.rules
    """
    return '''/* IDS Suite PolicyKit Rules
 * Allows members of the 'wheel' group to manage IDS/AV services
 * without password prompts.
 *
 * Install: sudo cp this-file /etc/polkit-1/rules.d/50-ids-suite.rules
 */

polkit.addRule(function(action, subject) {
    // Allow systemctl operations for specific services
    if (action.id == "org.freedesktop.systemd1.manage-units") {
        var unit = action.lookup("unit");
        var allowedUnits = [
            "suricata-laptop.service",
            "suricata.service",
            "snort.service",
            "clamav-daemon.service",
            "clamav-freshclam.service",
            "clamav-clamonacc.service",
            "clamd@scan.service"
        ];

        for (var i = 0; i < allowedUnits.length; i++) {
            if (unit == allowedUnits[i] && subject.isInGroup("wheel")) {
                return polkit.Result.YES;
            }
        }
    }

    // Allow pkexec for specific security tools
    if (action.id == "org.freedesktop.policykit.exec") {
        var program = action.lookup("program");
        var allowedPrograms = [
            "/usr/bin/suricata-update",
            "/usr/bin/suricatasc",
            "/usr/bin/freshclam",
            "/usr/bin/clamscan",
            "/usr/local/bin/ids-cleanup",
            "/usr/local/bin/av-cleanup"
        ];

        for (var i = 0; i < allowedPrograms.length; i++) {
            if (program == allowedPrograms[i] && subject.isInGroup("wheel")) {
                return polkit.Result.YES;
            }
        }
    }

    return polkit.Result.NOT_HANDLED;
});
'''


def install_polkit_rules() -> CommandResult:
    """Install PolicyKit rules for passwordless operation."""
    rules_content = generate_polkit_rules()
    rules_path = "/etc/polkit-1/rules.d/50-ids-suite.rules"

    temp_path = None
    try:
        # Create temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.rules', delete=False) as f:
            f.write(rules_content)
            temp_path = f.name

        result = run_privileged_batch([
            f"cp {shlex.quote(temp_path)} {shlex.quote(rules_path)}",
            f"chmod 644 {shlex.quote(rules_path)}",
        ])

        return result
    finally:
        # Cleanup temp file
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass
