"""
ClamAV Service manager
"""

import os
import subprocess
import glob
import re
from typing import Callable, Optional

from ids_suite.services.systemd import SystemdService, ServiceResult, run_privileged_command
from ids_suite.services.privilege_helper import run_privileged_batch, CommandResult


class ClamAVService:
    """Service manager for ClamAV antivirus suite

    Uses batched privilege escalation to minimize password prompts.
    All start/stop operations are combined into a single pkexec call.
    """

    def __init__(self):
        self.daemon = SystemdService("clamav-daemon")
        self.freshclam = SystemdService("clamav-freshclam")
        self.clamonacc = SystemdService("clamav-clamonacc")

    def _convert_result(self, cmd_result: CommandResult) -> ServiceResult:
        """Convert CommandResult to ServiceResult for API compatibility"""
        return ServiceResult(
            success=cmd_result.success,
            message=cmd_result.message,
            returncode=cmd_result.returncode,
            stdout=cmd_result.stdout,
            stderr=cmd_result.stderr
        )

    def start(self, callback: Optional[Callable[[ServiceResult], None]] = None) -> None:
        """Start all ClamAV services with single auth prompt"""
        cmd_result = run_privileged_batch([
            "systemctl start clamav-daemon",
            "systemctl start clamav-freshclam",
            "systemctl start clamav-clamonacc",
        ])

        result = ServiceResult(
            success=cmd_result.success,
            message="ClamAV started" if cmd_result.success else cmd_result.message,
            returncode=cmd_result.returncode,
            stdout=cmd_result.stdout,
            stderr=cmd_result.stderr
        )
        if callback:
            callback(result)

    def stop(self, callback: Optional[Callable[[ServiceResult], None]] = None) -> None:
        """Stop all ClamAV services (in reverse order) with single auth prompt"""
        cmd_result = run_privileged_batch([
            "systemctl stop clamav-clamonacc",
            "systemctl stop clamav-freshclam",
            "systemctl stop clamav-daemon",
        ])

        result = ServiceResult(
            success=cmd_result.success,
            message="ClamAV stopped" if cmd_result.success else cmd_result.message,
            returncode=cmd_result.returncode,
            stdout=cmd_result.stdout,
            stderr=cmd_result.stderr
        )
        if callback:
            callback(result)

    def restart(self, callback: Optional[Callable[[ServiceResult], None]] = None) -> None:
        """Restart all ClamAV services with single auth prompt"""
        cmd_result = run_privileged_batch([
            "systemctl restart clamav-daemon",
            "systemctl restart clamav-freshclam",
            "systemctl restart clamav-clamonacc",
        ])

        result = ServiceResult(
            success=cmd_result.success,
            message="ClamAV restarted" if cmd_result.success else cmd_result.message,
            returncode=cmd_result.returncode,
            stdout=cmd_result.stdout,
            stderr=cmd_result.stderr
        )
        if callback:
            callback(result)

    def is_daemon_running(self) -> bool:
        """Check if clamav-daemon is running"""
        return self.daemon.is_active()

    def is_freshclam_running(self) -> bool:
        """Check if clamav-freshclam is running"""
        return self.freshclam.is_active()

    def is_clamonacc_running(self) -> bool:
        """Check if clamav-clamonacc (on-access scanning) is running"""
        return self.clamonacc.is_active()

    def update_signatures(self, callback: Optional[Callable[[ServiceResult], None]] = None) -> None:
        """Update virus signatures using freshclam with single auth prompt"""
        # Batch: stop freshclam, run freshclam manually, restart freshclam
        cmd_result = run_privileged_batch([
            "systemctl stop clamav-freshclam",
            "freshclam",
            "systemctl start clamav-freshclam",
        ])

        result = ServiceResult(
            success=cmd_result.success,
            message="Signatures updated" if cmd_result.success else cmd_result.message,
            returncode=cmd_result.returncode,
            stdout=cmd_result.stdout,
            stderr=cmd_result.stderr
        )
        if callback:
            callback(result)

    def get_signature_count(self) -> str:
        """Get total number of virus signatures using pure Python (no shell injection risk)"""
        try:
            clamav_dir = "/var/lib/clamav"
            total_signatures = 0

            # Find all .cld and .cvd signature database files
            sig_files = glob.glob(os.path.join(clamav_dir, "*.cld"))
            sig_files.extend(glob.glob(os.path.join(clamav_dir, "*.cvd")))

            for sig_file in sig_files:
                if os.path.isfile(sig_file):
                    try:
                        # Use list-based subprocess (no shell injection)
                        result = subprocess.run(
                            ["sigtool", "--info", sig_file],
                            capture_output=True, text=True, timeout=10
                        )
                        if result.returncode == 0:
                            # Parse "Number of signatures: NNNN"
                            match = re.search(r'Number of signatures:\s*(\d+)', result.stdout)
                            if match:
                                total_signatures += int(match.group(1))
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        continue

            if total_signatures > 0:
                return str(total_signatures)
        except Exception:
            pass
        return "N/A"

    def get_quarantine_count(self) -> int:
        """Get number of quarantined files"""
        quarantine_dir = "/var/lib/clamav/quarantine"
        try:
            if os.path.exists(quarantine_dir):
                return len([f for f in os.listdir(quarantine_dir) if os.path.isfile(os.path.join(quarantine_dir, f))])
        except Exception:
            pass
        return 0

    def clean_logs(self, callback: Optional[Callable[[ServiceResult], None]] = None) -> None:
        """Clean ClamAV logs using cleanup script"""
        result = run_privileged_command("/usr/local/bin/av-cleanup")
        if callback:
            callback(result)

    def open_logs(self) -> None:
        """Open ClamAV log directory in file manager"""
        log_dir = "/var/log/clamav"
        if os.path.exists(log_dir):
            subprocess.Popen(["xdg-open", log_dir])

    def get_status_info(self) -> dict:
        """Get detailed status information"""
        return {
            'daemon_running': self.is_daemon_running(),
            'freshclam_running': self.is_freshclam_running(),
            'clamonacc_running': self.is_clamonacc_running(),
            'signature_count': self.get_signature_count(),
            'quarantine_count': self.get_quarantine_count(),
        }


class ClamAVScanner:
    """ClamAV file/directory scanner"""

    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self.cancelled = False

    def scan(
        self,
        path: str,
        recursive: bool = True,
        on_output: Optional[Callable[[str], None]] = None,
        on_complete: Optional[Callable[[int], None]] = None
    ) -> None:
        """Start a scan of the specified path"""
        self.cancelled = False

        cmd = ["clamscan"]
        if recursive:
            cmd.append("-r")
        cmd.extend(["--infected", "--remove=no", path])

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            for line in iter(self.process.stdout.readline, ''):
                if self.cancelled:
                    self.process.terminate()
                    break
                if on_output:
                    on_output(line.rstrip())

            self.process.wait()
            if on_complete:
                on_complete(self.process.returncode)

        except Exception as e:
            if on_output:
                on_output(f"Error: {str(e)}")
            if on_complete:
                on_complete(-1)

    def cancel(self) -> None:
        """Cancel the current scan"""
        self.cancelled = True
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass

    def is_scanning(self) -> bool:
        """Check if a scan is in progress"""
        return self.process is not None and self.process.poll() is None
