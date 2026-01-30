"""
IDS Service manager for Suricata and Snort
"""

import os
import subprocess
import glob
from typing import Callable, Optional

from ids_suite.services.systemd import SystemdService, ServiceResult, run_privileged_command
from ids_suite.services.privilege_helper import run_privileged_batch
from ids_suite.engines import IDSEngine


class IDSService:
    """Service manager for IDS engines (Suricata, Snort)"""

    def __init__(self, engine: IDSEngine):
        self.engine = engine
        self.service = SystemdService(engine.get_service_name())

    def start(self, callback: Optional[Callable[[ServiceResult], None]] = None) -> None:
        """Start the IDS service"""
        result = self.service.start()
        if callback:
            callback(result)

    def stop(self, callback: Optional[Callable[[ServiceResult], None]] = None) -> None:
        """Stop the IDS service"""
        result = self.service.stop()
        if callback:
            callback(result)

    def restart(self, callback: Optional[Callable[[ServiceResult], None]] = None) -> None:
        """Restart the IDS service"""
        result = self.service.restart()
        if callback:
            callback(result)

    def is_running(self) -> bool:
        """Check if the IDS service is running"""
        return self.service.is_active()

    def update_rules(self, callback: Optional[Callable[[ServiceResult], None]] = None) -> None:
        """Update IDS rules (Suricata-specific)"""
        if self.engine.get_name() == "Suricata":
            result = run_privileged_command("suricata-update --no-test")
        else:
            # Snort rule update would be different
            result = ServiceResult(
                success=False,
                message="Rule update not implemented for this engine",
                returncode=1
            )
        if callback:
            callback(result)

    def reload_rules(self, callback: Optional[Callable[[ServiceResult], None]] = None) -> None:
        """Reload rules without full restart"""
        if self.engine.get_name() == "Suricata":
            result = run_privileged_command("suricatasc -c reload-rules")
        else:
            result = self.service.reload()
        if callback:
            callback(result)

    def update_and_reload(self, callback: Optional[Callable[[ServiceResult], None]] = None) -> None:
        """Update rules and reload Suricata with single auth prompt"""
        if self.engine.get_name() == "Suricata":
            cmd_result = run_privileged_batch([
                "suricata-update --no-test",
                "suricatasc -c reload-rules",
            ])
            result = ServiceResult(
                success=cmd_result.success,
                message="Rules updated and reloaded" if cmd_result.success else cmd_result.message,
                returncode=cmd_result.returncode,
                stdout=cmd_result.stdout,
                stderr=cmd_result.stderr
            )
        else:
            result = ServiceResult(
                success=False,
                message="Update and reload not implemented for this engine",
                returncode=1
            )
        if callback:
            callback(result)

    def clean_logs(self, callback: Optional[Callable[[ServiceResult], None]] = None) -> None:
        """Clean IDS logs using cleanup script"""
        result = run_privileged_command("/usr/local/bin/ids-cleanup")
        if callback:
            callback(result)

    def open_config(self) -> None:
        """Open the IDS configuration file in default editor"""
        config_path = self.engine.get_config_path()
        if os.path.exists(config_path):
            subprocess.Popen(["xdg-open", config_path])

    def open_logs(self) -> None:
        """Open the IDS log directory in file manager"""
        log_dir = os.path.dirname(self.engine.get_log_path())
        if os.path.exists(log_dir):
            subprocess.Popen(["xdg-open", log_dir])

    def get_rule_count(self) -> int:
        """Get the number of loaded rules using pure Python (no shell injection risk)"""
        if self.engine.get_name() == "Suricata":
            try:
                rules_dir = "/var/lib/suricata/rules"
                if os.path.exists(rules_dir):
                    count = 0
                    # Use glob for safe file enumeration
                    for rule_file in glob.glob(os.path.join(rules_dir, "*.rules")):
                        try:
                            with open(rule_file, 'r', errors='ignore') as f:
                                for line in f:
                                    if line.strip().startswith('alert'):
                                        count += 1
                        except (IOError, OSError):
                            continue
                    return count
            except Exception:
                pass
        return 0

    def get_status_info(self) -> dict:
        """Get detailed status information"""
        return {
            'name': self.engine.get_name(),
            'service': self.engine.get_service_name(),
            'running': self.is_running(),
            'installed': self.engine.is_installed(),
            'config_path': self.engine.get_config_path(),
            'log_path': self.engine.get_log_path(),
            'rule_count': self.get_rule_count(),
        }
