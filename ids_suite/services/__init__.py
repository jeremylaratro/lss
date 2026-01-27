"""
Services module - System service management for IDS and ClamAV
"""

from ids_suite.services.systemd import SystemdService, ServiceResult, run_privileged_command
from ids_suite.services.ids_service import IDSService
from ids_suite.services.clamav_service import ClamAVService, ClamAVScanner
from ids_suite.services.privilege_helper import (
    PrivilegeHelper,
    CommandResult,
    run_privileged_batch,
    restart_ids_services,
    restart_clamav_services,
    start_clamav_services,
    stop_clamav_services,
    update_and_reload_suricata,
    update_clamav_signatures,
    generate_polkit_rules,
    install_polkit_rules,
)

__all__ = [
    'SystemdService',
    'ServiceResult',
    'run_privileged_command',
    'IDSService',
    'ClamAVService',
    'ClamAVScanner',
    'PrivilegeHelper',
    'CommandResult',
    'run_privileged_batch',
    'restart_ids_services',
    'restart_clamav_services',
    'start_clamav_services',
    'stop_clamav_services',
    'update_and_reload_suricata',
    'update_clamav_signatures',
    'generate_polkit_rules',
    'install_polkit_rules',
]
