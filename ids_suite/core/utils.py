"""
Utility functions for the Security Suite
"""

import os
import grp
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple


class LinuxDistro(Enum):
    """Supported Linux distribution families."""
    FEDORA = "fedora"      # Fedora, RHEL, CentOS, Rocky, Alma
    DEBIAN = "debian"      # Debian, Ubuntu, Mint, Pop!_OS
    ARCH = "arch"          # Arch, Manjaro, EndeavourOS
    UNKNOWN = "unknown"


@dataclass
class DistroConfig:
    """Distribution-specific configuration paths and service names."""
    distro: LinuxDistro

    # ClamAV configuration
    clamav_daemon_service: str
    clamav_freshclam_service: str
    clamav_socket: str
    clamav_user: str
    clamav_group: str
    clamav_config_dir: str

    # Firewall
    firewall_type: str  # "firewalld" or "ufw"

    # PolicyKit admin group
    admin_group: str  # "wheel" or "sudo"


def detect_distro() -> LinuxDistro:
    """Detect the Linux distribution family.

    Reads /etc/os-release to determine the distribution.
    Returns LinuxDistro enum value.
    """
    os_release = Path("/etc/os-release")

    if not os_release.exists():
        return LinuxDistro.UNKNOWN

    try:
        content = os_release.read_text().lower()

        # Check ID and ID_LIKE fields
        if "arch" in content:
            return LinuxDistro.ARCH
        elif any(d in content for d in ["fedora", "rhel", "centos", "rocky", "alma"]):
            return LinuxDistro.FEDORA
        elif any(d in content for d in ["debian", "ubuntu", "mint", "pop"]):
            return LinuxDistro.DEBIAN

        return LinuxDistro.UNKNOWN
    except (IOError, OSError):
        return LinuxDistro.UNKNOWN


def _detect_admin_group() -> str:
    """Detect whether 'wheel' or 'sudo' group exists for admin privileges."""
    try:
        grp.getgrnam('wheel')
        return 'wheel'
    except KeyError:
        pass

    try:
        grp.getgrnam('sudo')
        return 'sudo'
    except KeyError:
        pass

    return 'wheel'  # Default fallback


def _detect_clamav_user() -> Tuple[str, str]:
    """Detect ClamAV user and group for this system."""
    import pwd

    # Try Fedora first (clamupdate)
    try:
        pwd.getpwnam('clamupdate')
        grp.getgrnam('clamupdate')
        return ('clamupdate', 'clamupdate')
    except KeyError:
        pass

    # Try Debian/Arch (clamav)
    try:
        pwd.getpwnam('clamav')
        grp.getgrnam('clamav')
        return ('clamav', 'clamav')
    except KeyError:
        pass

    return ('root', 'root')


def _detect_firewall_type() -> str:
    """Detect whether system uses firewalld or ufw."""
    # Check for firewalld first
    if os.path.exists("/usr/bin/firewall-cmd") or os.path.exists("/bin/firewall-cmd"):
        return "firewalld"

    # Check for ufw
    if os.path.exists("/usr/sbin/ufw") or os.path.exists("/sbin/ufw"):
        return "ufw"

    # Check systemd service files
    if os.path.exists("/usr/lib/systemd/system/firewalld.service"):
        return "firewalld"
    if os.path.exists("/lib/systemd/system/ufw.service"):
        return "ufw"

    return "unknown"


def _find_clamav_socket() -> str:
    """Find the ClamAV socket path for this system."""
    possible_sockets = [
        "/var/run/clamav/clamd.ctl",       # Debian/Ubuntu
        "/run/clamav/clamd.sock",          # Arch
        "/var/run/clamd.scan/clamd.sock",  # Fedora with clamd@scan
        "/var/run/clamav/clamd.sock",      # Alternative
    ]

    for sock in possible_sockets:
        if os.path.exists(sock):
            return sock

    # Return distro-appropriate default
    distro = detect_distro()
    if distro == LinuxDistro.FEDORA:
        return "/var/run/clamd.scan/clamd.sock"
    elif distro == LinuxDistro.DEBIAN:
        return "/var/run/clamav/clamd.ctl"
    else:
        return "/run/clamav/clamd.sock"


def get_distro_config() -> DistroConfig:
    """Get the distribution-specific configuration for this system.

    Auto-detects the Linux distribution and returns appropriate
    service names, paths, and configuration for ClamAV, firewall, etc.
    """
    distro = detect_distro()
    clamav_user, clamav_group = _detect_clamav_user()
    admin_group = _detect_admin_group()
    firewall_type = _detect_firewall_type()
    clamav_socket = _find_clamav_socket()

    if distro == LinuxDistro.FEDORA:
        return DistroConfig(
            distro=distro,
            clamav_daemon_service="clamd@scan",
            clamav_freshclam_service="clamav-freshclam",
            clamav_socket=clamav_socket,
            clamav_user=clamav_user,
            clamav_group=clamav_group,
            clamav_config_dir="/etc/clamd.d",
            firewall_type=firewall_type,
            admin_group=admin_group,
        )
    elif distro == LinuxDistro.DEBIAN:
        return DistroConfig(
            distro=distro,
            clamav_daemon_service="clamav-daemon",
            clamav_freshclam_service="clamav-freshclam",
            clamav_socket=clamav_socket,
            clamav_user=clamav_user,
            clamav_group=clamav_group,
            clamav_config_dir="/etc/clamav",
            firewall_type=firewall_type,
            admin_group=admin_group,
        )
    elif distro == LinuxDistro.ARCH:
        return DistroConfig(
            distro=distro,
            clamav_daemon_service="clamav-daemon",
            clamav_freshclam_service="clamav-freshclam",
            clamav_socket=clamav_socket,
            clamav_user=clamav_user,
            clamav_group=clamav_group,
            clamav_config_dir="/etc/clamav",
            firewall_type=firewall_type,
            admin_group=admin_group,
        )
    else:
        # Unknown - use runtime detection for everything
        return DistroConfig(
            distro=distro,
            clamav_daemon_service="clamav-daemon",
            clamav_freshclam_service="clamav-freshclam",
            clamav_socket=clamav_socket,
            clamav_user=clamav_user,
            clamav_group=clamav_group,
            clamav_config_dir="/etc/clamav",
            firewall_type=firewall_type,
            admin_group=admin_group,
        )


# Cache the config to avoid repeated filesystem checks
_cached_config: Optional[DistroConfig] = None


def get_system_config() -> DistroConfig:
    """Get cached system configuration (singleton pattern)."""
    global _cached_config
    if _cached_config is None:
        _cached_config = get_distro_config()
    return _cached_config


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/LAN (should not be sent to threat intel APIs).

    Returns True for:
    - 10.0.0.0/8 (Class A private)
    - 172.16.0.0/12 (Class B private)
    - 192.168.0.0/16 (Class C private)
    - 127.0.0.0/8 (Loopback)
    - 169.254.0.0/16 (Link-local)
    - 224.0.0.0/4 (Multicast)
    - 0.0.0.0/8 (Invalid/this network)
    - ::1, fe80::/10, fc00::/7 (IPv6 private/link-local)
    """
    if not ip or not isinstance(ip, str):
        return True  # Invalid, don't look up

    ip = ip.strip()

    # Handle IPv6
    if ':' in ip:
        ip_lower = ip.lower()
        # IPv6 loopback
        if ip_lower == '::1':
            return True
        # IPv6 link-local (fe80::/10)
        if ip_lower.startswith('fe80:'):
            return True
        # IPv6 unique local (fc00::/7 - includes fd00::/8)
        if ip_lower.startswith('fc') or ip_lower.startswith('fd'):
            return True
        # IPv6 multicast (ff00::/8)
        if ip_lower.startswith('ff'):
            return True
        return False

    # IPv4 validation and checks
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return True  # Invalid format

        octets = [int(p) for p in parts]
        if not all(0 <= o <= 255 for o in octets):
            return True  # Invalid range

        first, second = octets[0], octets[1]

        # 0.0.0.0/8 - Invalid/current network
        if first == 0:
            return True

        # 10.0.0.0/8 - Class A private
        if first == 10:
            return True

        # 127.0.0.0/8 - Loopback
        if first == 127:
            return True

        # 169.254.0.0/16 - Link-local (APIPA)
        if first == 169 and second == 254:
            return True

        # 172.16.0.0/12 - Class B private (172.16.0.0 - 172.31.255.255)
        if first == 172 and 16 <= second <= 31:
            return True

        # 192.168.0.0/16 - Class C private
        if first == 192 and second == 168:
            return True

        # 224.0.0.0/4 - Multicast (224.0.0.0 - 239.255.255.255)
        if 224 <= first <= 239:
            return True

        # 240.0.0.0/4 - Reserved (240.0.0.0 - 255.255.255.255)
        if first >= 240:
            return True

        return False

    except (ValueError, AttributeError):
        return True  # Invalid, don't look up
