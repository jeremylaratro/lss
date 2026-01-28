"""
Cross-OS compatibility tests for Debian, Arch, and Fedora systems.

These tests ensure the IDS Suite will work correctly when deployed on
different Linux distributions by testing:
1. Distribution detection
2. Service name resolution
3. Path detection
4. User/group detection
5. Firewall type detection
"""

import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from ids_suite.core.utils import (
    LinuxDistro,
    DistroConfig,
    detect_distro,
    get_distro_config,
    get_system_config,
    _detect_admin_group,
    _detect_clamav_user,
    _detect_firewall_type,
    _find_clamav_socket,
    is_private_ip,
)


class TestDistroDetection:
    """Test Linux distribution detection from /etc/os-release."""

    def test_detect_fedora(self):
        """Detect Fedora from os-release content.

        WHY THIS MATTERS:
        Fedora uses different service names (clamd@scan) and users (clamupdate)
        than Debian/Arch. Correct detection ensures services are managed properly.
        """
        fedora_content = '''
NAME="Fedora Linux"
VERSION="42 (Workstation Edition)"
ID=fedora
VERSION_ID=42
PLATFORM_ID="platform:f42"
'''
        with patch('pathlib.Path.exists', return_value=True):
            with patch('pathlib.Path.read_text', return_value=fedora_content):
                distro = detect_distro()
                assert distro == LinuxDistro.FEDORA

    def test_detect_debian(self):
        """Detect Debian from os-release content."""
        debian_content = '''
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
ID=debian
'''
        with patch('pathlib.Path.exists', return_value=True):
            with patch('pathlib.Path.read_text', return_value=debian_content):
                distro = detect_distro()
                assert distro == LinuxDistro.DEBIAN

    def test_detect_ubuntu(self):
        """Detect Ubuntu (Debian-based) from os-release content."""
        ubuntu_content = '''
NAME="Ubuntu"
VERSION="24.04 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
'''
        with patch('pathlib.Path.exists', return_value=True):
            with patch('pathlib.Path.read_text', return_value=ubuntu_content):
                distro = detect_distro()
                assert distro == LinuxDistro.DEBIAN

    def test_detect_arch(self):
        """Detect Arch Linux from os-release content."""
        arch_content = '''
NAME="Arch Linux"
PRETTY_NAME="Arch Linux"
ID=arch
'''
        with patch('pathlib.Path.exists', return_value=True):
            with patch('pathlib.Path.read_text', return_value=arch_content):
                distro = detect_distro()
                assert distro == LinuxDistro.ARCH

    def test_detect_manjaro(self):
        """Detect Manjaro (Arch-based) from os-release content."""
        manjaro_content = '''
NAME="Manjaro Linux"
ID=manjaro
ID_LIKE=arch
'''
        with patch('pathlib.Path.exists', return_value=True):
            with patch('pathlib.Path.read_text', return_value=manjaro_content):
                distro = detect_distro()
                assert distro == LinuxDistro.ARCH

    def test_detect_rocky(self):
        """Detect Rocky Linux (RHEL-based) from os-release content."""
        rocky_content = '''
NAME="Rocky Linux"
VERSION="9.3 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel centos fedora"
'''
        with patch('pathlib.Path.exists', return_value=True):
            with patch('pathlib.Path.read_text', return_value=rocky_content):
                distro = detect_distro()
                assert distro == LinuxDistro.FEDORA

    def test_detect_unknown_missing_file(self):
        """Return UNKNOWN when os-release doesn't exist."""
        with patch('pathlib.Path.exists', return_value=False):
            distro = detect_distro()
            assert distro == LinuxDistro.UNKNOWN

    def test_detect_unknown_unrecognized(self):
        """Return UNKNOWN for unrecognized distributions."""
        weird_content = '''
NAME="SomeObscureLinux"
ID=obscure
'''
        with patch('pathlib.Path.exists', return_value=True):
            with patch('pathlib.Path.read_text', return_value=weird_content):
                distro = detect_distro()
                assert distro == LinuxDistro.UNKNOWN


class TestClamAVServiceNames:
    """
    BUSINESS LOGIC: ClamAV service names vary by distribution.

    Fedora/RHEL: clamd@scan (template unit)
    Debian/Ubuntu: clamav-daemon
    Arch: clamav-daemon (or clamd.service)

    Using the wrong service name = ClamAV won't start/stop correctly.
    """

    def test_fedora_uses_clamd_scan(self):
        """Fedora uses clamd@scan service (template unit)."""
        with patch('ids_suite.core.utils.detect_distro', return_value=LinuxDistro.FEDORA):
            with patch('ids_suite.core.utils._detect_clamav_user', return_value=('clamupdate', 'clamupdate')):
                with patch('ids_suite.core.utils._detect_admin_group', return_value='wheel'):
                    with patch('ids_suite.core.utils._detect_firewall_type', return_value='firewalld'):
                        with patch('ids_suite.core.utils._find_clamav_socket', return_value='/var/run/clamd.scan/clamd.sock'):
                            config = get_distro_config()

        assert config.clamav_daemon_service == "clamd@scan"
        assert config.clamav_freshclam_service == "clamav-freshclam"

    def test_debian_uses_clamav_daemon(self):
        """Debian uses clamav-daemon service."""
        with patch('ids_suite.core.utils.detect_distro', return_value=LinuxDistro.DEBIAN):
            with patch('ids_suite.core.utils._detect_clamav_user', return_value=('clamav', 'clamav')):
                with patch('ids_suite.core.utils._detect_admin_group', return_value='sudo'):
                    with patch('ids_suite.core.utils._detect_firewall_type', return_value='ufw'):
                        with patch('ids_suite.core.utils._find_clamav_socket', return_value='/var/run/clamav/clamd.ctl'):
                            config = get_distro_config()

        assert config.clamav_daemon_service == "clamav-daemon"
        assert config.clamav_freshclam_service == "clamav-freshclam"

    def test_arch_uses_clamav_daemon(self):
        """Arch uses clamav-daemon service."""
        with patch('ids_suite.core.utils.detect_distro', return_value=LinuxDistro.ARCH):
            with patch('ids_suite.core.utils._detect_clamav_user', return_value=('clamav', 'clamav')):
                with patch('ids_suite.core.utils._detect_admin_group', return_value='wheel'):
                    with patch('ids_suite.core.utils._detect_firewall_type', return_value='ufw'):
                        with patch('ids_suite.core.utils._find_clamav_socket', return_value='/run/clamav/clamd.sock'):
                            config = get_distro_config()

        assert config.clamav_daemon_service == "clamav-daemon"


class TestClamAVSocketPaths:
    """
    BUSINESS LOGIC: ClamAV socket paths vary by distribution.

    Wrong socket path = can't communicate with clamd for scanning.
    This would break the entire antivirus functionality.
    """

    def test_finds_existing_socket(self):
        """Should find socket that actually exists on filesystem."""
        # Simulate Debian socket exists
        def mock_exists(path):
            return path == "/var/run/clamav/clamd.ctl"

        with patch('os.path.exists', side_effect=mock_exists):
            socket = _find_clamav_socket()
            assert socket == "/var/run/clamav/clamd.ctl"

    def test_finds_arch_socket(self):
        """Should find Arch Linux socket path."""
        def mock_exists(path):
            return path == "/run/clamav/clamd.sock"

        with patch('os.path.exists', side_effect=mock_exists):
            socket = _find_clamav_socket()
            assert socket == "/run/clamav/clamd.sock"

    def test_finds_fedora_socket(self):
        """Should find Fedora clamd@scan socket path."""
        def mock_exists(path):
            return path == "/var/run/clamd.scan/clamd.sock"

        with patch('os.path.exists', side_effect=mock_exists):
            socket = _find_clamav_socket()
            assert socket == "/var/run/clamd.scan/clamd.sock"

    def test_fallback_to_distro_default(self):
        """When no socket exists, use distro-appropriate default."""
        with patch('os.path.exists', return_value=False):
            with patch('ids_suite.core.utils.detect_distro', return_value=LinuxDistro.DEBIAN):
                socket = _find_clamav_socket()
                assert socket == "/var/run/clamav/clamd.ctl"

            with patch('ids_suite.core.utils.detect_distro', return_value=LinuxDistro.FEDORA):
                socket = _find_clamav_socket()
                assert socket == "/var/run/clamd.scan/clamd.sock"


class TestClamAVUser:
    """
    BUSINESS LOGIC: ClamAV runs as different users on different distros.

    Fedora: clamupdate:clamupdate
    Debian/Arch: clamav:clamav

    Wrong user = permission errors on signature databases.
    """

    def test_detects_fedora_clamupdate(self):
        """Detect clamupdate user on Fedora."""
        import pwd

        def mock_getpwnam(name):
            if name == 'clamupdate':
                return MagicMock()
            raise KeyError(name)

        def mock_getgrnam(name):
            if name == 'clamupdate':
                return MagicMock()
            raise KeyError(name)

        with patch('pwd.getpwnam', side_effect=mock_getpwnam):
            with patch('grp.getgrnam', side_effect=mock_getgrnam):
                user, group = _detect_clamav_user()
                assert user == 'clamupdate'
                assert group == 'clamupdate'

    def test_detects_debian_clamav(self):
        """Detect clamav user on Debian."""
        def mock_getpwnam(name):
            if name == 'clamav':
                return MagicMock()
            raise KeyError(name)

        def mock_getgrnam(name):
            if name == 'clamav':
                return MagicMock()
            raise KeyError(name)

        with patch('pwd.getpwnam', side_effect=mock_getpwnam):
            with patch('grp.getgrnam', side_effect=mock_getgrnam):
                user, group = _detect_clamav_user()
                assert user == 'clamav'
                assert group == 'clamav'

    def test_fallback_to_root(self):
        """Fallback to root when no ClamAV user found."""
        with patch('pwd.getpwnam', side_effect=KeyError):
            with patch('grp.getgrnam', side_effect=KeyError):
                user, group = _detect_clamav_user()
                assert user == 'root'
                assert group == 'root'


class TestFirewallDetection:
    """
    BUSINESS LOGIC: Different distros use different firewalls.

    Fedora/RHEL: firewalld with firewall-cmd
    Debian/Ubuntu/Arch: ufw (Uncomplicated Firewall)

    Wrong firewall commands = network rules won't apply correctly.
    """

    def test_detects_firewalld(self):
        """Detect firewalld on Fedora-like systems."""
        def mock_exists(path):
            return path == "/usr/bin/firewall-cmd"

        with patch('os.path.exists', side_effect=mock_exists):
            fw = _detect_firewall_type()
            assert fw == "firewalld"

    def test_detects_ufw(self):
        """Detect ufw on Debian-like systems."""
        def mock_exists(path):
            return path == "/usr/sbin/ufw"

        with patch('os.path.exists', side_effect=mock_exists):
            fw = _detect_firewall_type()
            assert fw == "ufw"

    def test_detects_firewalld_from_systemd(self):
        """Detect firewalld from systemd service file."""
        def mock_exists(path):
            return path == "/usr/lib/systemd/system/firewalld.service"

        with patch('os.path.exists', side_effect=mock_exists):
            fw = _detect_firewall_type()
            assert fw == "firewalld"

    def test_returns_unknown_when_none_found(self):
        """Return 'unknown' when no firewall detected."""
        with patch('os.path.exists', return_value=False):
            fw = _detect_firewall_type()
            assert fw == "unknown"


class TestAdminGroup:
    """
    BUSINESS LOGIC: PolicyKit uses different admin groups.

    Fedora/Arch: wheel group
    Debian/Ubuntu: sudo group

    Wrong group = users can't authenticate for privileged operations.
    """

    def test_detects_wheel_group(self):
        """Detect wheel group (Fedora/Arch)."""
        def mock_getgrnam(name):
            if name == 'wheel':
                return MagicMock()
            raise KeyError(name)

        with patch('grp.getgrnam', side_effect=mock_getgrnam):
            group = _detect_admin_group()
            assert group == 'wheel'

    def test_detects_sudo_group(self):
        """Detect sudo group (Debian)."""
        def mock_getgrnam(name):
            if name == 'sudo':
                return MagicMock()
            raise KeyError(name)

        with patch('grp.getgrnam', side_effect=mock_getgrnam):
            group = _detect_admin_group()
            assert group == 'sudo'

    def test_fallback_to_wheel(self):
        """Fallback to wheel when neither group exists."""
        with patch('grp.getgrnam', side_effect=KeyError):
            group = _detect_admin_group()
            assert group == 'wheel'


class TestDistroConfigIntegration:
    """Integration tests for complete distro configuration."""

    def test_fedora_complete_config(self):
        """Complete configuration for Fedora."""
        fedora_os_release = 'NAME="Fedora Linux"\nID=fedora'

        with patch('pathlib.Path.exists', return_value=True):
            with patch('pathlib.Path.read_text', return_value=fedora_os_release):
                with patch('pwd.getpwnam', return_value=MagicMock()):
                    with patch('grp.getgrnam', return_value=MagicMock()):
                        with patch('os.path.exists', return_value=False):
                            config = get_distro_config()

        assert config.distro == LinuxDistro.FEDORA
        assert config.clamav_daemon_service == "clamd@scan"
        assert config.admin_group in ['wheel', 'sudo']
        assert config.clamav_config_dir == "/etc/clamd.d"

    def test_debian_complete_config(self):
        """Complete configuration for Debian."""
        debian_os_release = 'NAME="Debian GNU/Linux"\nID=debian'

        with patch('pathlib.Path.exists', return_value=True):
            with patch('pathlib.Path.read_text', return_value=debian_os_release):
                with patch('pwd.getpwnam', return_value=MagicMock()):
                    with patch('grp.getgrnam', return_value=MagicMock()):
                        with patch('os.path.exists', return_value=False):
                            config = get_distro_config()

        assert config.distro == LinuxDistro.DEBIAN
        assert config.clamav_daemon_service == "clamav-daemon"
        assert config.clamav_config_dir == "/etc/clamav"

    def test_arch_complete_config(self):
        """Complete configuration for Arch."""
        arch_os_release = 'NAME="Arch Linux"\nID=arch'

        with patch('pathlib.Path.exists', return_value=True):
            with patch('pathlib.Path.read_text', return_value=arch_os_release):
                with patch('pwd.getpwnam', return_value=MagicMock()):
                    with patch('grp.getgrnam', return_value=MagicMock()):
                        with patch('os.path.exists', return_value=False):
                            config = get_distro_config()

        assert config.distro == LinuxDistro.ARCH
        assert config.clamav_daemon_service == "clamav-daemon"
        assert config.clamav_config_dir == "/etc/clamav"


class TestCachedConfig:
    """Test singleton pattern for system config caching."""

    def test_config_is_cached(self):
        """Configuration should be cached after first call."""
        import ids_suite.core.utils as utils

        # Reset cache
        utils._cached_config = None

        with patch('ids_suite.core.utils.get_distro_config') as mock_get:
            mock_config = DistroConfig(
                distro=LinuxDistro.FEDORA,
                clamav_daemon_service="clamd@scan",
                clamav_freshclam_service="clamav-freshclam",
                clamav_socket="/var/run/clamd.scan/clamd.sock",
                clamav_user="clamupdate",
                clamav_group="clamupdate",
                clamav_config_dir="/etc/clamd.d",
                firewall_type="firewalld",
                admin_group="wheel",
            )
            mock_get.return_value = mock_config

            # First call should invoke get_distro_config
            config1 = get_system_config()
            assert mock_get.call_count == 1

            # Second call should use cache
            config2 = get_system_config()
            assert mock_get.call_count == 1  # Still 1, not 2

            assert config1 is config2

        # Reset cache after test
        utils._cached_config = None


class TestDistroConfigDataclass:
    """Test DistroConfig dataclass properties."""

    def test_dataclass_fields(self):
        """All required fields are present."""
        config = DistroConfig(
            distro=LinuxDistro.DEBIAN,
            clamav_daemon_service="clamav-daemon",
            clamav_freshclam_service="clamav-freshclam",
            clamav_socket="/var/run/clamav/clamd.ctl",
            clamav_user="clamav",
            clamav_group="clamav",
            clamav_config_dir="/etc/clamav",
            firewall_type="ufw",
            admin_group="sudo",
        )

        assert config.distro == LinuxDistro.DEBIAN
        assert config.clamav_daemon_service == "clamav-daemon"
        assert config.clamav_freshclam_service == "clamav-freshclam"
        assert config.clamav_socket == "/var/run/clamav/clamd.ctl"
        assert config.clamav_user == "clamav"
        assert config.clamav_group == "clamav"
        assert config.clamav_config_dir == "/etc/clamav"
        assert config.firewall_type == "ufw"
        assert config.admin_group == "sudo"


class TestCrossOSCommandGeneration:
    """
    Test that generated commands will work on target distributions.

    These tests verify the configuration produces valid systemctl commands.
    """

    def test_fedora_systemctl_commands(self):
        """Fedora systemctl commands use correct service names."""
        with patch('ids_suite.core.utils.detect_distro', return_value=LinuxDistro.FEDORA):
            with patch('ids_suite.core.utils._detect_clamav_user', return_value=('clamupdate', 'clamupdate')):
                with patch('ids_suite.core.utils._detect_admin_group', return_value='wheel'):
                    with patch('ids_suite.core.utils._detect_firewall_type', return_value='firewalld'):
                        with patch('ids_suite.core.utils._find_clamav_socket', return_value='/var/run/clamd.scan/clamd.sock'):
                            config = get_distro_config()

        # These are the commands that would be generated
        start_cmd = f"systemctl start {config.clamav_daemon_service}"
        stop_cmd = f"systemctl stop {config.clamav_daemon_service}"

        assert start_cmd == "systemctl start clamd@scan"
        assert stop_cmd == "systemctl stop clamd@scan"

    def test_debian_systemctl_commands(self):
        """Debian systemctl commands use correct service names."""
        with patch('ids_suite.core.utils.detect_distro', return_value=LinuxDistro.DEBIAN):
            with patch('ids_suite.core.utils._detect_clamav_user', return_value=('clamav', 'clamav')):
                with patch('ids_suite.core.utils._detect_admin_group', return_value='sudo'):
                    with patch('ids_suite.core.utils._detect_firewall_type', return_value='ufw'):
                        with patch('ids_suite.core.utils._find_clamav_socket', return_value='/var/run/clamav/clamd.ctl'):
                            config = get_distro_config()

        start_cmd = f"systemctl start {config.clamav_daemon_service}"
        stop_cmd = f"systemctl stop {config.clamav_daemon_service}"

        assert start_cmd == "systemctl start clamav-daemon"
        assert stop_cmd == "systemctl stop clamav-daemon"

    def test_chown_command_uses_correct_user(self):
        """chown commands use distro-appropriate user."""
        with patch('ids_suite.core.utils.detect_distro', return_value=LinuxDistro.FEDORA):
            with patch('ids_suite.core.utils._detect_clamav_user', return_value=('clamupdate', 'clamupdate')):
                with patch('ids_suite.core.utils._detect_admin_group', return_value='wheel'):
                    with patch('ids_suite.core.utils._detect_firewall_type', return_value='firewalld'):
                        with patch('ids_suite.core.utils._find_clamav_socket', return_value='/var/run/clamd.scan/clamd.sock'):
                            fedora_config = get_distro_config()

        with patch('ids_suite.core.utils.detect_distro', return_value=LinuxDistro.DEBIAN):
            with patch('ids_suite.core.utils._detect_clamav_user', return_value=('clamav', 'clamav')):
                with patch('ids_suite.core.utils._detect_admin_group', return_value='sudo'):
                    with patch('ids_suite.core.utils._detect_firewall_type', return_value='ufw'):
                        with patch('ids_suite.core.utils._find_clamav_socket', return_value='/var/run/clamav/clamd.ctl'):
                            debian_config = get_distro_config()

        fedora_chown = f"chown {fedora_config.clamav_user}:{fedora_config.clamav_group} /var/lib/clamav/daily.cvd"
        debian_chown = f"chown {debian_config.clamav_user}:{debian_config.clamav_group} /var/lib/clamav/daily.cvd"

        assert fedora_chown == "chown clamupdate:clamupdate /var/lib/clamav/daily.cvd"
        assert debian_chown == "chown clamav:clamav /var/lib/clamav/daily.cvd"


class TestPrivateIPDetection:
    """
    BUSINESS LOGIC: Never send private/LAN IPs to threat intelligence APIs.

    WHY THIS MATTERS:
    1. API Rate Limiting - Wasting queries on private IPs burns API credits
    2. Privacy - Private IPs shouldn't leave the network
    3. Accuracy - Private IPs will return false positives or errors from APIs
    4. Performance - Skip unnecessary network calls for internal traffic

    This function is the gatekeeper that protects against all these issues.
    """

    # IPv4 Private Ranges
    def test_class_a_private_10_x_x_x(self):
        """10.0.0.0/8 - Class A private network (large enterprises, VPNs)."""
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("10.255.255.255") is True
        assert is_private_ip("10.100.50.25") is True

    def test_class_b_private_172_16_to_31(self):
        """172.16.0.0/12 - Class B private (medium enterprises)."""
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("172.31.255.255") is True
        assert is_private_ip("172.20.100.50") is True
        # Just outside the range - should be public
        assert is_private_ip("172.15.255.255") is False
        assert is_private_ip("172.32.0.1") is False

    def test_class_c_private_192_168_x_x(self):
        """192.168.0.0/16 - Class C private (home networks, small offices)."""
        assert is_private_ip("192.168.0.1") is True
        assert is_private_ip("192.168.1.1") is True  # Common router
        assert is_private_ip("192.168.255.255") is True

    def test_loopback_127_x_x_x(self):
        """127.0.0.0/8 - Loopback (localhost, never external)."""
        assert is_private_ip("127.0.0.1") is True
        assert is_private_ip("127.255.255.255") is True

    def test_link_local_169_254_x_x(self):
        """169.254.0.0/16 - Link-local APIPA (DHCP failure fallback)."""
        assert is_private_ip("169.254.1.1") is True
        assert is_private_ip("169.254.255.255") is True

    def test_multicast_224_to_239(self):
        """224.0.0.0/4 - Multicast addresses."""
        assert is_private_ip("224.0.0.1") is True
        assert is_private_ip("239.255.255.255") is True

    def test_reserved_240_plus(self):
        """240.0.0.0/4 - Reserved for future use."""
        assert is_private_ip("240.0.0.1") is True
        assert is_private_ip("255.255.255.255") is True

    def test_zero_network(self):
        """0.0.0.0/8 - Current network (invalid source)."""
        assert is_private_ip("0.0.0.0") is True
        assert is_private_ip("0.1.2.3") is True

    # Public IPs (should return False)
    def test_public_ips_are_lookupable(self):
        """Public IPs should be sent to threat intel APIs."""
        # Google DNS
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("8.8.4.4") is False
        # Cloudflare DNS
        assert is_private_ip("1.1.1.1") is False
        # Random public IPs
        assert is_private_ip("185.234.123.45") is False
        assert is_private_ip("203.0.113.50") is False

    # IPv6 Support
    def test_ipv6_loopback(self):
        """::1 - IPv6 loopback."""
        assert is_private_ip("::1") is True

    def test_ipv6_link_local(self):
        """fe80::/10 - IPv6 link-local."""
        assert is_private_ip("fe80::1") is True
        assert is_private_ip("fe80::a1b2:c3d4") is True

    def test_ipv6_unique_local(self):
        """fc00::/7 - IPv6 unique local (like private IPs)."""
        assert is_private_ip("fc00::1") is True
        assert is_private_ip("fd00::1") is True
        assert is_private_ip("fdab:cdef:1234::1") is True

    def test_ipv6_multicast(self):
        """ff00::/8 - IPv6 multicast."""
        assert is_private_ip("ff02::1") is True

    def test_ipv6_public(self):
        """Public IPv6 should be lookupable."""
        assert is_private_ip("2001:4860:4860::8888") is False  # Google DNS

    # Edge cases and error handling
    def test_invalid_input_returns_true(self):
        """Invalid input should return True (don't look up garbage)."""
        assert is_private_ip("") is True
        assert is_private_ip(None) is True
        assert is_private_ip("not-an-ip") is True
        assert is_private_ip("192.168.1") is True  # Incomplete
        assert is_private_ip("192.168.1.256") is True  # Invalid octet
        assert is_private_ip("192.168.1.1.1") is True  # Too many octets

    def test_whitespace_handling(self):
        """Handle whitespace in IP strings."""
        assert is_private_ip("  10.0.0.1  ") is True
        assert is_private_ip("  8.8.8.8  ") is False
