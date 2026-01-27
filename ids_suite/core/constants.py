"""
Application constants - colors, paths, timeouts, and configuration values
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Colors:
    """Color scheme matching polybar theme"""
    BG = '#2c3746'
    BG_ALT = '#343f53'
    FG = '#ffffff'
    BLUE = '#176ef1'
    RED = '#fd3762'
    TEAL = '#2aacaa'
    YELLOW = '#f7c067'
    ORANGE = '#f77067'
    PURPLE = '#cb75f7'
    CYAN = '#5cc6d1'
    GRAY = '#9cacad'
    GREEN = '#2aacaa'

    @classmethod
    def as_dict(cls) -> dict:
        """Return colors as dictionary for compatibility"""
        return {
            'bg': cls.BG,
            'bg_alt': cls.BG_ALT,
            'fg': cls.FG,
            'blue': cls.BLUE,
            'red': cls.RED,
            'teal': cls.TEAL,
            'yellow': cls.YELLOW,
            'orange': cls.ORANGE,
            'purple': cls.PURPLE,
            'cyan': cls.CYAN,
            'gray': cls.GRAY,
            'green': cls.GREEN,
        }


@dataclass(frozen=True)
class Paths:
    """File system paths for IDS/AV components"""
    # Suricata paths
    SURICATA_BIN = "/usr/bin/suricata"
    SURICATA_BIN_ALT = "/usr/local/bin/suricata"
    SURICATA_EVE_LOG = "/var/log/suricata/eve.json"
    SURICATA_CONFIG = "/etc/suricata/suricata.yaml"
    SURICATA_RULES = "/var/lib/suricata/rules"

    # Snort paths
    SNORT_BIN = "/usr/bin/snort"
    SNORT_BIN_ALT = "/usr/local/bin/snort"
    SNORT_ALERT_LOG = "/var/log/snort/alert_json.txt"
    SNORT_CONFIG = "/etc/snort/snort.lua"

    # ClamAV paths
    CLAMSCAN_BIN = "/usr/bin/clamscan"
    FRESHCLAM_BIN = "/usr/bin/freshclam"
    CLAMD_SOCKET = "/var/run/clamd.scan/clamd.sock"

    # GeoIP database
    GEOIP_DB = "/usr/share/GeoIP/GeoLite2-City.mmdb"

    # Settings storage
    SETTINGS_FILE = "~/.config/security-suite/settings.json"


@dataclass(frozen=True)
class Timeouts:
    """Timeout values in milliseconds"""
    AUTO_REFRESH = 5000  # 5 seconds
    API_REQUEST = 10000  # 10 seconds
    SCAN_CHECK = 1000    # 1 second
    STATUS_UPDATE = 2000 # 2 seconds


@dataclass(frozen=True)
class Limits:
    """Various limit values"""
    MAX_ALERTS_DISPLAY = 1000
    MAX_LOG_LINES = 500
    DATA_RETENTION_MINUTES = 120
    CACHE_TTL_SECONDS = 300  # 5 minutes for threat intel cache
    IP_LOOKUP_WINDOW_DAYS = 3


@dataclass(frozen=True)
class ServiceNames:
    """Systemd service names"""
    SURICATA = "suricata-laptop"
    SNORT = "snort"
    CLAMD = "clamd@scan"
    FRESHCLAM = "clamav-freshclam"


@dataclass(frozen=True)
class Fonts:
    """Font configurations"""
    FAMILY = "Hack Nerd Font"
    SIZE_SMALL = 9
    SIZE_NORMAL = 10
    SIZE_LARGE = 12
    SIZE_TITLE = 14


# Severity levels and their display properties
SEVERITY_COLORS = {
    1: ('CRITICAL', '#fd3762'),  # Red
    2: ('HIGH', '#f77067'),      # Orange
    3: ('MEDIUM', '#f7c067'),    # Yellow
    4: ('LOW', '#5cc6d1'),       # Cyan
}

# Default severity for unknown levels
DEFAULT_SEVERITY = ('INFO', '#9cacad')

# Protocol display names
PROTOCOL_NAMES = {
    'TCP': 'TCP',
    'UDP': 'UDP',
    'ICMP': 'ICMP',
    'HTTP': 'HTTP',
    'TLS': 'TLS',
    'DNS': 'DNS',
}

# Keyring service name
KEYRING_SERVICE = "security-suite"
