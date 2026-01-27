# IDS Suite Module Guide

## Package Overview

The `ids_suite` package is organized into six primary modules, each with a specific responsibility:

| Module | Purpose | Key Classes |
|--------|---------|-------------|
| `core` | Configuration, constants, utilities | `Config`, `Colors`, `Paths` |
| `engines` | IDS engine abstraction | `IDSEngine`, `SuricataEngine`, `SnortEngine` |
| `models` | Data structures | `Alert`, `EVEFileReader` |
| `threat_intel` | Threat intelligence APIs | `VirusTotalClient`, `OTXClient`, etc. |
| `services` | System service management | `IDSService`, `ClamAVService` |
| `ui` | GUI components | `SecurityControlPanel`, `WidgetFactory` |

---

## Core Module (`ids_suite.core`)

The foundation layer providing configuration, constants, and utilities.

### Files

| File | Description |
|------|-------------|
| `config.py` | Singleton configuration manager |
| `constants.py` | Immutable constants (colors, paths, timeouts) |
| `dependencies.py` | Optional dependency detection |
| `utils.py` | Utility functions |

### Usage Example

```python
from ids_suite.core import Config, Colors, is_private_ip

# Configuration (singleton)
config = Config()
config.auto_refresh = True
config.save()

# Colors
print(Colors.BLUE)  # '#176ef1'
colors = Colors.as_dict()  # For widget styling

# Utilities
if not is_private_ip("8.8.8.8"):
    # Safe to send to external API
    pass
```

### Design Notes

- **Config**: Uses singleton pattern to ensure consistent settings across the application
- **Constants**: Uses frozen dataclasses for immutability and type safety
- **Dependencies**: Lazy loading prevents import errors when optional packages are missing

---

## Engines Module (`ids_suite.engines`)

Provides an abstraction layer for different IDS engines using the Strategy pattern.

### Files

| File | Description |
|------|-------------|
| `base.py` | Abstract base class `IDSEngine` |
| `suricata.py` | Suricata implementation |
| `snort.py` | Snort 3 implementation |

### Class Hierarchy

```
IDSEngine (ABC)
├── SuricataEngine
└── SnortEngine
```

### Adding a New Engine

To add support for a new IDS engine:

```python
from ids_suite.engines.base import IDSEngine

class ZeekEngine(IDSEngine):
    def get_name(self) -> str:
        return "Zeek"

    def get_service_name(self) -> str:
        return "zeek"

    def get_log_path(self) -> str:
        return "/var/log/zeek/current/conn.log"

    def get_config_path(self) -> str:
        return "/opt/zeek/share/zeek/site/local.zeek"

    def is_installed(self) -> bool:
        return os.path.exists("/opt/zeek/bin/zeek")

    def parse_alert(self, line: str) -> Optional[Dict[str, Any]]:
        # Parse Zeek log format
        ...
```

### Alert Dictionary Format

All engines return alerts in a consistent format:

```python
{
    'engine': str,      # 'suricata' or 'snort'
    'timestamp': str,   # ISO format
    'severity': int,    # 1 (critical) to 4 (low)
    'signature': str,   # Alert signature/message
    'src_ip': str,
    'src_port': str,
    'dest_ip': str,
    'dest_port': str,
    'proto': str,       # TCP, UDP, ICMP, etc.
    'category': str,    # Alert category
    'sid': str,         # Signature ID
    'raw': dict         # Original parsed JSON
}
```

---

## Models Module (`ids_suite.models`)

Data structures and file readers.

### Files

| File | Description |
|------|-------------|
| `alert.py` | Alert dataclass |
| `eve_reader.py` | EVE JSON incremental reader |

### Alert Class Features

```python
@dataclass
class Alert:
    # Fields
    engine: str
    timestamp: str
    severity: int
    signature: str
    src_ip: str
    src_port: str
    dest_ip: str
    dest_port: str
    proto: str
    category: str
    sid: str
    raw: Dict[str, Any]

    # Properties
    @property
    def severity_label(self) -> str:
        """Returns 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or 'INFO'"""

    # Methods
    def to_dict(self) -> Dict[str, Any]: ...
    def matches_filter(self, hidden_signatures=None, ...) -> bool: ...

    # Class methods
    @classmethod
    def from_dict(cls, data: Dict) -> Optional['Alert']: ...
```

### EVEFileReader Features

The EVEFileReader handles:

- **Incremental reading**: Tracks file position for efficient updates
- **Rotation detection**: Monitors inode changes to handle log rotation
- **Truncation detection**: Resets position if file is truncated
- **Initial load**: Uses `tail` command for fast startup loading

```python
reader = EVEFileReader("/var/log/suricata")

# Startup: load recent events
initial_lines = reader.initial_load(num_lines=10000)

# Periodic refresh: get only new lines
while True:
    new_lines = reader.read_new_lines(max_lines=5000)
    process_lines(new_lines)
    time.sleep(5)
```

---

## Threat Intel Module (`ids_suite.threat_intel`)

Threat intelligence API integrations with caching and rate limiting.

### Files

| File | Description |
|------|-------------|
| `cache.py` | TTL-based cache |
| `tracker.py` | IP lookup history tracker |
| `base.py` | Abstract base class (optional) |
| `virustotal.py` | VirusTotal API v3 |
| `otx.py` | AlienVault OTX |
| `threatfox.py` | ThreatFox (abuse.ch) |
| `abuseipdb.py` | AbuseIPDB |

### Client Comparison

| Client | API Key Required | Rate Limit | Capabilities |
|--------|-----------------|------------|--------------|
| VirusTotal | Yes | 4/min (free) | IP, hash, domain |
| OTX | Yes | Generous | IP, hash, domain |
| ThreatFox | No | None | IOC lookup |
| AbuseIPDB | Yes | 1000/day (free) | IP reputation |

### Caching Strategy

All clients use the `ThreatIntelCache` with 24-hour TTL:

```python
class VirusTotalClient:
    def __init__(self, api_key):
        self.cache = ThreatIntelCache(ttl_hours=24)

    def lookup_ip(self, ip: str) -> dict:
        cache_key = f"ip:{ip}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached  # Return cached result

        result = self._make_request(...)
        self.cache.set(cache_key, result)
        return result
```

### IP Lookup Tracking

The `IPLookupTracker` prevents duplicate lookups:

```python
tracker = IPLookupTracker(window_hours=12)

# Check before making API call
if tracker.should_lookup(ip):
    result = client.lookup_ip(ip)
    status = 'dangerous' if result.get('malicious', 0) > 0 else 'safe'
    tracker.record_lookup(ip, status)
else:
    # Use cached result
    status = tracker.get_result(ip)
```

---

## Services Module (`ids_suite.services`)

System service management with privilege escalation.

### Files

| File | Description |
|------|-------------|
| `systemd.py` | Low-level systemd wrapper |
| `ids_service.py` | IDS-specific operations |
| `clamav_service.py` | ClamAV suite management |

### Privilege Escalation

All privileged operations use `pkexec` for PolicyKit authentication:

```python
def _run_systemctl(self, action: str, use_pkexec: bool = True):
    cmd = f"pkexec systemctl {action} {self.service_name}"
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return ServiceResult(...)
```

### Callback Pattern

Services support async callbacks for UI integration:

```python
def start(self, callback: Optional[Callable[[ServiceResult], None]] = None):
    result = self.service.start()
    if callback:
        callback(result)
```

### ClamAVService Components

The ClamAV service manages three systemd units:

1. `clamav-daemon` - Main scanning daemon
2. `clamav-freshclam` - Signature update service
3. `clamav-clamonacc` - On-access scanning

```python
service = ClamAVService()

# Start all three services in correct order
service.start()

# Stop in reverse order
service.stop()

# Check individual components
service.is_daemon_running()
service.is_freshclam_running()
service.is_clamonacc_running()
```

---

## UI Module (`ids_suite.ui`)

GUI components built with Tkinter/CustomTkinter.

### Files

| File | Description |
|------|-------------|
| `widget_factory.py` | Widget abstraction layer |
| `main_window.py` | Main application window |

### WidgetFactory

Provides seamless switching between CustomTkinter (modern) and ttk (fallback):

```python
factory = WidgetFactory(colors)

# These work identically regardless of CustomTkinter availability
button = factory.create_button(parent, text="Click", command=handler)
entry = factory.create_entry(parent, textvariable=var)
```

### SecurityControlPanel Tabs

The main window contains these tabs:

**Monitoring Tabs:**
- Overview - Summary statistics and recent activity
- Alerts - IDS alerts with filtering and export
- Traffic - Network traffic analysis
- Local - Localhost/development activity
- DNS - DNS query analysis

**ClamAV Tabs:**
- AV - ClamAV status and statistics
- Quarantine - Quarantined file management
- Scan - On-demand scanning

**Analytics:**
- Stats - Charts and visualizations (requires matplotlib)

**Settings:**
- Suricata Settings - IDS configuration
- ClamAV Settings - Antivirus configuration
- Threat Intel - API key management
- General Settings - Application preferences

**Security:**
- Connections - Active network connections
- Logs - System log viewer
- Firewall - Firewall rule management
- Security Audit - System security checks

---

## Module Interaction Example

Complete workflow showing module interactions:

```python
import tkinter as tk
from ids_suite.engines import SuricataEngine
from ids_suite.models import EVEFileReader
from ids_suite.threat_intel import VirusTotalClient, IPLookupTracker
from ids_suite.services import IDSService
from ids_suite.core import is_private_ip

# Initialize components
engine = SuricataEngine()
service = IDSService(engine)
reader = EVEFileReader()
vt_client = VirusTotalClient(api_key="...")
tracker = IPLookupTracker()

# Ensure IDS is running
if not service.is_running():
    service.start()

# Load initial alerts
lines = reader.initial_load()
for line in lines:
    alert = engine.parse_alert(line)
    if alert:
        # Check threat intel for external IPs
        src_ip = alert['src_ip']
        if not is_private_ip(src_ip) and tracker.should_lookup(src_ip):
            intel = vt_client.lookup_ip(src_ip)
            if intel.get('malicious', 0) > 0:
                tracker.record_lookup(src_ip, 'dangerous')
                print(f"Dangerous IP: {src_ip}")
            else:
                tracker.record_lookup(src_ip, 'safe')
```
