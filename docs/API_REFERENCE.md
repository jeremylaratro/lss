# IDS Suite API Reference

## Package: `ids_suite`

### Top-Level Exports

```python
from ids_suite import Config, SecurityControlPanel

__version__ = "2.9.1"
```

---

## Module: `ids_suite.core`

### `Config`

Singleton configuration manager with property-based access.

```python
from ids_suite.core import Config

config = Config()
```

**Properties:**

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `auto_refresh` | `bool` | `True` | Enable automatic data refresh |
| `refresh_interval` | `int` | `5000` | Refresh interval in milliseconds |
| `data_retention_minutes` | `int` | `120` | How long to retain event data |
| `engine_filter` | `str` | `'all'` | IDS engine filter (`'all'`, `'suricata'`, `'snort'`) |
| `hidden_signatures` | `set` | `set()` | Signatures to hide from display |
| `hidden_src_ips` | `set` | `set()` | Source IPs to hide |
| `hidden_dest_ips` | `set` | `set()` | Destination IPs to hide |
| `hidden_categories` | `set` | `set()` | Categories to hide |

**Methods:**

```python
config.save() -> bool           # Persist settings to disk
config.get(key, default=None)   # Get setting value
config.set(key, value)          # Set setting value
config.reset()                  # Reset to defaults
```

---

### `Colors`

Frozen dataclass with color constants matching polybar theme.

```python
from ids_suite.core.constants import Colors

Colors.BG        # '#2c3746'
Colors.BG_ALT    # '#343f53'
Colors.FG        # '#ffffff'
Colors.BLUE      # '#176ef1'
Colors.RED       # '#fd3762'
Colors.TEAL      # '#2aacaa'
Colors.YELLOW    # '#f7c067'
Colors.ORANGE    # '#f77067'
Colors.PURPLE    # '#cb75f7'
Colors.CYAN      # '#5cc6d1'
Colors.GRAY      # '#9cacad'
Colors.GREEN     # '#2aacaa'

# Get as dictionary
colors_dict = Colors.as_dict()
```

---

### `is_private_ip`

Check if an IP address is private/LAN.

```python
from ids_suite.core.utils import is_private_ip

is_private_ip("192.168.1.1")   # True
is_private_ip("10.0.0.1")       # True
is_private_ip("8.8.8.8")        # False
is_private_ip("::1")            # True (IPv6 loopback)
is_private_ip("fe80::1")        # True (IPv6 link-local)
```

**Returns:** `True` if the IP is private, invalid, or should not be sent to external APIs.

---

### Dependency Detection

```python
from ids_suite.core.dependencies import (
    CTK_AVAILABLE,         # CustomTkinter installed
    MATPLOTLIB_AVAILABLE,  # matplotlib installed
    GEOIP_AVAILABLE,       # geoip2 installed
    KEYRING_AVAILABLE,     # keyring installed
    REQUESTS_AVAILABLE,    # requests installed
)

# Lazy getters for optional modules
from ids_suite.core.dependencies import (
    get_ctk,               # Returns customtkinter or None
    get_keyring,           # Returns keyring or None
    get_requests,          # Returns requests or None
    get_geoip,             # Returns geoip2 or None
    get_matplotlib_components,  # Returns (FigureCanvasTkAgg, Figure, mdates) or (None, None, None)
)
```

---

## Module: `ids_suite.engines`

### `IDSEngine` (Abstract Base Class)

```python
from ids_suite.engines import IDSEngine

class IDSEngine(ABC):
    def get_name(self) -> str: ...
    def get_service_name(self) -> str: ...
    def get_log_path(self) -> str: ...
    def get_config_path(self) -> str: ...
    def is_installed(self) -> bool: ...
    def parse_alert(self, line: str) -> Optional[Dict[str, Any]]: ...
```

### `SuricataEngine`

```python
from ids_suite.engines import SuricataEngine

engine = SuricataEngine()

engine.get_name()         # "Suricata"
engine.get_service_name() # "suricata-laptop"
engine.get_log_path()     # "/var/log/suricata/eve.json"
engine.get_config_path()  # "/etc/suricata/suricata.yaml"
engine.is_installed()     # True/False

# Parse EVE JSON line
alert = engine.parse_alert('{"event_type":"alert","alert":{"signature":"..."}}')
# Returns: {'engine': 'suricata', 'timestamp': '...', 'severity': 1, ...}
```

### `SnortEngine`

```python
from ids_suite.engines import SnortEngine

engine = SnortEngine()

engine.get_name()         # "Snort"
engine.get_service_name() # "snort"
engine.get_log_path()     # "/var/log/snort/alert_json.txt"
engine.get_config_path()  # "/etc/snort/snort.lua"
```

---

## Module: `ids_suite.models`

### `Alert`

Dataclass representing a parsed IDS alert.

```python
from ids_suite.models import Alert

alert = Alert(
    engine='suricata',
    timestamp='2024-01-15T10:30:00',
    severity=1,
    signature='ET MALWARE Known Malicious',
    src_ip='192.168.1.100',
    src_port='54321',
    dest_ip='10.0.0.1',
    dest_port='443',
    proto='TCP',
    category='Malware',
    sid='2024001',
    raw={}
)

# Properties
alert.severity_label  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or 'INFO'

# Methods
alert.to_dict()       # Convert to dictionary
alert.matches_filter(hidden_signatures={'...'})  # Check filter criteria

# Class methods
Alert.from_dict({'engine': 'suricata', ...})  # Create from dictionary
```

### `EVEFileReader`

Incremental EVE JSON file reader with log rotation detection.

```python
from ids_suite.models import EVEFileReader

reader = EVEFileReader(base_path="/var/log/suricata")

# Initial load (uses tail for efficiency)
lines = reader.initial_load(num_lines=10000)

# Incremental read (tracks file position)
new_lines = reader.read_new_lines(max_lines=5000)

# Reset state
reader.reset()
```

---

## Module: `ids_suite.threat_intel`

### `ThreatIntelCache`

TTL-based cache for threat intelligence lookups.

```python
from ids_suite.threat_intel import ThreatIntelCache

cache = ThreatIntelCache(ttl_hours=24)

cache.set("ip:8.8.8.8", {"reputation": 0})
result = cache.get("ip:8.8.8.8")  # Returns cached data or None if expired
cache.remove("ip:8.8.8.8")
cache.clear()
cache.cleanup_expired()  # Remove all expired entries
```

### `IPLookupTracker`

Tracks IP lookups to avoid duplicate API queries within a time window.

```python
from ids_suite.threat_intel import IPLookupTracker

tracker = IPLookupTracker(window_hours=12)

tracker.should_lookup("8.8.8.8")      # True if not recently looked up
tracker.record_lookup("8.8.8.8", "safe")  # Record result
tracker.get_result("8.8.8.8")         # Get cached result
tracker.get_stats()                   # {'active': 10, 'dangerous': 2}
```

### `VirusTotalClient`

VirusTotal API v3 client with rate limiting.

```python
from ids_suite.threat_intel import VirusTotalClient

client = VirusTotalClient(api_key="your_api_key")

# IP lookup
result = client.lookup_ip("8.8.8.8")
# {'indicator': '8.8.8.8', 'type': 'ip', 'malicious': 0, 'suspicious': 0,
#  'harmless': 85, 'reputation': 0, 'country': 'US', 'as_owner': 'Google LLC'}

# Hash lookup
result = client.lookup_hash("44d88612fea8a8f36de82e1278abb02f")

# Domain lookup
result = client.lookup_domain("example.com")
```

### `OTXClient`

AlienVault OTX (Open Threat Exchange) client.

```python
from ids_suite.threat_intel import OTXClient

client = OTXClient(api_key="your_api_key")

result = client.lookup_ip("8.8.8.8")
# {'indicator': '8.8.8.8', 'type': 'ip', 'pulse_count': 5,
#  'reputation': 0, 'country': 'United States', 'pulses': [...]}
```

### `ThreatFoxClient`

ThreatFox (abuse.ch) client - no API key required.

```python
from ids_suite.threat_intel import ThreatFoxClient

client = ThreatFoxClient()

result = client.lookup_ioc("malicious.example.com")
# {'indicator': '...', 'found': True, 'ioc_type': 'domain',
#  'threat_type': 'botnet_cc', 'malware': 'Emotet', ...}
```

### `AbuseIPDBClient`

AbuseIPDB client for IP reputation.

```python
from ids_suite.threat_intel import AbuseIPDBClient

client = AbuseIPDBClient(api_key="your_api_key")

result = client.lookup_ip("8.8.8.8")
# {'indicator': '8.8.8.8', 'type': 'ip', 'abuse_score': 0,
#  'total_reports': 0, 'country': 'US', 'isp': 'Google LLC', ...}
```

---

## Module: `ids_suite.services`

### `ServiceResult`

Dataclass for service operation results.

```python
from ids_suite.services.systemd import ServiceResult

@dataclass
class ServiceResult:
    success: bool
    message: str
    returncode: int
    stdout: str = ""
    stderr: str = ""
```

### `SystemdService`

Wrapper for systemd service control with privilege escalation.

```python
from ids_suite.services import SystemdService

service = SystemdService("suricata-laptop")

service.start()       # ServiceResult
service.stop()        # ServiceResult
service.restart()     # ServiceResult
service.reload()      # ServiceResult
service.is_active()   # bool
service.is_enabled()  # bool
service.status()      # ServiceResult
service.enable()      # ServiceResult
service.disable()     # ServiceResult
```

### `IDSService`

High-level IDS service management.

```python
from ids_suite.engines import SuricataEngine
from ids_suite.services import IDSService

engine = SuricataEngine()
service = IDSService(engine)

service.start(callback=on_complete)
service.stop(callback=on_complete)
service.restart(callback=on_complete)
service.is_running()              # bool
service.update_rules(callback)    # Suricata-specific
service.reload_rules(callback)
service.clean_logs(callback)
service.open_config()             # Opens in default editor
service.open_logs()               # Opens log directory
service.get_rule_count()          # int
service.get_status_info()         # dict
```

### `ClamAVService`

ClamAV daemon and scanner management.

```python
from ids_suite.services import ClamAVService

service = ClamAVService()

service.start(callback)
service.stop(callback)
service.is_daemon_running()       # bool
service.is_freshclam_running()    # bool
service.is_clamonacc_running()    # bool
service.update_signatures(callback)
service.get_signature_count()     # str (e.g., "8500000")
service.get_quarantine_count()    # int
service.clean_logs(callback)
service.open_logs()
service.get_status_info()         # dict
```

### `ClamAVScanner`

On-demand file/directory scanner.

```python
from ids_suite.services.clamav_service import ClamAVScanner

scanner = ClamAVScanner()

def on_output(line):
    print(line)

def on_complete(returncode):
    print(f"Scan completed with code {returncode}")

scanner.scan(
    path="/home/user/Downloads",
    recursive=True,
    on_output=on_output,
    on_complete=on_complete
)

scanner.is_scanning()  # bool
scanner.cancel()       # Terminate scan
```

---

## Module: `ids_suite.ui`

### `WidgetFactory`

Factory for creating themed widgets with CustomTkinter or ttk fallback.

```python
from ids_suite.ui import WidgetFactory
from ids_suite.core.constants import Colors

factory = WidgetFactory(Colors.as_dict())

button = factory.create_button(parent, text="Click Me", command=handler)
entry = factory.create_entry(parent, textvariable=var, width=20)
frame = factory.create_frame(parent, corner_radius=10)
label = factory.create_label(parent, text="Label")
textbox = factory.create_textbox(parent, height=10)
checkbox = factory.create_checkbox(parent, text="Option", variable=var)
segmented = factory.create_segmented_button(parent, values=["A", "B", "C"])
card = factory.create_card(parent, title="Section Title")
slider = factory.create_slider(parent, from_=0, to=100, variable=var)
progress = factory.create_progress_bar(parent, mode='determinate')
dropdown = factory.create_option_menu(parent, variable=var, values=["A", "B"])
```

### `SecurityControlPanel`

Main application window with all tabs and functionality.

```python
import tkinter as tk
from ids_suite.ui import SecurityControlPanel

root = tk.Tk()
app = SecurityControlPanel(root)
root.mainloop()
```

**Key Methods:**

| Method | Description |
|--------|-------------|
| `refresh_all()` | Refresh all tabs |
| `refresh_status()` | Update service status indicators |
| `refresh_alerts()` | Refresh alerts tab |
| `start_ids()` | Start IDS service |
| `stop_ids()` | Stop IDS service |
| `start_clamav()` | Start ClamAV services |
| `stop_clamav()` | Stop ClamAV services |
| `start_scan(path)` | Start ClamAV scan |
| `export_alerts()` | Export alerts to CSV |

---

## Error Handling

All API clients return error dictionaries on failure:

```python
result = client.lookup_ip("invalid")

if 'error' in result:
    print(f"Error: {result['error']}")
else:
    print(f"Result: {result}")
```

Common error keys:
- `'error'`: Error message string
- `'is_private'`: True if IP was private (not sent to API)
