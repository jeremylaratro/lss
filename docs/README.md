# IDS Suite - Security Suite Control Panel

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-green.svg)](https://www.linux.org/)

**Version 2.9.1** - A comprehensive, modular GUI for managing Suricata/Snort IDS and ClamAV Antivirus on Linux systems.

## Features

- **Multi-IDS Support**: Manage both Suricata and Snort 3 from a unified interface
- **Real-time Monitoring**: Live alerts, traffic analysis, DNS queries, and localhost activity
- **Threat Intelligence**: Integrated lookups via VirusTotal, AlienVault OTX, ThreatFox, and AbuseIPDB
- **ClamAV Integration**: Daemon control, on-demand scanning, quarantine management
- **Analytics Dashboard**: Visual statistics with matplotlib charts
- **Modern UI**: Dark theme with CustomTkinter support (fallback to ttk)
- **Modular Architecture**: Clean separation of concerns for maintainability

## Quick Start

### Prerequisites

- Python 3.8+
- Suricata and/or Snort 3 (optional, but recommended)
- ClamAV (optional)
- Linux with systemd

### Installation

```bash
# Clone the repository
git clone https://github.com/jeremylaratro/lss.git
cd lss

# Install dependencies
pip install -r requirements.txt

# Run the application
python idsgui.py
```

### Optional Dependencies

```bash
# Modern UI (recommended)
pip install customtkinter

# Analytics charts
pip install matplotlib

# Secure API key storage
pip install keyring

# Threat intelligence lookups
pip install requests

# GeoIP lookups
pip install geoip2
```

## Package Structure

```
lss2/
├── idsgui.py              # Entry point
└── ids_suite/             # Main package
    ├── core/              # Configuration, constants, utilities
    ├── engines/           # IDS engine abstractions (Suricata, Snort)
    ├── models/            # Data structures (Alert, EVEFileReader)
    ├── threat_intel/      # Threat intelligence API clients
    ├── services/          # System service management
    └── ui/                # GUI components
```

## Documentation

- [Architecture Overview](./ARCHITECTURE.md)
- [API Reference](./API_REFERENCE.md)
- [Module Guide](./MODULES.md)
- [Configuration Guide](./CONFIGURATION.md)

## Usage Examples

### Basic Launch

```python
from ids_suite import SecurityControlPanel
import tkinter as tk

root = tk.Tk()
app = SecurityControlPanel(root)
root.mainloop()
```

### Programmatic Service Control

```python
from ids_suite.engines import SuricataEngine
from ids_suite.services import IDSService

# Create engine and service
engine = SuricataEngine()
service = IDSService(engine)

# Check status
if service.is_running():
    print("Suricata is running")
else:
    service.start()
```

### Threat Intelligence Lookup

```python
from ids_suite.threat_intel import VirusTotalClient

client = VirusTotalClient(api_key="your_api_key")
result = client.lookup_ip("8.8.8.8")
print(f"Reputation: {result.get('reputation', 'Unknown')}")
```

## Configuration

API keys are stored securely using the system keyring:

```python
from ids_suite.core.dependencies import get_keyring

keyring = get_keyring()
if keyring:
    keyring.set_password("security-suite", "virustotal", "your_api_key")
```

Settings are persisted to `~/.config/security-suite/settings.json`.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.
