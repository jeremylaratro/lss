# IDS Suite Configuration Guide

## Quick Start

The application works out of the box with sensible defaults. Optional configuration enables advanced features.

## Configuration Files

### Application Settings

**Location:** `~/.config/security-suite/settings.json`

```json
{
  "auto_refresh": true,
  "refresh_interval": 5000,
  "data_retention_minutes": 120,
  "hidden_signatures": [],
  "hidden_src_ips": [],
  "hidden_dest_ips": [],
  "hidden_categories": [],
  "engine_filter": "all",
  "selected_time_range": "live"
}
```

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `auto_refresh` | bool | `true` | Enable automatic data refresh |
| `refresh_interval` | int | `5000` | Refresh interval in milliseconds |
| `data_retention_minutes` | int | `120` | How long to keep events in memory |
| `hidden_signatures` | list | `[]` | Alert signatures to hide |
| `hidden_src_ips` | list | `[]` | Source IPs to hide |
| `hidden_dest_ips` | list | `[]` | Destination IPs to hide |
| `hidden_categories` | list | `[]` | Alert categories to hide |
| `engine_filter` | string | `"all"` | IDS engine filter: `"all"`, `"suricata"`, `"snort"` |
| `selected_time_range` | string | `"live"` | Time range for alerts |

### IP Lookup History

**Location:** `~/.config/ids-suite/ip_lookups.json`

```json
{
  "8.8.8.8": {
    "timestamp": "2024-01-15T10:30:00",
    "result": "safe"
  },
  "malicious.example.com": {
    "timestamp": "2024-01-15T09:00:00",
    "result": "dangerous"
  }
}
```

Entries older than 12 hours are automatically cleaned up.

---

## API Key Configuration

API keys are stored securely in the system keyring.

### Setting API Keys via GUI

1. Open the application
2. Navigate to **Threat Intel** tab
3. Enter API keys in the respective fields
4. Click **Save**

### Setting API Keys via CLI

```python
import keyring

# VirusTotal
keyring.set_password("security-suite", "virustotal", "your-api-key")

# AlienVault OTX
keyring.set_password("security-suite", "otx", "your-api-key")

# AbuseIPDB
keyring.set_password("security-suite", "abuseipdb", "your-api-key")
```

### Obtaining API Keys

| Service | Free Tier | Get Key |
|---------|-----------|---------|
| VirusTotal | 4 requests/min | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| AlienVault OTX | Generous limits | [otx.alienvault.com](https://otx.alienvault.com/api) |
| ThreatFox | Unlimited | No key required |
| AbuseIPDB | 1000/day | [abuseipdb.com](https://www.abuseipdb.com/pricing) |

---

## IDS Configuration

### Suricata

**Configuration File:** `/etc/suricata/suricata.yaml`

**Required Settings for IDS Suite:**

```yaml
# Enable EVE JSON logging
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - flow

# Service name (matches systemd)
# Default expects: suricata-laptop
```

**Systemd Service:** The application expects `suricata-laptop.service`. If your service has a different name, modify `ids_suite/engines/suricata.py`:

```python
def get_service_name(self) -> str:
    return "your-service-name"  # e.g., "suricata"
```

### Snort 3

**Configuration File:** `/etc/snort/snort.lua`

**Required Settings:**

```lua
-- Enable JSON alert output
alert_json = {
    file = true,
    limit = 100,
    fields = "timestamp msg proto src_ap dst_ap priority class sid"
}
```

**Log Location:** `/var/log/snort/alert_json.txt`

---

## ClamAV Configuration

### Required Services

The application manages these systemd services:

1. `clamav-daemon` (clamd)
2. `clamav-freshclam` (signature updates)
3. `clamav-clamonacc` (on-access scanning)

### Quarantine Directory

**Location:** `/var/lib/clamav/quarantine`

Ensure this directory exists and has proper permissions:

```bash
sudo mkdir -p /var/lib/clamav/quarantine
sudo chown clamav:clamav /var/lib/clamav/quarantine
sudo chmod 750 /var/lib/clamav/quarantine
```

---

## Optional Dependencies

### CustomTkinter (Modern UI)

```bash
pip install customtkinter
```

Provides modern, dark-themed widgets. Falls back to ttk if not installed.

### Matplotlib (Analytics Charts)

```bash
pip install matplotlib
```

Enables the Stats tab with visual charts. Tab shows installation message if missing.

### GeoIP (Geographic Lookups)

```bash
pip install geoip2
```

Requires MaxMind GeoLite2 database:

```bash
# Download database (requires MaxMind account)
wget https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City...

# Place in expected location
sudo mkdir -p /usr/share/GeoIP
sudo mv GeoLite2-City.mmdb /usr/share/GeoIP/
```

### Keyring (Secure Key Storage)

```bash
pip install keyring
```

Uses system keyring (GNOME Keyring, KWallet, etc.) for secure API key storage.

---

## Environment Variables

The application does not currently use environment variables, but you can extend it:

```python
# In ids_suite/core/config.py
import os

class Config:
    @property
    def api_key_virustotal(self):
        return os.environ.get('VT_API_KEY') or self._get_from_keyring('virustotal')
```

---

## Permissions

### PolicyKit Configuration

The application uses `pkexec` for privileged operations. To avoid password prompts, create a PolicyKit rule:

**File:** `/etc/polkit-1/rules.d/50-security-suite.rules`

```javascript
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.policykit.exec" &&
        action.lookup("program") == "/usr/bin/systemctl" &&
        subject.isInGroup("wheel")) {
        return polkit.Result.YES;
    }
});
```

### File Permissions

Ensure the user can read IDS logs:

```bash
# Add user to suricata group
sudo usermod -aG suricata $USER

# Or adjust log permissions
sudo chmod 644 /var/log/suricata/eve.json
```

---

## Troubleshooting

### "API key not configured"

1. Check if keyring is installed: `pip show keyring`
2. Verify key is stored: `python -c "import keyring; print(keyring.get_password('security-suite', 'virustotal'))"`
3. Try setting key again via GUI or CLI

### "Permission denied" reading logs

1. Check log file permissions: `ls -la /var/log/suricata/`
2. Add user to appropriate group: `sudo usermod -aG suricata $USER`
3. Log out and back in for group changes to take effect

### Service control fails

1. Verify service name: `systemctl status suricata-laptop`
2. Check PolicyKit rules
3. Try manual control: `pkexec systemctl start suricata-laptop`

### Charts not showing

1. Install matplotlib: `pip install matplotlib`
2. Restart the application
3. Check for errors in terminal output

### CustomTkinter not working

1. Install/upgrade: `pip install --upgrade customtkinter`
2. Check Python version (requires 3.7+)
3. Fallback to ttk is automatic if issues occur
