# IDS Suite Test Infrastructure

Comprehensive pytest-based test suite for the IDS Suite application.

## Overview

This test infrastructure provides comprehensive unit testing for the IDS Suite, with coverage across:
- Core utilities (IP validation, configuration, validators)
- Threat intelligence clients and caching
- IDS service management and engines
- ClamAV service integration
- Alert models and EVE log parsing
- UI logic (pure functions testable without display)

## Structure

```
tests/
├── __init__.py              # Test package initialization
├── conftest.py              # Shared pytest fixtures
└── unit/
    ├── __init__.py
    ├── test_abuseipdb.py    # AbuseIPDB threat intel client
    ├── test_alert.py        # Alert model tests
    ├── test_cache.py        # Threat intel cache tests
    ├── test_clamav_service.py # ClamAV service tests
    ├── test_config.py       # Configuration singleton tests
    ├── test_engines.py      # Suricata/Snort engine tests
    ├── test_eve_reader.py   # EVE file reader tests
    ├── test_ids_service.py  # IDS service tests
    ├── test_otx.py          # AlienVault OTX client tests
    ├── test_privilege_helper.py # Privilege escalation tests
    ├── test_systemd.py      # Systemd service tests
    ├── test_threatfox.py    # ThreatFox client tests
    ├── test_threat_intel_base.py # Base TI client tests
    ├── test_tracker.py      # IP lookup tracker tests
    ├── test_ui_logic.py     # UI pure logic tests
    ├── test_utils.py        # Core utility tests
    ├── test_validators.py   # Input validation tests
    └── test_virustotal.py   # VirusTotal client tests
```

## Test Coverage

Current test coverage by module:

| Module | Coverage | Description |
|--------|----------|-------------|
| `core/utils.py` | 100% | IP validation (RFC1918, IPv4, IPv6) |
| `core/validators.py` | 95%+ | Input validation functions |
| `core/config.py` | 90%+ | Configuration management |
| `threat_intel/cache.py` | 100% | TTL-based caching |
| `threat_intel/base.py` | 98% | Base TI client |
| `threat_intel/virustotal.py` | 98% | VirusTotal API client |
| `threat_intel/otx.py` | 100% | AlienVault OTX client |
| `threat_intel/abuseipdb.py` | 100% | AbuseIPDB client |
| `threat_intel/threatfox.py` | 100% | ThreatFox client |
| `threat_intel/tracker.py` | 98% | IP lookup tracking |
| `services/clamav_service.py` | 91% | ClamAV integration |
| `services/ids_service.py` | 100% | IDS service management |
| `services/systemd.py` | 100% | Systemd service wrapper |
| `engines/suricata.py` | 100% | Suricata engine |
| `engines/snort.py` | 96% | Snort engine |
| `models/alert.py` | 100% | Alert data model |
| `models/eve_reader.py` | 85% | EVE JSON log reader |

**Total: 680+ unit tests**

## Running Tests

### Run All Tests
```bash
pytest tests/
```

### Run with Coverage
```bash
pytest tests/ --cov=ids_suite --cov-report=html
```

### Run Specific Test File
```bash
pytest tests/unit/test_utils.py -v
```

### Run Specific Test Class
```bash
pytest tests/unit/test_utils.py::TestIsPrivateIP -v
```

### Run with Markers
```bash
# Run only unit tests
pytest tests/ -m unit

# Exclude slow tests
pytest tests/ -m "not slow"
```

## Common Test Commands

```bash
# Quick validation (stop on first failure)
pytest tests/ -x

# Verbose output with local variables
pytest tests/ -v -l

# Run last failed tests
pytest tests/ --lf

# Show slowest tests
pytest tests/ --durations=10

# Run without coverage (faster)
pytest tests/ --no-cov
```

## Coverage Reports

After running tests with coverage:

```bash
# HTML report (interactive)
pytest tests/ --cov=ids_suite --cov-report=html
xdg-open htmlcov/index.html

# Terminal report with missing lines
pytest tests/ --cov=ids_suite --cov-report=term-missing

# XML for CI/CD
pytest tests/ --cov=ids_suite --cov-report=xml
```

## Writing Tests

### Test Organization
```python
class TestFeatureName:
    """Test suite for FeatureName"""

    def test_basic_operation(self):
        """Test basic functionality"""
        # Arrange
        # Act
        # Assert

    def test_edge_case(self):
        """Test edge case handling"""
        pass
```

### Using Fixtures
```python
def test_with_fixtures(temp_dir, mock_eve_event):
    """Test using shared fixtures from conftest.py"""
    assert os.path.exists(temp_dir)
    assert mock_eve_event['event_type'] == 'alert'
```

### Parametrized Tests
```python
@pytest.mark.parametrize("ip,expected", [
    ("10.0.0.1", True),
    ("8.8.8.8", False),
])
def test_multiple_cases(ip, expected):
    assert is_private_ip(ip) == expected
```

## Shared Fixtures (conftest.py)

Key fixtures available:
- `temp_dir`: Temporary directory with cleanup
- `mock_eve_file`: Pre-populated EVE JSON file
- `mock_eve_event`: Single EVE JSON event
- `mock_threat_intel_result`: TI API response
- `sample_ips`: Categorized IP samples
- `mock_keyring`: Mocked keyring for API keys
- `clean_cache`: Fresh ThreatIntelCache instance

## CI/CD Integration

```bash
# JUnit XML output
pytest tests/ --junitxml=junit.xml

# Full CI run
pytest tests/ --cov=ids_suite --cov-report=xml --cov-report=term
```

## Troubleshooting

### Import Errors
```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

### Slow Tests
```bash
# Skip slow tests
pytest tests/ -m "not slow"

# Parallel execution (requires pytest-xdist)
pytest tests/ -n auto
```
