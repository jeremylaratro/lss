# Test Suite Quick Start

Quick reference for running tests in the IDS Suite project.

## Run All Tests

```bash
# Quick run (no coverage)
pytest tests/

# With coverage
pytest tests/ --cov=ids_suite --cov-report=term-missing
```

## Run Specific Tests

```bash
# Single file
pytest tests/unit/test_utils.py

# Single class
pytest tests/unit/test_utils.py::TestIsPrivateIP

# Single test
pytest tests/unit/test_utils.py::TestIsPrivateIP::test_class_a_private_start
```

## Common Options

```bash
# Verbose output
pytest tests/ -v

# Stop on first failure
pytest tests/ -x

# Show local variables on failure
pytest tests/ -l

# Run last failed tests
pytest tests/ --lf

# Run without coverage (faster)
pytest tests/ --no-cov
```

## Coverage Reports

```bash
# HTML report (opens in browser)
pytest tests/ --cov=ids_suite --cov-report=html
xdg-open htmlcov/index.html

# Terminal report with missing lines
pytest tests/ --cov=ids_suite --cov-report=term-missing

# XML for CI/CD
pytest tests/ --cov=ids_suite --cov-report=xml
```

## Test Markers

```bash
# Run only unit tests
pytest tests/ -m unit

# Exclude slow tests
pytest tests/ -m "not slow"
```

## Test Statistics

```bash
# Show test collection without running
pytest tests/ --co -q

# Show test durations
pytest tests/ --durations=10
```

## Current Test Suite

**680+ tests** across 18 test files:

| Test File | Focus Area |
|-----------|------------|
| test_utils.py | IP validation, utilities |
| test_validators.py | Input validation |
| test_config.py | Configuration management |
| test_cache.py | Threat intel caching |
| test_threat_intel_base.py | Base TI client |
| test_virustotal.py | VirusTotal API |
| test_otx.py | AlienVault OTX API |
| test_abuseipdb.py | AbuseIPDB API |
| test_threatfox.py | ThreatFox API |
| test_tracker.py | IP lookup tracking |
| test_clamav_service.py | ClamAV integration |
| test_ids_service.py | IDS service management |
| test_systemd.py | Systemd wrapper |
| test_engines.py | Suricata/Snort engines |
| test_alert.py | Alert data model |
| test_eve_reader.py | EVE log parsing |
| test_privilege_helper.py | Privilege escalation |
| test_ui_logic.py | UI pure logic functions |

## Coverage Targets

Most modules have 75%+ coverage, with many at 95-100%.

## Need Help?

See `TESTING_README.md` for comprehensive documentation.
