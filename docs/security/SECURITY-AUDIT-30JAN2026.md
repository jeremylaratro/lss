# Security Audit Report: IDS Suite Control Panel

**Date:** 30 January 2026
**Version:** 2.9.1
**Scope:** Full-stack security review including SAST, logic review, supply chain, input validation, API security, and fuzzing

---

## Executive Summary

| Risk Level | Count | Status |
|------------|-------|--------|
| **CRITICAL** | 1 | Requires immediate fix |
| **HIGH** | 6 | Fix within 1 week |
| **MEDIUM** | 12 | Fix within 30 days |
| **LOW** | 8 | Technical debt |
| **INFO** | 3 | Best practice improvements |

**Overall Security Posture:** The codebase demonstrates strong security awareness with command whitelisting, input validation, and proper privilege separation. However, several shell injection vulnerabilities and missing TLS verification require immediate attention.

---

## 1. CRITICAL FINDINGS

### 1.1 Shell Injection via Unsanitized SID Input
**Severity:** CRITICAL
**Location:** `ids_suite/ui/main_window.py:4334-4336`

```python
# VULNERABLE: User SID interpolated into pkexec bash command
["pkexec", "bash", "-c", f"echo '{sid}' >> /etc/suricata/disable.conf"]
```

**Impact:** Root command execution if SID validation bypassed
**Fix:** Write SID to temp file, use pkexec to append, or use `run_privileged_batch()` with proper validation

---

## 2. HIGH SEVERITY FINDINGS

### 2.1 Shell Injection in EVE File Reader
**Location:** `ids_suite/models/eve_reader.py:154-157`

```python
# VULNERABLE: shell=True with file path
result = subprocess.run(
    f"tail -{num_lines} '{self.current_file}'",
    shell=True, capture_output=True, text=True
)
```

**Fix:** Use list-based invocation:
```python
subprocess.run(["tail", f"-{num_lines}", self.current_file], ...)
```

### 2.2 Shell Injection in IDS Service
**Location:** `ids_suite/services/ids_service.py:113-116`

```python
# VULNERABLE: shell=True with glob patterns
f"cat {rules_dir}/*.rules 2>/dev/null | grep -c '^alert'"
```

**Fix:** Use Python's `glob` and native file operations

### 2.3 Missing TLS Certificate Verification
**Location:** All `threat_intel/*.py` files

**Impact:** Man-in-the-middle attacks could intercept API keys
**Fix:** Add `verify=True` to all `requests` calls (or rely on default)

### 2.4 No Rate Limiting on API Clients
**Location:** `threat_intel/abuseipdb.py`, `otx.py`, `threatfox.py`

**Impact:** API quota exhaustion, potential service bans
**Fix:** Implement rate limiting similar to VirusTotal client

### 2.5 Missing requirements.txt
**Location:** Project root

**Impact:** No dependency pinning, vulnerability scanning impossible
**Fix:** Create requirements.txt with pinned versions and hashes

### 2.6 Type Mismatch in run_privileged_command
**Location:** `ids_suite/services/ids_service.py:46, 60, 91`

```python
# BUG: String passed where List[str] expected - will fail at runtime
run_privileged_command("suricata-update --no-test")  # Wrong
run_privileged_command(["suricata-update", "--no-test"])  # Correct
```

---

## 3. MEDIUM SEVERITY FINDINGS

### 3.1 TOCTOU Race Condition in Privilege Helper
**Location:** `ids_suite/services/privilege_helper.py:408-462`

Temp file created, then executed with pkexec - race window exists.

**Fix:** Use `tempfile.mkdtemp()` with 0o700 permissions

### 3.2 Unrestricted Restore Destination
**Location:** `ids_suite/ui/tabs/quarantine_tab.py:359-377`

Quarantined files can be restored to ANY location as root.

**Fix:** Add `allowed_dirs` restriction for restore destinations

### 3.3 Shell Commands in ClamAV Service
**Location:** `ids_suite/services/clamav_service.py:124-128`

Complex shell pipeline with `shell=True`.

**Fix:** Use Python's `glob` and subprocess list-based calls

### 3.4 Shell Command in Quarantine Cleanup
**Location:** `ids_suite/ui/tabs/quarantine_tab.py:259-264`

Unnecessary `shell=True` for static command.

**Fix:** `subprocess.run(["pkexec", "/usr/local/bin/av-cleanup"], ...)`

### 3.5 Thread Safety Issues in Async Runner
**Location:** `ids_suite/ui/components/async_runner.py:32, 95-96, 102, 215`

`_active_threads` list modified without locks.

**Fix:** Add `threading.Lock()` to protect shared state

### 3.6 Threat Intel Cache Not Thread-Safe
**Location:** `ids_suite/threat_intel/cache.py`

Dictionary operations without synchronization.

**Fix:** Add `threading.Lock()` for cache operations

### 3.7 OTX Client Missing SSRF Protection
**Location:** `ids_suite/threat_intel/otx.py:35-54`

No `is_private_ip()` check before API calls.

**Fix:** Add private IP filtering like other clients

### 3.8 Unsafe Path Validation Timing
**Location:** `ids_suite/services/privilege_helper.py:272-297`

Path resolved before privileged operation - symlink swap possible.

**Fix:** Use `O_NOFOLLOW` or resolve paths inside privileged context

### 3.9-3.12 Additional shell=True Usage
Multiple locations use `shell=True` unnecessarily - see detailed findings.

---

## 4. LOW SEVERITY FINDINGS

| ID | Location | Issue | Fix |
|----|----------|-------|-----|
| 4.1 | `core/config.py:57-66` | Settings file permissions not explicit | Use `os.open()` with 0o600 |
| 4.2 | `threat_intel/tracker.py:44-51` | IP tracker file permissions | Set explicit permissions |
| 4.3 | `core/validators.py:17-20` | No IPv6 support in validator | Use `ipaddress` module |
| 4.4 | `services/privilege_helper.py:658-712` | PolicyKit allows passwordless for wheel | Document security implications |
| 4.5 | TOCTOU in quarantine_tab.py | Time-of-check vs time-of-use (mitigated) | Re-validate before operation |
| 4.6 | `threat_intel/threatfox.py:19-66` | No IOC validation before API call | Add validation |
| 4.7 | Insecure temp file in main_window.py | Predictable `/tmp/` paths for systemd | Use `tempfile.mkstemp()` |
| 4.8 | Exception message exposure | Raw errors could leak internal details | Sanitize error messages |

---

## 5. SECURITY STRENGTHS

The codebase demonstrates excellent security practices:

1. **Command Whitelisting** - `ALLOWED_COMMANDS` dictionary in `privilege_helper.py` provides defense-in-depth
2. **Input Validation Framework** - Dedicated `validators.py` with pattern-based validation
3. **Private IP Filtering** - Comprehensive `is_private_ip()` prevents LAN IP leakage to external APIs
4. **List-Based Subprocess** - Most subprocess calls correctly use list form
5. **Service Name Validation** - Regex validation for systemd service names
6. **Path Canonicalization** - Using `os.path.realpath()` to prevent basic traversal
7. **Secure Credential Storage** - Keyring integration for API keys
8. **Request Timeouts** - All API calls have 30-second timeouts

---

## 6. SUPPLY CHAIN ANALYSIS

### Dependencies Identified (from source code)
| Package | Type | Risk |
|---------|------|------|
| requests | Required | Needs version pinning |
| customtkinter | Optional | Needs version pinning |
| matplotlib | Optional | Needs version pinning |
| geoip2 | Optional | Needs version pinning |
| keyring | Optional | Needs version pinning |
| pytest | Dev | Needs version pinning |

### Missing Security Infrastructure
- No `requirements.txt` with pinned versions
- No integrity hashes for dependencies
- No SBOM (Software Bill of Materials)
- No CI/CD security scanning

---

## 7. FUZZING RESULTS

### Crash Vectors Identified: 47

| Attack Surface | Vectors | Critical |
|----------------|---------|----------|
| File Parsing | 10 | 1 (shell injection) |
| IP Address Handling | 8 | 0 |
| Path Handling | 7 | 0 |
| API Response Handling | 6 | 0 |
| Command Arguments | 16 | 0 |

### Test Infrastructure Created
- `tests/test_fuzzing.py` - 60+ test cases
- `fuzzing_harness.py` - Atheris-based fuzzer with 7 targets
- `crash_vector_demo.py` - Interactive vulnerability demonstration

---

## 8. PRIORITIZED REMEDIATION PLAN

### Immediate (This Week)
| Priority | Issue | Effort | Impact |
|----------|-------|--------|--------|
| 1 | Fix SID shell injection (Critical 1.1) | Low | Critical |
| 2 | Fix EVE reader shell injection (High 2.1) | Low | High |
| 3 | Fix type mismatch bug (High 2.6) | Low | High |
| 4 | Create requirements.txt (High 2.5) | Low | High |

### Short-term (2 Weeks)
| Priority | Issue | Effort | Impact |
|----------|-------|--------|--------|
| 5 | Remove all shell=True usage | Medium | High |
| 6 | Add TLS verification | Low | High |
| 7 | Implement rate limiting | Medium | Medium |
| 8 | Add thread locks | Low | Medium |

### Medium-term (30 Days)
| Priority | Issue | Effort | Impact |
|----------|-------|--------|--------|
| 9 | Fix TOCTOU race conditions | Medium | Medium |
| 10 | Restrict restore destinations | Low | Medium |
| 11 | Add IPv6 validation support | Low | Low |
| 12 | Add API response schema validation | Medium | Low |
| 13 | Implement CI/CD security scanning | Medium | Medium |

---

## 9. TRUST BOUNDARY ANALYSIS

```
┌─────────────────────────────────────────────────────────────────┐
│                        USER SPACE (Low Trust)                    │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────┐ │
│  │ GUI Inputs  │  │ Log Parsing  │  │ API Responses (Untrust) │ │
│  │ - Ports     │  │ - EVE JSON   │  │ - VirusTotal            │ │
│  │ - SIDs      │  │ - Config     │  │ - AbuseIPDB             │ │
│  │ - Paths     │  │              │  │ - OTX                   │ │
│  └──────┬──────┘  └──────┬───────┘  └───────────┬─────────────┘ │
│         │                │                      │               │
│         ▼                ▼                      ▼               │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              INPUT VALIDATION LAYER                         ││
│  │  validators.py, is_private_ip(), path validation            ││
│  └──────────────────────────┬──────────────────────────────────┘│
└─────────────────────────────┼───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PRIVILEGE BOUNDARY                            │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              privilege_helper.py                            ││
│  │  - Command whitelist    - Path validation                   ││
│  │  - Argument validation  - Service name validation           ││
│  └──────────────────────────┬──────────────────────────────────┘│
└─────────────────────────────┼───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      ROOT SPACE (High Trust)                     │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────┐ │
│  │ systemctl   │  │ firewall-cmd │  │ File Operations         │ │
│  │ Service Ops │  │ Firewall Ops │  │ /etc, /var/lib configs  │ │
│  └─────────────┘  └──────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 10. CONCLUSION

The IDS Suite Control Panel has a solid security foundation with proper whitelisting and validation infrastructure. However, **6 high-severity vulnerabilities** require immediate attention, particularly the shell injection issues and missing TLS verification.

**Key Actions:**
1. Eliminate all `shell=True` subprocess usage
2. Create `requirements.txt` with pinned dependencies
3. Add TLS certificate verification to API calls
4. Implement rate limiting across all threat intel clients
5. Add thread synchronization to shared state

After remediation, the application will have a strong security posture suitable for production use in security-critical environments.

---

## Appendix: Files Reviewed

- `ids_suite/core/` - config.py, constants.py, dependencies.py, utils.py, validators.py
- `ids_suite/services/` - privilege_helper.py, systemd.py, clamav_service.py, ids_service.py
- `ids_suite/models/` - eve_reader.py, alert.py
- `ids_suite/threat_intel/` - base.py, cache.py, tracker.py, virustotal.py, abuseipdb.py, otx.py, threatfox.py
- `ids_suite/ui/` - main_window.py, tabs/quarantine_tab.py, components/async_runner.py
- `ids_suite/engines/` - base.py, suricata.py, snort.py
