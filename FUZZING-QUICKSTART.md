# Fuzzing Quick Start Guide
**Date:** 30 January 2026

## Quick Reference

### Run Fuzzing Tests (5 minutes)
```bash
cd /home/jay/Documents/cyber/dev/lss2
pytest tests/test_fuzzing.py -v
```

### Run Fuzzing Harness (1 hour)
```bash
cd /home/jay/Documents/cyber/dev/lss2
pip install atheris
timeout 3600 python3 fuzzing_harness.py
```

### Check Results
```bash
# Test results
pytest tests/test_fuzzing.py -v --tb=short

# Fuzzer crashes (if any)
ls -la crash-* 2>/dev/null || echo "No crashes found"
```

## Key Findings at a Glance

1. **CRITICAL Shell Injection** - `ids_suite/models/eve_reader.py:154`
   - Fix: Replace `shell=True` with list-based subprocess call

2. **HIGH Memory Exhaustion** - No JSON size limits
   - Fix: Add 1MB max input validation

3. **47 Total Crash Vectors** identified and documented

## Files Created

| File | Purpose | Size |
|------|---------|------|
| FUZZING-STRATEGY-30JAN2026.md | Full documentation | ~50KB |
| FUZZING-OUTBRIEF-30JAN2026.md | Executive summary | ~8KB |
| fuzzing_harness.py | Atheris fuzzer | ~10KB |
| tests/test_fuzzing.py | Test suite | ~18KB |

## Documentation Structure

```
FUZZING-STRATEGY-30JAN2026.md    <- Full details, all test cases
├── 1. File Parsing (10 vectors)
├── 2. IP Handling (8 vectors)
├── 3. Path Handling (7 vectors)
├── 4. API Responses (6 vectors)
└── 5. CLI Arguments (16 vectors)

FUZZING-OUTBRIEF-30JAN2026.md    <- Concise summary
├── Executive Summary
├── Critical Findings
├── Attack Surface Coverage
└── Recommended Fixes

fuzzing_harness.py                <- Atheris fuzzer
tests/test_fuzzing.py             <- Pytest tests
```

## Priority Remediation

1. Fix shell injection (CRITICAL)
2. Add JSON size limits (HIGH)
3. Run full fuzzing campaign (24h)
4. Implement remaining fixes (MEDIUM)
