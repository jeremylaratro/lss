# Test Coverage Expansion Plan
## Target: 95% Coverage | Created: 27 JAN 2026

---

## Current Baseline (27 JAN 2026)

| Module | Stmts | Miss | Coverage | Status |
|--------|-------|------|----------|--------|
| core/__init__.py | 5 | 0 | 100% | DONE |
| core/config.py | 90 | 3 | 97% | DONE |
| core/constants.py | 64 | 1 | 98% | DONE |
| core/dependencies.py | 64 | 28 | 53% | NEEDS WORK |
| core/utils.py | 42 | 0 | 100% | DONE |
| core/validators.py | 122 | 7 | 95% | DONE |
| engines/__init__.py | 4 | 0 | 100% | DONE |
| engines/base.py | 21 | 6 | 71% | NEEDS WORK |
| engines/snort.py | 47 | 1 | 96% | DONE |
| engines/suricata.py | 24 | 0 | 100% | DONE |
| models/__init__.py | 3 | 0 | 100% | DONE |
| models/alert.py | 39 | 0 | 100% | DONE |
| models/eve_reader.py | 107 | 16 | 85% | NEEDS WORK |
| services/__init__.py | 5 | 0 | 100% | DONE |
| services/clamav_service.py | 99 | 4 | 91% | CLOSE |
| services/ids_service.py | 68 | 0 | 100% | DONE |
| services/privilege_helper.py | 266 | 58 | 79% | NEEDS WORK |
| services/systemd.py | 76 | 0 | 100% | DONE |
| threat_intel/__init__.py | 7 | 0 | 100% | DONE |
| threat_intel/abuseipdb.py | 34 | 0 | 100% | DONE |
| threat_intel/base.py | 45 | 1 | 98% | DONE |
| threat_intel/cache.py | 28 | 0 | 100% | DONE |
| threat_intel/otx.py | 58 | 0 | 100% | DONE |
| threat_intel/threatfox.py | 37 | 0 | 100% | DONE |
| threat_intel/tracker.py | 78 | 2 | 98% | DONE |
| threat_intel/virustotal.py | 72 | 1 | 98% | DONE |
| ui/__init__.py | 3 | 0 | 100% | DONE |
| ui/components/__init__.py | 3 | 3 | 0% | NEEDS WORK |
| ui/components/async_runner.py | 89 | 89 | 0% | NEEDS WORK |
| ui/components/treeview_builder.py | 76 | 76 | 0% | NEEDS WORK |
| ui/main_window.py | 4640 | 4407 | 4% | NEEDS WORK |
| ui/tabs/__init__.py | 6 | 6 | 0% | NEEDS WORK |
| ui/tabs/alerts_tab.py | 727 | 727 | 0% | NEEDS WORK |
| ui/tabs/base_tab.py | 58 | 58 | 0% | NEEDS WORK |
| ui/tabs/dns_tab.py | 185 | 185 | 0% | NEEDS WORK |
| ui/tabs/quarantine_tab.py | 209 | 209 | 0% | NEEDS WORK |
| ui/tabs/traffic_tab.py | 245 | 245 | 0% | NEEDS WORK |
| ui/widget_factory.py | 68 | 51 | 18% | NEEDS WORK |

**Overall: 7819 statements, 6184 missed = 21% coverage**
**Target: 95% coverage**

---

## Priority Analysis

### Tier 1: Backend Modules Below 95% (HIGH PRIORITY)
These are testable without UI dependencies:

1. **core/dependencies.py** (53%) - 28 statements missing
2. **engines/base.py** (71%) - 6 statements missing
3. **services/privilege_helper.py** (79%) - 58 statements missing
4. **models/eve_reader.py** (85%) - 16 statements missing
5. **services/clamav_service.py** (91%) - 4 statements missing

### Tier 2: UI Components (MEDIUM PRIORITY)
Can test logic without display:

6. **ui/widget_factory.py** (18%) - 51 statements missing
7. **ui/components/async_runner.py** (0%) - 89 statements
8. **ui/components/treeview_builder.py** (0%) - 76 statements

### Tier 3: UI Tabs (LOWER PRIORITY - Heavy UI)
Mostly require GUI mocking:

9. **ui/tabs/base_tab.py** (0%) - 58 statements
10. **ui/tabs/alerts_tab.py** (0%) - 727 statements
11. **ui/tabs/dns_tab.py** (0%) - 185 statements
12. **ui/tabs/traffic_tab.py** (0%) - 245 statements
13. **ui/tabs/quarantine_tab.py** (0%) - 209 statements

### Tier 4: Main Window (LOWEST PRIORITY - Massive)
14. **ui/main_window.py** (4%) - 4407 statements missing

---

## Execution Plan

### Phase 1: Backend to 95%+ (Est: 40-50 tests)
- [ ] core/dependencies.py → 95%
- [ ] engines/base.py → 95%
- [ ] services/privilege_helper.py → 95%
- [ ] models/eve_reader.py → 95%
- [ ] services/clamav_service.py → 95%

### Phase 2: UI Components (Est: 30-40 tests)
- [ ] ui/widget_factory.py → 95%
- [ ] ui/components/async_runner.py → 95%
- [ ] ui/components/treeview_builder.py → 95%
- [ ] ui/tabs/base_tab.py → 95%

### Phase 3: UI Tab Logic (Est: 60-80 tests)
Extract and test pure logic from:
- [ ] alerts_tab.py pure functions
- [ ] dns_tab.py pure functions
- [ ] traffic_tab.py pure functions
- [ ] quarantine_tab.py pure functions

### Phase 4: Main Window Logic (Est: 100+ tests)
Extract and test pure logic from:
- [ ] main_window.py settings methods
- [ ] main_window.py data processing
- [ ] main_window.py utility functions

---

## Test Estimation

| Phase | Modules | Est. Tests | Target Coverage |
|-------|---------|------------|-----------------|
| 1 | Backend gaps | 40-50 | 95%+ all backend |
| 2 | UI components | 30-40 | 95%+ components |
| 3 | Tab logic | 60-80 | 50%+ tabs |
| 4 | Main window | 100+ | 30%+ main |

**Note:** UI modules with heavy tkinter dependencies will have lower coverage targets since GUI code is difficult to unit test. Focus is on extracting and testing pure logic functions.

---

## Success Criteria

1. All backend modules (core, engines, models, services, threat_intel) at 95%+
2. UI component modules at 95%+
3. Overall project coverage reaches 60%+ (realistic with heavy UI)
4. No regressions in existing tests
