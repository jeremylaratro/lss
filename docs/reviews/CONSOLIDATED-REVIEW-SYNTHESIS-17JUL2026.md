# lss2 — Consolidated Review Synthesis (17JUL2026)

Synthesis of two model reviews plus direct system verification.

- Opus broad bug-hunt → `OPUS-BUG-REVIEW-17JUL2026.md`
- Fable 5 design/doctrine review → `FABLE-DESIGN-REVIEW-17JUL2026.md`
- Direct verification against the live Fedora host (this machine).

All three converge on the same story: **the code that ships is a single 8,227-line
`main_window.py` that updates Tk widgets from a background thread and swallows every
error, while a cleaner extracted architecture (tabs/, services/, AsyncRunner) sits
fully built but never wired in and is what the test suite actually tests.**

---

## 1. Why "IDS logs don't populate" (confirmed root causes, in order of impact)

The live view (alerts + protocol counts + activity feed) is fed by one in-memory
buffer, `eve_event_buffer`, built by `_update_eve_buffer()` (`main_window.py:5472`).
Every failure mode below yields an **empty grid with no error message**:

1. **Off-main-thread UI mutation (CRIT).** The 5s auto-refresh runs in a daemon
   thread and mutates the treeview/status/buttons directly. Tcl/Tk is not
   thread-safe → corrupted or no-op updates. `main_window.py:7499-7521, 7580-7583`.
2. **EVE reader swallows all I/O errors (CRIT).** `eve_reader.py:114` catches
   `PermissionError` with a comment promising a tail fallback — the body is a bare
   `pass`. Returns `[]`. On any host where logs aren't group-readable: zero alerts,
   silently, forever. `eve_reader.py:114-116, 137-166`.
3. **Retention prunes the buffer to empty (HIGH).** `initial_load(10000)` tails 10k
   lines, then the buffer is immediately pruned to events newer than `now − 120min`
   (`5501-5506`). If Suricata is stopped/restarting or traffic is quiet, the newest
   event is older than 120 min → buffer empties. The 10k load is wasted; live mode
   can only ever hold the last 120 min.
4. **Timezone landmine (HIGH).** `data['timestamp'][:19]` strips the `-0400` offset
   and string-compares to a naive `datetime.now()`. Fine on this box; on a
   UTC-logging host with a non-UTC clock, all events look hours old → pruned to empty.
5. **Reversed slice drops newest alerts (HIGH).** `new_alerts_data[-200:]` on a
   newest-first list keeps the **oldest** 200. `main_window.py:5666-5669`.
6. **Engine filter = "Snort" skips every event (MED).** `5623-5625`.
7. **Config ignored.** `data_retention_minutes` is hardcoded `120` at
   `main_window.py:168`, shadowing the configurable `Config` property → retention
   changes never take effect.

**Environmental note:** on this host right now, `eve.json` contains only
`flow`/`stats` events (0 `alert` events), so an empty *alerts* view is partly
legitimate — but the code defects above mean the user can never tell the difference
between "no alerts" and "the pipe is broken."

---

## 2. Why "buttons don't always work" (confirmed)

Wiring is actually clean — an audit of ~140 `command=`/`.bind()` targets found no
misrouted/missing/no-op handlers and no loop late-binding bugs. Buttons misbehave for
two structural reasons:

1. **The 5s off-thread refresh (CRIT-1 above) destabilizes the whole UI**, so any
   button pressed mid-refresh can no-op or corrupt state.
2. **Service control targets the wrong systemd unit — machine-dependent.** Two
   conflicting sources of truth:
   - `constants.py`: `SURICATA="suricata-laptop"`, `CLAMD="clamd@scan"`, …
   - `clamav_service.py`: hardcodes Debian names (`clamav-daemon`,
     `clamav-clamonacc`) and ignores the constants entirely.
   - Verified on this host: `suricata-laptop`=active but `suricata`=failed;
     `clamav-daemon`=active but `clamd@scan`=inactive. So status/start/stop hit a
     live unit or a dead one depending on which module routes the call.
3. **Firewall buttons fail silently (HIGH-2).** `firewall-cmd`/`ufw` aren't in the
   privilege whitelist, so `run_privileged_batch` rejects them and `_fw_control`
   discards the failure. `privilege_helper.py:22-76`, `main_window.py:3090-3184`.
4. **Settings-tab Start/Stop/Restart never reflect running state (MED-6).** Only the
   top-bar buttons do. `main_window.py:1208-1210, 1429-1447`.

---

## 3. Doctrine findings

- **The polybar/i3 widget — the owner's most-valued feature — is not in this repo.**
  Only `widget_factory.py` (tkinter helpers) exists. The widget lives unversioned on
  the system.
- **The tab-extraction refactor never cut over.** `tabs/*.py`, `services/*`, and
  `AsyncRunner` are never instantiated by the running app, yet the tests exercise
  them → green tests, buggy app. A strangler-fig migration that never strangled.
- **No `logging`, ~68 broad `except` blocks.** The app is structurally incapable of
  telling the user when something failed.

---

## 4. Prioritized fix plan

### P0 — make the current app actually work
1. **Marshal all widget updates to the main thread** (`root.after`/`after_idle`); keep
   I/O in threads, hand results back. Single highest-leverage fix (kills CRIT-1 →
   both the log-population and flaky-button symptoms). Route through the existing
   unused `AsyncRunner`.
2. **Stop swallowing errors in `EVEFileReader`**; implement the sudo/tail fallback or
   surface a health banner. Add `logging`.
3. **Fix live retention:** show the most-recent N events regardless of wall-clock age
   (retention as a display filter, tz-aware); stop the load-10k-then-prune-to-empty.
4. **Fix the `[-200:]` slice** to keep the newest alerts.
5. **One auto-detected source of truth for unit names** at startup
   (`clamav-daemon` vs `clamd@scan`; `suricata` vs `suricata-laptop`) → settings.json.
6. **Whitelist `firewall-cmd`/`ufw`** (or surface the rejection).

### P1 — stop lying to yourself
7. Resolve the dead-code fork: wire the extracted tabs in and delete the monolith
   copies, **or** delete the extracted tabs. Point tests at what actually runs.
8. Add a persistent in-UI health strip + logging. Make failure visible.
9. Readonly severity combobox; fix Snort-skips-all; settings-tab buttons reflect state.
10. **Commit the polybar widget into the repo.**

### P2 — target architecture (see §5)

---

## 5. The web-dashboard decision

**Verdict: do NOT migrate to a web dashboard to replicate the current 17-tab UI.**

- A web viewer for `eve.json` already exists as a single Go binary — **EveBox**
  (SQLite-embedded, no ELK). **SELKS/Scirius** and **Kibana/Grafana** cover
  hunting/analytics. Rebuilding that in any stack is an unwinnable, permanent
  maintenance tax. For the dashboard tabs: **yes, you'd be reinventing Kibana, and
  you'd lose.**
- But lss2's genuinely differentiated features — **polkit-mediated service control**
  and **local config editing** — are things a browser app does *worse* (they'd need
  an authenticated privileged local daemon = security liability). A desktop process
  inheriting the user's polkit session is the correct shape.

**So: shed the parts that duplicate Kibana/EveBox; double down on the parts that
don't.** Be "the systemd-tray for your host IDS," and deep-link "Browse alerts →"
straight into EveBox.

### Recommended target architecture
1. **`lssd`** — headless, single-threaded collector. Tails `eve.json`, maintains
   rolling alert counts + service health, writes an atomic `status.json`. Single
   thread makes the whole class of concurrency bugs structurally impossible.
2. **polybar widget (in-repo)** — reads `status.json`. Zero logic.
3. **`lssctl`** — polkit-scoped start/stop/restart + config, single auto-detected
   source of truth for unit names.
4. **Slim control panel (≤2,500 lines)** — glance + control only; deep-links to
   EveBox for deep alert browsing.
5. *(Optional, if the web itch persists)* `lssd` serves a ~200-line localhost status
   page from the same `status.json`. That's a status endpoint, not a SIEM — not
   reinventing Kibana.
