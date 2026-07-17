# lss2 — Design, Doctrine & Product Review
**Date:** 17JUL2026 · **Reviewer:** Fable (step-back design review; a separate reviewer covers line-level bugs)
**Scope:** Architecture, design decisions, product direction. Grounded in code as read, not docs as written.

---

## 1. Doctrine — what this app should be

**lss2 should be a thin, reliable *glance-and-control* layer for the security services already running on this machine — not a desktop SIEM.**

The owner's revealed preference says it plainly: the three things that earn their keep are (1) the i3/polybar
widget with live alert counts, (2) start/stop/restart of Suricata/ClamAV, and (3) config editing from a UI.
Every one of those is a *small* problem. Meanwhile the codebase's mass sits in the opposite place: a 17-tab
dashboard with analytics charts, GeoIP displays, JA3/JA4 browsing, historical alert queries, DNS grouping,
threat-intel enrichment — a hobby-scale reimplementation of EveBox + Kibana + a SOAR enrichment pipeline,
in tkinter, competing with mature free tools it can never beat on that turf.

The sharpest version of this product:

> **"The systemd-tray for your host IDS."** A headless collector that always knows alert counts and service
> health; a bar widget that shows them; one keypress to a control surface that starts/stops services and edits
> configs with a single polkit prompt. For *reading* alerts in depth, it hands off to a purpose-built viewer
> (EveBox) instead of being one.

Telling detail: **the polybar widget — the single most valued feature — is not even in this repo.** The README
screenshots it, `privilege_helper.py` mentions "essential for polybar/taskbar usage," the color palette
"matches the polybar theme"… but there is no widget script, no status-file contract, no module that emits
alert counts for the bar. The product's crown jewel lives in dotfiles somewhere while 8,227 lines serve the
features nobody asked to keep. That inversion is the core product problem.

---

## 2. Architecture assessment

### 2.1 The monolith is real — but the worse problem is the *fake* modular layer around it

`ids_suite/ui/main_window.py`: **8,227 lines, one class (`SecurityControlPanel`), 282 methods.** It builds all
17 tabs, parses EVE JSON, shells out to `systemctl`/`pkexec`/`firewall-cmd`/`suricata-update` inline, manages
caches, does threat-intel lookups, and owns all state. That's bad, but it's a known, ordinary kind of bad.

The extraordinary finding is that **the entire "clean architecture" surrounding it is dead code**:

- `ids_suite/ui/tabs/` contains `AlertsTab` (1,404 lines), `TrafficTab` (490), `QuarantineTab` (463),
  `DNSTab` (449), plus `BaseTab`. **`main_window.py` imports none of them.** It still runs its own
  `create_alerts_tab()` etc. The strangler fig was planted and never allowed to strangle.
- `ids_suite/ui/components/async_runner.py` — a correct, tested, documented solution to the app's #1 defect
  (see §2.2) — **is never imported by the live code path.**
- `ids_suite/services/` (`IDSService`, `SystemdService`, `ClamAVService`) — **also unwired.** `main_window.py`
  imports only `run_privileged_batch` and otherwise calls `subprocess.run` directly, ~50+ times.
  Proof the service layer never executes: `IDSService.update_rules()` passes a *string*
  (`"suricata-update --no-test"`) to `run_privileged_command()`, which explicitly rejects non-list input —
  it would fail 100% of the time if anything called it.
- The consequence is live: **current git status shows `tabs/alerts_tab.py` modified** — effort is being spent
  maintaining code that never runs. And the unit-test suite (`test_base_tab`, `test_async_runner`,
  `test_ids_service`, `test_clamav_service`…) largely tests the dead layer. **Green tests, buggy app** — the
  test suite is measuring the architecture the docs describe, not the one the user launches.
- `docs/ARCHITECTURE.md` presents the layered UI→Services→Engines diagram as current fact. It is aspiration
  documented as reality, which actively misleads every future session (human or AI) working on this repo.

**Verdict on the tab-extraction effort:** the *direction* was right and the infrastructure (BaseTab,
AsyncRunner, TreeviewBuilder) is decent. The *execution model* was wrong: extraction without cutover is
negative-value work. Four tabs were rewritten in parallel and never switched on, so the repo now carries two
diverging implementations of its most complex screens. Rule going forward: **an extraction PR is not done
until `main_window.py` instantiates the new class and the old method is deleted.** Never two implementations
across a commit boundary.

### 2.2 The threading model is the root cause of "quite buggy"

This is the highest-confidence single finding of the review. `refresh_all()` (main_window.py:7499):

```python
def refresh_all(self):
    def do_refresh():
        self.refresh_status()      # configures Tk labels/buttons
        self.refresh_stats()       # stat_widgets[key].configure(...)
        self.refresh_activity()    # activity_text.delete()/insert()
        ...
        self.refresh_alerts()      # treeview inserts
    threading.Thread(target=do_refresh, daemon=True).start()
```

Every 5 seconds (`start_auto_refresh`), a **daemon thread directly mutates Tk widgets**. Tkinter is not
thread-safe; calling widget methods off the main thread is undefined behavior — sometimes it works, sometimes
updates are silently dropped, sometimes callbacks die inside the Tcl interpreter with no Python traceback.
That is a precise mechanical explanation for the observed symptoms: *"IDS logs don't populate, buttons
flaky"* — intermittently, unreproducibly, silently.

Compounding failures in the same loop:

- **No reentrancy guard.** A new refresh thread spawns every 5s whether or not the previous finished. Slow
  `systemctl`/file reads ⇒ overlapping threads.
- **`EVEFileReader` is stateful (position, inode) and not thread-safe**, yet `_update_eve_buffer()` is called
  concurrently from the auto-refresh thread, the initial-load thread, and main-thread tab population
  (`_populate_initial_tabs` calls the same `refresh_*` functions on the main thread). Concurrent seek/tell on
  shared reader state corrupts the read position ⇒ lost or duplicated EVE lines ⇒ *"logs don't populate."*
- **`eve_event_buffer` is a plain list, rebuilt and iterated concurrently** with no lock.
- The ironic part: **`AsyncRunner` implements the correct pattern** (work in thread, UI marshalled through
  `root.after(0, ...)`) and sits unused ten lines of import away.

The threading *doctrine* the app needs is boring and well-known: **one poller, main-thread-only widget
mutation.** A single `root.after`-driven tick; I/O snapshots gathered in one worker (or via AsyncRunner);
results applied to widgets on the main thread. For a tkinter app polling local services, `async_runner` is an
appropriate mechanism — the failure is that the live code predates it and was never migrated.

### 2.3 Configuration doctrine: three sources of truth, all disagreeing

- `core/constants.py` defines `ServiceNames.SURICATA = "suricata-laptop"` — a **machine-specific custom unit
  name baked into a "constants" module**. `main_window.py` doesn't even use the constant; it re-hardcodes
  `"suricata-laptop"` inline in at least 5 subprocess calls. Anyone running stock `suricata.service` gets a
  permanently-red status icon and dead buttons.
- `_refresh_service_status_cache()` — the self-described "SINGLE function" for status — queries
  `clamav-daemon` (the **Debian** unit name). `constants.py` says `clamd@scan`; the README's Fedora install
  instructions (the only tested platform!) enable `clamd@scan`. So on Fedora the ClamAV status cache is
  *always inactive*, start/stop buttons sit in the wrong enabled/disabled states, and the dashboard lies.
  More flaky buttons, explained.
- The polkit whitelist in `privilege_helper.py` carries a third list of service names.

Doctrine fix: service unit names, log paths, and eve.json location are **user configuration with auto-detect,
resolved once at startup** (`systemctl list-units 'suricata*' 'clamd*' ...`), stored in the existing
`~/.config/security-suite/settings.json`, and consumed from exactly one module.

### 2.4 Error-handling doctrine: silence as a design principle

The codebase's consistent posture toward failure is to eat it: **68 broad `except` blocks and 22 bare
`print()`s in main_window.py; zero use of the `logging` module anywhere in `ids_suite/`.** The flagship
example is `EVEFileReader.read_new_lines()`:

```python
except PermissionError:
    # Fall back to tail command for permission issues
    pass   # <- the fallback does not exist
```

On Fedora, `/var/log/suricata` is typically `root:suricata` with 750/640 modes. A user not in the `suricata`
group gets **an app that runs perfectly and shows zero events forever, with no error surfaced anywhere** —
almost certainly the literal "IDS logs don't populate" bug. Similar: `initial_load()` swallows all
exceptions; buffer pruning does lexical string comparison between EVE timestamps and naive local time
(silently drops everything if Suricata logs UTC); `_update_eve_buffer` prints to a stdout nobody watches.

Doctrine fix: an app whose one job is *observability of security services* must be observable itself.
(1) `logging` to `~/.local/state/lss/lss.log`; (2) a **persistent in-UI health strip** — "eve.json: readable ·
last event 4s ago · suricata unit: found" — that turns every silent precondition (permissions, missing unit,
empty log) into a visible red chip with the fix command. This one widget converts the whole class of
"silently buggy" into "tells you what's wrong."

---

## 3. Gaps & self-conflict summary

| # | Gap / self-fight | Evidence |
|---|---|---|
| 1 | Refresh loop mutates Tk from worker threads; no reentrancy guard | `refresh_all` (7499), `start_auto_refresh` (7580) |
| 2 | Extracted tabs + AsyncRunner + services layer are unwired dead code, still being edited & tested | no imports in main_window; git status; `IDSService.update_rules` type bug |
| 3 | Service names: hardcoded machine-specific + Debian/Fedora mismatch across 3 modules | constants.py:93, main_window.py:5313, privilege_helper whitelist |
| 4 | Permission failure on eve.json is invisible; promised fallback unimplemented | eve_reader.py:114–116 |
| 5 | No logging, no health surface; 68 broad excepts | grep counts, §2.4 |
| 6 | Polybar widget (top-valued feature) absent from repo; no status-export contract | repo-wide grep |
| 7 | ARCHITECTURE.md documents a runtime that doesn't exist | §2.1 |
| 8 | Stateful `EVEFileReader` shared across threads without lock | §2.2 |
| 9 | Feature mass (analytics/geo/historical/TI browsing) duplicates EveBox/Kibana poorly | §4 |
| 10 | Test suite validates the dead layer, not the live path — false confidence | tests/unit vs live imports |

---

## 4. The web-dashboard decision

**Verdict: No. Do not migrate this to a web dashboard. You would be reinventing EveBox — an existing,
excellent, single-binary web dashboard for exactly this data — and the parts of lss2 actually worth keeping
are precisely the parts a web dashboard does worst.**

The honest competitive map:

| Tool | What it is | What it covers of lss2 |
|---|---|---|
| **EveBox** | Single Go binary; web UI over eve.json (direct or via ES/SQLite); alert triage, escalation, search, reporting | Alerts tab, Traffic, DNS, historical queries, most of Overview — *better than lss2 does* |
| **Scirius / SELKS** | Stamus' Suricata rule management + full ELK-based hunting distro | Rule-source management, analytics, hunting |
| **Kibana / Grafana** | General log/metric dashboards over ES / any datasource | Analytics tab, trends, geo maps, top-talkers |
| **fail2ban/firewalld GUIs, cockpit** | Service + firewall management | Firewall tab, some audit |

If "browse and analyze my IDS alerts" is the job, `dnf install evebox` (point it at eve.json, it embeds
SQLite — no ELK needed) ends the discussion in an afternoon. Rebuilding that UI — in tkinter *or* in a web
stack — is scope creep with a permanent maintenance tax and no ceiling you can reach.

What existing tools **don't** give you — and where lss2 is genuinely differentiated:

1. **The bar widget.** EveBox will never put an alert count in polybar. This is yours.
2. **One-click privileged service control with a curated polkit whitelist.** Web apps are actively *worse*
   here — a browser page invoking pkexec/systemctl on the host means building an authenticated privileged
   local daemon, which is a security liability you shouldn't want. A desktop process inheriting the user's
   session and polkit agent is the *right* shape for this job.
3. **Opinionated config editing** (suricata.yaml toggles, clamd.conf, rule sources, scheduled scans) with
   validation and single-prompt batched apply. Scirius does rules, but nothing lightweight does "my machine's
   suricata + clamav knobs."

So the strategic answer to "how do we make this actually useful" is (c) from the question: **stop competing
with the viewers; become the thin control+glance layer on top of them.** The dashboard tabs aren't the
product — they're the cost center. tkinter vs web was never the real question; *SIEM vs control-panel* is,
and control-panel wins on every axis the owner cares about.

One nuance: if, after using EveBox, a small "nice web view" itch remains, the target architecture below makes
it cheap — a ~200-line page served by the collector daemon on localhost showing counts + service status.
That's an optional skin over an API, not a migration.

---

## 5. Recommended target architecture & roadmap

### Target shape (3 small components + 1 shrunken app, replacing 1 monolith)

```
┌─────────────┐   status.json / unix socket   ┌──────────────────────┐
│    lssd      │ ─────────────────────────────▶ │ polybar/i3blocks     │
│  collector   │                                │ widget (IN REPO)     │
│  (headless)  │                                └──────────────────────┘
│ - tails eve.json (EVEFileReader — reused!)    ┌──────────────────────┐
│ - alert counts by severity/window             │ lss-panel (tkinter)  │
│ - systemd unit status (event-driven or poll)  │ - service control    │
│ - writes ~/.cache/lss/status.json atomically ▶│ - config editing     │
│ - optional: localhost HTTP for a web skin     │ - health strip       │
└─────────────┘                                 │ - glance overview    │
        │                                       │ - "Open in EveBox" → │
   polkit-scoped actions (lssctl / privilege_helper)  browser deep-link │
        ▼                                       └──────────────────────┘
  systemctl / suricata-update / clamd            EveBox owns alert browsing
```

- **`lssd`** — the one honest new build. Small headless Python process (systemd user service). It is the
  *only* reader of eve.json and the *only* caller of `systemctl is-active`. Emits an atomic
  `~/.cache/lss/status.json`: `{alerts_1h, alerts_24h, by_severity, last_event_ts, services:{...}, errors:[...]}`.
  Reuses `EVEFileReader` (fixed: surface PermissionError) — single-threaded, so the thread-safety problem
  evaporates by design.
- **Widget in-repo.** A ~30-line polybar/i3blocks script reading status.json becomes a first-class,
  versioned, documented artifact. The crown jewel finally lives in the crown.
- **`lssctl`** — CLI wrapping `privilege_helper` (start/stop/restart/rule-update/config-apply). The panel and
  the widget's click actions both call it; ship the optional polkit rules file so the bar widget can restart
  Suricata without a password prompt storm.
- **`lss-panel`** — the surviving GUI, target ≤2,500 lines: Overview (reads status.json — no parsing),
  IDS config, ClamAV config + quarantine, service control, health strip. tkinter stays; it's the right tool
  for a local control panel. **Deleted outright:** Analytics, Geo, historical alert queries, Traffic/DNS
  browsing, threat-intel browsing tabs → replaced by an "Open in EveBox" button. (Keep the auto-TI-enrichment
  *of the alert count tooltip* only if it's actually used; the TI clients are clean and can move to lssd.)

### Roadmap

**P0 — Stop the bleeding (days, in the current monolith):**
1. Fix the refresh loop: gather I/O in one worker (AsyncRunner), apply *all* widget updates on the main
   thread; add a reentrancy guard. This alone should kill most "flaky/doesn't populate" reports.
2. Surface eve.json permission failure (health strip or even a messagebox once) + `logging` setup.
3. Service-name resolution: auto-detect units at startup into settings.json; delete all inline
   `"suricata-laptop"` / `"clamav-daemon"` literals.

**P1 — Settle the dead code (1 session):** Decide per component: wire it in *now* or delete it. Recommended:
delete the 4 extracted tabs (they'll be rewritten smaller in P3 anyway), keep AsyncRunner (wire in P0), keep
services layer only if lssd will use it. Rewrite ARCHITECTURE.md to describe reality.

**P2 — Extract `lssd` + ship the widget (the strategic move):** Move EVEFileReader + status logic into the
daemon; commit the polybar script + polkit rules + systemd user unit. Install EveBox; add the deep-link.

**P3 — Shrink the panel:** Delete the SIEM tabs; port the survivors (config, service control, quarantine)
onto BaseTab for real this time — extraction *with* cutover, one tab per commit.

**P4 (optional):** localhost HTTP endpoint on lssd + a single static page, only if genuinely wanted.

### What success looks like
The bar always shows the truth. Clicking it opens a panel that starts in <1s, whose buttons always match
reality, and that says *why* when something can't work. Deep alert investigation is one click away in a tool
maintained by someone else. Total first-party surface: ~3–4k lines instead of 15.5k — small enough to keep
honest.
