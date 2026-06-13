# macOS Persistence Radar

macOS Persistence Radar is a local-first defensive audit tool for inventorying, scoring, and explaining macOS persistence mechanisms. It is intended for blue-team, DFIR, and security-audit use.

The scanner is read-only by default. It does not delete, disable, modify, hide, or create persistence items. Watch mode is documented and user-started only.

## Install

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

PySide6 is required for the GUI. The CLI can still be useful in restricted environments.

## Usage

```bash
persistence-radar scan
persistence-radar scan --debug
persistence-radar scan --json
persistence-radar scan --all
persistence-radar scan --module launchd
persistence-radar scan --module browser_extensions
persistence-radar coverage
persistence-radar chains
persistence-radar posture
persistence-radar timeline --format html --output timeline.html
persistence-radar malware-kb
persistence-radar doctor
persistence-radar baseline create clean-install
persistence-radar baseline compare clean-install
persistence-radar watch --interval 30
persistence-radar export --format html --output report.html
persistence-radar export --format json --output report.json
persistence-radar export --format md --output report.md
python -m persistence_radar.main
```

## macOS App Icon and PyInstaller

The runtime PySide6 window icon is bundled at `persistence_radar/assets/icons/macos-persistence-radar-icon.png`.
The macOS app bundle icon for PyInstaller is `assets/icons/macos-persistence-radar-icon.icns`.

Regenerate the `.icns` after changing the PNG:

```bash
python3 scripts/generate_icns.py
```

Build the macOS app bundle with the included spec:

```bash
pyinstaller --clean --noconfirm macOS-Persistence-Radar.spec
```

The resulting `.app` uses the Radar icon instead of the default Python icon.

Snapshots are stored in SQLite at `~/.local/share/macos-persistence-radar/radar.sqlite3` unless `--db` is supplied.

## Supported Persistence Locations

- LaunchAgents: `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/System/Library/LaunchAgents`
- LaunchDaemons: `/Library/LaunchDaemons`, `/System/Library/LaunchDaemons`
- launchctl runtime state: `launchctl print`, `launchctl print-disabled`
- Background Task Management and SMAppService records
- Login Items and Background Item indicators
- Re-opened Applications/session restore indicators
- Cron jobs, at jobs, periodic scripts, and `/Library/Scripts`
- Shell startup files: `.zshrc`, `.bashrc`, `.bash_profile`, `.profile`, `/etc/zshrc`, `/etc/bashrc`
- Authorization plugins
- Browser extension profile paths for Safari, Chrome, Chromium, Edge, Brave, and Firefox
- Browser native messaging hosts
- Configuration profile stores: `/Library/Managed Preferences`, `/var/db/ConfigurationProfiles`
- Certificate trust stores
- System, Network, DNS, VPN, content filter, and Endpoint Security extension inventory where available
- Privileged helper tools: `/Library/PrivilegedHelperTools`
- PATH and executable hijack indicators
- Bounded support-directory hunt in Application Support, Containers, Group Containers, Preferences, shared, and temp paths
- Local user and group data sources
- TCC/privacy database indicators where readable

## MITRE ATT&CK Alignment

MITRE ATT&CK documents Launch Agents as `T1543.001` and Launch Daemons as `T1543.004`: macOS persistence mechanisms loaded by `launchd` from standard plist locations. macOS Persistence Radar applies those IDs to launchd findings and includes them in CLI, GUI, and exported reports.

Additional mappings used where relevant:

- `T1547.015` Login Items
- `T1059` Command and Scripting Interpreter
- `T1037` Boot or Logon Initialization Scripts
- `T1554` Compromise Host Software Binary
- `T1562` Impair Defenses

## Risk Scoring

Findings are scored as `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. Higher risk is assigned when evidence indicates:

- Launchd plists run from `/tmp`, `/var/tmp`, `/Users/Shared`, Downloads, hidden user directories, or world-writable paths
- Target executables are unsigned, invalidly signed, or missing
- `RunAtLoad` and `KeepAlive` are both enabled
- Labels mimic Apple or trusted vendor naming outside `/System`
- Commands invoke `curl`, `bash`, `sh`, `python`, `osascript`, `nc`, `ncat`, `perl`, `ruby`, `chmod`, `chflags`, `base64`, `openssl`, or remote URLs
- Root-owned items reference writable executables
- Items are new compared with a selected baseline

## GUI

Launch the GUI:

```bash
python -m persistence_radar.main
```

On first launch, the Welcome screen explains that macOS Persistence Radar is read-only by default, does not remove or modify system files, and does not install background persistence. Use **Start First Scan** to begin or **View Required Permissions** for Full Disk Access guidance.

## Full Disk Access

Full Disk Access improves visibility into protected user and system locations. Without it, some scanners may report warnings or partial coverage.

To grant access:

1. Open System Settings.
2. Go to Privacy & Security.
3. Open Full Disk Access.
4. Add `macOS Persistence Radar.app` or the terminal/Python interpreter used to run from source.
5. Restart the app and scan again.

The app remains read-only; this permission improves visibility only.

The interface is dark-mode-first and includes Dashboard, Inventory, Findings, Baselines, Watch Mode, Reports, Settings, and About. Scans run in a worker thread so the interface remains responsive. Scanner permission errors are shown as warnings and do not stop the rest of the scan.

Screenshot placeholders:

- `docs/screenshots/dashboard.png`
- `docs/screenshots/findings.png`
- `docs/screenshots/detail-pane.png`
- `docs/screenshots/baselines.png`
- `docs/screenshots/reports.png`

The Dashboard shows total persistence items, total findings, per-scanner counts, scanner warnings/errors, active filters, critical/high findings, unsigned executables, suspicious commands, world-writable references, MITRE techniques observed, and last scan time. The Inventory view shows all discovered persistence items, including normal `INFO` items. The Findings view shows risky/suspicious items by default and includes search, severity/category/MITRE filters, an “only new since baseline” toggle, a “Show INFO / normal items” toggle, reset filters, severity badges, and a right-side evidence detail pane.

Coverage, Chain View, and Scanner Diagnostics pages show which persistence methods are scanned, relationships between mechanisms and executables, and per-module counts/warnings/errors.

The Trust and Reputation Engine adds a 0-100 reputation score, confidence level, and `Legitimate` / `Unknown` / `Suspicious` classification for every item. It explains positive and negative indicators such as Apple signing, notarization, Team ID, known vendor patterns, baseline history, path risk, writable paths, hidden locations, signature validity, app presence, and bundle identifier consistency. Reputation is advisory only and never automatically whitelists or suppresses an item.

The Timeline page shows observed, new, removed, modified, signature-change, and hash-change events. It supports filtering by date, severity, and persistence mechanism, plus JSON/HTML/Markdown export. The Dashboard includes a Security Posture Score and heat map by mechanism/severity. The Malware Library is artifact correlation only and does not execute malware or inspect memory.

Inventory, Findings, Timeline, and Chain View support DFIR-style sortable columns. Severity uses security ordering (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) rather than alphabetical ordering. Click a header to sort ascending, click again for descending, and click a third time to return to the default sort. Shift-click adds secondary sort keys while preserving filters.

If a scan discovers zero inventory items, the Dashboard diagnostics explain likely causes such as unreadable paths, scanner errors, an unusual scan root, or active filters.

## Reports

Reports can be exported to HTML, JSON, and Markdown. HTML is intended to be client-ready and includes an executive summary, severity counts, top risks, MITRE ATT&CK coverage, remediation checklist, timestamp, hostname, macOS version, scanner version, and finding appendix. Markdown is GitHub-friendly. JSON remains machine-readable and includes metadata, summary, and findings.

## Safety and Remediation

No destructive action is performed automatically. Remediation guidance is limited to recommendations and suggested investigation paths. Any future destructive operation must require an explicit `--apply` style opt-in and clear warnings before execution.

Safe release defaults:

- Read-only mode by default
- No automatic remediation
- No deletion buttons
- No auto-start LaunchAgent
- No background persistence installed by the app
- Suggested commands are displayed for verification only and are not executed

## Diagnostics

Run:

```bash
persistence-radar doctor
```

Doctor prints app version, Python version, macOS version, current user, app path, database path, log path, Full Disk Access likelihood, readable/unreadable scanner paths, enabled scanner module count, and last scan status. GUI errors and unhandled exceptions are logged under:

```text
~/Library/Logs/macOSPersistenceRadar/
```

Use the Settings page **Open Logs Folder** button to inspect logs.

## Threat Model

This tool helps defenders identify persistence mechanisms that are suspicious, newly introduced, poorly owned, unsigned, writable, or inconsistent with a known-good baseline. It is not a malware scanner, EDR replacement, or proof that a system is clean. Attackers with root privileges may tamper with files, logs, signatures, databases, and scanner visibility.

## Limitations

- Some macOS data sources require Full Disk Access or root to inspect completely.
- Background Items and TCC records vary by macOS version and permission state.
- Code signing and notarization checks depend on local macOS tools such as `codesign` and `spctl`.
- Browser extension metadata parsing is intentionally conservative in this version.
- Baseline comparisons are only as trustworthy as the selected baseline.

## Tests

```bash
python3 -m pytest -q
```

Acceptance coverage includes sample LaunchAgent detection, suspicious `curl` and `bash` ProgramArguments, graceful signing status, baseline added/removed/modified diffs, JSON and HTML export, and GUI import without root.

## Legal and Ethical Use

Use macOS Persistence Radar only on systems you own or are authorized to assess. It is built for defensive security operations, incident response, and audit workflows.
