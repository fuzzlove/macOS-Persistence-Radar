# Changelog

## 0.1.0 - Initial Public Release

- Initial release of macOS Persistence Radar, a read-only defensive macOS persistence inventory and audit tool.
- Scanner coverage includes launchd, login/background items, shell startup files, cron/periodic jobs, browser extensions, native messaging hosts, configuration profiles, privileged helpers, authorization plugins, certificate trust, system extensions, TCC indicators, user/group sources, and bounded support-artifact hunting.
- Known limitations: some paths require Full Disk Access, command output varies across macOS versions, reputation and malware artifact matching are correlation aids only, and baseline quality depends on when the baseline was captured.

- Added packaged application icon assets and PyInstaller `.icns` bundle configuration.
- Added Trust and Reputation Engine with 0-100 scores, confidence, classification, positive indicators, negative indicators, GUI reputation columns, and Trust Breakdown detail panel.
- Added Persistence Timeline with first seen, last seen, created/modified time, new/removed/modified/signature/hash events, GUI filters, and timeline export.
- Added advanced sortable columns for Findings, Inventory, Timeline, and Chain View with security-order severity sorting, header indicators, Shift-click multi-column sorting, and quick sort buttons.
- Added Security Posture Score and heat map dashboard.
- Added Malware Artifact Library for artifact-only correlation across supported macOS malware families.
- Added a scan result model with `inventory_items`, `findings`, `scanner_counts`, `warnings`, and `errors`.
- Added scanner debug logging, `persistence-radar scan --debug`, and `persistence-radar doctor`.
- Added `persistence-radar scan --all`, `scan --module`, `coverage`, and `chains`.
- Added advanced scanners for Background Task Management/SMAppService, launchctl runtime state, authorization plugins, native messaging hosts, certificate trust, system extensions, PATH hijack conditions, and bounded Application Support hunting.
- Expanded browser extension, shell startup, cron/periodic, profile, and privileged-helper coverage.
- Added Coverage, Chain View, and Scanner Diagnostics GUI pages.
- Added a separate Inventory GUI page for all discovered persistence items.
- Findings now exclude normal `INFO` inventory by default.
- Added per-scanner counts and GUI diagnostics for warnings, errors, active filters, and zero-result scans.
- Improved launchd scanning for exact standard paths, parse-error inventory items, expanded evidence fields, and faster protected-system handling.
- Added a dark-mode-first PySide6 interface with dashboard, findings, baselines, watch mode, reports, settings, and about screens.
- Added reusable GUI components for severity badges, stat cards, filter bars, detail panels, and empty states.
- Added threaded GUI scanning so long scans do not freeze the application.
- Added scanner error handling in the GUI so individual scanner failures are shown as warnings and other scanners continue.
- Improved HTML, Markdown, and JSON reports with executive summary, severity counts, MITRE coverage, top risks, remediation checklist, metadata, and finding appendix.
- Added baseline comparison UI actions and “new persistence item” labeling.
- Added sample findings fixture for report and product demos.
- Preserved read-only scanner behavior and CLI commands.
