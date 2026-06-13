from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import logging
import os
import platform
import pwd
import sys
import time

from persistence_radar import __version__
from persistence_radar.core.database import DEFAULT_DB_PATH
from persistence_radar.core.app_logging import get_log_dir
from persistence_radar.core.models import Finding, PersistenceChain, PersistenceItem
from persistence_radar.core.timeline import enrich_file_times
from persistence_radar.core.trust import apply_trust
from persistence_radar.core.malware_kb import apply_malware_correlation
from persistence_radar.core.posture import calculate_posture
from persistence_radar.core.timeline import events_for_inventory

LOGGER = logging.getLogger("persistence_radar.scan")


@dataclass(slots=True)
class ScanResult:
    inventory_items: list[Finding] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    scanner_counts: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    active_filters: dict[str, str | bool] = field(default_factory=dict)
    skipped_paths: list[str] = field(default_factory=list)
    coverage: dict[str, dict[str, str]] = field(default_factory=dict)
    chains: list[PersistenceChain] = field(default_factory=list)
    timeline_events: list = field(default_factory=list)
    posture: dict = field(default_factory=dict)
    scan_metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "inventory_items": [item.to_dict() for item in self.inventory_items],
            "findings": [item.to_dict() for item in self.findings],
            "persistence_items": [PersistenceItem.from_finding(item).to_dict() for item in self.inventory_items],
            "scanner_counts": self.scanner_counts,
            "warnings": self.warnings,
            "errors": self.errors,
            "active_filters": self.active_filters,
            "skipped_paths": self.skipped_paths,
            "coverage": self.coverage,
            "chains": [chain.to_dict() for chain in self.chains],
            "timeline_events": [event.to_dict() for event in self.timeline_events],
            "posture": self.posture,
            "scan_metadata": self.scan_metadata,
        }


def split_findings(items: list[Finding]) -> list[Finding]:
    return [item for item in items if str(item.severity) != "INFO"]


def launchd_counts(items: list[Finding]) -> dict[str, int]:
    return {
        "LaunchAgents found": sum(1 for item in items if item.category == "LaunchAgent"),
        "LaunchDaemons found": sum(1 for item in items if item.category == "LaunchDaemon"),
    }


def default_scanner_counts(items: list[Finding]) -> dict[str, int]:
    counts = launchd_counts(items)
    counts.update(
        {
            "Login Items found": sum(1 for item in items if item.category == "Login Items"),
            "Shell startup files found": sum(1 for item in items if item.category == "Shell Startup"),
            "Cron entries found": sum(1 for item in items if item.category == "Cron/At"),
            "Browser extensions found": sum(1 for item in items if item.category == "Browser Extension"),
            "Profiles found": sum(1 for item in items if item.category == "Configuration Profile"),
            "Privileged helpers found": sum(1 for item in items if item.category == "Privileged Helper"),
            "Background tasks found": sum(1 for item in items if item.category == "Background Task"),
            "Native messaging hosts found": sum(1 for item in items if item.category == "Native Messaging Host"),
            "Authorization plugins found": sum(1 for item in items if item.category == "Authorization Plugin"),
            "System extensions found": sum(1 for item in items if item.category == "System Extension"),
            "Certificate trust stores found": sum(1 for item in items if item.category == "Certificate Trust"),
            "launchctl runtime items found": sum(1 for item in items if item.category == "launchctl Runtime"),
            "PATH hijack indicators found": sum(1 for item in items if item.category == "PATH Hijack"),
            "Application support artifacts found": sum(1 for item in items if item.category == "Application Support Hunt"),
            "Re-opened application items found": sum(1 for item in items if item.category == "Re-opened Applications"),
            "TCC indicators found": sum(1 for item in items if item.category == "TCC"),
            "User/group sources found": sum(1 for item in items if item.category == "Users and Groups"),
        }
    )
    return counts


def coverage_catalog() -> dict[str, dict[str, str]]:
    return {
        "launchd": {"name": "LaunchAgents/Daemons", "mitre": "T1543.001/T1543.004"},
        "launchctl": {"name": "launchctl Runtime", "mitre": "T1543.001/T1543.004"},
        "background_tasks": {"name": "Background Task Management / SMAppService", "mitre": "T1547.015"},
        "login_items": {"name": "Login Items / Re-opened Applications", "mitre": "T1547.015/T1547.007"},
        "cron": {"name": "Cron, at, periodic, Library Scripts", "mitre": "T1059"},
        "shell_startup": {"name": "Shell Startup", "mitre": "T1037/T1059"},
        "path_hijack": {"name": "PATH and Executable Hijack", "mitre": "T1574"},
        "browser_extensions": {"name": "Browser Extensions", "mitre": "Persistence via browser extension"},
        "native_messaging": {"name": "Browser Native Messaging Hosts", "mitre": "T1554"},
        "profiles": {"name": "Configuration Profiles / MDM", "mitre": "T1562"},
        "certificates": {"name": "Certificate Trust", "mitre": "Traffic interception risk"},
        "system_extensions": {"name": "System / Network Extensions", "mitre": "T1562"},
        "authorization_plugins": {"name": "Authorization Plugins", "mitre": "T1556"},
        "privileged_helpers": {"name": "Privileged Helpers", "mitre": "T1543.004/T1554"},
        "application_support": {"name": "Application Support Hunt", "mitre": "Multiple"},
        "users_groups": {"name": "Users and Groups", "mitre": "Account persistence"},
        "tcc": {"name": "TCC Privacy Grants", "mitre": "T1562"},
    }


def _selected_scanners(module: str | None = None):
    from persistence_radar.scanners import SCANNER_MODULES, SCANNERS

    if module:
        if module not in SCANNER_MODULES:
            raise ValueError(f"unknown scanner module: {module}")
        return [(module, SCANNER_MODULES[module])]
    return SCANNERS


def build_chains(items: list[Finding]) -> list[PersistenceChain]:
    chains: list[PersistenceChain] = []
    by_exec: dict[str, list[Finding]] = {}
    for item in items:
        if item.executable_path:
            by_exec.setdefault(item.executable_path, []).append(item)
    for executable, linked in by_exec.items():
        if len(linked) < 2:
            continue
        severity_score = sum({"INFO": 0, "LOW": 10, "MEDIUM": 25, "HIGH": 50, "CRITICAL": 80}.get(str(item.severity), 0) for item in linked)
        chains.append(
            PersistenceChain(
                chain_id=f"exec-chain:{executable}",
                title=f"Shared executable chain: {executable}",
                item_ids=[item.id for item in linked],
                relationship=" -> ".join(item.category for item in linked),
                mitre_technique_id=", ".join(sorted({item.mitre_technique_id for item in linked if item.mitre_technique_id})),
                risk_score=severity_score,
                risk_factors=["multiple persistence mechanisms reference the same executable"],
            )
        )
    helpers = [item for item in items if item.category == "Privileged Helper"]
    launchd = [item for item in items if item.category in {"LaunchDaemon", "LaunchAgent"}]
    native = [item for item in items if item.category == "Native Messaging Host"]
    suspicious_paths = [item for item in items if item.category == "Application Support Hunt"]
    if launchd and helpers:
        chains.append(PersistenceChain("launchd-helper-chain", "Launchd to privileged helper relationship", [*(item.id for item in launchd[:5]), *(item.id for item in helpers[:5])], "LaunchDaemon -> PrivilegedHelperTool", "T1543.004", 50, ["privileged helper launch relationship"]))
    if native and suspicious_paths:
        chains.append(PersistenceChain("native-suspicious-exec-chain", "Native messaging to suspicious executable path", [*(item.id for item in native[:5]), *(item.id for item in suspicious_paths[:5])], "Browser Extension -> NativeMessagingHost -> Local Executable", "T1554", 65, ["browser native messaging can bridge to local executables"]))
    return chains


def run_scan(root: str = "/", debug: bool = False, module: str | None = None) -> ScanResult:
    from persistence_radar.scanners.launchd import scan_launchd

    if debug:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")
    started = time.time()
    inventory: list[Finding] = []
    warnings: list[str] = []
    errors: list[str] = []
    for name, scanner in _selected_scanners(module):
        LOGGER.debug("starting scanner: %s", name)
        before = len(inventory)
        try:
            if scanner is scan_launchd:
                items = scanner(root=root, warnings=warnings, debug=debug)
            else:
                items = scanner(root=root)
            inventory.extend(items)
            LOGGER.debug("scanner %s returned %d item(s)", name, len(items))
        except PermissionError as exc:
            warning = f"{name}: Permission denied: {exc}"
            LOGGER.warning(warning)
            warnings.append(warning)
        except Exception as exc:  # Scanner boundary: preserve partial inventory and report failure.
            error = f"{name}: {type(exc).__name__}: {exc}"
            LOGGER.exception("scanner failed: %s", name)
            errors.append(error)
        finally:
            LOGGER.debug("scanner %s cumulative delta=%d", name, len(inventory) - before)
    enrich_file_times(inventory)
    apply_malware_correlation(inventory)
    counts = default_scanner_counts(inventory)
    apply_trust(inventory)
    return ScanResult(
        inventory_items=inventory,
        findings=split_findings(inventory),
        scanner_counts=counts,
        warnings=warnings,
        errors=errors,
        active_filters={
            "severity": "All",
            "category": "All",
            "mitre": "All",
            "show_info": True,
        },
        skipped_paths=[],
        coverage=coverage_catalog(),
        chains=build_chains(inventory),
        timeline_events=events_for_inventory(inventory),
        posture=calculate_posture(inventory),
        scan_metadata={
            "started_at": datetime_now_iso(),
            "duration_seconds": round(time.time() - started, 2),
            "status": "completed_with_errors" if errors else "completed_with_warnings" if warnings else "completed",
            "module": module or "all",
        },
    )


def datetime_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def scanner_paths(root: str = "/") -> list[Path]:
    root_path = Path(root)
    paths = [
        Path.home() / "Library" / "LaunchAgents" if root == "/" else root_path / "Users",
        root_path / "Library" / "LaunchAgents" if root != "/" else Path("/Library/LaunchAgents"),
        root_path / "Library" / "LaunchDaemons" if root != "/" else Path("/Library/LaunchDaemons"),
        root_path / "System" / "Library" / "LaunchAgents" if root != "/" else Path("/System/Library/LaunchAgents"),
        root_path / "System" / "Library" / "LaunchDaemons" if root != "/" else Path("/System/Library/LaunchDaemons"),
        root_path / "Library" / "PrivilegedHelperTools" if root != "/" else Path("/Library/PrivilegedHelperTools"),
        root_path / "Library" / "Managed Preferences" if root != "/" else Path("/Library/Managed Preferences"),
    ]
    return paths


def doctor(root: str = "/") -> dict:
    paths = scanner_paths(root)
    readable = [str(path) for path in paths if path.exists() and os.access(path, os.R_OK)]
    unreadable = [str(path) for path in paths if path.exists() and not os.access(path, os.R_OK)]
    plist_count = 0
    for path in paths:
        if path.is_dir() and os.access(path, os.R_OK):
            try:
                plist_count += len(list(path.glob("*.plist")))
            except OSError:
                pass
    try:
        user = pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        user = str(os.getuid())
    return {
        "macos_version": platform.platform(),
        "python_version": sys.version.split()[0],
        "app_version": __version__,
        "current_user": user,
        "app_path": str(Path(sys.argv[0]).resolve()) if sys.argv else "",
        "readable_scanner_paths": readable,
        "unreadable_scanner_paths": unreadable,
        "plist_files_found": plist_count,
        "database_path": str(DEFAULT_DB_PATH),
        "log_path": str(get_log_dir()),
        "full_disk_access_likely": "yes" if not unreadable else "unknown",
        "scanner_modules_enabled": len(coverage_catalog()),
        "last_scan_status": "unknown",
        "settings_file_path": str(Path.home() / ".config" / "macos-persistence-radar" / "settings.json"),
        "active_filters": {"severity": "All", "category": "All", "mitre": "All", "show_info": True},
    }
