from __future__ import annotations

from pathlib import Path
import os
import stat
import time
from itertools import islice

from persistence_radar.core.models import Finding, Severity
from persistence_radar.core.scoring import command_has_suspicious_token
from persistence_radar.scanners.common import display_path, root_join, stat_metadata, user_home_paths

SCRIPT_SUFFIXES = {".sh", ".bash", ".zsh", ".py", ".pl", ".rb", ".command"}


def _candidate_roots(root: str) -> list[Path]:
    bases = [root_join(root, "/Users/Shared"), root_join(root, "/private/tmp"), root_join(root, "/var/tmp")]
    for home in user_home_paths(root):
        bases.extend(
            [
                home / "Library" / "Application Support",
                home / "Library" / "Containers",
                home / "Library" / "Group Containers",
                home / "Library" / "Preferences",
            ]
        )
    return bases


def scan_application_support(root: str = "/") -> list[Finding]:
    findings = []
    now = time.time()
    for base in _candidate_roots(root):
        if not base.is_dir():
            continue
        for item in islice(base.rglob("*"), 1500):
            if not item.is_file():
                continue
            try:
                mode = item.stat().st_mode
                recent = now - item.stat().st_mtime < 7 * 24 * 3600
            except OSError:
                continue
            hidden = any(part.startswith(".") for part in item.parts)
            executable = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
            suspicious_script = False
            if item.suffix in SCRIPT_SUFFIXES:
                try:
                    suspicious_script = command_has_suspicious_token(item.read_text(encoding="utf-8", errors="replace")[:20000])
                except OSError:
                    suspicious_script = False
            if not (hidden and executable or recent and executable or suspicious_script):
                continue
            owner, permissions = stat_metadata(item)
            findings.append(
                Finding(
                    id=f"app-support-hunt:{display_path(root, item)}",
                    title=f"Suspicious support artifact: {item.name}",
                    severity=Severity.MEDIUM if suspicious_script or hidden else Severity.LOW,
                    category="Application Support Hunt",
                    path=display_path(root, item),
                    executable_path=display_path(root, item) if executable else "",
                    owner=owner,
                    permissions=permissions,
                    explanation="This bounded hunt found an executable or script in common support/shared/temp locations with suspicious indicators. It is only flagged when indicators exist.",
                    recommendation="Correlate this artifact with launchd, login item, browser native messaging, or helper references before taking action.",
                    raw_evidence={"hidden_path": hidden, "executable": executable, "recently_modified": recent, "suspicious_script": suspicious_script},
                )
            )
    return findings
