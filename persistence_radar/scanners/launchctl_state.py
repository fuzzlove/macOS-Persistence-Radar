from __future__ import annotations

from pathlib import Path
import os
import re
import subprocess

from persistence_radar.core.mitre import technique
from persistence_radar.core.models import Finding, Severity
from persistence_radar.core.scoring import APPLE_LABEL_RE, path_is_suspicious


LABEL_RE = re.compile(r"\b(label|service)\s*=\s*([A-Za-z0-9_.-]+)|\b([A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+)\b")
PATH_RE = re.compile(r"(/[^\s;]+\.plist)")


def _run(args: list[str]) -> tuple[str, str]:
    result = subprocess.run(args, capture_output=True, text=True, timeout=10, check=False)
    return result.stdout, result.stderr


def _known_plists(root: str) -> dict[str, str]:
    labels = {}
    for base in (
        Path.home() / "Library/LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
        Path("/System/Library/LaunchAgents"),
        Path("/System/Library/LaunchDaemons"),
    ):
        if root != "/" and base.is_absolute():
            base = Path(root) / str(base).lstrip("/")
        if base.is_dir():
            for plist in base.glob("*.plist"):
                labels[plist.stem] = str(plist)
    return labels


def scan_launchctl_state(root: str = "/") -> list[Finding]:
    if root != "/":
        return []
    uid = os.getuid()
    commands = [
        ["launchctl", "print", f"gui/{uid}"],
        ["launchctl", "print", "system"],
        ["launchctl", "print-disabled", f"gui/{uid}"],
        ["launchctl", "print-disabled", "system"],
    ]
    known = _known_plists(root)
    mitre_agent = technique("launch_agent")
    findings = []
    for command in commands:
        try:
            stdout, stderr = _run(command)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"{' '.join(command)} failed: {exc}") from exc
        text = stdout + "\n" + stderr
        labels = {match.group(2) or match.group(3) for match in LABEL_RE.finditer(text)}
        paths = {match.group(1) for match in PATH_RE.finditer(text)}
        for label in sorted(label for label in labels if label):
            disk_path = known.get(label, "")
            unusual = any(path_is_suspicious(path) for path in paths)
            mimics = bool(APPLE_LABEL_RE.match(label)) and disk_path and not disk_path.startswith("/System/")
            missing_plist = not disk_path and "." in label
            if not (missing_plist or unusual or mimics):
                continue
            severity = Severity.HIGH if missing_plist or mimics else Severity.MEDIUM
            findings.append(
                Finding(
                    id=f"launchctl:{' '.join(command)}:{label}",
                    title=f"launchctl runtime job: {label}",
                    severity=severity,
                    category="launchctl Runtime",
                    mitre_technique_id=mitre_agent[0],
                    mitre_technique_name=mitre_agent[1],
                    path=disk_path,
                    explanation="launchctl runtime state contains a loaded or disabled job with indicators that do not cleanly match standard on-disk launchd inventory.",
                    recommendation="Compare launchctl state with the plist path and validate whether the job should be loaded.",
                    raw_evidence={"command": command, "label": label, "known_plist": disk_path, "missing_plist": missing_plist, "paths_seen": sorted(paths)},
                )
            )
    return findings
