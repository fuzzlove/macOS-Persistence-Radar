from __future__ import annotations

from pathlib import Path
import hashlib
import logging
import plistlib
import shlex
from xml.parsers.expat import ExpatError

from persistence_radar.core.hashing import sha256_file
from persistence_radar.core.mitre import technique
from persistence_radar.core.models import Finding, Severity
from persistence_radar.core.scoring import command_has_suspicious_token, is_protected_system_path, is_world_writable, path_is_suspicious, score_finding
from persistence_radar.core.signing import code_signature_status, notarization_status
from persistence_radar.scanners.common import is_root_owned, is_writable, root_join, stat_metadata, user_home_paths

LOGGER = logging.getLogger("persistence_radar.scanners.launchd")


def _display_path(root: str | Path, path: Path) -> str:
    if str(root) == "/":
        return str(path)
    try:
        return "/" + str(path.relative_to(root)).lstrip("/")
    except ValueError:
        return str(path)


def _expand_executable(path: str, plist_path: Path) -> str:
    if not path:
        return ""
    if path.startswith("~/"):
        return str(Path.home() / path[2:])
    target = Path(path)
    if target.is_absolute():
        return str(target)
    return str((plist_path.parent / target).resolve())


def _command_from_plist(data: dict, plist_path: Path) -> tuple[str, str]:
    program = data.get("Program")
    args = data.get("ProgramArguments")
    if isinstance(args, list) and args:
        command = " ".join(shlex.quote(str(arg)) for arg in args)
        executable = _expand_executable(str(args[0]), plist_path)
        return command, executable
    if isinstance(program, str):
        return program, _expand_executable(program, plist_path)
    return "", ""


def _launchd_fields(data: dict) -> dict:
    keys = (
        "Label",
        "Program",
        "ProgramArguments",
        "RunAtLoad",
        "KeepAlive",
        "StartInterval",
        "StartCalendarInterval",
        "StandardOutPath",
        "StandardErrorPath",
        "WorkingDirectory",
    )
    return {key: data.get(key) for key in keys if key in data}


def _finding_id(category: str, display_path: str, label: str) -> str:
    raw = f"{category}:{display_path}:{label}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def _build_launchd_finding(plist_path: Path, display_path: str, category: str, user_context: str) -> Finding | None:
    try:
        with plist_path.open("rb") as handle:
            data = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException, ValueError, ExpatError) as exc:
        mitre_id, mitre_name = technique("launch_agent" if category == "LaunchAgent" else "launch_daemon")
        owner, permissions = stat_metadata(plist_path)
        return Finding(
            id=_finding_id(category, display_path, "unreadable"),
            title=f"Unreadable {category} plist",
            severity=Severity.MEDIUM,
            category=category,
            mitre_technique_id=mitre_id,
            mitre_technique_name=mitre_name,
            path=display_path,
            user_context=user_context,
            owner=owner,
            permissions=permissions,
            explanation=f"The {category} file could not be parsed as a plist: {exc}.",
            recommendation="Inspect this file manually and verify whether launchd can load it.",
            raw_evidence={"parse_error": str(exc)},
        )
    if not isinstance(data, dict):
        return None

    label = str(data.get("Label", plist_path.stem))
    command, executable = _command_from_plist(data, plist_path)
    owner, permissions = stat_metadata(plist_path)
    executable_on_disk = Path(executable) if executable else Path()
    protected_executable = is_protected_system_path(executable)
    suspicious_reference = path_is_suspicious(executable) or command_has_suspicious_token(command)
    if protected_executable:
        signature = "system-protected"
    elif executable and suspicious_reference:
        signature = code_signature_status(executable_on_disk)
    elif executable:
        signature = "not-checked"
    else:
        signature = "unknown"
    evidence = {
        "path": display_path,
        "label": label,
        "command": command,
        "executable_path": executable,
        "run_at_load": bool(data.get("RunAtLoad")),
        "keep_alive": bool(data.get("KeepAlive")),
        "code_signature_status": signature,
        "root_owned": is_root_owned(plist_path),
        "executable_writable": is_writable(executable_on_disk) if executable else False,
    }
    severity, reasons = score_finding(evidence)
    mitre_id, mitre_name = technique("launch_agent" if category == "LaunchAgent" else "launch_daemon")
    mechanism = "Launch Agents" if category == "LaunchAgent" else "Launch Daemons"
    explanation_parts = [
        f"{mechanism} are macOS persistence mechanisms loaded by launchd from standard plist locations.",
        f"This item defines label '{label}'.",
    ]
    if reasons:
        explanation_parts.append("Risk factors: " + "; ".join(reasons) + ".")
    elif data.get("RunAtLoad"):
        explanation_parts.append("It is configured to run when launchd loads the plist.")
    return Finding(
        id=_finding_id(category, display_path, label),
        title=f"{category}: {label}",
        severity=severity,
        category=category,
        mitre_technique_id=mitre_id,
        mitre_technique_name=mitre_name,
        path=display_path,
        executable_path=executable,
        command=command,
        user_context=user_context,
        owner=owner,
        permissions=permissions,
        sha256=sha256_file(executable),
        code_signature_status=signature,
        notarization_status="not-checked" if executable else "unknown",
        explanation=" ".join(explanation_parts),
        recommendation="Validate the plist owner, command, signature, and business purpose before considering removal.",
        raw_evidence={
            "plist": data,
            "launchd_fields": _launchd_fields(data),
            "world_writable_plist": is_world_writable(plist_path),
            **evidence,
        },
    )


def _home_launch_agent_dirs(root: str | Path) -> list[Path]:
    if str(root) == "/":
        dirs = [Path.home() / "Library" / "LaunchAgents"]
    else:
        dirs = []
    for user_home in user_home_paths(root):
        dirs.append(user_home / "Library" / "LaunchAgents")
    unique = []
    seen = set()
    for directory in dirs:
        if directory not in seen:
            seen.add(directory)
            unique.append(directory)
    return unique


def _scan_directory(
    base: Path,
    root: str | Path,
    category: str,
    user_context: str,
    findings: list[Finding],
    warnings: list[str],
) -> None:
    LOGGER.debug("launchd scanning directory: %s", base)
    if not base.exists():
        LOGGER.debug("launchd directory missing: %s", base)
        return
    if not base.is_dir():
        warnings.append(f"Launchd path is not a directory: {base}")
        return
    try:
        plist_paths = sorted(base.glob("*.plist"))
    except PermissionError as exc:
        warnings.append(f"Permission denied reading launchd directory {base}: {exc}")
        return
    except OSError as exc:
        warnings.append(f"Unable to read launchd directory {base}: {exc}")
        return
    LOGGER.debug("launchd directory %s plist_count=%d", base, len(plist_paths))
    for plist_path in plist_paths:
        finding = _build_launchd_finding(plist_path, _display_path(root, plist_path), category, user_context)
        if finding:
            findings.append(finding)


def scan_launchd(root: str = "/", warnings: list[str] | None = None, debug: bool = False) -> list[Finding]:
    if debug:
        LOGGER.setLevel(logging.DEBUG)
    warnings = warnings if warnings is not None else []
    findings: list[Finding] = []

    for base in _home_launch_agent_dirs(root):
        _scan_directory(base, root, "LaunchAgent", base.parent.parent.name, findings, warnings)
    for directory in ("/Library/LaunchAgents", "/System/Library/LaunchAgents"):
        _scan_directory(root_join(root, directory), root, "LaunchAgent", "system", findings, warnings)
    for directory in ("/Library/LaunchDaemons", "/System/Library/LaunchDaemons"):
        _scan_directory(root_join(root, directory), root, "LaunchDaemon", "root", findings, warnings)
    return findings
