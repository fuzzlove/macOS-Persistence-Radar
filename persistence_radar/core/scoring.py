from __future__ import annotations

from pathlib import Path
import os
import re
import stat

from persistence_radar.core.models import Severity

SUSPICIOUS_DIRS = (
    "/tmp",
    "/private/tmp",
    "/var/tmp",
    "/Users/Shared",
    "/Downloads",
)
SUSPICIOUS_INTERPRETERS = {
    "curl",
    "bash",
    "sh",
    "python",
    "python3",
    "osascript",
    "nc",
    "ncat",
    "perl",
    "ruby",
    "chmod",
    "chflags",
    "base64",
    "openssl",
}
REMOTE_URL_RE = re.compile(r"https?://|ftp://", re.IGNORECASE)
APPLE_LABEL_RE = re.compile(r"^(com\.apple\.|com\.microsoft\.autoupdate\.|com\.google\.)")
PROTECTED_SYSTEM_PREFIXES = ("/System/", "/usr/bin/", "/bin/", "/sbin/", "/usr/sbin/")


def is_world_writable(path: str | Path) -> bool:
    try:
        mode = Path(path).stat().st_mode
    except OSError:
        return False
    return bool(mode & stat.S_IWOTH)


def path_is_suspicious(path: str) -> bool:
    if not path:
        return False
    expanded = os.path.expanduser(path)
    parts = Path(expanded).parts
    return (
        any(expanded.startswith(prefix) for prefix in SUSPICIOUS_DIRS)
        or "/Downloads/" in expanded
        or any(part.startswith(".") for part in parts[2:])
    )


def command_has_suspicious_token(command: str) -> bool:
    tokens = {Path(piece).name.lower() for piece in command.replace(",", " ").split()}
    return bool(tokens & SUSPICIOUS_INTERPRETERS) or bool(REMOTE_URL_RE.search(command))


def is_protected_system_path(path: str) -> bool:
    return bool(path) and path.startswith(PROTECTED_SYSTEM_PREFIXES)


def score_finding(evidence: dict, is_new: bool = False) -> tuple[Severity, list[str]]:
    score = 0
    reasons: list[str] = []
    executable = evidence.get("executable_path", "")
    command = evidence.get("command", "")
    label = evidence.get("label", "")
    plist_path = evidence.get("path", "")

    if path_is_suspicious(executable) or path_is_suspicious(command):
        score += 35
        reasons.append("runs from or references a commonly abused writable/user-controlled path")
    if evidence.get("code_signature_status") in {"unsigned", "invalid"} and not is_protected_system_path(executable):
        score += 25
        reasons.append("target executable is unsigned or has an invalid signature")
    if evidence.get("run_at_load") and evidence.get("keep_alive"):
        score += 20
        reasons.append("RunAtLoad and KeepAlive are both enabled")
    if label and APPLE_LABEL_RE.match(label) and not plist_path.startswith("/System/"):
        score += 20
        reasons.append("label mimics trusted vendor or system naming outside a system path")
    if command_has_suspicious_token(command):
        score += 25
        reasons.append("command invokes a scripting/downloader utility or remote URL")
    if executable and not Path(os.path.expanduser(executable)).exists():
        score += 20
        reasons.append("target executable is missing while the persistence definition remains")
    if evidence.get("root_owned") and evidence.get("executable_writable"):
        score += 30
        reasons.append("root-owned item references a writable executable")
    if is_new:
        score += 15
        reasons.append("item is new compared with the selected baseline")

    if score >= 75:
        return Severity.CRITICAL, reasons
    if score >= 45:
        return Severity.HIGH, reasons
    if score >= 20:
        return Severity.MEDIUM, reasons
    if score > 0:
        return Severity.LOW, reasons
    return Severity.INFO, reasons
