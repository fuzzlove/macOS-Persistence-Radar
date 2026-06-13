from __future__ import annotations

from pathlib import Path

from persistence_radar.core.models import Finding, Severity
from persistence_radar.core.scoring import is_world_writable
from persistence_radar.scanners.common import display_path, root_join, user_home_paths

SHELL_FILES = (".zshrc", ".zprofile", ".zlogin", ".bashrc", ".bash_profile", ".profile")
COMMON_BINARIES = ("ssh", "curl", "sudo", "osascript", "python", "sh", "bash", "zsh")
STANDARD_DIRS = {"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/opt/homebrew/bin"}


def _path_lines(path: Path) -> list[str]:
    try:
        return [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if "PATH=" in line]
    except OSError:
        return []


def scan_path_hijack(root: str = "/") -> list[Finding]:
    files = [root_join(root, "/etc/zshrc"), root_join(root, "/etc/profile"), root_join(root, "/etc/bashrc")]
    for home in user_home_paths(root):
        files.extend(home / name for name in SHELL_FILES)
    findings = []
    for file in files:
        if not file.is_file():
            continue
        risky_lines = []
        for line in _path_lines(file):
            value = line.split("=", 1)[-1].strip('"').strip("'")
            dirs = [part for part in value.split(":") if part]
            for index, directory in enumerate(dirs):
                if (directory not in STANDARD_DIRS and index < 3 and (directory.startswith("/tmp") or directory.startswith("/Users") or directory == ".")) or is_world_writable(directory):
                    risky_lines.append(line)
                    break
        if risky_lines:
            findings.append(
                Finding(
                    id=f"path-hijack:{display_path(root, file)}",
                    title=f"Possible PATH hijack condition: {file.name}",
                    severity=Severity.HIGH,
                    category="PATH Hijack",
                    path=display_path(root, file),
                    command="\n".join(risky_lines),
                    explanation="Writable or unusual directories early in PATH can cause common commands to resolve to attacker-controlled executables.",
                    recommendation="Move trusted system directories before writable locations and inspect common binaries in non-standard paths.",
                    raw_evidence={"path_lines": risky_lines, "common_binaries": COMMON_BINARIES},
                )
            )
    return findings
