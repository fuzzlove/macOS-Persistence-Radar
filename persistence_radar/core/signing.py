from __future__ import annotations

from pathlib import Path
import shutil
import subprocess


def code_signature_status(path: str | Path) -> str:
    target = Path(path)
    if not target.exists():
        return "missing"
    codesign = shutil.which("codesign")
    if not codesign:
        return "unknown"
    result = subprocess.run(
        [codesign, "--verify", "--deep", "--strict", str(target)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode == 0:
        return "valid"
    output = f"{result.stdout} {result.stderr}".lower()
    if "code object is not signed" in output or "not signed" in output:
        return "unsigned"
    return "invalid"


def notarization_status(path: str | Path) -> str:
    target = Path(path)
    if not target.exists():
        return "missing"
    spctl = shutil.which("spctl")
    if not spctl:
        return "unknown"
    result = subprocess.run(
        [spctl, "--assess", "--type", "execute", "--verbose=4", str(target)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode == 0:
        output = f"{result.stdout} {result.stderr}".lower()
        return "accepted-notarized" if "notarized" in output else "accepted"
    return "rejected"
