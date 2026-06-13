from __future__ import annotations

from pathlib import Path
import hashlib


def sha256_file(path: str | Path) -> str:
    target = Path(path)
    if not target.is_file():
        return ""
    digest = hashlib.sha256()
    try:
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()
