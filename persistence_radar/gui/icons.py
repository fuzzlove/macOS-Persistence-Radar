from __future__ import annotations

from pathlib import Path
import sys

from PySide6.QtGui import QIcon


def resource_path(relative_path: str) -> Path:
    """Resolve assets both from source checkout and PyInstaller bundles."""
    bundle_root = getattr(sys, "_MEIPASS", None)
    if bundle_root:
        return Path(bundle_root) / "persistence_radar" / relative_path
    return Path(__file__).resolve().parents[1] / relative_path


def app_icon() -> QIcon:
    return QIcon(str(resource_path("assets/icons/macos-persistence-radar-icon.png")))
