# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

ROOT = Path.cwd()
ICON = ROOT / "assets" / "icons" / "macos-persistence-radar-icon.icns"
PNG_ICON = ROOT / "persistence_radar" / "assets" / "icons" / "macos-persistence-radar-icon.png"
ICNS_ICON = ROOT / "persistence_radar" / "assets" / "icons" / "macos-persistence-radar-icon.icns"

a = Analysis(
    ["persistence_radar/main.py"],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[
        (str(PNG_ICON), "persistence_radar/assets/icons"),
        (str(ICNS_ICON), "persistence_radar/assets/icons"),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="macOS Persistence Radar",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ICON),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="macOS Persistence Radar",
)

app = BUNDLE(
    coll,
    name="macOS Persistence Radar.app",
    icon=str(ICON),
    bundle_identifier="com.liquidskysecurity.macos-persistence-radar",
    info_plist={
        "CFBundleName": "macOS Persistence Radar",
        "CFBundleDisplayName": "macOS Persistence Radar",
        "CFBundleShortVersionString": "0.1.0",
        "CFBundleVersion": "0.1.0",
        "NSHighResolutionCapable": True,
    },
)
