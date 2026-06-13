from __future__ import annotations

from pathlib import Path
import os
import pwd
import grp
import stat


def root_join(root: str | Path, absolute_path: str) -> Path:
    root_path = Path(root)
    if str(root_path) == "/":
        return Path(absolute_path)
    return root_path / absolute_path.lstrip("/")


def stat_metadata(path: Path) -> tuple[str, str]:
    try:
        info = path.stat()
    except OSError:
        return "", ""
    try:
        owner = pwd.getpwuid(info.st_uid).pw_name
    except KeyError:
        owner = str(info.st_uid)
    permissions = stat.filemode(info.st_mode)
    return owner, permissions


def stat_metadata_full(path: Path) -> tuple[str, str, str, str]:
    try:
        info = path.stat()
    except OSError:
        return "", "", "", ""
    try:
        owner = pwd.getpwuid(info.st_uid).pw_name
    except KeyError:
        owner = str(info.st_uid)
    try:
        group = grp.getgrgid(info.st_gid).gr_name
    except KeyError:
        group = str(info.st_gid)
    return owner, group, stat.filemode(info.st_mode), str(int(info.st_mtime))


def display_path(root: str | Path, path: Path) -> str:
    if str(root) == "/":
        return str(path)
    try:
        return "/" + str(path.relative_to(root)).lstrip("/")
    except ValueError:
        return str(path)


def is_root_owned(path: Path) -> bool:
    try:
        return path.stat().st_uid == 0
    except OSError:
        return False


def is_writable(path: Path) -> bool:
    return os.access(path, os.W_OK)


def user_home_paths(root: str | Path) -> list[Path]:
    paths = [root_join(root, "/Users")]
    home = Path.home()
    if str(root) == "/" and home.exists():
        paths.append(home.parent)
    seen = set()
    result = []
    for base in paths:
        if base in seen or not base.is_dir():
            continue
        seen.add(base)
        result.extend([item for item in base.iterdir() if item.is_dir()])
    return result
