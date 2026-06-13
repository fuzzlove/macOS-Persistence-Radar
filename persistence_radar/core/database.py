from __future__ import annotations

from pathlib import Path
import json
import sqlite3

from persistence_radar.core.models import Finding
from persistence_radar.core.timeline import enrich_file_times


DEFAULT_DB_PATH = Path.home() / ".local" / "share" / "macos-persistence-radar" / "radar.sqlite3"


class RadarDatabase:
    def __init__(self, path: str | Path | None = DEFAULT_DB_PATH) -> None:
        self.path = Path(path or DEFAULT_DB_PATH)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.initialize()

    def initialize(self) -> None:
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS snapshots (
                name TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                findings_json TEXT NOT NULL
            )
            """
        )
        self.connection.commit()

    def save_snapshot(self, name: str, findings: list[Finding], created_at: str) -> None:
        enrich_file_times(findings)
        previous_by_id: dict[str, Finding] = {}
        for snapshot in self.list_snapshots():
            try:
                for item in self.load_snapshot(snapshot["name"]):
                    previous_by_id.setdefault(item.id, item)
            except (KeyError, json.JSONDecodeError):
                continue
        for finding in findings:
            previous = previous_by_id.get(finding.id)
            if previous:
                finding.first_seen = previous.first_seen or finding.first_seen
            else:
                finding.first_seen = finding.first_seen or created_at
            finding.last_seen = created_at
        payload = json.dumps([finding.to_dict() for finding in findings], indent=2, sort_keys=True)
        self.connection.execute(
            "INSERT OR REPLACE INTO snapshots (name, created_at, findings_json) VALUES (?, ?, ?)",
            (name, created_at, payload),
        )
        self.connection.commit()

    def load_snapshot(self, name: str) -> list[Finding]:
        row = self.connection.execute(
            "SELECT findings_json FROM snapshots WHERE name = ?",
            (name,),
        ).fetchone()
        if row is None:
            raise KeyError(f"snapshot not found: {name}")
        return [Finding.from_dict(item) for item in json.loads(row["findings_json"])]

    def list_snapshots(self) -> list[dict[str, str]]:
        rows = self.connection.execute(
            "SELECT name, created_at FROM snapshots ORDER BY created_at DESC"
        ).fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        self.connection.close()
