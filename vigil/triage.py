"""Triage state: Wazuh alerts are read-only, so whether you've acknowledged
or closed one (and why) is kept in a small local SQLite file, keyed by the
alert's document ID."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

STATUSES = ("open", "acknowledged", "closed")

SCHEMA = """
CREATE TABLE IF NOT EXISTS triage (
    alert_id   TEXT PRIMARY KEY,
    status     TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    updated_at REAL NOT NULL
);
"""


class TriageStore:
    def __init__(self, path: str | Path):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def statuses(self, alert_ids: list[str]) -> dict[str, str]:
        """Status for each ID; anything never triaged is 'open'."""
        out = dict.fromkeys(alert_ids, "open")
        for start in range(0, len(alert_ids), 500):   # SQLite caps bound parameters
            chunk = alert_ids[start:start + 500]
            marks = ",".join("?" * len(chunk))
            for row in self.conn.execute(
                    f"SELECT alert_id, status FROM triage WHERE alert_id IN ({marks})", chunk):
                out[row["alert_id"]] = row["status"]
        return out

    def get(self, alert_id: str) -> dict:
        row = self.conn.execute("SELECT * FROM triage WHERE alert_id = ?", (alert_id,)).fetchone()
        return dict(row) if row else {"alert_id": alert_id, "status": "open", "note": "", "updated_at": None}

    def set(self, alert_ids: list[str], status: str, note: str | None = None) -> None:
        if status not in STATUSES:
            raise ValueError(f"unknown status {status!r}")
        now = time.time()
        with self.conn:
            for aid in alert_ids:
                if note is None:
                    # keep any existing note when only the status changes
                    self.conn.execute(
                        "INSERT INTO triage (alert_id, status, updated_at) VALUES (?, ?, ?) "
                        "ON CONFLICT(alert_id) DO UPDATE SET status = excluded.status, "
                        "updated_at = excluded.updated_at", (aid, status, now))
                else:
                    self.conn.execute(
                        "INSERT INTO triage (alert_id, status, note, updated_at) VALUES (?, ?, ?, ?) "
                        "ON CONFLICT(alert_id) DO UPDATE SET status = excluded.status, "
                        "note = excluded.note, updated_at = excluded.updated_at",
                        (aid, status, note, now))
