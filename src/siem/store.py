"""SQLite event store. Re-ingesting the same log file doesn't create duplicates."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path

from .models import Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY,
    digest    TEXT UNIQUE NOT NULL,
    timestamp TEXT NOT NULL,
    source    TEXT NOT NULL,
    action    TEXT NOT NULL,
    host      TEXT,
    user      TEXT,
    src_ip    TEXT,
    outcome   TEXT,
    event_id  INTEGER,
    message   TEXT,
    raw       TEXT,
    extra     TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip   ON events(src_ip);
"""

COLUMNS = ("timestamp", "source", "action", "host", "user", "src_ip",
           "outcome", "event_id", "message", "raw", "extra")


def _digest(event: Event) -> str:
    return hashlib.sha256(f"{event.source}\x00{event.timestamp.isoformat()}\x00{event.raw}".encode()).hexdigest()


class EventStore:
    def __init__(self, path: str | Path):
        self.conn = sqlite3.connect(str(path))
        self.conn.executescript(SCHEMA)

    def add(self, events: list[Event]) -> int:
        """Insert events, skipping ones already stored. Returns how many were new."""
        before = self.count()
        self.conn.executemany(
            f"INSERT OR IGNORE INTO events (digest, {', '.join(COLUMNS)}) VALUES (?{', ?' * len(COLUMNS)})",
            [(_digest(e), e.timestamp.isoformat(), e.source, e.action, e.host, e.user, e.src_ip,
              e.outcome, e.event_id, e.message, e.raw, json.dumps(e.extra)) for e in events],
        )
        self.conn.commit()
        return self.count() - before

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def all(self) -> list[Event]:
        rows = self.conn.execute(f"SELECT {', '.join(COLUMNS)} FROM events ORDER BY timestamp, id")
        out = []
        for row in rows:
            d = dict(zip(COLUMNS, row))
            d["timestamp"] = datetime.fromisoformat(d["timestamp"])
            d["extra"] = json.loads(d["extra"] or "{}")
            d["message"] = d["message"] or ""
            d["raw"] = d["raw"] or ""
            out.append(Event(**d))
        return out

    def close(self) -> None:
        self.conn.close()
