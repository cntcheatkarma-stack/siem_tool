"""The normalized event schema every parser produces, and the alert type."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def severity_rank(severity: str) -> int:
    """Higher number = more severe. Unknown severities sort lowest."""
    try:
        return SEVERITIES.index(severity.lower())
    except ValueError:
        return -1


@dataclass
class Event:
    """One log record, normalized so rules don't care where it came from.

    timestamp  always timezone-aware UTC
    source     which parser produced it ("linux_auth", "windows")
    action     what happened, e.g. "logon", "sudo", "account_created", "powershell"
    outcome    "success", "failure", or None when it doesn't apply
    extra      parser-specific fields (logon_type, command, target_user, ...)
    """

    timestamp: datetime
    source: str
    action: str
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    outcome: str | None = None
    event_id: int | None = None
    message: str = ""
    raw: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def get(self, name: str) -> Any:
        """Look up a field by name: top-level attributes first, then `extra`.

        `extra.logon_type` and `logon_type` both work.
        """
        if name.startswith("extra."):
            return self.extra.get(name[6:])
        if name in self.__dataclass_fields__ and name != "extra":
            return getattr(self, name)
        return self.extra.get(name)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    description: str
    mitre: list[str]
    group: dict[str, Any]
    events: list[Event]

    @property
    def first_seen(self) -> datetime:
        return min(e.timestamp for e in self.events)

    @property
    def last_seen(self) -> datetime:
        return max(e.timestamp for e in self.events)

    @property
    def count(self) -> int:
        return len(self.events)

    def context(self) -> dict[str, Any]:
        """The group fields, or for ungrouped alerts the host/user/source of the event."""
        if self.group:
            return self.group
        e = self.events[0]
        return {k: v for k, v in (("host", e.host), ("user", e.user), ("src_ip", e.src_ip)) if v}

    def summary(self) -> str:
        who = ", ".join(f"{k}={v}" for k, v in self.context().items()) or "-"
        return f"{self.title} ({who}, {self.count} event{'s' if self.count != 1 else ''})"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "mitre": self.mitre,
            "group": self.group,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "count": self.count,
            "events": [e.to_dict() for e in self.events],
        }
