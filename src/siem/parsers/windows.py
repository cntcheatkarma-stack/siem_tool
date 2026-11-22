"""Parser for Windows event logs exported as JSON.

Accepts JSON Lines (one event per line) or a JSON array, in either of two shapes:

1. Nested, as produced by evtx_dump and similar tools:
   {"Event": {"System": {"EventID": 4625, "Computer": "...", "TimeCreated": {...}},
              "EventData": {"TargetUserName": "...", "IpAddress": "..."}}}
2. Flat, as produced by Get-WinEvent | ConvertTo-Json style exports:
   {"EventID": 4625, "TimeCreated": "...", "Computer": "...", "TargetUserName": "..."}
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from ..models import Event
from ..timeutil import parse_iso_utc

LOGON_TYPES = {
    2: "interactive", 3: "network", 4: "batch", 5: "service", 7: "unlock",
    8: "network_cleartext", 9: "new_credentials", 10: "remote_interactive", 11: "cached",
}
EMPTY = {"", "-", "null", "None"}


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    return None if value in EMPTY else value


def _scalar(value: Any) -> Any:
    """evtx_dump sometimes wraps values as {"#text": ..., "#attributes": {...}}."""
    if isinstance(value, dict):
        return value.get("#text", value.get("value"))
    return value


def parse_time(value: Any) -> datetime:
    """Parse Windows timestamps, including 7-digit fractions and a trailing Z."""
    if isinstance(value, dict):
        attrs = value.get("#attributes", value)
        value = attrs.get("SystemTime")
    if value is None:
        raise ValueError("event has no timestamp")
    return parse_iso_utc(value)   # handles Windows' 7-digit fractions and the trailing Z


def _flatten(record: dict[str, Any]) -> dict[str, Any]:
    """Bring both input shapes to one flat dict of fields."""
    if "Event" in record and isinstance(record["Event"], dict):
        ev = record["Event"]
        system = ev.get("System") or {}
        data = ev.get("EventData") or {}
        flat = {k: _scalar(v) for k, v in data.items()} if isinstance(data, dict) else {}
        flat["EventID"] = _scalar(system.get("EventID"))
        flat["Computer"] = system.get("Computer")
        flat["Channel"] = system.get("Channel")
        flat["TimeCreated"] = system.get("TimeCreated")
        security = system.get("Security") or {}
        if isinstance(security, dict):
            flat.setdefault("UserID", (security.get("#attributes") or security).get("UserID"))
        execution = (system.get("Execution") or {})
        execution = execution.get("#attributes", execution) if isinstance(execution, dict) else {}
        if "ProcessID" in execution:
            flat.setdefault("ProcessID", execution["ProcessID"])
        return flat
    return dict(record)


def _iter_records(text: str):
    stripped = text.lstrip()
    if stripped.startswith("["):
        yield from json.loads(stripped)
        return
    for line in text.splitlines():
        line = line.strip()
        if line:
            yield json.loads(line)


def _to_event(f: dict[str, Any], raw: str) -> Event:
    event_id = int(f["EventID"])
    ts = parse_time(f.get("TimeCreated"))
    host = _clean(f.get("Computer"))
    base = dict(timestamp=ts, source="windows", host=host, event_id=event_id, raw=raw)

    if event_id in (4624, 4625):
        logon_type = int(f["LogonType"]) if _clean(f.get("LogonType")) else None
        extra = {"logon_type": logon_type, "logon_type_name": LOGON_TYPES.get(logon_type),
                 "domain": _clean(f.get("TargetDomainName")), "workstation": _clean(f.get("WorkstationName"))}
        if event_id == 4625:
            extra["status"] = _clean(f.get("Status"))
            extra["sub_status"] = _clean(f.get("SubStatus"))
        outcome = "success" if event_id == 4624 else "failure"
        user = _clean(f.get("TargetUserName"))
        return Event(action="logon", outcome=outcome, user=user, src_ip=_clean(f.get("IpAddress")),
                     message=f"{'Logon' if outcome == 'success' else 'Failed logon'} for {user}", extra=extra, **base)

    if event_id == 4672:
        user = _clean(f.get("SubjectUserName"))
        return Event(action="special_privileges", outcome="success", user=user,
                     message=f"Special privileges assigned to {user}",
                     extra={"privileges": _clean(f.get("PrivilegeList"))}, **base)

    if event_id == 4720:
        new_user, actor = _clean(f.get("TargetUserName")), _clean(f.get("SubjectUserName"))
        return Event(action="account_created", outcome="success", user=new_user,
                     message=f"Account {new_user} created by {actor}", extra={"created_by": actor}, **base)

    if event_id == 4104:
        script = f.get("ScriptBlockText") or ""
        return Event(action="powershell", user=_clean(f.get("UserID")), message=script,
                     extra={"script_block_id": _clean(f.get("ScriptBlockId")), "path": _clean(f.get("Path")),
                            "process_id": f.get("ProcessID")}, **base)

    if event_id == 1102:
        user = _clean(f.get("SubjectUserName"))
        return Event(action="log_cleared", outcome="success", user=user,
                     message=f"Security audit log cleared by {user}", **base)

    return Event(action=f"event_{event_id}", message=str(f.get("Message", "")), **base)


def parse_windows(text: str) -> tuple[list[Event], int]:
    """Parse Windows JSON events. Returns (events, records_skipped)."""
    events, skipped = [], 0
    for record in _iter_records(text):
        try:
            flat = _flatten(record)
            events.append(_to_event(flat, json.dumps(record, separators=(",", ":"))))
        except (KeyError, TypeError, ValueError):
            skipped += 1
    return events, skipped
