"""Timestamp parsing that behaves the same on Python 3.10 and newer.

Python 3.10's datetime.fromisoformat only accepts 3 or 6 fractional digits and
offsets written as +HH:MM. Logs use 1-7 digits (Windows writes 7), a trailing Z,
and sometimes +HHMM, so normalize first.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

_FRACTION = re.compile(r"\.(\d+)")
_OFFSET = re.compile(r"([+-]\d{2})(\d{2})$")


def parse_iso_utc(text: str) -> datetime:
    """Parse an ISO 8601 timestamp and return it as timezone-aware UTC.

    Naive timestamps are assumed to already be UTC.
    """
    s = str(text).strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    s = _OFFSET.sub(r"\1:\2", s)
    s = _FRACTION.sub(lambda m: "." + (m[1] + "000000")[:6], s, count=1)
    ts = datetime.fromisoformat(s)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)
