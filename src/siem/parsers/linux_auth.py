"""Parser for Linux auth logs (/var/log/auth.log on Debian/Ubuntu, /var/log/secure on RHEL).

Handles both the classic syslog timestamp ("Nov 21 03:14:07") and the
RFC 3339 timestamp newer rsyslog configs write ("2026-11-21T03:14:07.123+00:00").
Classic syslog lines have no year or timezone: we assume UTC and the given year.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from ..models import Event
from ..timeutil import parse_iso_utc

SYSLOG_HEADER = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\s(?P<prog>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$"
)
ISO_HEADER = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s"
    r"(?P<host>\S+)\s(?P<prog>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$"
)

# --- sshd -------------------------------------------------------------------
SSH_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)"
)
SSH_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
SSH_INVALID_USER = re.compile(r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)")

# --- sudo -------------------------------------------------------------------
SUDO_OK = re.compile(
    r"^\s*(?P<user>\S+) : (?:.*?; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; "
    r"USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$"
)
SUDO_DENIED = re.compile(r"^\s*(?P<user>\S+) : (?:.*?; )?user NOT in sudoers")
SUDO_AUTH_FAIL = re.compile(r"^\s*(?P<user>\S+) : \d+ incorrect password attempts?")

# --- account management ---------------------------------------------------
USERADD = re.compile(r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+)")
USERDEL = re.compile(r"^delete user '(?P<user>[^']+)'")

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def _syslog_time(mon: str, day: str, hms: str, year: int) -> datetime:
    h, m, s = (int(x) for x in hms.split(":"))
    ts = datetime(year, MONTHS[mon], int(day), h, m, s, tzinfo=timezone.utc)
    # A December log read in January would otherwise land 11 months in the future.
    if ts - datetime.now(timezone.utc) > timedelta(days=2):
        ts = ts.replace(year=year - 1)
    return ts


_iso_time = parse_iso_utc


def _classify(prog: str, msg: str) -> dict | None:
    """Map one program message to event fields, or None if we don't care about it."""
    if prog == "sshd":
        if m := SSH_FAILED.match(msg):
            return dict(action="logon", outcome="failure", user=m["user"], src_ip=m["ip"],
                        extra={"method": m["method"], "invalid_user": bool(m["invalid"]),
                               "port": int(m["port"]), "service": "ssh"})
        if m := SSH_ACCEPTED.match(msg):
            return dict(action="logon", outcome="success", user=m["user"], src_ip=m["ip"],
                        extra={"method": m["method"], "port": int(m["port"]), "service": "ssh"})
        if m := SSH_INVALID_USER.match(msg):
            # sshd logs this *and* a "Failed password" line for the same attempt, so it gets
            # its own action instead of counting as a second failed logon.
            return dict(action="invalid_user", outcome="failure", user=m["user"], src_ip=m["ip"],
                        extra={"service": "ssh"})
        return None

    if prog == "sudo":
        # Failures first: a denied line also contains "TTY=... COMMAND=..." and would
        # otherwise be misread as a successful sudo.
        if m := SUDO_DENIED.match(msg):
            cmd = SUDO_OK.match(msg)
            return dict(action="sudo", outcome="failure", user=m["user"],
                        extra={"reason": "not_in_sudoers", "command": cmd["cmd"].strip() if cmd else None})
        if m := SUDO_AUTH_FAIL.match(msg):
            return dict(action="sudo", outcome="failure", user=m["user"],
                        extra={"reason": "bad_password"})
        if m := SUDO_OK.match(msg):
            return dict(action="sudo", outcome="success", user=m["user"],
                        extra={"target_user": m["target"], "command": m["cmd"].strip(),
                               "tty": m["tty"], "pwd": m["pwd"]})
        return None

    if prog == "useradd" and (m := USERADD.match(msg)):
        return dict(action="account_created", outcome="success", user=m["user"],
                    extra={"uid": int(m["uid"])})
    if prog == "userdel" and (m := USERDEL.match(msg)):
        return dict(action="account_deleted", outcome="success", user=m["user"])
    return None


def parse_linux_auth(text: str, year: int | None = None) -> tuple[list[Event], int]:
    """Parse auth.log text. Returns (events, lines_skipped)."""
    year = year or datetime.now(timezone.utc).year
    events, skipped = [], 0
    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if m := SYSLOG_HEADER.match(line):
            ts = _syslog_time(m["mon"], m["day"], m["time"], year)
        elif m := ISO_HEADER.match(line):
            ts = _iso_time(m["ts"])
        else:
            skipped += 1
            continue
        fields = _classify(m["prog"], m["msg"])
        if fields is None:
            skipped += 1
            continue
        events.append(Event(timestamp=ts, source="linux_auth", host=m["host"],
                            message=m["msg"], raw=line, **fields))
    return events, skipped
