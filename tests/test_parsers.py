import json
from datetime import datetime, timezone

from siem.parsers.linux_auth import parse_linux_auth
from siem.parsers.windows import parse_time, parse_windows


def one(text, **kw):
    events, skipped = parse_linux_auth(text, year=2026, **kw)
    assert len(events) == 1, (events, skipped)
    return events[0]


# ---------------------------------------------------------------- linux ---

def test_ssh_failed_password():
    e = one("Nov 20 03:00:05 web01 sshd[4300]: Failed password for deploy from 203.0.113.50 port 40100 ssh2")
    assert (e.action, e.outcome, e.user, e.src_ip, e.host) == ("logon", "failure", "deploy", "203.0.113.50", "web01")
    assert e.timestamp == datetime(2026, 11, 20, 3, 0, 5, tzinfo=timezone.utc)
    assert e.extra["invalid_user"] is False


def test_ssh_failed_invalid_user():
    e = one("Nov 20 02:10:02 web01 sshd[1]: Failed password for invalid user oracle from 198.51.100.23 port 5 ssh2")
    assert e.user == "oracle" and e.extra["invalid_user"] is True


def test_ssh_accepted_publickey():
    e = one("Nov  2 08:01:12 web01 sshd[5001]: Accepted publickey for alice from 192.0.2.10 port 50522 ssh2: ED25519 SHA256:x")
    assert (e.outcome, e.user, e.extra["method"]) == ("success", "alice", "publickey")
    assert e.timestamp.day == 2


def test_invalid_user_line_is_not_a_logon():
    e = one("Nov 20 02:10:00 web01 sshd[1]: Invalid user admin from 198.51.100.23 port 51000")
    assert e.action == "invalid_user"


def test_sudo_success_and_command():
    e = one("Nov 20 03:04:02 web01 sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")
    assert (e.action, e.outcome, e.user) == ("sudo", "success", "deploy")
    assert e.extra["command"] == "/bin/bash" and e.extra["target_user"] == "root"


def test_sudo_not_in_sudoers_is_a_failure():
    # Regression: this line also contains TTY=/COMMAND= and used to parse as a success.
    e = one("Nov 20 03:20:40 web01 sudo: www-data : user NOT in sudoers ; TTY=unknown ; PWD=/var/www ; "
            "USER=root ; COMMAND=/bin/sh")
    assert (e.outcome, e.user, e.extra["reason"], e.extra["command"]) == ("failure", "www-data", "not_in_sudoers", "/bin/sh")


def test_useradd():
    e = one("Nov 20 03:05:40 web01 useradd[4402]: new user: name=sysupdate, UID=1002, GID=1002, home=/home/sysupdate")
    assert (e.action, e.user, e.extra["uid"]) == ("account_created", "sysupdate", 1002)


def test_iso_timestamp_header_converted_to_utc():
    e = one("2026-11-20T05:00:05.123456-05:00 web01 sshd[9]: Failed password for root from 203.0.113.9 port 1 ssh2")
    assert e.timestamp == datetime(2026, 11, 20, 10, 0, 5, 123456, tzinfo=timezone.utc)


def test_unrelated_and_garbage_lines_are_skipped():
    events, skipped = parse_linux_auth(
        "Nov 20 00:17:01 web01 CRON[1]: pam_unix(cron:session): session opened for user root\n"
        "this is not a log line\n\n", year=2026)
    assert events == [] and skipped == 2


# -------------------------------------------------------------- windows ---

def test_windows_flat_4625():
    rec = {"EventID": 4625, "TimeCreated": "2026-11-20T14:00:00.1234567Z", "Computer": "DC01",
           "TargetUserName": "Administrator", "IpAddress": "203.0.113.77", "LogonType": 3}
    (e,), skipped = parse_windows(json.dumps(rec))
    assert (e.action, e.outcome, e.user, e.src_ip, e.host) == ("logon", "failure", "Administrator", "203.0.113.77", "DC01")
    assert e.extra["logon_type_name"] == "network"
    assert e.timestamp == datetime(2026, 11, 20, 14, 0, 0, 123456, tzinfo=timezone.utc)


def test_windows_nested_4104():
    rec = {"Event": {"System": {"EventID": 4104, "Computer": "MarySue",
                                "TimeCreated": {"#attributes": {"SystemTime": "2026-11-20T14:11:47.0000000Z"}},
                                "Execution": {"#attributes": {"ProcessID": 1216}}},
                     "EventData": {"ScriptBlockText": "del .\\Top_Secret.txt", "Path": ""}}}
    (e,), _ = parse_windows(json.dumps(rec))
    assert (e.action, e.host, e.message) == ("powershell", "MarySue", "del .\\Top_Secret.txt")
    assert e.extra["process_id"] == 1216 and e.extra["path"] is None


def test_windows_json_array_and_dash_ip():
    recs = [{"EventID": 4624, "TimeCreated": "2026-11-20T07:55:00Z", "TargetUserName": "bob", "IpAddress": "-"},
            {"EventID": 1102, "TimeCreated": "2026-11-20T14:20:05Z", "SubjectUserName": "Administrator"}]
    events, _ = parse_windows(json.dumps(recs))
    assert [e.action for e in events] == ["logon", "log_cleared"]
    assert events[0].src_ip is None


def test_windows_bad_record_is_skipped():
    events, skipped = parse_windows('{"EventID": 4625}\n{"no": "id"}\n')
    assert events == [] and skipped == 2


def test_parse_time_variants():
    assert parse_time({"#attributes": {"SystemTime": "2026-01-01T00:00:00.9999999Z"}}).microsecond == 999999
    assert parse_time("2026-01-01T05:00:00+05:00").hour == 0


def test_iso_parsing_is_python310_safe():
    from siem.timeutil import parse_iso_utc
    assert parse_iso_utc("2026-11-20T03:00:05.1Z").microsecond == 100000
    assert parse_iso_utc("2026-11-20T03:00:05.1234567Z").microsecond == 123456
    assert parse_iso_utc("2026-11-20T03:00:05-0500").hour == 8
    assert parse_iso_utc("2026-11-20 03:00:05").tzinfo is not None
