"""Run the whole pipeline on the sample logs and check the attack story is detected."""

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from siem.cli import main
from siem.engine import load_rules, run_rules
from siem.models import Event
from siem.parsers import parse_file
from siem.report import write_html
from siem.store import EventStore

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def sample_events():
    events = []
    for f in sorted(SAMPLES.glob("*")):
        if f.suffix in (".log", ".jsonl"):
            events += parse_file(f, year=2026)[0]
    return events


def test_sample_attack_story_is_detected():
    alerts = run_rules(load_rules(), sample_events())
    assert Counter(a.rule_id for a in alerts) == Counter({
        "success-after-brute-force": 2,    # SSH on web01 and RDP/SMB on DC01
        "brute-force-login": 2,
        "new-account-created": 2,
        "audit-log-cleared": 1,
        "password-spray": 1,               # slow spray: under the brute-force rate, caught by distinct users
        "suspicious-powershell": 1,
        "sudo-root-shell": 1,
        "sudo-denied": 1,
        "special-privileges-unexpected": 1,
        "powershell-file-deletion": 1,
    })


def test_normal_activity_is_quiet():
    alerts = run_rules(load_rules(), sample_events())
    involved = {(e.user, e.src_ip) for a in alerts for e in a.events}
    assert ("alice", "192.0.2.10") not in involved, "one typo by alice should not alert"
    assert not any(e.user == "bob" for a in alerts for e in a.events)
    assert not any("Get-Process" in e.message for a in alerts for e in a.events)


def test_store_deduplicates_reingest(tmp_path):
    db = tmp_path / "siem.db"
    store = EventStore(db)
    events = sample_events()
    assert store.add(events) == len(events)
    assert store.add(events) == 0
    loaded = store.all()
    assert len(loaded) == len(events)
    assert loaded[0].timestamp.tzinfo is not None
    assert run_rules(load_rules(), loaded) and len(run_rules(load_rules(), loaded)) == 13
    store.close()


def test_html_report_escapes_log_content(tmp_path):
    evil = Event(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), source="test", action="account_created",
                 user="<script>alert(1)</script>", raw='useradd: new user: name=<img src=x onerror=alert(1)>')
    alerts = run_rules(load_rules(), [evil])
    out = tmp_path / "r.html"
    write_html(alerts, [evil], out)
    html = out.read_text()
    assert "<script>alert(1)" not in html and "<img src=x" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_cli_run_writes_outputs_and_fail_on(tmp_path, capsys):
    j, h = tmp_path / "a.json", tmp_path / "r.html"
    code = main(["run", str(SAMPLES), "--year", "2026", "--json", str(j), "--html", str(h), "--fail-on", "critical"])
    assert code == 2                                   # critical alerts present
    data = json.loads(j.read_text())
    assert data["summary"]["critical"] == 3 and len(data["alerts"]) == 13
    assert h.read_text().startswith("<!DOCTYPE html>")
    assert "success-after-brute-force" in capsys.readouterr().out


def test_cli_ingest_then_detect(tmp_path):
    db = str(tmp_path / "s.db")
    assert main(["ingest", str(SAMPLES), "--year", "2026", "--db", db]) == 0
    assert main(["detect", "--db", db, "--min-severity", "high"]) == 0
