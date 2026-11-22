from datetime import datetime, timedelta, timezone

import pytest

from siem.engine import Rule, RuleError, compile_filter, load_rules, parse_duration, run_rules
from siem.models import Event

T0 = datetime(2026, 11, 20, 3, 0, 0, tzinfo=timezone.utc)


def ev(sec=0, action="logon", outcome="failure", user="deploy", ip="203.0.113.50", **kw):
    return Event(timestamp=T0 + timedelta(seconds=sec), source="test", action=action,
                 outcome=outcome, user=user, src_ip=ip, **kw)


def rule(**d):
    base = {"id": "r", "title": "R", "severity": "high"}
    return Rule.from_dict({**base, **d})


BRUTE = dict(type="threshold", filter={"action": "logon", "outcome": "failure"},
             group_by=["src_ip"], threshold=5, window="5m")


# ------------------------------------------------------------------ filters ---

def test_filter_equality_is_case_insensitive():
    assert compile_filter({"user": "DEPLOY"})(ev())


def test_filter_operators():
    e = ev(message="IEX (New-Object Net.WebClient)", extra={"logon_type": 3})
    assert compile_filter({"user": {"in": ["root", "deploy"]}})(e)
    assert not compile_filter({"user": {"not_in": ["deploy"]}})(e)
    assert compile_filter({"message": {"regex": r"\bIEX\b"}})(e)
    assert compile_filter({"message": {"contains_any": ["webclient"]}})(e)
    assert compile_filter({"logon_type": {"gte": 3, "lte": 3}})(e)
    assert compile_filter({"extra.logon_type": [2, 3]})(e)
    assert compile_filter({"host": {"exists": False}})(e)


def test_not_in_does_not_match_missing_field():
    assert not compile_filter({"user": {"not_in": ["SYSTEM"]}})(ev(user=None))


def test_unknown_operator_is_rejected():
    with pytest.raises(RuleError):
        compile_filter({"user": {"startswith": "a"}})


def test_parse_duration():
    assert parse_duration("90s") == timedelta(seconds=90)
    assert parse_duration("5m") == timedelta(minutes=5)
    assert parse_duration(30) == timedelta(seconds=30)
    with pytest.raises(RuleError):
        parse_duration("five minutes")


def test_rule_validation():
    with pytest.raises(RuleError, match="missing required key 'severity'"):
        Rule.from_dict({"id": "x", "title": "x", "type": "match"})
    with pytest.raises(RuleError, match="needs key"):
        rule(type="threshold", filter={})


# ---------------------------------------------------------------- threshold ---

def test_threshold_fires_at_threshold_not_below():
    r = rule(**BRUTE)
    assert r.evaluate([ev(i * 10) for i in range(4)]) == []
    (alert,) = r.evaluate([ev(i * 10) for i in range(5)])
    assert alert.count == 5 and alert.group == {"src_ip": "203.0.113.50"}


def test_threshold_one_alert_per_burst_and_splits_on_gap():
    r = rule(**BRUTE)
    burst1 = [ev(i * 10) for i in range(12)]
    burst2 = [ev(3600 + i * 10) for i in range(6)]
    alerts = r.evaluate(burst1 + burst2)
    assert [a.count for a in alerts] == [12, 6]


def test_threshold_respects_window():
    r = rule(**BRUTE)                       # 5 in 5 minutes
    slow = [ev(i * 90) for i in range(6)]   # 5 events span 6 minutes
    assert r.evaluate(slow) == []


def test_threshold_groups_separately():
    r = rule(**BRUTE)
    mixed = [ev(i, ip=f"198.51.100.{i % 3}") for i in range(12)]   # 4 per IP
    assert r.evaluate(mixed) == []


def test_distinct_threshold_detects_spray_not_single_account():
    r = rule(**{**BRUTE, "distinct": "user", "window": "10m"})
    single_account = [ev(i * 5, user="admin") for i in range(20)]
    assert r.evaluate(single_account) == []
    spray = [ev(i * 110, user=u) for i, u in enumerate(["admin", "test", "oracle", "ubuntu", "guest"])]
    (alert,) = r.evaluate(spray)
    assert alert.count == 5


# ----------------------------------------------------------------- sequence ---

SEQ = dict(type="sequence", group_by=["src_ip"], within="15m",
           first={"filter": {"action": "logon", "outcome": "failure"}, "min_count": 5},
           then={"filter": {"action": "logon", "outcome": "success"}})


def test_sequence_fires_after_enough_failures():
    events = [ev(i * 10) for i in range(6)] + [ev(100, outcome="success")]
    (alert,) = rule(**SEQ).evaluate(events)
    assert alert.count == 7 and alert.events[-1].outcome == "success"


def test_sequence_needs_min_count():
    events = [ev(i * 10) for i in range(4)] + [ev(100, outcome="success")]
    assert rule(**SEQ).evaluate(events) == []


def test_sequence_order_matters():
    events = [ev(0, outcome="success")] + [ev(10 + i, outcome="failure") for i in range(6)]
    assert rule(**SEQ).evaluate(events) == []


def test_sequence_other_ip_success_does_not_count():
    events = [ev(i * 10) for i in range(6)] + [ev(100, outcome="success", ip="192.0.2.10")]
    assert rule(**SEQ).evaluate(events) == []


def test_sequence_does_not_reuse_failures_for_second_success():
    events = [ev(i * 10) for i in range(6)] + [ev(100, outcome="success"), ev(130, outcome="success")]
    assert len(rule(**SEQ).evaluate(events)) == 1


# -------------------------------------------------------------------- match ---

def test_match_ungrouped_is_one_alert_per_event():
    r = rule(type="match", filter={"action": "account_created"})
    alerts = r.evaluate([ev(0, action="account_created", user="a"), ev(5, action="account_created", user="b")])
    assert [a.events[0].user for a in alerts] == ["a", "b"]


def test_match_grouped_merges_within_window():
    r = rule(type="match", filter={"action": "sudo", "outcome": "failure"}, group_by=["user"], window="1h")
    events = [ev(0, action="sudo"), ev(30, action="sudo"), ev(7200, action="sudo")]
    assert [a.count for a in r.evaluate(events)] == [2, 1]


# --------------------------------------------------------- built-in rules ---

def test_builtin_rules_load_with_unique_ids():
    rules = load_rules()
    assert len(rules) >= 10
    assert len({r.id for r in rules}) == len(rules)
    assert all(r.mitre for r in rules), "every rule should map to MITRE ATT&CK"


def test_run_rules_sorts_by_severity():
    rules = [rule(id="low", severity="low", type="match", filter={"action": "logon"}),
             rule(id="crit", severity="critical", type="match", filter={"action": "logon"})]
    assert [a.rule_id for a in run_rules(rules, [ev()])] == ["crit", "low"]
