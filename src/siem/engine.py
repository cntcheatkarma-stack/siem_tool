"""Detection engine: loads YAML rules and runs them over normalized events.

Three rule types:

match      every event that passes the filter is an alert (optionally grouped)
threshold  N matching events (or N distinct values of a field) per group inside a time window
sequence   at least N "first" events followed by a "then" event, per group, inside a time window

Filters are a mapping of field -> condition:

    action: logon                  equality (case-insensitive for strings)
    event_id: [4624, 4625]         value is one of the list
    user: {not_in: [SYSTEM]}       operators: in, not_in, regex, contains_any, exists, gte, lte
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from importlib import resources
from pathlib import Path
from typing import Any, Callable

import yaml

from .models import SEVERITIES, Alert, Event, severity_rank

RULE_TYPES = ("match", "threshold", "sequence")
OPERATORS = ("in", "not_in", "regex", "contains_any", "exists", "gte", "lte")


class RuleError(ValueError):
    pass


# ------------------------------------------------------------------ filters ---

def _norm(value: Any) -> Any:
    return value.lower() if isinstance(value, str) else value


def _compile_condition(name: str, cond: Any) -> Callable[[Any], bool]:
    if isinstance(cond, list):
        allowed = {_norm(v) for v in cond}
        return lambda v: _norm(v) in allowed
    if not isinstance(cond, dict):
        target = _norm(cond)
        return lambda v: _norm(v) == target

    checks: list[Callable[[Any], bool]] = []
    for op, arg in cond.items():
        if op not in OPERATORS:
            raise RuleError(f"field '{name}': unknown operator '{op}' (use one of {', '.join(OPERATORS)})")
        if op == "in":
            s = {_norm(x) for x in arg}
            checks.append(lambda v, s=s: _norm(v) in s)
        elif op == "not_in":
            s = {_norm(x) for x in arg}
            checks.append(lambda v, s=s: v is not None and _norm(v) not in s)
        elif op == "regex":
            pattern = re.compile(arg, re.IGNORECASE)
            checks.append(lambda v, p=pattern: v is not None and p.search(str(v)) is not None)
        elif op == "contains_any":
            subs = [str(x).lower() for x in arg]
            checks.append(lambda v, subs=subs: v is not None and any(x in str(v).lower() for x in subs))
        elif op == "exists":
            checks.append(lambda v, want=bool(arg): (v is not None) == want)
        elif op == "gte":
            checks.append(lambda v, a=arg: v is not None and v >= a)
        elif op == "lte":
            checks.append(lambda v, a=arg: v is not None and v <= a)
    return lambda v: all(c(v) for c in checks)


def compile_filter(spec: dict[str, Any] | None) -> Callable[[Event], bool]:
    """Turn a filter mapping into a function Event -> bool."""
    if not spec:
        return lambda e: True
    if not isinstance(spec, dict):
        raise RuleError("filter must be a mapping of field: condition")
    parts = [(name, _compile_condition(name, cond)) for name, cond in spec.items()]
    return lambda e: all(check(e.get(name)) for name, check in parts)


def parse_duration(text: str | int) -> timedelta:
    """'30s', '5m', '2h', '1d' -> timedelta. A bare number means seconds."""
    if isinstance(text, (int, float)):
        return timedelta(seconds=text)
    m = re.fullmatch(r"\s*(\d+)\s*([smhd]?)\s*", str(text))
    if not m:
        raise RuleError(f"bad duration '{text}' (use e.g. 30s, 5m, 2h)")
    n, unit = int(m[1]), m[2] or "s"
    unit_name = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[unit]
    return timedelta(**{unit_name: n})


# -------------------------------------------------------------------- rules ---

@dataclass
class Rule:
    id: str
    title: str
    type: str
    severity: str
    description: str = ""
    mitre: list[str] = field(default_factory=list)
    group_by: list[str] = field(default_factory=list)
    spec: dict[str, Any] = field(default_factory=dict)
    source_file: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any], source_file: str = "") -> "Rule":
        where = f"{source_file or 'rule'}"
        for key in ("id", "title", "type", "severity"):
            if key not in d:
                raise RuleError(f"{where}: missing required key '{key}'")
        if d["type"] not in RULE_TYPES:
            raise RuleError(f"{where}: type must be one of {', '.join(RULE_TYPES)}")
        if d["severity"] not in SEVERITIES:
            raise RuleError(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
        rule = cls(id=d["id"], title=d["title"], type=d["type"], severity=d["severity"],
                   description=(d.get("description") or "").strip(), mitre=list(d.get("mitre") or []),
                   group_by=list(d.get("group_by") or []), spec=d, source_file=source_file)
        rule._compile()
        return rule

    def _compile(self) -> None:
        s = self.spec
        try:
            if self.type == "match":
                self._filter = compile_filter(s.get("filter"))
                self._window = parse_duration(s["window"]) if "window" in s else None
            elif self.type == "threshold":
                self._filter = compile_filter(s.get("filter"))
                self._window = parse_duration(s["window"])
                self._threshold = int(s["threshold"])
                self._distinct = s.get("distinct")
            else:
                first, then = s["first"], s["then"]
                self._first = compile_filter(first.get("filter"))
                self._min_count = int(first.get("min_count", 1))
                self._then = compile_filter(then.get("filter"))
                self._window = parse_duration(s["within"])
        except KeyError as exc:
            raise RuleError(f"{self.source_file or self.id}: '{self.type}' rule needs key {exc}") from None

    # -- evaluation ----------------------------------------------------------

    def _key(self, e: Event) -> tuple | None:
        values = tuple(e.get(f) for f in self.group_by)
        return None if any(v is None for v in values) else values

    def _groups(self, events: list[Event], keep: Callable[[Event], bool]) -> dict[tuple, list[Event]]:
        groups: dict[tuple, list[Event]] = defaultdict(list)
        for e in events:
            if keep(e) and (k := self._key(e)) is not None:
                groups[k].append(e)
        return groups

    def _alert(self, key: tuple, evs: list[Event]) -> Alert:
        return Alert(rule_id=self.id, title=self.title, severity=self.severity, description=self.description,
                     mitre=self.mitre, group=dict(zip(self.group_by, key)), events=evs)

    def evaluate(self, events: list[Event]) -> list[Alert]:
        """`events` must be sorted by timestamp."""
        return getattr(self, f"_eval_{self.type}")(events)

    def _eval_match(self, events: list[Event]) -> list[Alert]:
        if not self.group_by:
            return [self._alert((), [e]) for e in events if self._filter(e)]
        alerts = []
        for key, evs in self._groups(events, self._filter).items():
            alerts += [self._alert(key, burst) for burst in _bursts(evs, self._window)]
        return alerts

    def _eval_threshold(self, events: list[Event]) -> list[Alert]:
        alerts = []
        for key, evs in self._groups(events, self._filter).items():
            i, n = 0, len(evs)
            seen: Counter = Counter()
            j = 0
            while j < n:
                seen[self._value(evs[j])] += 1
                while evs[j].timestamp - evs[i].timestamp > self._window:
                    seen[self._value(evs[i])] -= 1
                    if seen[self._value(evs[i])] == 0:
                        del seen[self._value(evs[i])]
                    i += 1
                hits = len(seen) if self._distinct else (j - i + 1)
                if hits >= self._threshold:
                    # Keep absorbing the rest of the burst so one attack = one alert.
                    k = j + 1
                    while k < n and evs[k].timestamp - evs[k - 1].timestamp <= self._window:
                        k += 1
                    alerts.append(self._alert(key, evs[i:k]))
                    i = j = k
                    seen = Counter()
                    continue
                j += 1
        return alerts

    def _value(self, e: Event) -> Any:
        return _norm(e.get(self._distinct)) if self._distinct else id(e)

    def _eval_sequence(self, events: list[Event]) -> list[Alert]:
        firsts = self._groups(events, self._first)
        alerts = []
        for key, thens in self._groups(events, self._then).items():
            prior = firsts.get(key, [])
            consumed_until = None   # first-events before this point already belong to an alert
            for t in thens:
                window = [f for f in prior
                          if t.timestamp - self._window <= f.timestamp <= t.timestamp and f is not t
                          and (consumed_until is None or f.timestamp > consumed_until)]
                if len(window) >= self._min_count:
                    alerts.append(self._alert(key, window + [t]))
                    consumed_until = t.timestamp
        return alerts


def _bursts(evs: list[Event], gap: timedelta | None) -> list[list[Event]]:
    """Split a sorted list wherever two neighbours are more than `gap` apart."""
    if gap is None:
        return [evs]
    out, cur = [], [evs[0]]
    for prev, e in zip(evs, evs[1:]):
        if e.timestamp - prev.timestamp > gap:
            out.append(cur)
            cur = []
        cur.append(e)
    out.append(cur)
    return out


# ------------------------------------------------------------------ loading ---

def default_rules_dir() -> Path:
    return Path(str(resources.files("siem") / "detections"))


def load_rules(path: str | Path | None = None) -> list[Rule]:
    """Load every *.yml / *.yaml rule from a directory (or a single file)."""
    path = Path(path) if path else default_rules_dir()
    files = sorted(path.glob("*.yml")) + sorted(path.glob("*.yaml")) if path.is_dir() else [path]
    rules, ids = [], set()
    for f in files:
        docs = [d for d in yaml.safe_load_all(f.read_text(encoding="utf-8")) if d]
        for d in docs:
            rule = Rule.from_dict(d, source_file=f.name)
            if rule.id in ids:
                raise RuleError(f"{f.name}: duplicate rule id '{rule.id}'")
            ids.add(rule.id)
            rules.append(rule)
    return rules


def run_rules(rules: list[Rule], events: list[Event]) -> list[Alert]:
    """Run every rule and return alerts, most severe and then earliest first."""
    events = sorted(events, key=lambda e: e.timestamp)
    alerts = [a for r in rules for a in r.evaluate(events)]
    return sorted(alerts, key=lambda a: (-severity_rank(a.severity), a.first_seen))
