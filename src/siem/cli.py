"""Command-line interface.

    siem run LOGS...       parse logs and detect in one step (no database needed)
    siem ingest LOGS...    parse logs into a SQLite database
    siem detect            run rules over everything in the database
    siem rules             list the loaded detection rules
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .engine import RuleError, load_rules, run_rules
from .models import SEVERITIES, Alert, Event, severity_rank
from .parsers import PARSERS, parse_file
from .report import console_table, severity_counts, write_html, write_json
from .store import EventStore


def _expand(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            files += sorted(f for f in p.rglob("*") if f.is_file() and not f.name.startswith("."))
        elif p.is_file():
            files.append(p)
        else:
            raise SystemExit(f"siem: no such file or directory: {raw}")
    return files


def _parse_all(args) -> list[Event]:
    events: list[Event] = []
    for f in _expand(args.logs):
        evs, skipped = parse_file(f, fmt=args.format, year=args.year)
        print(f"  parsed {f}: {len(evs)} events ({skipped} lines skipped)", file=sys.stderr)
        events += evs
    return events


def _report(alerts: list[Alert], events: list[Event], args) -> int:
    shown = [a for a in alerts if severity_rank(a.severity) >= severity_rank(args.min_severity)]
    print(console_table(shown))
    counts = severity_counts(shown)
    print("\n" + "  ".join(f"{s}: {n}" for s, n in counts.items()), file=sys.stderr)
    if args.json:
        write_json(shown, Path(args.json))
        print(f"wrote {args.json}", file=sys.stderr)
    if args.html:
        write_html(shown, events, Path(args.html))
        print(f"wrote {args.html}", file=sys.stderr)
    if args.fail_on and any(severity_rank(a.severity) >= severity_rank(args.fail_on) for a in shown):
        return 2
    return 0


def cmd_run(args) -> int:
    events = _parse_all(args)
    return _report(run_rules(load_rules(args.rules), events), events, args)


def cmd_ingest(args) -> int:
    events = _parse_all(args)
    store = EventStore(args.db)
    new = store.add(events)
    print(f"stored {new} new events in {args.db} ({store.count()} total)", file=sys.stderr)
    store.close()
    return 0


def cmd_detect(args) -> int:
    if not Path(args.db).exists():
        raise SystemExit(f"siem: database {args.db} not found. Run 'siem ingest' first.")
    store = EventStore(args.db)
    events = store.all()
    store.close()
    return _report(run_rules(load_rules(args.rules), events), events, args)


def cmd_rules(args) -> int:
    rules = load_rules(args.rules)
    rows = [("ID", "TYPE", "SEVERITY", "MITRE", "TITLE")]
    rows += [(r.id, r.type, r.severity, ",".join(r.mitre), r.title)
             for r in sorted(rules, key=lambda r: (-severity_rank(r.severity), r.id))]
    w = [max(len(r[i]) for r in rows) for i in range(4)]
    for r in rows:
        print(f"{r[0]:<{w[0]}}  {r[1]:<{w[1]}}  {r[2]:<{w[2]}}  {r[3]:<{w[3]}}  {r[4]}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="siem", description="Lightweight SIEM: parse logs, detect, report.")
    p.add_argument("--version", action="version", version=f"siem-tool {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_input(sp):
        sp.add_argument("logs", nargs="+", help="log files or directories")
        sp.add_argument("--format", choices=sorted(PARSERS), help="force a parser (default: auto-detect)")
        sp.add_argument("--year", type=int, help="year for syslog timestamps, which have none (default: this year)")

    def add_output(sp):
        sp.add_argument("--rules", help="rules directory or file (default: built-in detections)")
        sp.add_argument("--json", metavar="FILE", help="write alerts as JSON")
        sp.add_argument("--html", metavar="FILE", help="write an HTML report")
        sp.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide alerts below this level")
        sp.add_argument("--fail-on", choices=SEVERITIES, help="exit with code 2 if any alert is at least this severe")

    sp = sub.add_parser("run", help="parse logs and detect in one step")
    add_input(sp); add_output(sp); sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("ingest", help="parse logs into the SQLite store")
    add_input(sp); sp.add_argument("--db", default="siem.db"); sp.set_defaults(func=cmd_ingest)

    sp = sub.add_parser("detect", help="run rules over the SQLite store")
    sp.add_argument("--db", default="siem.db"); add_output(sp); sp.set_defaults(func=cmd_detect)

    sp = sub.add_parser("rules", help="list detection rules")
    sp.add_argument("--rules", help="rules directory or file"); sp.set_defaults(func=cmd_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except RuleError as exc:
        print(f"siem: rule error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
