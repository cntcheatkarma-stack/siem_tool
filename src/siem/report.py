"""Output: console table, JSON export, and a self-contained HTML report.

Every value in the HTML report comes from log data, which an attacker can
control (usernames, script blocks, SSH banners...). Everything is escaped
with html.escape, so a username like <script> renders as text instead of
running in the analyst's browser.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path

from . import __version__
from .models import SEVERITIES, Alert, Event

SEV_COLORS = {"critical": "#b42318", "high": "#d4581f", "medium": "#b8860b", "low": "#2f6fb3", "info": "#6b7280"}


def _fmt(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S")


# ------------------------------------------------------------------ console ---

def console_table(alerts: list[Alert]) -> str:
    if not alerts:
        return "No alerts."
    rows = [("SEVERITY", "FIRST SEEN (UTC)", "RULE", "SUMMARY")]
    rows += [(a.severity.upper(), _fmt(a.first_seen), a.rule_id, a.summary()) for a in alerts]
    widths = [max(len(r[i]) for r in rows) for i in range(3)]
    return "\n".join(f"{r[0]:<{widths[0]}}  {r[1]:<{widths[1]}}  {r[2]:<{widths[2]}}  {r[3]}" for r in rows)


def severity_counts(alerts: list[Alert]) -> dict[str, int]:
    c = Counter(a.severity for a in alerts)
    return {s: c.get(s, 0) for s in reversed(SEVERITIES)}


# --------------------------------------------------------------------- json ---

def write_json(alerts: list[Alert], path: Path) -> None:
    payload = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "tool": f"siem-tool {__version__}",
        "summary": severity_counts(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# --------------------------------------------------------------------- html ---

def _bar_rows(counter: Counter, limit: int = 8) -> str:
    items = counter.most_common(limit)
    if not items:
        return '<p class="dim">None.</p>'
    top = items[0][1]
    return "".join(
        f'<div class="bar"><span class="lbl">{escape(str(k))}</span>'
        f'<span class="track"><span class="fill" style="width:{v / top * 100:.0f}%"></span></span>'
        f'<span class="num">{v}</span></div>'
        for k, v in items
    )


def _alert_rows(alerts: list[Alert]) -> str:
    if not alerts:
        return '<p class="dim">No alerts. Either the logs are clean or the rules need tuning.</p>'
    out = []
    for a in alerts:
        color = SEV_COLORS.get(a.severity, "#6b7280")
        group = ", ".join(f"{escape(str(k))}={escape(str(v))}" for k, v in a.context().items()) or "-"
        mitre = " ".join(
            f'<a href="https://attack.mitre.org/techniques/{escape(t.replace(".", "/"))}/" target="_blank" '
            f'rel="noopener">{escape(t)}</a>' for t in a.mitre)
        evidence = "\n".join(escape(e.raw) for e in a.events[:50])
        more = f"\n… {a.count - 50} more" if a.count > 50 else ""
        out.append(f"""
<details class="alert">
  <summary>
    <span class="sev" style="background:{color}">{escape(a.severity.upper())}</span>
    <span class="title">{escape(a.title)}</span>
    <span class="meta">{group} · {a.count} event{'s' if a.count != 1 else ''} · {_fmt(a.first_seen)}</span>
  </summary>
  <div class="body">
    <p>{escape(a.description)}</p>
    <p class="dim">Rule <code>{escape(a.rule_id)}</code> · MITRE ATT&amp;CK {mitre or '-'} ·
       {_fmt(a.first_seen)} → {_fmt(a.last_seen)} UTC</p>
    <pre>{evidence}{escape(more)}</pre>
  </div>
</details>""")
    return "".join(out)


def _timeline(events: list[Event]) -> str:
    if not events:
        return '<p class="dim">No events.</p>'
    start = min(e.timestamp for e in events).replace(minute=0, second=0, microsecond=0)
    end = max(e.timestamp for e in events)
    # Hourly buckets for up to three days of logs, daily beyond that.
    step = timedelta(hours=1) if end - start <= timedelta(days=3) else timedelta(days=1)
    if step == timedelta(days=1):
        start = start.replace(hour=0)
    key = (lambda t: start + ((t - start) // step) * step)
    counts = Counter(key(e.timestamp) for e in events)
    buckets, t = [], start
    while t <= end:                       # include empty buckets so the axis is to scale
        buckets.append((t, counts.get(t, 0)))
        t += step
    top = max(counts.values())
    hourly = step == timedelta(hours=1)
    cols = "".join(
        f'<div class="col" title="{escape(b.strftime("%Y-%m-%d %H:00" if hourly else "%Y-%m-%d"))}: {n} events">'
        f'<span style="height:{n / top * 100:.0f}%"></span>'
        f'<em>{escape(b.strftime("%H" if hourly else "%m-%d")) if i % max(1, len(buckets) // 12) == 0 else ""}</em></div>'
        for i, (b, n) in enumerate(buckets))
    unit = "hour" if hourly else "day"
    return f'<div class="timeline">{cols}</div><p class="dim">Events per {unit} (UTC). Hover a bar for the count.</p>'


def write_html(alerts: list[Alert], events: list[Event], path: Path) -> None:
    counts = severity_counts(alerts)
    span = f"{_fmt(min(e.timestamp for e in events))} → {_fmt(max(e.timestamp for e in events))} UTC" if events else "no events"
    failures = [e for e in events if e.action == "logon" and e.outcome == "failure"]
    techniques = Counter(t for a in alerts for t in a.mitre)
    cards = "".join(
        f'<div class="card"><span class="n" style="color:{SEV_COLORS[s]}">{n}</span><span>{s}</span></div>'
        for s, n in counts.items())
    hosts = sorted({e.host for e in events if e.host})

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SIEM report</title>
<style>
  :root {{ --bg:#f6f7f9; --card:#fff; --fg:#1f2328; --dim:#646d78; --line:#dde1e6; --accent:#2f6fb3; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg:#111418; --card:#1a1f25; --fg:#e6e9ee; --dim:#97a1ad; --line:#2d343c; --accent:#6ea8e8; }} }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui, -apple-system, sans-serif; }}
  main {{ max-width:960px; margin:0 auto; padding:32px 18px 64px; }}
  h1 {{ margin:0 0 4px; font-size:26px; }} h2 {{ font-size:17px; margin:32px 0 10px; }}
  .dim {{ color:var(--dim); font-size:13px; }}
  .cards {{ display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin-top:20px; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:12px; text-align:center; }}
  .card .n {{ display:block; font-size:28px; font-weight:650; font-variant-numeric:tabular-nums; }}
  .card span:last-child {{ color:var(--dim); font-size:12px; text-transform:uppercase; letter-spacing:.06em; }}
  .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }}
  .panel {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }}
  .panel h2 {{ margin-top:0; }}
  .bar {{ display:grid; grid-template-columns:150px 1fr 40px; gap:8px; align-items:center; font-size:13px; margin:5px 0; }}
  .bar .lbl {{ overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-family:ui-monospace, monospace; }}
  .track {{ background:var(--line); border-radius:4px; height:10px; }}
  .fill {{ display:block; height:100%; background:var(--accent); border-radius:4px; }}
  .num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  .timeline {{ display:flex; align-items:flex-end; gap:3px; height:120px; padding-bottom:16px; }}
  .col {{ flex:1; height:100%; display:flex; flex-direction:column; justify-content:flex-end; position:relative; }}
  .col span {{ background:var(--accent); border-radius:3px 3px 0 0; min-height:2px; }}
  .col em {{ position:absolute; bottom:-16px; left:0; right:0; text-align:center; font-size:10px; color:var(--dim); font-style:normal; }}
  .alert {{ background:var(--card); border:1px solid var(--line); border-radius:10px; margin:8px 0; }}
  .alert summary {{ cursor:pointer; padding:10px 14px; display:flex; gap:10px; align-items:baseline; flex-wrap:wrap; }}
  .sev {{ color:#fff; font-size:11px; font-weight:700; letter-spacing:.05em; padding:2px 7px; border-radius:4px; }}
  .title {{ font-weight:600; }} .meta {{ color:var(--dim); font-size:13px; }}
  .body {{ padding:0 14px 12px; border-top:1px solid var(--line); }}
  pre {{ background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:10px; overflow-x:auto; font-size:12px; white-space:pre; }}
  code {{ font-family:ui-monospace, monospace; }} a {{ color:var(--accent); }}
  @media (max-width:700px) {{ .grid {{ grid-template-columns:1fr; }} .cards {{ grid-template-columns:repeat(3,1fr); }} }}
</style></head>
<body><main>
  <h1>SIEM report</h1>
  <p class="dim">{len(events)} events · {len(alerts)} alerts · {escape(span)} · hosts: {escape(", ".join(hosts) or "-")}</p>
  <div class="cards">{cards}</div>

  <h2>Alerts</h2>
  {_alert_rows(alerts)}

  <h2>Activity</h2>
  <div class="panel">{_timeline(events)}</div>

  <div class="grid" style="margin-top:18px">
    <div class="panel"><h2>Top sources of failed logons</h2>{_bar_rows(Counter(e.src_ip for e in failures if e.src_ip))}</div>
    <div class="panel"><h2>Most-targeted accounts</h2>{_bar_rows(Counter(e.user for e in failures if e.user))}</div>
    <div class="panel"><h2>MITRE ATT&amp;CK techniques</h2>{_bar_rows(techniques)}</div>
    <div class="panel"><h2>Events by type</h2>{_bar_rows(Counter(e.action for e in events))}</div>
  </div>

  <p class="dim" style="margin-top:40px">Generated {_fmt(datetime.now(timezone.utc))} UTC by siem-tool {__version__}.</p>
</main></body></html>
"""
    path.write_text(html, encoding="utf-8")
