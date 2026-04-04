"""
Output reporters — JSON, CSV, and HTML report generation.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from jinja2 import Environment, BaseLoader

from evtxplorer.engine import Finding, SEVERITY_ORDER


# ---------------------------------------------------------------------------
# Summary dataclass
# ---------------------------------------------------------------------------

@dataclass
class AnalysisSummary:
    source_files: list[str]
    total_events_parsed: int
    total_findings: int
    findings_by_severity: dict[str, int]
    findings_by_rule: dict[str, int]
    findings_by_technique: dict[str, int]
    findings_by_tactic: dict[str, int]
    generated_at: str = ""

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(tz=timezone.utc).isoformat()


def build_summary(
    findings: list[Finding],
    source_files: list[str],
    total_events: int,
) -> AnalysisSummary:
    by_severity: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    by_rule: dict[str, int] = {}
    by_technique: dict[str, int] = {}
    by_tactic: dict[str, int] = {}

    for f in findings:
        by_severity[f.rule.severity] = by_severity.get(f.rule.severity, 0) + 1
        by_rule[f.rule.name] = by_rule.get(f.rule.name, 0) + 1

        if f.rule.mitre_id:
            label = f"{f.rule.mitre_id}: {f.rule.technique.name}" if f.rule.technique else f.rule.mitre_id
            by_technique[label] = by_technique.get(label, 0) + 1

        if f.rule.technique:
            for tactic in f.rule.technique.tactic:
                by_tactic[tactic] = by_tactic.get(tactic, 0) + 1

    return AnalysisSummary(
        source_files=source_files,
        total_events_parsed=total_events,
        total_findings=len(findings),
        findings_by_severity=by_severity,
        findings_by_rule=by_rule,
        findings_by_technique=by_technique,
        findings_by_tactic=by_tactic,
    )


# ---------------------------------------------------------------------------
# JSON reporter
# ---------------------------------------------------------------------------

def write_json(findings: list[Finding], summary: AnalysisSummary, out: Path | TextIO):
    payload = {
        "summary": {
            "generated_at":          summary.generated_at,
            "source_files":          summary.source_files,
            "total_events_parsed":   summary.total_events_parsed,
            "total_findings":        summary.total_findings,
            "findings_by_severity":  summary.findings_by_severity,
            "findings_by_rule":      summary.findings_by_rule,
            "findings_by_technique": summary.findings_by_technique,
            "findings_by_tactic":    summary.findings_by_tactic,
        },
        "findings": [f.to_dict() for f in findings],
    }
    text = json.dumps(payload, indent=2, default=str)
    if isinstance(out, Path):
        out.write_text(text, encoding="utf-8")
    else:
        out.write(text)


# ---------------------------------------------------------------------------
# CSV reporter
# ---------------------------------------------------------------------------

_CSV_FIELDS = [
    "timestamp", "severity", "rule_id", "rule_name",
    "mitre_id", "mitre_name", "mitre_tactic",
    "computer", "event_id", "description",
]


def write_csv(findings: list[Finding], out: Path | TextIO):
    def _open():
        if isinstance(out, Path):
            return open(out, "w", newline="", encoding="utf-8")
        return out

    fh = _open()
    try:
        writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for f in findings:
            d = f.to_dict()
            d["mitre_tactic"] = "; ".join(d.get("mitre_tactic", []))
            writer.writerow(d)
    finally:
        if isinstance(out, Path):
            fh.close()


# ---------------------------------------------------------------------------
# HTML reporter
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>EVTXplorer Report</title>
  <style>
    :root {
      --bg: #0d1117; --surface: #161b22; --border: #30363d;
      --text: #e6edf3; --muted: #8b949e;
      --critical: #f85149; --high: #ff7b72; --medium: #d29922;
      --low: #3fb950; --info: #58a6ff;
      --accent: #58a6ff;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.6; }
    header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 24px 32px; display: flex; justify-content: space-between; align-items: center; }
    header h1 { font-size: 1.4rem; font-weight: 600; }
    header span { color: var(--muted); font-size: 0.85rem; }
    .container { max-width: 1280px; margin: 0 auto; padding: 32px; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }
    .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }
    .stat-card .val { font-size: 2rem; font-weight: 700; }
    .stat-card .lbl { color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: .06em; margin-top: 4px; }
    .sev-critical .val { color: var(--critical); }
    .sev-high .val    { color: var(--high); }
    .sev-medium .val  { color: var(--medium); }
    .sev-low .val     { color: var(--low); }
    .sev-info .val    { color: var(--info); }
    .sev-total .val   { color: var(--accent); }
    h2 { font-size: 1rem; font-weight: 600; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
    table { width: 100%; border-collapse: collapse; margin-bottom: 32px; font-size: 0.85rem; }
    th { text-align: left; padding: 10px 12px; background: var(--surface); color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: .06em; border-bottom: 1px solid var(--border); position: sticky; top: 0; }
    td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
    tr:hover td { background: #1c2128; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; }
    .badge-critical { background: rgba(248,81,73,.15); color: var(--critical); }
    .badge-high     { background: rgba(255,123,114,.15); color: var(--high); }
    .badge-medium   { background: rgba(210,153,34,.15); color: var(--medium); }
    .badge-low      { background: rgba(63,185,80,.15); color: var(--low); }
    .badge-info     { background: rgba(88,166,255,.15); color: var(--info); }
    .mitre-link { color: var(--accent); text-decoration: none; font-family: monospace; font-size: 0.8rem; }
    .mitre-link:hover { text-decoration: underline; }
    .mono { font-family: monospace; font-size: 0.8rem; color: var(--muted); }
    details summary { cursor: pointer; color: var(--accent); font-size: 0.75rem; margin-top: 4px; }
    pre { background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 8px; font-size: 0.72rem; overflow-x: auto; margin-top: 8px; white-space: pre-wrap; color: var(--muted); }
    footer { text-align: center; padding: 32px; color: var(--muted); font-size: 0.75rem; border-top: 1px solid var(--border); }
  </style>
</head>
<body>
  <header>
    <h1>🔍 EVTXplorer — Detection Report</h1>
    <span>Generated {{ summary.generated_at }}</span>
  </header>
  <div class="container">

    <div class="stats">
      <div class="stat-card sev-total">
        <div class="val">{{ summary.total_findings }}</div>
        <div class="lbl">Total Findings</div>
      </div>
      {% for sev in ["critical","high","medium","low","info"] %}
      <div class="stat-card sev-{{ sev }}">
        <div class="val">{{ summary.findings_by_severity.get(sev, 0) }}</div>
        <div class="lbl">{{ sev|title }}</div>
      </div>
      {% endfor %}
      <div class="stat-card">
        <div class="val" style="color:var(--muted)">{{ summary.total_events_parsed }}</div>
        <div class="lbl">Events Parsed</div>
      </div>
    </div>

    <h2>Findings</h2>
    {% if findings %}
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Timestamp</th>
          <th>Rule</th>
          <th>MITRE</th>
          <th>Computer</th>
          <th>Event ID</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        {% for f in findings %}
        <tr>
          <td><span class="badge badge-{{ f.rule.severity }}">{{ f.rule.severity }}</span></td>
          <td class="mono">{{ f.timestamp[:19].replace("T"," ") if f.timestamp else "—" }}</td>
          <td>
            <strong>{{ f.rule.name }}</strong><br>
            <span class="mono">{{ f.rule.id }}</span>
          </td>
          <td>
            {% if f.rule.mitre_id %}
            <a class="mitre-link" href="{{ f.rule.technique.url if f.rule.technique else '#' }}" target="_blank">
              {{ f.rule.mitre_id }}
            </a><br>
            <span style="font-size:.75rem;color:var(--muted)">{{ f.rule.technique.name if f.rule.technique else '' }}</span>
            {% endif %}
          </td>
          <td class="mono">{{ f.computer or "—" }}</td>
          <td class="mono">{{ f.event_id }}</td>
          <td>
            {{ f.rule.description }}
            {% if f.data %}
            <details>
              <summary>Event data</summary>
              <pre>{{ f.data | tojson(indent=2) }}</pre>
            </details>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <p style="color:var(--muted);padding:24px 0;">No findings detected.</p>
    {% endif %}

    <h2>MITRE ATT&amp;CK Coverage</h2>
    <table>
      <thead><tr><th>Technique</th><th>Findings</th></tr></thead>
      <tbody>
        {% for tech, count in summary.findings_by_technique.items() | sort(attribute=1, reverse=True) %}
        <tr>
          <td>{{ tech }}</td>
          <td>{{ count }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>

    <h2>Source Files</h2>
    <ul style="list-style:none;color:var(--muted);font-family:monospace;font-size:.85rem;">
      {% for f in summary.source_files %}<li>{{ f }}</li>{% endfor %}
    </ul>

  </div>
  <footer>EVTXplorer v0.1.0 — github.com/NexusFang-Tech/evtxplorer</footer>
</body>
</html>"""


def write_html(findings: list[Finding], summary: AnalysisSummary, out: Path | TextIO):
    env = Environment(loader=BaseLoader())
    env.filters["tojson"] = lambda val, indent=None: json.dumps(val, indent=indent, default=str)
    template = env.from_string(_HTML_TEMPLATE)
    rendered = template.render(findings=findings, summary=summary)
    if isinstance(out, Path):
        out.write_text(rendered, encoding="utf-8")
    else:
        out.write(rendered)


import json  # noqa: E402 — needed in module scope for the filter
