"""
Detection engine — loads YAML rules and evaluates them against normalized event records.

Rule schema
-----------
Each rule is a YAML file (or inline dict) with this structure:

    id: EVT-001
    name: "Brute Force Login Attempts"
    description: "Detects repeated failed logon attempts indicating password guessing."
    severity: high          # critical | high | medium | low | info
    mitre: T1110.001        # single technique ID
    tags: [credential-access, brute-force]
    references:
      - https://learn.microsoft.com/...
    match:
      event_id: 4625        # required: int or list[int]
      channel: Security     # optional: substring match against channel
      provider: ""          # optional: substring match against provider name
      data:                 # optional: EventData field conditions
        LogonType: "3"      # exact match
    threshold:              # optional: aggregation window
      count: 5              # fire only after N matches within window_seconds
      window_seconds: 60
      group_by: [computer, data.TargetUserName]   # aggregate key fields
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from evtxplorer import mitre
from evtxplorer.parser import (
    FIELD_CHANNEL, FIELD_DATA, FIELD_EVENT_ID,
    FIELD_PROVIDER, FIELD_COMPUTER, FIELD_TIMESTAMP,
    FIELD_USER_ID,
)

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: str
    mitre_id: str
    tags: list[str]
    references: list[str]
    # match conditions
    event_ids: list[int]
    channel_contains: str
    provider_contains: str
    data_conditions: dict[str, str]
    # optional threshold
    threshold_count: int
    threshold_window: int
    threshold_group_by: list[str]
    # resolved MITRE metadata (filled post-load)
    technique: mitre.Technique | None = field(default=None, repr=False)

    def __post_init__(self):
        self.technique = mitre.get(self.mitre_id)
        if self.mitre_id and not self.technique:
            logger.warning(
                "Rule %s references unknown MITRE technique %s", self.id, self.mitre_id
            )


@dataclass
class Finding:
    rule: Rule
    event: dict
    timestamp: str
    matched_at: float = field(default_factory=time.time)
    # For threshold findings: list of contributing events
    contributing_events: list[dict] = field(default_factory=list)
    is_threshold_finding: bool = False

    # Convenience accessors
    @property
    def computer(self) -> str:
        return self.event.get(FIELD_COMPUTER, "")

    @property
    def event_id(self) -> int:
        return self.event.get(FIELD_EVENT_ID, 0)

    @property
    def data(self) -> dict:
        return self.event.get(FIELD_DATA, {})

    def to_dict(self) -> dict:
        t = self.rule.technique
        return {
            "rule_id":          self.rule.id,
            "rule_name":        self.rule.name,
            "severity":         self.rule.severity,
            "mitre_id":         self.rule.mitre_id,
            "mitre_name":       t.name if t else "",
            "mitre_tactic":     t.tactic if t else [],
            "mitre_url":        t.url if t else "",
            "tags":             self.rule.tags,
            "timestamp":        self.timestamp,
            "computer":         self.computer,
            "event_id":         self.event_id,
            "event_data":       self.data,
            "description":      self.rule.description,
            "references":       self.rule.references,
            "threshold_count":  len(self.contributing_events) if self.is_threshold_finding else 1,
        }


# ---------------------------------------------------------------------------
# Rule loader
# ---------------------------------------------------------------------------

def load_rules(rules_dir: Path) -> list[Rule]:
    """Load all .yml / .yaml rule files from a directory."""
    rules: list[Rule] = []
    for path in sorted(rules_dir.glob("**/*.y*ml")):
        try:
            with path.open() as fh:
                docs = list(yaml.safe_load_all(fh))
            for doc in docs:
                if not doc:
                    continue
                rule = _parse_rule(doc, source=str(path))
                if rule:
                    rules.append(rule)
            logger.debug("Loaded %d rule(s) from %s", len(docs), path.name)
        except Exception as exc:
            logger.error("Failed to load rule file %s: %s", path, exc)
    logger.info("Loaded %d rules total from %s", len(rules), rules_dir)
    return rules


def _parse_rule(doc: dict, source: str) -> Rule | None:
    try:
        match = doc.get("match", {})
        raw_ids = match.get("event_id", [])
        event_ids = [raw_ids] if isinstance(raw_ids, int) else list(raw_ids)

        threshold = doc.get("threshold", {})

        return Rule(
            id=doc["id"],
            name=doc["name"],
            description=doc.get("description", ""),
            severity=doc.get("severity", "medium").lower(),
            mitre_id=doc.get("mitre", ""),
            tags=doc.get("tags", []),
            references=doc.get("references", []),
            event_ids=event_ids,
            channel_contains=match.get("channel", ""),
            provider_contains=match.get("provider", ""),
            data_conditions=match.get("data", {}),
            threshold_count=threshold.get("count", 0),
            threshold_window=threshold.get("window_seconds", 0),
            threshold_group_by=threshold.get("group_by", []),
        )
    except KeyError as exc:
        logger.error("Rule in %s missing required field: %s", source, exc)
        return None


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------

class DetectionEngine:
    """
    Evaluates a stream of normalized event records against loaded rules.

    Usage:
        engine = DetectionEngine(rules)
        for event in parser.parse_file(path):
            findings = engine.evaluate(event)
            for finding in findings:
                ...
        # Flush any pending threshold findings
        for finding in engine.flush():
            ...
    """

    def __init__(self, rules: list[Rule]):
        self.rules = rules
        # threshold state: rule_id → group_key → list[event]
        self._threshold_state: dict[str, dict[str, list[dict]]] = defaultdict(
            lambda: defaultdict(list)
        )

    def evaluate(self, event: dict) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            if not self._matches(rule, event):
                continue
            if rule.threshold_count > 0:
                result = self._handle_threshold(rule, event)
                if result:
                    findings.append(result)
            else:
                findings.append(Finding(
                    rule=rule,
                    event=event,
                    timestamp=event.get(FIELD_TIMESTAMP, ""),
                ))
        return findings

    def flush(self) -> list[Finding]:
        """Return any threshold findings that never reached count but have events."""
        findings: list[Finding] = []
        for rule_id, groups in self._threshold_state.items():
            rule = next((r for r in self.rules if r.id == rule_id), None)
            if not rule:
                continue
            for group_key, events in groups.items():
                if len(events) >= rule.threshold_count:
                    findings.append(Finding(
                        rule=rule,
                        event=events[-1],
                        timestamp=events[-1].get(FIELD_TIMESTAMP, ""),
                        contributing_events=events,
                        is_threshold_finding=True,
                    ))
        return findings

    # ── Private helpers ──────────────────────────────────────────────────────

    def _matches(self, rule: Rule, event: dict) -> bool:
        # Event ID must match
        if rule.event_ids and event.get(FIELD_EVENT_ID) not in rule.event_ids:
            return False

        # Channel substring match (case-insensitive)
        if rule.channel_contains:
            channel = event.get(FIELD_CHANNEL, "")
            if rule.channel_contains.lower() not in channel.lower():
                return False

        # Provider substring match (case-insensitive)
        if rule.provider_contains:
            provider = event.get(FIELD_PROVIDER, "")
            if rule.provider_contains.lower() not in provider.lower():
                return False

        # EventData field conditions
        data = event.get(FIELD_DATA, {})
        for field_name, expected in rule.data_conditions.items():
            actual = data.get(field_name, "")
            if isinstance(expected, list):
                if actual not in [str(e) for e in expected]:
                    return False
            else:
                if actual != str(expected):
                    return False

        return True

    def _handle_threshold(self, rule: Rule, event: dict) -> Finding | None:
        group_key = self._group_key(rule, event)
        bucket = self._threshold_state[rule.id][group_key]

        # Evict events outside the time window
        if rule.threshold_window > 0 and bucket:
            now_ts = _parse_timestamp(event.get(FIELD_TIMESTAMP, ""))
            if now_ts is not None:
                bucket[:] = [
                    e for e in bucket
                    if _parse_timestamp(e.get(FIELD_TIMESTAMP, "")) is not None
                    and now_ts - _parse_timestamp(e.get(FIELD_TIMESTAMP, "")) <= rule.threshold_window
                ]

        bucket.append(event)

        if len(bucket) >= rule.threshold_count:
            finding = Finding(
                rule=rule,
                event=event,
                timestamp=event.get(FIELD_TIMESTAMP, ""),
                contributing_events=list(bucket),
                is_threshold_finding=True,
            )
            bucket.clear()
            return finding
        return None

    def _group_key(self, rule: Rule, event: dict) -> str:
        parts: list[str] = []
        data = event.get(FIELD_DATA, {})
        for field_path in rule.threshold_group_by:
            if field_path.startswith("data."):
                parts.append(data.get(field_path[5:], ""))
            elif field_path == "computer":
                parts.append(event.get(FIELD_COMPUTER, ""))
            elif field_path == "user_id":
                parts.append(event.get(FIELD_USER_ID, ""))
            else:
                parts.append(str(event.get(field_path, "")))
        return "|".join(parts) or "_default"


def _parse_timestamp(ts: str) -> float | None:
    """Parse ISO-8601 timestamp to Unix float. Returns None on failure."""
    if not ts:
        return None
    from datetime import datetime, timezone
    try:
        # Remove trailing Z, handle optional microseconds
        clean = ts.rstrip("Z").split("+")[0]
        dt = datetime.fromisoformat(clean).replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None
