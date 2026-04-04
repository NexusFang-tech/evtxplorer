"""Tests for output reporters."""

from __future__ import annotations
import csv
import json
import io
from pathlib import Path

import pytest

from evtxplorer.engine import load_rules, DetectionEngine
from evtxplorer.reporter import build_summary, write_json, write_csv, write_html
from tests.conftest import make_event

RULES_DIR = Path(__file__).parent.parent / "rules"


@pytest.fixture(scope="module")
def sample_findings():
    rules = load_rules(RULES_DIR)
    engine = DetectionEngine(rules)
    events = [
        make_event(event_id=1102),
        make_event(event_id=4625, channel="Security"),
        make_event(event_id=7045, channel="System"),
        make_event(event_id=4624, channel="Security", data={"LogonType": "10"}),
    ]
    findings = []
    for ev in events:
        findings.extend(engine.evaluate(ev))
    return findings


@pytest.fixture(scope="module")
def sample_summary(sample_findings):
    return build_summary(sample_findings, source_files=["test.xml"], total_events=10)


class TestJSONReporter:
    def test_writes_valid_json(self, sample_findings, sample_summary):
        buf = io.StringIO()
        write_json(sample_findings, sample_summary, buf)
        data = json.loads(buf.getvalue())
        assert "summary" in data
        assert "findings" in data

    def test_summary_fields_present(self, sample_findings, sample_summary):
        buf = io.StringIO()
        write_json(sample_findings, sample_summary, buf)
        data = json.loads(buf.getvalue())
        s = data["summary"]
        assert "total_findings" in s
        assert "findings_by_severity" in s
        assert "findings_by_technique" in s

    def test_finding_has_mitre_fields(self, sample_findings, sample_summary):
        buf = io.StringIO()
        write_json(sample_findings, sample_summary, buf)
        data = json.loads(buf.getvalue())
        for f in data["findings"]:
            assert "mitre_id" in f
            assert "mitre_name" in f
            assert "severity" in f


class TestCSVReporter:
    def test_writes_valid_csv(self, sample_findings):
        buf = io.StringIO()
        write_csv(sample_findings, buf)
        buf.seek(0)
        reader = csv.DictReader(buf)
        rows = list(reader)
        assert len(rows) == len(sample_findings)

    def test_csv_has_expected_columns(self, sample_findings):
        buf = io.StringIO()
        write_csv(sample_findings, buf)
        buf.seek(0)
        reader = csv.DictReader(buf)
        assert set(reader.fieldnames or []) >= {"severity", "rule_name", "mitre_id", "computer"}


class TestHTMLReporter:
    def test_writes_html(self, sample_findings, sample_summary):
        buf = io.StringIO()
        write_html(sample_findings, sample_summary, buf)
        html = buf.getvalue()
        assert "<!DOCTYPE html>" in html
        assert "EVTXplorer" in html

    def test_html_contains_findings(self, sample_findings, sample_summary):
        buf = io.StringIO()
        write_html(sample_findings, sample_summary, buf)
        html = buf.getvalue()
        # Each finding's rule name should appear in the report
        for f in sample_findings:
            assert f.rule.name in html
