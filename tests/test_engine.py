"""Tests for the detection engine and rule matching."""

from __future__ import annotations
import pytest
from pathlib import Path

from evtxplorer.engine import DetectionEngine, load_rules, Rule
from tests.conftest import make_event

RULES_DIR = Path(__file__).parent.parent / "rules"


@pytest.fixture(scope="session")
def rules():
    return load_rules(RULES_DIR)


@pytest.fixture(scope="session")
def engine(rules):
    return DetectionEngine(rules)


class TestRuleLoading:
    def test_loads_rules_from_directory(self, rules):
        assert len(rules) >= 15, f"Expected ≥15 rules, got {len(rules)}"

    def test_all_rules_have_required_fields(self, rules):
        for rule in rules:
            assert rule.id, f"Rule missing id: {rule}"
            assert rule.name, f"Rule missing name: {rule}"
            assert rule.severity in ("critical", "high", "medium", "low", "info")

    def test_rules_with_mitre_have_resolved_technique(self, rules):
        for rule in rules:
            if rule.mitre_id:
                assert rule.technique is not None, \
                    f"Rule {rule.id} has MITRE {rule.mitre_id} but technique not resolved"


class TestEventMatching:
    def test_detects_failed_logon(self, rules):
        engine = DetectionEngine(rules)
        ev = make_event(event_id=4625, channel="Security")
        findings = engine.evaluate(ev)
        rule_ids = {f.rule.id for f in findings}
        assert "EVT-C001" in rule_ids

    def test_no_false_positive_on_successful_logon(self, rules):
        engine = DetectionEngine(rules)
        ev = make_event(event_id=4624, channel="Security", data={"LogonType": "5"})
        findings = engine.evaluate(ev)
        # Should not fire brute force rules
        rule_ids = {f.rule.id for f in findings}
        assert "EVT-C001" not in rule_ids
        assert "EVT-C002" not in rule_ids

    def test_detects_log_cleared(self, rules):
        engine = DetectionEngine(rules)
        ev = make_event(event_id=1102)
        findings = engine.evaluate(ev)
        rule_ids = {f.rule.id for f in findings}
        assert "EVT-P006" in rule_ids

    def test_log_cleared_is_critical(self, rules):
        engine = DetectionEngine(rules)
        ev = make_event(event_id=1102)
        findings = engine.evaluate(ev)
        critical = [f for f in findings if f.rule.id == "EVT-P006"]
        assert critical[0].rule.severity == "critical"

    def test_detects_rdp_logon(self, rules):
        engine = DetectionEngine(rules)
        ev = make_event(event_id=4624, channel="Security", data={"LogonType": "10"})
        findings = engine.evaluate(ev)
        rule_ids = {f.rule.id for f in findings}
        assert "EVT-L001" in rule_ids

    def test_detects_new_service(self, rules):
        engine = DetectionEngine(rules)
        ev = make_event(event_id=7045, channel="System")
        findings = engine.evaluate(ev)
        rule_ids = {f.rule.id for f in findings}
        assert "EVT-L004" in rule_ids

    def test_channel_filter_prevents_false_match(self, rules):
        engine = DetectionEngine(rules)
        # 4625 on non-Security channel should not match EVT-C001
        ev = make_event(event_id=4625, channel="Application")
        findings = engine.evaluate(ev)
        rule_ids = {f.rule.id for f in findings}
        assert "EVT-C001" not in rule_ids

    def test_data_condition_matching(self, rules):
        engine = DetectionEngine(rules)
        # RDP logon = LogonType 10
        ev_rdp = make_event(event_id=4624, channel="Security", data={"LogonType": "10"})
        ev_net = make_event(event_id=4624, channel="Security", data={"LogonType": "3"})
        rdp_findings = {f.rule.id for f in engine.evaluate(ev_rdp)}
        net_findings = {f.rule.id for f in engine.evaluate(ev_net)}
        assert "EVT-L001" in rdp_findings
        assert "EVT-L001" not in net_findings


class TestThresholdDetection:
    def test_brute_force_threshold_fires_at_count(self, rules):
        engine = DetectionEngine(rules)
        results = []
        for i in range(10):
            ts = f"2024-06-15T10:00:{i:02d}.000000Z"
            ev = make_event(
                event_id=4625,
                channel="Security",
                computer="DC01",
                timestamp=ts,
                data={"TargetUserName": "admin", "LogonType": "3"},
            )
            results.extend(engine.evaluate(ev))

        threshold_findings = [f for f in results if f.rule.id == "EVT-C002"]
        assert len(threshold_findings) == 1
        assert threshold_findings[0].is_threshold_finding
        assert len(threshold_findings[0].contributing_events) == 10

    def test_threshold_resets_after_firing(self, rules):
        engine = DetectionEngine(rules)
        # Fire first threshold
        for i in range(10):
            ts = f"2024-06-15T10:00:{i:02d}.000000Z"
            ev = make_event(
                event_id=4625, channel="Security", computer="DC01",
                timestamp=ts, data={"TargetUserName": "admin"},
            )
            engine.evaluate(ev)

        # Fire second round — should produce another finding
        second_results = []
        for i in range(10):
            ts = f"2024-06-15T10:01:{i:02d}.000000Z"
            ev = make_event(
                event_id=4625, channel="Security", computer="DC01",
                timestamp=ts, data={"TargetUserName": "admin"},
            )
            second_results.extend(engine.evaluate(ev))

        threshold_findings = [f for f in second_results if f.rule.id == "EVT-C002"]
        assert len(threshold_findings) == 1

    def test_threshold_groups_by_key(self, rules):
        engine = DetectionEngine(rules)
        # Two different users — should not combine into single threshold
        for i in range(5):
            ts = f"2024-06-15T10:00:{i:02d}.000000Z"
            ev = make_event(
                event_id=4625, channel="Security", computer="DC01",
                timestamp=ts, data={"TargetUserName": "userA"},
            )
            engine.evaluate(ev)
            ev2 = make_event(
                event_id=4625, channel="Security", computer="DC01",
                timestamp=ts, data={"TargetUserName": "userB"},
            )
            engine.evaluate(ev2)

        # Neither user reached threshold of 10
        flushed = engine.flush()
        threshold_findings = [f for f in flushed if f.rule.id == "EVT-C002"]
        assert len(threshold_findings) == 0  # 5 < threshold of 10
