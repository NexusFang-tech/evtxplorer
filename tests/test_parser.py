"""Tests for the event log parser."""

from __future__ import annotations
import pytest
from pathlib import Path

from evtxplorer.parser import parse_file, FIELD_EVENT_ID, FIELD_CHANNEL, FIELD_DATA

FIXTURES = Path(__file__).parent / "fixtures"


class TestXMLParser:
    def test_parses_brute_force_fixture(self):
        events = list(parse_file(FIXTURES / "brute_force.xml"))
        assert len(events) == 12
        for ev in events:
            assert ev[FIELD_EVENT_ID] == 4625
            assert "Security" in ev[FIELD_CHANNEL]

    def test_parses_log_cleared_fixture(self):
        events = list(parse_file(FIXTURES / "log_cleared.xml"))
        assert len(events) == 1
        assert events[0][FIELD_EVENT_ID] == 1102

    def test_parses_rdp_logon_fixture(self):
        events = list(parse_file(FIXTURES / "rdp_logon.xml"))
        assert len(events) == 1
        ev = events[0]
        assert ev[FIELD_EVENT_ID] == 4624
        assert ev[FIELD_DATA].get("LogonType") == "10"

    def test_parses_mixed_scenario(self):
        events = list(parse_file(FIXTURES / "mixed_scenario.xml"))
        assert len(events) == 54  # 35 recon + 15 brute + 1 rdp + 1 user + 1 group + 1 clear
        event_ids = {ev[FIELD_EVENT_ID] for ev in events}
        assert 4625 in event_ids
        assert 4624 in event_ids
        assert 1102 in event_ids

    def test_normalizes_event_data_fields(self):
        events = list(parse_file(FIXTURES / "brute_force.xml"))
        data = events[0][FIELD_DATA]
        assert data["TargetUserName"] == "administrator"
        assert data["LogonType"] == "3"

    def test_unsupported_extension_raises(self):
        with pytest.raises(ValueError, match="Unsupported file type"):
            list(parse_file(Path("test.log")))
