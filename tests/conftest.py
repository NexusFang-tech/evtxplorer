"""Shared fixtures for EVTXplorer tests."""

from __future__ import annotations
import pytest
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def make_event(
    event_id: int = 4624,
    channel: str = "Security",
    computer: str = "TESTPC",
    timestamp: str = "2024-06-15T10:00:00.000000Z",
    provider: str = "Microsoft-Windows-Security-Auditing",
    data: dict | None = None,
) -> dict:
    """Build a normalized event dict for testing."""
    return {
        "event_id":    event_id,
        "channel":     channel,
        "computer":    computer,
        "timestamp":   timestamp,
        "provider":    provider,
        "level":       "0",
        "task":        "",
        "user_id":     "",
        "data":        data or {},
        "raw_xml":     "",
        "source_file": "test",
    }
