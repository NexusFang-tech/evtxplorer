"""
Event log parser — handles both .evtx binary files and exported XML logs.
Normalizes records into a consistent dict schema for the detection engine.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Generator
import logging

logger = logging.getLogger(__name__)

# Windows Event Log XML namespace
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_NS_MAP = {"e": _NS}

# Normalized record schema keys
FIELD_EVENT_ID    = "event_id"
FIELD_CHANNEL     = "channel"
FIELD_COMPUTER    = "computer"
FIELD_TIMESTAMP   = "timestamp"
FIELD_PROVIDER    = "provider"
FIELD_LEVEL       = "level"
FIELD_TASK        = "task"
FIELD_USER_ID     = "user_id"
FIELD_DATA        = "data"          # dict of EventData Name→Value pairs
FIELD_RAW_XML     = "raw_xml"
FIELD_SOURCE_FILE = "source_file"


def parse_file(path: Path) -> Generator[dict, None, None]:
    """
    Auto-detect file type and yield normalized event records.

    Supports:
      - .evtx  — binary Windows Event Log (requires python-evtx)
      - .xml   — single exported event log XML (one <Events> root)
      - .txt   — same as .xml, some export tools use .txt
    """
    suffix = path.suffix.lower()
    if suffix == ".evtx":
        yield from _parse_evtx(path)
    elif suffix in (".xml", ".txt"):
        yield from _parse_xml(path)
    else:
        raise ValueError(
            f"Unsupported file type '{suffix}'. "
            "Supported: .evtx, .xml, .txt (exported XML)"
        )


# ---------------------------------------------------------------------------
# EVTX binary parser
# ---------------------------------------------------------------------------

def _parse_evtx(path: Path) -> Generator[dict, None, None]:
    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as e_views  # noqa: F401 — imported for side-effects
    except ImportError:
        raise ImportError(
            "python-evtx is required to parse .evtx files. "
            "Install it with: pip install python-evtx"
        )

    logger.info("Parsing EVTX binary: %s", path)
    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                normalized = _normalize_xml_string(xml_str, source=str(path))
                if normalized:
                    yield normalized
            except Exception as exc:
                logger.debug("Skipping malformed record: %s", exc)


# ---------------------------------------------------------------------------
# Exported XML parser
# ---------------------------------------------------------------------------

def _parse_xml(path: Path) -> Generator[dict, None, None]:
    logger.info("Parsing exported XML log: %s", path)
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError as exc:
        raise ValueError(f"Malformed XML in {path}: {exc}") from exc

    # Handle both <Events> wrapper and bare <Event> root
    if root.tag.endswith("Events") or root.tag == "Events":
        events = list(root)
    elif root.tag.endswith("Event") or root.tag == "Event":
        events = [root]
    else:
        # Try iterating children that look like events
        events = [
            child for child in root
            if child.tag.endswith("Event") or child.tag == "Event"
        ]

    for elem in events:
        try:
            xml_str = ET.tostring(elem, encoding="unicode")
            normalized = _normalize_xml_string(xml_str, source=str(path))
            if normalized:
                yield normalized
        except Exception as exc:
            logger.debug("Skipping malformed element: %s", exc)


# ---------------------------------------------------------------------------
# XML → normalized dict
# ---------------------------------------------------------------------------

def _normalize_xml_string(xml_str: str, source: str) -> dict | None:
    """Parse a single <Event> XML string into a normalized dict."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    def find(tag: str):
        # Try namespaced first, then bare
        el = root.find(f".//{{{_NS}}}{tag}")
        if el is None:
            el = root.find(f".//{tag}")
        return el

    system = find("System")
    if system is None:
        return None

    def sys_text(tag: str) -> str:
        el = system.find(f"{{{_NS}}}{tag}")
        if el is None:
            el = system.find(tag)
        return (el.text or "").strip() if el is not None else ""

    def sys_attr(tag: str, attr: str) -> str:
        el = system.find(f"{{{_NS}}}{tag}")
        if el is None:
            el = system.find(tag)
        return el.attrib.get(attr, "") if el is not None else ""

    # Pull EventData Name/Value pairs
    data: dict[str, str] = {}
    event_data = find("EventData")
    if event_data is not None:
        for item in event_data:
            name = item.attrib.get("Name", "")
            value = (item.text or "").strip()
            if name:
                data[name] = value
            else:
                # Unnamed data — store positionally
                data[f"param{len(data)}"] = value

    # UserData fallback (some providers use this instead of EventData)
    user_data = find("UserData")
    if user_data is not None and not data:
        for child in user_data.iter():
            if child.text and child.text.strip():
                tag_name = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                data[tag_name] = child.text.strip()

    try:
        event_id = int(sys_attr("EventID", "") or sys_text("EventID") or 0)
    except ValueError:
        event_id = 0

    return {
        FIELD_EVENT_ID:    event_id,
        FIELD_CHANNEL:     sys_attr("Channel", "") or sys_text("Channel"),
        FIELD_COMPUTER:    sys_text("Computer"),
        FIELD_TIMESTAMP:   sys_attr("TimeCreated", "SystemTime"),
        FIELD_PROVIDER:    sys_attr("Provider", "Name"),
        FIELD_LEVEL:       sys_text("Level"),
        FIELD_TASK:        sys_text("Task"),
        FIELD_USER_ID:     sys_attr("Security", "UserID"),
        FIELD_DATA:        data,
        FIELD_RAW_XML:     xml_str,
        FIELD_SOURCE_FILE: source,
    }
