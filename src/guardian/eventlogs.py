from __future__ import annotations

"""Structured parsing helpers for Windows Event Log output.

The scanner asks wevtutil for XML and keeps normalized event metadata instead
of searching an unstructured, localized text dump. A conservative text parser
remains for old reports and portable unit tests.
"""

import re
import xml.etree.ElementTree as ET
from typing import Any

_EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _child_text(parent: ET.Element | None, name: str) -> str:
    if parent is None:
        return ""
    for child in parent:
        if _local_name(child.tag).lower() == name.lower():
            return (child.text or "").strip()
    return ""


def _parse_xml_events(output: str) -> list[dict[str, Any]]:
    text = output.lstrip("\ufeff\r\n \t")
    if not text:
        return []
    # wevtutil normally returns an <Events> wrapper. Some providers / Windows
    # builds may return a single <Event>; tolerate either form.
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        # Accommodate concatenated Event fragments from wrappers that omit the
        # outer node. This is deliberately not a general XML recovery parser.
        fragments = re.findall(r"<Event\b.*?</Event>", text, flags=re.IGNORECASE | re.DOTALL)
        if not fragments:
            return []
        root = ET.fromstring("<Events>" + "".join(fragments) + "</Events>")

    elements = [root] if _local_name(root.tag).lower() == "event" else [
        element for element in root.iter() if _local_name(element.tag).lower() == "event"
    ]
    records: list[dict[str, Any]] = []
    for event in elements:
        system = next((x for x in event if _local_name(x.tag).lower() == "system"), None)
        provider_node = next((x for x in (system if system is not None else ()) if _local_name(x.tag).lower() == "provider"), None)
        time_node = next((x for x in (system if system is not None else ()) if _local_name(x.tag).lower() == "timecreated"), None)
        execution_node = next((x for x in (system if system is not None else ()) if _local_name(x.tag).lower() == "execution"), None)
        data: dict[str, str] = {}
        for container in event:
            if _local_name(container.tag).lower() == "eventdata":
                for node in container:
                    if _local_name(node.tag).lower() == "data":
                        key = node.attrib.get("Name") or node.attrib.get("name") or f"Data{len(data) + 1}"
                        data[str(key)] = (node.text or "").strip()
            elif _local_name(container.tag).lower() == "userdata":
                # UserData providers often nest named XML fields rather than
                # using EventData/Data. Preserve each leaf by its local tag.
                for node in container.iter():
                    if node is container or list(node):
                        continue
                    value = (node.text or "").strip()
                    if value:
                        data.setdefault(_local_name(node.tag), value)
        provider = provider_node.attrib.get("Name", "") if provider_node is not None else ""
        timestamp = time_node.attrib.get("SystemTime", "") if time_node is not None else ""
        records.append({
            "event_id": _child_text(system, "EventID"),
            "channel": _child_text(system, "Channel"),
            "provider": provider,
            "timestamp": timestamp,
            "record_id": _child_text(system, "EventRecordID"),
            "execution_pid": execution_node.attrib.get("ProcessID", "") if execution_node is not None else "",
            "execution_tid": execution_node.attrib.get("ThreadID", "") if execution_node is not None else "",
            "data": data,
            "raw": ET.tostring(event, encoding="unicode")[:12000],
            "format": "xml",
        })
    return records


def _parse_legacy_text(output: str) -> list[dict[str, Any]]:
    if not output.strip():
        return []
    chunks = re.split(r"(?=^\s*Event\[\d+\]:\s*$)", output, flags=re.IGNORECASE | re.MULTILINE)
    records: list[dict[str, Any]] = []
    for chunk in chunks:
        if not chunk.strip():
            continue
        data: dict[str, str] = {}
        for line in chunk.splitlines():
            match = re.match(r"^\s*([A-Za-z][A-Za-z0-9 _./()-]{0,80})\s*:\s*(.*?)\s*$", line)
            if match:
                key, value = match.groups()
                key = key.strip()
                if key.lower() in {"event id", "provider", "channel", "time created", "event record id", "process id", "thread id"}:
                    continue
                data[key] = value
        event_id = re.search(r"\bEvent\s*ID\s*:\s*(\d+)", chunk, flags=re.IGNORECASE)
        provider = re.search(r"\bProvider\s*:\s*(.+)", chunk, flags=re.IGNORECASE)
        channel = re.search(r"\bChannel\s*:\s*(.+)", chunk, flags=re.IGNORECASE)
        time_match = re.search(r"\bTime\s*Created\s*:\s*(.+)", chunk, flags=re.IGNORECASE)
        record_match = re.search(r"\bEvent\s*Record\s*ID\s*:\s*(\d+)", chunk, flags=re.IGNORECASE)
        records.append({
            "event_id": event_id.group(1) if event_id else "",
            "channel": channel.group(1).strip() if channel else "",
            "provider": provider.group(1).strip() if provider else "",
            "timestamp": time_match.group(1).strip() if time_match else "",
            "record_id": record_match.group(1) if record_match else "",
            "execution_pid": "",
            "execution_tid": "",
            "data": data,
            "raw": chunk[:12000],
            "format": "text",
        })
    return records


def parse_event_log_output_with_status(output: str) -> tuple[list[dict[str, Any]], str]:
    """Parse an Event Log response and report whether XML parsing succeeded.

    Status is one of ``xml``, ``legacy_text``, ``empty`` or ``parse_error``.
    A malformed XML response must not be mistaken for an empty-but-successful
    channel read in the investigation coverage report.
    """
    if not output or not output.strip():
        return [], "empty"
    text = output.lstrip("\ufeff\r\n \t")
    if text.startswith("<"):
        records = _parse_xml_events(text)
        if records:
            return records, "xml"
        # ``<Events />`` is a valid empty query. An actual Event element with
        # no parseable records means the response was malformed / truncated.
        if re.search(r"<Event(?:\s|>)", text, flags=re.IGNORECASE):
            return [], "parse_error"
        try:
            ET.fromstring(text)
            return [], "xml"
        except ET.ParseError:
            return [], "parse_error"
    legacy = _parse_legacy_text(output)
    return legacy, "legacy_text" if legacy else "empty"


def parse_event_log_output(output: str) -> list[dict[str, Any]]:
    """Parse wevtutil XML, falling back to legacy text for old logs/tests."""
    return parse_event_log_output_with_status(output)[0]


def event_text(record: dict[str, Any]) -> str:
    """Return fields only (not provider metadata) as searchable normalized text."""
    data = record.get("data", {})
    if isinstance(data, dict):
        return "\n".join(f"{key}: {value}" for key, value in data.items()).lower()
    return str(data).lower()


def event_field(record: dict[str, Any], *names: str) -> str:
    data = record.get("data", {})
    if not isinstance(data, dict):
        return ""
    wanted = {name.replace("_", "").replace(" ", "").lower() for name in names}
    for key, value in data.items():
        normalized = str(key).replace("_", "").replace(" ", "").lower()
        if normalized in wanted:
            return str(value or "").strip()
    return ""
