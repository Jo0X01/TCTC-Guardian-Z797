from __future__ import annotations

"""Targeted real-time telemetry for the analyzed TCTC/Z797 chain.

The sensor subscribes to existing Windows Event Log providers and watches only
sample-specific Temp\\Local staging roots. It does not inject into processes,
install a driver, alter audit policy, or contact any remote infrastructure.
"""

import ctypes
import hashlib
import json
import os
import queue
import re
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable

from .indicators import (
    KNOWN_SAMPLE_ARTIFACTS,
    is_known_staging_path,
    known_sample_artifact,
    normalized,
)
from guardian.models import Finding, utc_now
from guardian.scanner import sha256_file
from guardian.threat_profile import (
    CONFIRMED_CAMPAIGN_DOMAINS,
    CONFIRMED_CAMPAIGN_IPS,
)
from guardian import windows

EventCallback = Callable[[dict[str, Any]], None]

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_CHANNEL = "Security"
POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
TASK_SCHEDULER_CHANNEL = "Microsoft-Windows-TaskScheduler/Operational"
WMI_ACTIVITY_CHANNEL = "Microsoft-Windows-WMI-Activity/Operational"

# Sysmon: process, network, image, injection/process access/tampering, file,
# registry and DNS event families. Security and PowerShell are separate.
SUBSCRIPTIONS = (
    # Matches the shipped detect-only Sysmon XML; legacy Event 27 and events
    # not enabled by this policy are queried historically but not subscribed live.
    (
        SYSMON_CHANNEL,
        "*[System[(EventID=1 or EventID=2 or EventID=3 or EventID=4 or EventID=7 or EventID=8 or EventID=10 or EventID=11 or EventID=12 or EventID=13 or EventID=14 or EventID=16 or EventID=22 or EventID=25 or EventID=26 or EventID=29)]]",
        "Sysmon",
    ),
    (
        SECURITY_CHANNEL,
        "*[System[(EventID=4688 or EventID=4697 or EventID=4698 or EventID=4702)]]",
        "Security",
    ),
    (POWERSHELL_CHANNEL, "*[System[(EventID=4103 or EventID=4104)]]", "PowerShell"),
    (
        TASK_SCHEDULER_CHANNEL,
        "*[System[(EventID=106 or EventID=140 or EventID=141 or EventID=200 or EventID=201)]]",
        "Task Scheduler",
    ),
    (
        WMI_ACTIVITY_CHANNEL,
        "*[System[(EventID=5857 or EventID=5858 or EventID=5859 or EventID=5860 or EventID=5861)]]",
        "WMI Activity",
    ),
)

KNOWN_STAGING_NAMES = {
    "crandle.txt",
    "z797.ps1",
    "tctc.bba",
}
TARGET_MEMORY_PROCESSES = {"runtimebroker.exe", "explorer.exe", "chrome.exe"}


def sysmon_readiness() -> tuple[bool, str]:
    """Require a running Sysmon service and its Operational event channel.

    This verifies service/channel availability, not that every desired event
    filter is emitting records. The installer separately records its policy.
    """
    if not windows.IS_WINDOWS:
        return False, "Sysmon is available only on Windows."
    service_errors = []
    running_service = ""
    for service_name in ("Sysmon64", "Sysmon"):
        code, out, err = windows.run_command(
            ["sc.exe", "query", service_name], timeout=10
        )
        text = (out + "\n" + err).lower()
        if code == 0 and "running" in text:
            running_service = service_name
            break
        service_errors.append(
            f"{service_name}: {(err or out).strip() or 'not installed'}"
        )
    if not running_service:
        return False, "No running Sysmon service was found. " + "; ".join(
            service_errors
        )
    code, out, err = windows.run_command(
        ["wevtutil.exe", "gl", SYSMON_CHANNEL], timeout=10
    )
    if code != 0:
        return (
            False,
            f"{running_service} is running, but the Sysmon Operational channel is unavailable: {(err or out).strip()}",
        )
    program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
    marker_path = Path(program_data) / "TCTC Guardian Z797" / "sysmon-install.json"
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8-sig"))
        config_path = Path(str(marker.get("ConfigPath", "")))
        binary_path = Path(str(marker.get("BinaryPath", "")))
        expected_hash = str(marker.get("ConfigSha256", "")).lower()
        if (
            not config_path.is_file()
            or not binary_path.is_file()
            or len(expected_hash) != 64
        ):
            raise ValueError("installation marker paths or hash are incomplete")
        actual_hash = hashlib.sha256(config_path.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            raise ValueError(
                "the installed TCTC Sysmon configuration file no longer matches its recorded SHA-256"
            )
        config_text = config_path.read_text(encoding="utf-8-sig", errors="replace")
        if "<FileExecutableDetected" not in config_text:
            raise ValueError(
                "the managed Sysmon XML is missing the required PE-detection rule"
            )
        config_has_pe_block = "<FileBlockExecutable" in config_text
        if config_has_pe_block or marker.get("BlockPeCreation") is not False:
            raise ValueError(
                "this release requires the detect-only Sysmon policy; PE creation blocking must be disabled"
            )
        if str(marker.get("ServiceName", "")) != running_service:
            raise ValueError(
                "the running Sysmon service does not match the TCTC installation marker"
            )
        if not isinstance(marker.get("BlockPeCreation"), bool):
            raise ValueError(
                "the installed Sysmon PE-block mode is missing from the configuration marker"
            )
    except Exception as exc:
        return (
            False,
            f"Sysmon is running, but the TCTC-managed configuration could not be verified: {exc}. Restart TCTC Guardian Z797 to run its automatic Sysmon setup.",
        )
    return (
        True,
        f"{running_service} is running, {SYSMON_CHANNEL} is available, the TCTC Sysmon configuration hash is verified, and PE creation is detect-only.",
    )


CAMPAIGN_MARKERS = (
    "z797.ps1",
    "crandle.txt",
    "tctc.bba",
    "benderoflight.com",
    "survivomatic.com",
    "ruthaiv.com",
    "/nfront.php",
    "/nback.php",
    "93.94.52.29",
    "109.238.86.137",
)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_event_xml(xml_text: str) -> dict[str, Any]:
    """Parse an Event Log XML record into provider, id, time and named data."""
    root = ET.fromstring(xml_text)
    system = next((x for x in root if _local_name(x.tag) == "System"), None)
    if system is None:
        raise ValueError("Event XML has no System element")
    result: dict[str, Any] = {"data": {}}
    for node in system:
        name = _local_name(node.tag)
        if name == "Provider":
            result["provider"] = node.attrib.get("Name", "")
        elif name == "EventID":
            result["event_id"] = int((node.text or "0").strip() or 0)
        elif name == "EventRecordID":
            result["record_id"] = (node.text or "").strip()
        elif name == "Channel":
            result["channel"] = (node.text or "").strip()
        elif name == "TimeCreated":
            result["time"] = node.attrib.get("SystemTime", "")
        elif name == "Execution":
            result["system_pid"] = node.attrib.get("ProcessID", "")
    for section in root:
        section_name = _local_name(section.tag)
        if section_name == "EventData":
            for index, item in enumerate(section):
                if _local_name(item.tag) != "Data":
                    continue
                key = item.attrib.get("Name") or f"Data{index}"
                result["data"][key] = item.text or ""
        elif section_name == "UserData":
            for item in section.iter():
                if item is section or len(item):
                    continue
                result["data"].setdefault(_local_name(item.tag), item.text or "")
    result.setdefault("event_id", 0)
    result.setdefault("provider", "")
    result.setdefault("channel", "")
    result.setdefault("time", "")
    result.setdefault("system_pid", "")
    return result


def redact_sensitive_text(value: str, limit: int = 900) -> str:
    """Keep useful telemetry while masking common secrets before logging/reporting."""
    text = str(value or "")
    patterns = (
        (r"(?i)(--?password\s+)[^\s]+", r"\1<redacted>"),
        (r"(?i)(--?token\s+)[^\s]+", r"\1<redacted>"),
        (r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+", r"\1<redacted>"),
        (r"(?i)(access_token|refresh_token|client_secret)=([^&\s]+)", r"\1=<redacted>"),
    )
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text[:limit]


def _field(data: dict[str, str], *names: str) -> str:
    lower = {str(k).lower(): str(v or "") for k, v in data.items()}
    for name in names:
        if lower.get(name.lower()):
            return lower[name.lower()]
    return ""


def _sha256_from_sysmon(value: str) -> str:
    match = re.search(r"(?i)(?:^|[,;\s])SHA256=([0-9a-f]{64})(?:$|[,;\s])", value or "")
    if match:
        return match.group(1).lower()
    match = re.fullmatch(r"(?i)[0-9a-f]{64}", (value or "").strip())
    return match.group(0).lower() if match else ""


def _normalize_pid(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        return str(int(raw, 16) if raw.lower().startswith("0x") else int(raw, 10))
    except ValueError:
        return raw


def _has_process_write_access(value: str) -> bool:
    """Return whether Sysmon GrantedAccess contains process-modification rights."""
    raw = str(value or "").strip()
    if not raw:
        return False
    try:
        mask = int(raw, 16) if raw.lower().startswith("0x") else int(raw, 10)
    except ValueError:
        return False
    # PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE.
    return bool(mask & (0x0002 | 0x0008 | 0x0020))


def _under_staging(path: str) -> bool:
    if not path:
        return False
    try:
        return is_known_staging_path(path)
    except Exception:
        return False


def _is_target_process(path_or_name: str) -> bool:
    return (
        Path(str(path_or_name or "").replace("\\", "/")).name.lower()
        in TARGET_MEMORY_PROCESSES
    )


def build_subscription_plan(
    *,
    monitor_processes: bool = True,
    monitor_files: bool = True,
    monitor_network: bool = True,
    monitor_persistence: bool = True,
    monitor_powershell: bool = True,
) -> list[tuple[str, str, str]]:
    """Return provider subscriptions selected by the active monitoring sources."""
    plan: list[tuple[str, str, str]] = []
    # Mandatory Sysmon events are exactly the signals emitted by the shipped
    # detect-only XML. Do not subscribe to legacy Event 27 (PE blocking),
    # Event 23 (archive deletion) or unconfigured PipeEvent 17/18 filters.
    sysmon_ids: set[int] = {1, 2, 4, 11, 16, 26, 29}
    security_ids: set[int] = set()
    if monitor_processes:
        sysmon_ids.update({7, 8, 10, 25})
        security_ids.add(4688)
    if monitor_network:
        sysmon_ids.update({3, 22})
    if monitor_persistence:
        sysmon_ids.update({12, 13, 14})
        security_ids.update({4697, 4698, 4702})
    if sysmon_ids:
        ids = " or ".join(f"EventID={event_id}" for event_id in sorted(sysmon_ids))
        plan.append((SYSMON_CHANNEL, f"*[System[({ids})]]", "Sysmon"))
    if security_ids:
        ids = " or ".join(f"EventID={event_id}" for event_id in sorted(security_ids))
        plan.append((SECURITY_CHANNEL, f"*[System[({ids})]]", "Security"))
    if monitor_powershell:
        plan.append(
            (
                POWERSHELL_CHANNEL,
                "*[System[(EventID=4103 or EventID=4104)]]",
                "PowerShell",
            )
        )
    if monitor_persistence:
        plan.append(
            (
                TASK_SCHEDULER_CHANNEL,
                "*[System[(EventID=106 or EventID=140 or EventID=141 or EventID=200 or EventID=201)]]",
                "Task Scheduler",
            )
        )
        plan.append(
            (
                WMI_ACTIVITY_CHANNEL,
                "*[System[(EventID=5857 or EventID=5858 or EventID=5859 or EventID=5860 or EventID=5861)]]",
                "WMI Activity",
            )
        )
    return plan


class RealtimeCorrelator:
    """Correlate telemetry without process-name-only or filename-only containment."""

    def __init__(self, callback: EventCallback | None = None):
        self.callback = callback
        self._lock = threading.RLock()
        self.processes: dict[str, dict[str, Any]] = {}
        self.suspicious_pids: dict[str, float] = {}
        self.staged_paths: dict[str, float] = {}
        self.seen: dict[str, float] = {}
        self.finding_count = 0

    def _emit(self, level: str, message: str, detail: str = "") -> None:
        if self.callback:
            self.callback(
                {
                    "type": "log",
                    "level": level,
                    "message": message,
                    "detail": detail,
                    "time": utc_now(),
                }
            )

    def _finding(
        self,
        key: str,
        *,
        title: str,
        severity: str,
        confidence: str,
        category: str,
        description: str,
        evidence: list[str],
        path: str = "",
        sha256: str = "",
        remediation: str = "none",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        now = time.monotonic()
        with self._lock:
            self.seen = {k: v for k, v in self.seen.items() if now - v < 900}
            if key in self.seen:
                return
            self.seen[key] = now
        finding = Finding(
            title=title,
            severity=severity,
            confidence=confidence,
            category=category,
            description=description,
            evidence=evidence,
            path=path,
            sha256=sha256,
            remediation=remediation,
            metadata=metadata or {},
            stage_id="realtime",
        )
        self.finding_count += 1
        if self.callback:
            self.callback({"type": "finding", "finding": finding.to_dict()})

    def _remember_process(
        self, pid: str, record: dict[str, Any], suspicious: bool
    ) -> None:
        if not pid:
            return
        now = time.monotonic()
        with self._lock:
            self.processes[pid] = {**record, "seen": now, "suspicious": suspicious}
            # PID reuse is possible; retain only a short incident window.
            self.processes = {
                k: v
                for k, v in self.processes.items()
                if now - float(v.get("seen", now)) < 900
            }
            self.suspicious_pids = {
                k: v for k, v in self.suspicious_pids.items() if now - v < 900
            }
            if suspicious:
                self.suspicious_pids[pid] = now
            else:
                # A new process can reuse a recently suspicious PID. Its fresh
                # ProcessCreate record replaces the old state immediately.
                self.suspicious_pids.pop(pid, None)

    def _process_is_related(
        self, pid: str, parent_pid: str = "", process_guid: str = ""
    ) -> bool:
        """Check the process and up to four ancestors inside a short incident window.

        PID alone is not treated as an identity forever: the process map expires
        quickly, and Sysmon ProcessGuid can strengthen a match when available.
        """
        now = time.monotonic()
        with self._lock:
            if process_guid:
                matched = next(
                    (
                        (key, row)
                        for key, row in self.processes.items()
                        if row.get("guid") == process_guid
                    ),
                    None,
                )
                # A supplied GUID is the stable process identity. If it is not
                # known, do not fall back to a PID that may have been reused.
                if matched is None:
                    return False
                _matched_pid, matched_row = matched
                if now - float(matched_row.get("seen", 0)) >= 600:
                    return False
                if matched_row.get("suspicious"):
                    return True
                pending = [str(matched_row.get("parent_pid") or "")]
            else:
                pending = [x for x in (pid, parent_pid) if x]
            visited: set[str] = set()
            depth = 0
            while pending and depth < 5:
                candidate = pending.pop(0)
                if not candidate or candidate in visited:
                    continue
                visited.add(candidate)
                stamp = self.suspicious_pids.get(candidate)
                if stamp is not None and now - stamp < 600:
                    return True
                row = self.processes.get(candidate)
                if row and now - float(row.get("seen", 0)) < 600:
                    if row.get("suspicious"):
                        return True
                    ancestor = str(row.get("parent_pid") or "")
                    if ancestor and ancestor not in visited:
                        pending.append(ancestor)
                depth += 1
            return False

    def _event_process_relation(self, pid: str, process_guid: str, image: str) -> str:
        """Return direct/ancestor only after a complete GUID+PID+image join."""
        # A partial identity can be a PID-reuse or target/source confusion.
        # Never attribute an event if any of the three identity fields is absent.
        if not process_guid or not pid or not image:
            return ""
        now = time.monotonic()
        with self._lock:
            matched = next(
                (
                    (key, row)
                    for key, row in self.processes.items()
                    if row.get("guid") == process_guid
                ),
                None,
            )
            if matched is None:
                return ""
            recorded_pid, row = matched
            if now - float(row.get("seen", 0)) >= 600 or recorded_pid != pid:
                return ""
            expected_image = str(row.get("image") or "").replace("/", "\\").casefold()
            observed_image = str(image or "").replace("/", "\\").casefold()
            if not expected_image or expected_image != observed_image:
                return ""
            if row.get("suspicious"):
                return "direct"
            parent_pid = str(row.get("parent_pid") or "")
        return "ancestor" if parent_pid and self._process_is_related(parent_pid) else ""

    def _event_process_related(self, pid: str, process_guid: str, image: str) -> bool:
        """Boolean compatibility wrapper for callers that need any lineage."""
        return bool(self._event_process_relation(pid, process_guid, image))

    def _exact_artifact(self, path: str, digest: str) -> tuple[str | None, int | None]:
        """Require provider SHA-256, exact size, and a matching live on-disk hash.

        This method runs on the correlation worker, never in the native Event Log
        callback. Re-hashing prevents a replaced file at the same path from being
        treated as the executable that Sysmon originally observed.
        """
        normalized_digest = str(digest or "").lower()
        if not normalized_digest or normalized_digest not in KNOWN_SAMPLE_ARTIFACTS:
            return None, None
        try:
            if not path or not os.path.isfile(path) or os.path.islink(path):
                return None, None
            size = os.path.getsize(path)
            label = known_sample_artifact(normalized_digest, size)
            if not label:
                return None, size
            current_digest = sha256_file(path)
            if str(current_digest or "").lower() != normalized_digest:
                return None, size
            return label, size
        except OSError:
            return None, None

    def handle_event(self, event: dict[str, Any], source: str = "") -> None:
        event_id = int(event.get("event_id", 0) or 0)
        data = event.get("data") or {}
        provider = str(event.get("provider", ""))
        source = source or (
            "Sysmon" if "sysmon" in provider.lower() else "Windows Event Log"
        )

        # Task Scheduler / WMI channels are optional persistence context.
        # They are only surfaced when the event itself contains a recovered
        # campaign IOC or a sample-specific staging artifact/path.
        if source == "Task Scheduler":
            values = " ".join(str(value) for value in data.values()).lower()
            has_ioc = any(
                token in values
                for token in (
                    "benderoflight.com",
                    "survivomatic.com",
                    "ruthaiv.com",
                    "/nfront.php",
                    "/nback.php",
                    "93.94.52.29",
                    "109.238.86.137",
                )
            )
            has_sample_reference = any(
                token in values
                for token in (
                    "z797.ps1",
                    "crandle.txt",
                    "tctc.bba",
                )
            )
            if has_ioc or has_sample_reference:
                details = redact_sensitive_text(
                    " | ".join(str(v) for v in data.values())
                )
                self._finding(
                    f"task-scheduler:{event.get('record_id')}:{event_id}:{details[:180]}",
                    title="Scheduled-task history contains a Z797 campaign reference",
                    severity="High" if has_ioc else "Medium",
                    confidence="High" if has_ioc else "Medium",
                    category="Scheduled-task persistence telemetry",
                    description="A Task Scheduler event contains a recovered campaign destination or sample-associated staging reference. This records configuration/execution context only; no task is removed or disabled automatically.",
                    evidence=[f"Event ID: {event_id}", f"Task details: {details}"],
                    remediation="none",
                    metadata={
                        "event_id": event_id,
                        "source": source,
                        "campaign_attributed": has_ioc,
                        "context_only": not has_ioc,
                    },
                )
            return

        if source == "WMI Activity":
            values = " ".join(str(value) for value in data.values()).lower()
            has_ioc = any(
                token in values
                for token in (
                    "benderoflight.com",
                    "survivomatic.com",
                    "ruthaiv.com",
                    "/nfront.php",
                    "/nback.php",
                    "93.94.52.29",
                    "109.238.86.137",
                )
            )
            has_sample_reference = any(
                token in values
                for token in (
                    "z797.ps1",
                    "crandle.txt",
                    "tctc.bba",
                )
            )
            if has_ioc or has_sample_reference:
                client = _field(data, "ClientProcessName", "ClientProcess")
                pid = _normalize_pid(_field(data, "ClientProcessId", "ProcessId"))
                details = redact_sensitive_text(
                    " | ".join(str(v) for v in data.values())
                )
                self._finding(
                    f"wmi-activity:{event.get('record_id')}:{event_id}:{pid}",
                    title="WMI activity contains a Z797 campaign reference",
                    severity="High" if has_ioc else "Medium",
                    confidence="High" if has_ioc else "Medium",
                    category="WMI persistence / execution telemetry",
                    description="WMI-Activity telemetry contains a recovered campaign destination or sample-associated staging reference. This is evidence for review, not proof of a permanent WMI subscription or successful execution.",
                    evidence=[
                        f"Event ID: {event_id}",
                        f"Client process: {client or 'not supplied'}",
                        f"Client PID: {pid or 'not supplied'}",
                        f"WMI details: {details}",
                    ],
                    remediation="none",
                    metadata={
                        "event_id": event_id,
                        "source": source,
                        "pid": pid,
                        "client_process": client,
                        "campaign_attributed": has_ioc,
                        "context_only": not has_ioc,
                    },
                )
            return

        # Process creation: Sysmon EID 1 or Security EID 4688.
        if event_id == 4:
            state = _field(data, "State", "ServiceState").strip().lower()
            if "stop" in state:
                message = "Sysmon service reported a stopped state; continuous protection is no longer trustworthy."
                self._emit("ERROR", "Required Sysmon service stopped", message)
                if self.callback:
                    self.callback(
                        {
                            "type": "sensor_failure",
                            "sensor": "Sysmon",
                            "message": message,
                            "event_id": 4,
                        }
                    )
            return

        if event_id == 16:
            message = "Sysmon configuration changed while TCTC Guardian was monitoring. Monitoring is stopping until the managed policy is re-applied and verified."
            self._emit("ERROR", "Sysmon configuration changed", message)
            if self.callback:
                self.callback(
                    {
                        "type": "sensor_failure",
                        "sensor": "Sysmon",
                        "message": message,
                        "event_id": 16,
                    }
                )
            return

        if event_id in {1, 4688}:
            if event_id == 4688:
                # Security 4688: NewProcessId is the child; ProcessId is creator/parent.
                image = _field(data, "NewProcessName", "ProcessName")
                command = _field(data, "CommandLine", "ProcessCommandLine")
                parent = _field(data, "ParentProcessName")
                pid = _normalize_pid(_field(data, "NewProcessId"))
                parent_pid = _normalize_pid(_field(data, "ProcessId"))
                process_guid = ""
            else:
                image = _field(data, "Image")
                command = _field(data, "CommandLine", "ProcessCommandLine")
                parent = _field(data, "ParentImage")
                pid = _normalize_pid(
                    _field(data, "ProcessId") or str(event.get("system_pid", ""))
                )
                parent_pid = _normalize_pid(_field(data, "ParentProcessId"))
                process_guid = _field(data, "ProcessGuid")
            hashes = _sha256_from_sysmon(_field(data, "Hashes", "Hash"))
            image_norm = normalized(image)
            command_norm = normalized(command)
            path_in_scope = _under_staging(image)
            basename = Path(image.replace("\\", "/")).name.lower() if image else ""
            file_exists = bool(image and os.path.isfile(image))
            exact_label, file_size = (
                self._exact_artifact(image, hashes)
                if file_exists and hashes
                else (None, None)
            )

            # Exact raw SHA-256 is not accepted as an exact artifact until the
            # recorded file size also matches the local reconstruction record.
            if exact_label:
                self._remember_process(
                    pid,
                    {
                        "image": image,
                        "parent": parent,
                        "parent_pid": parent_pid,
                        "command": redact_sensitive_text(command),
                        "guid": process_guid,
                        "hash": hashes,
                    },
                    True,
                )
                self._finding(
                    f"exact-process:{pid}:{hashes}",
                    title="Exact TCTC sample artifact execution observed",
                    severity="Critical",
                    confidence="High",
                    category="Exact sample fingerprint",
                    description="A process-create event matches a locally verified TCTC artifact by SHA-256 and exact byte size.",
                    evidence=[
                        f"Source: {source}",
                        f"Image: {image}",
                        f"SHA-256: {hashes}",
                        f"Size: {file_size} bytes",
                        f"Parent image: {parent or 'not recorded'}",
                        f"PID: {pid}",
                    ],
                    path=image,
                    sha256=hashes,
                    remediation=(
                        "contain_exact_sample_process"
                        if file_exists and _under_staging(image)
                        else "none"
                    ),
                    metadata={
                        "pid": pid,
                        "parent_pid": parent_pid,
                        "process_guid": process_guid,
                        "exact_artifact": exact_label,
                        "hash_size_verified": True,
                        "expected_size": file_size,
                        "event_driven": True,
                    },
                )
                return

            # Sample-specific PowerShell detection requires a campaign token and
            # a download/staging or stealth context. Generic encoded PowerShell
            # and process names are intentionally not sufficient.
            has_campaign_marker = any(x in command_norm for x in CAMPAIGN_MARKERS)
            has_download = any(
                x in command_norm
                for x in (
                    "invoke-webrequest",
                    "downloadstring",
                    "start-bitstransfer",
                    "curl.exe",
                    "wget",
                    " iwr ",
                    "irm ",
                    "http://",
                    "https://",
                    "frombase64string",
                )
            )
            has_stealth = any(
                x in command_norm
                for x in (
                    "-windowstyle hidden",
                    "-w hidden",
                    "-executionpolicy bypass",
                    "-ep bypass",
                    "-encodedcommand",
                    "-enc ",
                    "-nop",
                    "-noprofile",
                )
            )
            script_host = basename in {
                "powershell.exe",
                "pwsh.exe",
                "cmd.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
            }
            suspicious = bool(
                script_host
                and has_campaign_marker
                and (has_download or has_stealth or path_in_scope)
            )
            parent_guid = _field(data, "ParentProcessGuid")
            # ParentProcessGuid belongs to the parent, not the child. Joining
            # the child's GUID here would sever valid ancestry correlation.
            parent_related = (
                self._event_process_related(parent_pid, parent_guid, parent)
                if parent_guid
                else self._process_is_related(parent_pid)
            )
            if suspicious or (parent_related and (path_in_scope or script_host)):
                # An inherited descendant remains useful for correlation, but
                # is not promoted to a directly IOC-matched process.
                self._remember_process(
                    pid,
                    {
                        "image": image,
                        "parent": parent,
                        "parent_pid": parent_pid,
                        "command": redact_sensitive_text(command),
                        "guid": process_guid,
                        "hash": hashes,
                    },
                    suspicious,
                )
                why = (
                    "TCTC campaign marker plus download/stealth/staging context"
                    if suspicious
                    else "Child process of a previously correlated TCTC-related process"
                )
                self._finding(
                    f"process-chain:{pid}:{normalized(image)}",
                    title="TCTC-related process execution chain detected",
                    severity="High" if suspicious else "Medium",
                    confidence="High" if suspicious else "Medium",
                    category="Process lineage",
                    description="A process-creation event is correlated with sample-specific command/path context. This is not based on executable name alone.",
                    evidence=[
                        f"Source: {source}",
                        f"Reason: {why}",
                        f"Image: {image}",
                        f"Parent image: {parent or 'not recorded'}",
                        f"PID / Parent PID: {pid} / {parent_pid}",
                        f"Command: {redact_sensitive_text(command)}",
                    ],
                    path=image,
                    sha256=hashes,
                    remediation="none",
                    metadata={
                        "pid": pid,
                        "parent_pid": parent_pid,
                        "process_guid": process_guid,
                        "source": source,
                    },
                )
            else:
                self._remember_process(
                    pid,
                    {
                        "image": image,
                        "parent": parent,
                        "parent_pid": parent_pid,
                        "command": redact_sensitive_text(command),
                        "guid": process_guid,
                        "hash": hashes,
                    },
                    False,
                )
            return

        # PowerShell Script Block / Module logging (4103/4104). This is a
        # telemetry surface, not an AMSI API hook; Script Block Logging must
        # already be enabled by system policy to provide 4104 records.
        if event_id in {4103, 4104}:
            script = _field(data, "ScriptBlockText", "ContextInfo", "Payload")
            text = normalized(script)
            campaign = any(
                x in text
                for x in (
                    "z797.ps1",
                    "crandle.txt",
                    "tctc.bba",
                    "benderoflight.com",
                    "survivomatic.com",
                    "ruthaiv.com",
                    "93.94.52.29",
                    "109.238.86.137",
                )
            )
            download = any(
                x in text
                for x in (
                    "invoke-webrequest",
                    "downloadstring",
                    "start-bitstransfer",
                    "curl.exe",
                    "http://",
                    "https://",
                )
            )
            stealth = any(
                x in text
                for x in (
                    "-windowstyle hidden",
                    "-executionpolicy bypass",
                    "frombase64string",
                    "invoke-expression",
                    "iex ",
                )
            )
            if campaign and (download or stealth or "temp\\local\\" in text):
                pid = str(event.get("system_pid", ""))
                self._remember_process(
                    pid,
                    {
                        "image": "powershell.exe",
                        "parent": "",
                        "parent_pid": "",
                        "command": "PowerShell script block",
                        "guid": "",
                        "hash": "",
                    },
                    True,
                )
                self._finding(
                    f"powershell-script:{event.get('record_id')}:{pid}",
                    title="TCTC-related PowerShell script telemetry detected",
                    severity="High",
                    confidence="High",
                    category="PowerShell Script Block telemetry",
                    description="PowerShell Operational telemetry contains an exact Z797 domain, URL or analysed artifact reference in a script-block or module record. This is Windows Script Block / Module logging, not a direct AMSI result feed.",
                    evidence=[
                        f"Event ID: {event_id}",
                        f"Provider: {provider}",
                        f"PowerShell PID: {pid or 'not recorded'}",
                        f"Script excerpt: {redact_sensitive_text(script)}",
                    ],
                    remediation="none",
                    metadata={
                        "pid": pid,
                        "event_id": event_id,
                        "record_id": event.get("record_id"),
                        "source": "PowerShell Operational",
                    },
                )
            return

        # Compatibility parser for Event 27 from an older or externally
        # managed Sysmon policy. The application does not configure this blocking event.
        if event_id == 27:
            target = _field(data, "TargetFilename")
            if not _under_staging(target):
                return
            image = _field(data, "Image")
            pid = _normalize_pid(_field(data, "ProcessId"))
            process_guid = _field(data, "ProcessGuid")
            hashes = _sha256_from_sysmon(_field(data, "Hashes"))
            known = KNOWN_SAMPLE_ARTIFACTS.get(hashes.lower()) if hashes else None
            related = self._process_is_related(pid, process_guid=process_guid)
            if not (known or related):
                return
            self._finding(
                f"sysmon-pe-block:{event.get('record_id')}:{os.path.normcase(target)}",
                title=(
                    "Sysmon blocked a PE with a recovered TCTC SHA-256"
                    if known
                    else "Sysmon blocked PE creation in TCTC staging"
                ),
                severity="Critical" if known else "High",
                confidence="High" if known else "Medium",
                category="Pre-execution prevention",
                description=(
                    "Sysmon FileBlockExecutable prevented a PE file from remaining in the analyzed Temp\\Local staging roots. Its event SHA-256 matches a recovered TCTC artifact; the file size is not available from this block event."
                    if known
                    else "Sysmon FileBlockExecutable prevented a PE file from remaining in the analyzed Temp\\Local staging roots. This is a prevention event, but the attempted PE hash is not in the recovered exact set."
                ),
                evidence=[
                    f"Event ID: 27",
                    f"Creator: {image or 'unknown'} (PID {pid or 'unknown'})",
                    f"Target: {target}",
                    f"SHA-256: {hashes or 'unavailable'}",
                    f"Recovered artifact size (not measured in this event): {known[0] if known else 'unknown'}",
                    f"Rule: {_field(data, 'RuleName') or 'TCTC TempLocal script-host PE block'}",
                ],
                path=target,
                sha256=hashes,
                remediation="none",
                metadata={
                    "pid": pid,
                    "process_image": image,
                    "sysmon_blocked": True,
                    "hash_size_verified": False,
                    "source": source,
                },
            )
            return

        # Event 29 is the only PE-creation behavior configured by the application.
        if event_id == 29:
            target = _field(data, "TargetFilename")
            if _under_staging(target):
                pid = _normalize_pid(_field(data, "ProcessId"))
                image = _field(data, "Image")
                event_hash = _sha256_from_sysmon(_field(data, "Hashes"))
                known_hash = bool(
                    event_hash and event_hash.lower() in KNOWN_SAMPLE_ARTIFACTS
                )
                known_name = (
                    Path(target.replace("\\", "/")).name.lower() in KNOWN_STAGING_NAMES
                )
                process_guid = _field(data, "ProcessGuid")
                actor_related = self._event_process_relation(pid, process_guid, image)
                # A hash from Event 29 is not a full fingerprint until its byte
                # size is re-read from the created file. Queue the path first;
                # the file worker emits an exact finding only after hash+size.
                if known_name or actor_related:
                    self._finding(
                        f"sysmon-pe-created:{event.get('record_id')}:{os.path.normcase(target)}",
                        title="Executable creation linked to the Z797 staging chain",
                        severity="Medium" if known_name else "High",
                        confidence="Medium" if known_name else "High",
                        category="Z797 PE staging",
                        description="Sysmon Event ID 29 found an executable created in the analysed staging path. The delivery filename or creator process links it to Z797; the live file must still pass SHA-256 and byte-size verification before quarantine.",
                        evidence=[
                            f"Event ID: 29",
                            f"Creator: {image or 'unknown'} (PID {pid or 'unknown'})",
                            f"Target: {target}",
                            f"SHA-256: {event_hash or 'not supplied'}",
                            "File size: pending live file verification",
                        ],
                        path=target,
                        remediation="none",
                        metadata={
                            "pid": pid,
                            "process_image": image,
                            "process_guid": process_guid,
                            "source": source,
                            "campaign_attributed": True,
                            "size_verification_pending": True,
                        },
                    )
                # Always run the exact SHA-256 / known-marker check, but don't
                # alert on arbitrary PE creation in a temporary directory.
                self.enqueue_file(target, pid, process_guid, image)
            return

        # Sysmon file timestamp manipulation / deletion telemetry is useful
        # when the chain tries to erase or timestomp its staging artefacts.
        if event_id in {2, 23, 26}:
            path = _field(data, "TargetFilename")
            if _under_staging(path):
                pid = _normalize_pid(_field(data, "ProcessId"))
                image = _field(data, "Image")
                basename = Path(path.replace("\\", "/")).name.lower()
                if basename in KNOWN_STAGING_NAMES or self._process_is_related(
                    pid, process_guid=_field(data, "ProcessGuid")
                ):
                    label = (
                        "File creation-time change"
                        if event_id == 2
                        else "Staging file deletion"
                    )
                    self._finding(
                        f"staging-cleanup:{event_id}:{event.get('record_id')}:{os.path.normcase(path)}",
                        title=f"{label} observed in TCTC staging area",
                        severity="High",
                        confidence="Medium",
                        category="Staging cleanup telemetry",
                        description="Sysmon recorded a timestamp change or deletion under the exact analyzed Temp\\Local staging roots. The event is preserved as cleanup evidence; it does not prove the deleted content was malicious unless independently hash-matched.",
                        evidence=[
                            f"Event ID: {event_id}",
                            f"Path: {path}",
                            f"Actor: {image or 'unknown'} (PID {pid or 'unknown'})",
                        ],
                        path=path,
                        remediation="none",
                        metadata={"pid": pid, "event_id": event_id, "source": source},
                    )
            return

        # Sysmon FileCreate or Security object access. Only inspect paths inside
        # the two sample staging roots; process attribution is retained.
        if event_id == 11:
            path = _field(data, "TargetFilename", "ObjectName", "FileName")
            if _under_staging(path):
                pid = _normalize_pid(
                    _field(data, "ProcessId", "SubjectProcessId")
                    or str(event.get("system_pid", ""))
                )
                image = _field(data, "Image", "ProcessName")
                process_guid = _field(data, "ProcessGuid")
                with self._lock:
                    self.staged_paths[os.path.normcase(os.path.abspath(path))] = (
                        time.monotonic()
                    )
                basename = Path(path.replace("\\", "/")).name.lower()
                if basename in KNOWN_STAGING_NAMES or self._process_is_related(
                    pid, process_guid=process_guid
                ):
                    self._finding(
                        f"staging-event:{event.get('record_id')}:{os.path.normcase(path)}",
                        title="TCTC staging-path file activity observed",
                        severity="Medium",
                        confidence="Medium",
                        category="Targeted file telemetry",
                        description="A file-create/access event occurred in the exact Temp\\Local staging area used by the analyzed chain. A filename/path match is contextual only; the file must pass exact SHA-256 and size verification before it is treated as a known sample artifact.",
                        evidence=[
                            f"Event ID: {event_id}",
                            f"Path: {path}",
                            f"Creating/accessing process: {image or 'not recorded'}",
                            f"PID: {pid or 'not recorded'}",
                            "File content is verified separately; no action is taken from the filename alone.",
                        ],
                        path=path,
                        remediation="none",
                        metadata={
                            "pid": pid,
                            "process_guid": process_guid,
                            "process_image": image,
                            "event_id": event_id,
                            "source": source,
                            "hash_size_verified": False,
                        },
                    )
            return

        # Image loads from the sample staging path are useful context, but are
        # only raised when the loading process is already correlated.
        if event_id == 7:
            image_loaded = _field(data, "ImageLoaded")
            process_image = _field(data, "Image")
            pid = _normalize_pid(_field(data, "ProcessId"))
            process_guid = _field(data, "ProcessGuid")
            if _under_staging(image_loaded) and self._process_is_related(
                pid, process_guid=process_guid
            ):
                self._finding(
                    f"staged-image-load:{event.get('record_id')}:{pid}:{normalized(image_loaded)}",
                    title="Staged image loaded by a TCTC-correlated process",
                    severity="High",
                    confidence="High",
                    category="Image-load correlation",
                    description="A process already linked to the Z797 incident loaded an image from the exact Temp\\Local staging area.",
                    evidence=[
                        f"Image loaded: {image_loaded}",
                        f"Process: {process_image or 'unknown'} (PID {pid})",
                        f"Process GUID: {process_guid or 'not recorded'}",
                    ],
                    path=image_loaded,
                    remediation="none",
                    metadata={
                        "pid": pid,
                        "process_guid": process_guid,
                        "process_image": process_image,
                        "event_id": 7,
                    },
                )
            return

        # Registry/service/task persistence is reported only when the created
        # value/action points to exact campaign markers or the staging root.
        # A generic Run-key edit or ordinary service installation is not enough.
        if event_id in {12, 13, 14, 4697, 4698, 4702}:
            target = _field(data, "TargetObject", "TaskName", "ServiceName")
            details = _field(
                data,
                "Details",
                "TaskContent",
                "ServiceFileName",
                "ImagePath",
                "ActionName",
            )
            actor_image = _field(data, "Image", "ProcessName")
            pid = _normalize_pid(_field(data, "ProcessId", "SubjectProcessId"))
            combined = normalized(" ".join((target, details, actor_image)))
            marker = any(token in combined for token in CAMPAIGN_MARKERS)
            staged_reference = any(
                token in combined for token in ("crandle.txt", "z797.ps1", "tctc.bba")
            )
            autorun_target = any(
                token in normalized(target)
                for token in (
                    "\\currentversion\\run",
                    "\\currentversion\\runonce",
                    "\\tasks\\",
                    "\\services\\",
                )
            ) or event_id in {4697, 4698}
            related = self._process_is_related(pid)
            if autorun_target and (marker or staged_reference or related):
                severity = "High" if marker or staged_reference else "Medium"
                self._finding(
                    f"persistence-event:{event_id}:{event.get('record_id')}:{target}:{pid}",
                    title="TCTC-correlated persistence change observed",
                    severity=severity,
                    confidence=severity,
                    category="Persistence telemetry",
                    description="A Run key, service or scheduled-task change contains a TCTC campaign marker, points into the exact staging tree, or was created by a previously correlated process. No registry/task/service change is removed automatically.",
                    evidence=[
                        f"Event ID: {event_id}",
                        f"Target: {target or 'not recorded'}",
                        f"Details: {redact_sensitive_text(details)}",
                        f"Actor: {actor_image or 'not recorded'} (PID {pid or 'unknown'})",
                    ],
                    path=target,
                    remediation="none",
                    metadata={"event_id": event_id, "pid": pid, "source": source},
                )
            return

        # Process access / remote-thread / tampering correlation. Attribution
        # is role-aware: Event 8/10's SourceProcessGuid is the actor; Event 25's
        # ProcessGuid is the image being tampered with. A target-side match or
        # staging path by itself must never turn an unrelated actor into TCTC.
        if event_id in {8, 10, 25}:
            if event_id == 25:
                source_image = ""
                target_image = _field(data, "Image")
                source_pid = ""
                target_pid = _normalize_pid(_field(data, "ProcessId"))
                source_guid = ""
                target_guid = _field(data, "ProcessGuid")
                relation = self._event_process_relation(
                    target_pid, target_guid, target_image
                )
                related = bool(relation)
                relevant_target = _is_target_process(target_image)
                behavior_label = "Process image tampering"
                behavior_detail = "Sysmon reported image-tampering telemetry in a monitored target process."
                access_raw = "not applicable"
                should_report_context = False
                actor_rights_match = True
            else:
                source_image = _field(data, "SourceImage")
                target_image = _field(data, "TargetImage")
                source_pid = _normalize_pid(_field(data, "SourceProcessId"))
                target_pid = _normalize_pid(_field(data, "TargetProcessId"))
                source_guid = _field(data, "SourceProcessGuid")
                target_guid = _field(data, "TargetProcessGuid")
                # Only the event's actor side can establish a process lineage.
                relation = self._event_process_relation(
                    source_pid, source_guid, source_image
                )
                related = bool(relation)
                relevant_target = _is_target_process(target_image)
                behavior_label = (
                    "Remote thread creation"
                    if event_id == 8
                    else "Cross-process memory access"
                )
                behavior_detail = (
                    "A remote-thread creation event targets a monitored process; the source process is correlated independently."
                    if event_id == 8
                    else "A ProcessAccess event targets a monitored process. Only write / VM-operation / thread-creation rights plus a source-process correlation can be campaign-linked."
                )
                access_raw = _field(data, "GrantedAccess")
                should_report_context = False
                actor_rights_match = event_id == 8 or _has_process_write_access(
                    access_raw
                )

            if relevant_target and related and actor_rights_match:
                self._finding(
                    f"process-behavior:{event_id}:{event.get('record_id')}:{source_pid}:{target_pid}",
                    title=f"{behavior_label} correlated with a TCTC process lineage",
                    severity="High" if relation == "direct" else "Medium",
                    confidence="High" if relation == "direct" else "Medium",
                    category="Process behavior correlation",
                    description=behavior_detail
                    + (
                        " The event identity matched a directly IOC-correlated process."
                        if relation == "direct"
                        else " The event identity matched a descendant of a correlated process; this is inherited lineage, not a direct IOC match."
                    ),
                    evidence=[
                        f"Event ID: {event_id}",
                        f"Source image: {source_image or 'not supplied'}",
                        f"Target image: {target_image or 'not supplied'}",
                        f"Source PID: {source_pid or 'not supplied'}",
                        f"Target PID: {target_pid or 'not supplied'}",
                        f"Granted access: {access_raw}",
                        f"Source Process GUID: {source_guid or 'not supplied'}",
                        f"Target Process GUID: {target_guid or 'not supplied'}",
                    ],
                    path=target_image or source_image,
                    remediation="none",
                    metadata={
                        "event_id": event_id,
                        "source_pid": source_pid,
                        "target_pid": target_pid,
                        "source_process_guid": source_guid,
                        "target_process_guid": target_guid,
                        "actor_side_correlated": True,
                        "correlation_basis": relation,
                        "source": source,
                    },
                )

            return

        if event_id in {17, 18}:
            image = _field(data, "Image")
            pid = _normalize_pid(_field(data, "ProcessId"))
            process_guid = _field(data, "ProcessGuid")
            pipe_name = _field(data, "PipeName")
            related = self._event_process_related(pid, process_guid, image)
            pipe_marker = any(token in pipe_name.lower() for token in CAMPAIGN_MARKERS)
            if related or pipe_marker:
                self._finding(
                    f"named-pipe:{event_id}:{event.get('record_id')}:{pid}:{pipe_name}",
                    title="Named-pipe activity associated with a Z797 process",
                    severity="High" if pipe_marker else "Medium",
                    confidence="High" if pipe_marker else "Medium",
                    category="Named-pipe behavior correlation",
                    description="Sysmon recorded named-pipe creation/connection with either an exact campaign marker or a verified recently correlated process identity. Named-pipe telemetry alone does not establish lateral movement.",
                    evidence=[
                        f"Event ID: {event_id}",
                        f"Pipe: {pipe_name or 'not recorded'}",
                        f"Process: {image or 'not recorded'} (PID {pid or 'unknown'})",
                        f"Process GUID: {process_guid or 'not recorded'}",
                    ],
                    path=pipe_name,
                    remediation="none",
                    metadata={
                        "event_id": event_id,
                        "pid": pid,
                        "process_guid": process_guid,
                        "campaign_pipe_marker": pipe_marker,
                        "process_correlated": related,
                    },
                )
            return

        # Network/DNS activity is raised only for the known campaign infra and
        # is never auto-blocked from a real-time event alone.
        if event_id in {3, 22}:
            destination_ip = _field(
                data, "DestinationIp", "QueryResults", "QueryResult"
            )
            destination_host = _field(data, "DestinationHostname", "QueryName", "Query")
            image = _field(data, "Image", "ProcessName")
            pid = _normalize_pid(
                _field(data, "ProcessId") or str(event.get("system_pid", ""))
            )
            process_guid = _field(data, "ProcessGuid")
            host_norm = destination_host.lower().rstrip(".")
            ip_norm = destination_ip.strip()
            is_campaign = (
                host_norm in CONFIRMED_CAMPAIGN_DOMAINS
                or ip_norm in CONFIRMED_CAMPAIGN_IPS
            )
            related = self._process_is_related(
                pid, process_guid=process_guid
            ) or _under_staging(image)
            if is_campaign:
                corroborated_domain = host_norm in CONFIRMED_CAMPAIGN_DOMAINS
                severity = "High" if related and corroborated_domain else "Medium"
                confidence = "High" if related and corroborated_domain else "Medium"
                self._finding(
                    f"network-event:{event_id}:{event.get('record_id')}:{pid}:{ip_norm}:{host_norm}",
                    title="Z797 campaign network / DNS indicator observed",
                    severity=severity,
                    confidence=confidence,
                    category="Network behavior correlation",
                    description="A configured Z797 campaign destination was contacted or queried. Correlation with a previously identified process or staging path raises confidence; an IP-only observation is not proof of infection because infrastructure can be reused.",
                    evidence=[
                        f"Event ID: {event_id}",
                        f"Process: {image or 'unknown'} (PID {pid})",
                        f"Destination IP: {ip_norm or 'not recorded'}",
                        f"Destination host: {host_norm or 'not recorded'}",
                        "The event is evidence only; no automatic firewall rule is created.",
                    ],
                    path=image,
                    remediation="none",
                    metadata={
                        "pid": pid,
                        "process_guid": process_guid,
                        "ip": ip_norm,
                        "hostname": host_norm,
                        "source": source,
                    },
                )
            return

    def handle_file(
        self,
        path: str,
        *,
        operation: str = "created",
        source_pid: str = "",
        source_image: str = "",
        source_guid: str = "",
    ) -> None:
        if not _under_staging(path) or not os.path.isfile(path) or os.path.islink(path):
            return
        try:
            # Wait briefly for the writer to finish. Hashing stays off the
            # Watchdog callback thread and streams in bounded chunks.
            previous = None
            stable = False
            for _ in range(5):
                st = os.stat(path)
                state = (st.st_size, st.st_mtime_ns)
                if state == previous:
                    stable = True
                    break
                previous = state
                time.sleep(0.2)
            if not stable:
                self._emit(
                    "INFO",
                    "Staging file is still changing; exact hash verification deferred",
                    path,
                )
                return
            # Verify the file identity did not change while hashing. A watcher
            # event can arrive while the writer still has the file open.
            before_hash = os.stat(path)
            digest = sha256_file(path)
            after_hash = os.stat(path)
            before_state = (before_hash.st_size, before_hash.st_mtime_ns)
            after_state = (after_hash.st_size, after_hash.st_mtime_ns)
            if before_state != after_state:
                self._emit(
                    "INFO",
                    "Staging file changed during hashing; exact verification deferred",
                    path,
                )
                return
            size = after_hash.st_size
            label = known_sample_artifact(digest, size)
            basename = Path(path).name.lower()
            if label:
                self._finding(
                    f"exact-file:{os.path.normcase(os.path.abspath(path))}:{digest}:{size}:{source_guid or source_pid or 'unattributed'}",
                    title="Exact TCTC sample artifact created in staging area",
                    severity="Critical",
                    confidence="High",
                    category="Exact sample fingerprint",
                    description="A newly created or modified file matches a locally verified TCTC artifact by SHA-256 and exact byte size. This is a confirmed file match; actual process execution is tracked separately.",
                    evidence=[
                        f"Path: {path}",
                        f"SHA-256: {digest}",
                        f"Size: {size} bytes",
                        f"Artifact: {label}",
                        f"Creating process: {source_image or 'not attributed by filesystem notification'}",
                        f"PID: {source_pid or 'not available'}",
                        f"Process GUID: {source_guid or 'not available'}",
                        f"Filesystem event: {operation}",
                    ],
                    path=path,
                    sha256=digest,
                    remediation="quarantine_file",
                    metadata={
                        "pid": source_pid,
                        "process_guid": source_guid,
                        "process_image": source_image,
                        "exact_artifact": label,
                        "hash_size_verified": True,
                        "expected_size": size,
                        "event_driven": True,
                    },
                )
            elif basename in KNOWN_STAGING_NAMES:
                self._finding(
                    f"staging-name:{os.path.normcase(os.path.abspath(path))}:{digest}",
                    title="Known TCTC staging filename observed (content not matched)",
                    severity="Medium",
                    confidence="Medium",
                    category="Targeted file telemetry",
                    description="The filename and exact staging path match the analyzed campaign pattern, but the SHA-256/size pair does not match a recovered artifact. This is not treated as a confirmed malware file and is not eligible for automatic quarantine.",
                    evidence=[
                        f"Path: {path}",
                        f"SHA-256: {digest}",
                        f"Size: {size} bytes",
                        f"Creating process: {source_image or 'unknown'}",
                        f"PID: {source_pid or 'not available'}",
                    ],
                    path=path,
                    sha256=digest,
                    remediation="none",
                    metadata={
                        "pid": source_pid,
                        "process_guid": source_guid,
                        "process_image": source_image,
                        "hash_size_verified": False,
                        "event_driven": True,
                    },
                )
        except (OSError, PermissionError) as exc:
            self._emit(
                "WARNING", "Could not hash newly created staging file", f"{path}: {exc}"
            )


class _EvtSubscribe:
    """Thin ctypes wrapper around the native Windows Event Log subscription API."""

    def __init__(
        self,
        on_event: Callable[[dict[str, Any]], None],
        on_error: Callable[[str], None],
    ):
        self.on_event = on_event
        self.on_error = on_error
        self.handles: list[int] = []
        self.callbacks: list[Any] = []
        self.api = None

    def _load(self) -> None:
        if os.name != "nt":
            raise OSError("Native Event Log subscriptions require Windows")
        api = ctypes.WinDLL("wevtapi.dll", use_last_error=True)
        api.EvtSubscribe.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        api.EvtSubscribe.restype = ctypes.c_void_p
        api.EvtRender.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        api.EvtRender.restype = ctypes.c_int
        api.EvtClose.argtypes = [ctypes.c_void_p]
        api.EvtClose.restype = ctypes.c_int
        self.api = api

    def _render_xml(self, event_handle: int) -> str:
        assert self.api is not None
        needed = ctypes.c_uint32(0)
        properties = ctypes.c_uint32(0)
        ok = self.api.EvtRender(
            None,
            event_handle,
            1,
            0,
            None,
            ctypes.byref(needed),
            ctypes.byref(properties),
        )
        error = ctypes.get_last_error()
        if ok or error != 122 or needed.value <= 0:
            raise ctypes.WinError(error or 13)
        char_count = (
            needed.value + ctypes.sizeof(ctypes.c_wchar) - 1
        ) // ctypes.sizeof(ctypes.c_wchar)
        buffer = ctypes.create_unicode_buffer(char_count + 1)
        ok = self.api.EvtRender(
            None,
            event_handle,
            1,
            ctypes.sizeof(buffer),
            ctypes.cast(buffer, ctypes.c_void_p),
            ctypes.byref(needed),
            ctypes.byref(properties),
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.value

    def subscribe(self, channel: str, query: str, label: str) -> None:
        if self.api is None:
            self._load()
        assert self.api is not None
        DWORD = ctypes.c_uint32
        PVOID = ctypes.c_void_p
        CALLBACK = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)(
            DWORD, DWORD, PVOID, PVOID
        )

        def deliver(action: int, _context: int, event_handle: int) -> int:
            # EVT_SUBSCRIBE_NOTIFY_ACTION: Error=0, Deliver=1. The event
            # handle is valid only during this callback and Windows closes it
            # on return; do not call EvtClose on the delivered event handle.
            if action == 1 and event_handle:
                try:
                    xml_text = self._render_xml(event_handle)
                    self.on_event(xml_text, label)
                except Exception as exc:
                    self.on_error(
                        f"{label} event could not be rendered: {type(exc).__name__}: {exc}"
                    )
            elif action == 0:
                self.on_error(
                    f"{label} subscription delivery error: {int(event_handle or 0)}"
                )
            return 0

        callback = CALLBACK(deliver)
        handle = self.api.EvtSubscribe(
            None,
            None,
            channel,
            query,
            None,
            None,
            ctypes.cast(callback, ctypes.c_void_p),
            1,
        )
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        self.callbacks.append(callback)
        self.handles.append(handle)

    def close(self) -> None:
        if self.api is not None:
            for handle in self.handles:
                try:
                    self.api.EvtClose(handle)
                except Exception:
                    pass
        self.handles.clear()
        # Keep callback references alive until this wrapper is destroyed; an
        # Event Log callback may still be unwinding as EvtClose returns.


class _FileHandler:
    def __init__(self, callback: Callable[[str, str], None], roots: list[str]):
        self.callback = callback
        self.roots = [os.path.normcase(os.path.abspath(x)) for x in roots]

    def _eligible(self, path: str) -> bool:
        candidate = os.path.normcase(os.path.abspath(path))
        for root in self.roots:
            try:
                if os.path.commonpath([candidate, root]) == root and candidate != root:
                    return True
            except ValueError:
                continue
        return False

    def on_created(self, event) -> None:
        if not event.is_directory and self._eligible(event.src_path):
            self.callback(event.src_path, "created")

    def on_modified(self, event) -> None:
        if not event.is_directory and self._eligible(event.src_path):
            self.callback(event.src_path, "modified")

    def on_moved(self, event) -> None:
        if not event.is_directory and self._eligible(event.dest_path):
            self.callback(event.dest_path, "moved into staging")


class RealtimeMonitor:
    """Owns future-event subscriptions and targeted filesystem notifications."""

    def __init__(
        self,
        callback: EventCallback | None = None,
        *,
        monitor_processes: bool = True,
        monitor_files: bool = True,
        monitor_network: bool = True,
        monitor_persistence: bool = True,
        monitor_powershell: bool = True,
    ):
        self.callback = callback
        self.monitor_processes = bool(monitor_processes)
        self.monitor_files = bool(monitor_files)
        self.monitor_network = bool(monitor_network)
        self.monitor_persistence = bool(monitor_persistence)
        self.monitor_powershell = bool(monitor_powershell)
        self.stop_event = threading.Event()
        self.correlator = RealtimeCorrelator(callback)
        self.subscription: _EvtSubscribe | None = None
        self.observer = None
        self.file_queue: queue.Queue[tuple[str, str, str, str, str]] = queue.Queue(
            maxsize=512
        )
        self.event_queue: queue.Queue[tuple[str, str]] = queue.Queue(maxsize=2048)
        self.file_worker: threading.Thread | None = None
        self.event_worker: threading.Thread | None = None
        self.status: dict[str, str] = {}
        self._started = False

    def _emit(self, level: str, message: str, detail: str = "") -> None:
        if self.callback:
            self.callback(
                {
                    "type": "log",
                    "level": level,
                    "message": message,
                    "detail": detail,
                    "time": utc_now(),
                }
            )

    def _enqueue_event(self, xml_text: str, source: str) -> None:
        # Called by the native Event Log callback. Keep it non-blocking; XML
        # parsing, correlation and finding construction run on a worker thread.
        try:
            self.event_queue.put_nowait((xml_text, source))
        except queue.Full:
            self._emit(
                "WARNING",
                "Real-time event queue is full; some telemetry may be delayed",
                source,
            )

    def _process_event(self, xml_text: str, source: str) -> None:
        try:
            parsed = parse_event_xml(xml_text)
            self.correlator.handle_event(parsed, source)
            # Sysmon Event 11 includes the creating process; pair it with the
            # filesystem notification so exact hashing and creator attribution
            # run on the file worker, not on the native callback thread.
            if int(parsed.get("event_id", 0) or 0) == 11:
                data = parsed.get("data") or {}
                path = _field(data, "TargetFilename")
                if path and _under_staging(path):
                    self._enqueue_file(
                        path,
                        "Sysmon FileCreate",
                        _field(data, "ProcessId"),
                        _field(data, "Image"),
                        _field(data, "ProcessGuid"),
                    )
        except Exception as exc:
            self._emit(
                "WARNING",
                "Could not process a real-time Windows event",
                f"{type(exc).__name__}: {exc}",
            )

    def _event_loop(self) -> None:
        while not self.stop_event.is_set() or not self.event_queue.empty():
            try:
                xml_text, source = self.event_queue.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                self._process_event(xml_text, source)
            finally:
                self.event_queue.task_done()

    def _enqueue_file(
        self,
        path: str,
        operation: str,
        pid: str = "",
        image: str = "",
        process_guid: str = "",
    ) -> None:
        try:
            self.file_queue.put_nowait((path, operation, pid, image, process_guid))
        except queue.Full:
            self._emit(
                "WARNING",
                "Real-time file event queue is full; some staging events may be delayed",
                path,
            )

    def _file_loop(self) -> None:
        while not self.stop_event.is_set() or not self.file_queue.empty():
            try:
                path, operation, pid, image, process_guid = self.file_queue.get(
                    timeout=0.25
                )
            except queue.Empty:
                continue
            try:
                self.correlator.handle_file(
                    path,
                    operation=operation,
                    source_pid=pid,
                    source_image=image,
                    source_guid=process_guid,
                )
            finally:
                self.file_queue.task_done()

    def start(self) -> dict[str, str]:
        if self._started:
            return dict(self.status)
        if os.name == "nt":
            ready, detail = sysmon_readiness()
            if not ready:
                raise RuntimeError(
                    "Sysmon is required for TCTC Guardian real-time monitoring. "
                    + detail
                    + " Restart TCTC Guardian Z797 to run its automatic Sysmon setup."
                )
        self._started = True
        if os.name != "nt":
            self.status["platform"] = "unavailable"
            self._emit("WARNING", "Native real-time monitoring is Windows-only")
            return dict(self.status)

        self.file_worker = threading.Thread(
            target=self._file_loop, name="TCTC-FileEventWorker", daemon=True
        )
        self.event_worker = threading.Thread(
            target=self._event_loop, name="TCTC-EventCorrelationWorker", daemon=True
        )
        self.file_worker.start()
        self.event_worker.start()

        subscriptions = build_subscription_plan(
            monitor_processes=self.monitor_processes,
            monitor_files=self.monitor_files,
            monitor_network=self.monitor_network,
            monitor_persistence=self.monitor_persistence,
            monitor_powershell=self.monitor_powershell,
        )

        self.subscription = _EvtSubscribe(
            self._enqueue_event, lambda msg: self._emit("WARNING", msg)
        )
        for channel, query, label in subscriptions:
            try:
                self.subscription.subscribe(channel, query, label)
                self.status[label] = "active"
                if label == "Security":
                    detail = "Subscription is open; emitted process/persistence events depend on the relevant Advanced Audit Policy. Process command-line data for 4688 requires its separate policy setting."
                elif label == "PowerShell":
                    detail = "Subscription is open; Event 4104 requires Script Block Logging, and 4103 requires Module Logging. This feed is not a direct AMSI result hook."
                elif label == "Sysmon":
                    detail = "Subscription is open; actual events depend on the installed Sysmon configuration. SHA-256 process hashes require HashAlgorithms to include SHA256."
                else:
                    detail = "Subscription is open; only future events emitted by this provider are received."
                self._emit(
                    "SUCCESS", f"Real-time {label} event subscription active", detail
                )
            except Exception as exc:
                text = str(exc)
                if label == "Sysmon":
                    detail = (
                        "Required Sysmon channel became unavailable after preflight; real-time attribution is degraded. "
                        + text
                    )
                    self.status[label] = "unavailable"
                    self._emit(
                        "WARNING", "Sysmon real-time telemetry unavailable", detail
                    )
                elif label == "Security":
                    self.status[label] = "unavailable"
                    self._emit(
                        "WARNING",
                        "Security telemetry unavailable",
                        "Enable the relevant Advanced Audit Policy subcategories: Process Creation (4688) and Security System Extension / Other Object Access Events for service/task changes. Command-line data requires its separate policy setting. "
                        + text,
                    )
                elif label == "PowerShell":
                    self.status[label] = "unavailable"
                    self._emit(
                        "WARNING",
                        "PowerShell operational telemetry unavailable",
                        "PowerShell Script Block Logging must already be enabled for 4104 events. "
                        + text,
                    )
                else:
                    self.status[label] = "unavailable"
                    self._emit(
                        "WARNING",
                        f"{label} real-time event subscription unavailable",
                        text,
                    )

        if self.status.get("Sysmon") != "active":
            detail = "Required Sysmon EvtSubscribe could not be opened; refusing to report active protection."
            self.stop()
            raise RuntimeError(detail)

        # Watch only the two sample-specific roots. A non-recursive watch on
        # each parent notices a later-created Local directory; existing roots
        # are watched recursively for new/modified artifacts.
        try:
            if not self.monitor_files:
                self.status["filesystem"] = "disabled"
                return dict(self.status)
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer

            outer = _FileHandler(self._enqueue_file, [])
            owner = self

            class Handler(FileSystemEventHandler):
                def on_created(self, event):
                    outer.on_created(event)
                    if (
                        event.is_directory
                        and os.path.basename(event.src_path).lower() == "local"
                    ):
                        owner._schedule_new_root(event.src_path)

                def on_modified(self, event):
                    outer.on_modified(event)

                def on_moved(self, event):
                    outer.on_moved(event)

            temp = os.environ.get("TEMP") or os.environ.get("TMP")
            windir = os.environ.get("WINDIR", r"C:\Windows")
            roots = []
            parents = []
            if temp:
                roots.append(os.path.join(temp, "Local"))
                parents.append(temp)
            roots.append(os.path.join(windir, "Temp", "Local"))
            parents.append(os.path.join(windir, "Temp"))
            outer.roots = [os.path.normcase(os.path.abspath(x)) for x in roots]
            self.observer = Observer()
            self._watch_handler = Handler()
            scheduled = 0
            for parent in dict.fromkeys(parents):
                if os.path.isdir(parent):
                    self.observer.schedule(self._watch_handler, parent, recursive=False)
                    scheduled += 1
            for root in roots:
                if os.path.isdir(root):
                    self.observer.schedule(self._watch_handler, root, recursive=True)
                    scheduled += 1
            if scheduled:
                self.observer.start()
                self.status["filesystem"] = "active"
                self._emit(
                    "SUCCESS",
                    "Targeted real-time staging-folder watcher active",
                    "Only the sample-specific Temp\\Local roots are watched; ordinary folders and processes are not scanned by this sensor.",
                )
            else:
                self.status["filesystem"] = "unavailable"
                self._emit(
                    "WARNING",
                    "Staging folder watcher could not start",
                    "The TEMP and Windows Temp parent directories were not accessible.",
                )
        except ImportError:
            self.status["filesystem"] = "unavailable"
            self._emit(
                "WARNING",
                "Real-time file watcher dependency is missing",
                "Install the packaged watchdog dependency; periodic targeted staging scans remain available.",
            )
        except Exception as exc:
            self.status["filesystem"] = "error"
            self._emit(
                "WARNING", "Targeted staging-folder watcher failed to start", str(exc)
            )
        return dict(self.status)

    def _schedule_new_root(self, path: str) -> None:
        if self.observer is None or not os.path.isdir(path):
            return
        expected = []
        temp = os.environ.get("TEMP") or os.environ.get("TMP")
        windir = os.environ.get("WINDIR", r"C:\Windows")
        if temp:
            expected.append(os.path.join(temp, "Local"))
        expected.append(os.path.join(windir, "Temp", "Local"))
        if os.path.normcase(os.path.abspath(path)) not in {
            os.path.normcase(os.path.abspath(x)) for x in expected
        }:
            return
        try:
            self.observer.schedule(self._watch_handler, path, recursive=True)
            self._emit(
                "INFO",
                "New sample-specific staging directory detected; recursive event watch attached",
                path,
            )
        except Exception as exc:
            self._emit(
                "WARNING", "Could not attach watcher to new staging directory", str(exc)
            )

    def stop(self) -> None:
        self.stop_event.set()
        # Keep the subscription wrapper (and its ctypes callback references)
        # alive until Event Log callbacks have been closed and workers drained.
        subscription = self.subscription
        if subscription:
            subscription.close()
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=5)
            except Exception:
                pass
            self.observer = None
        if self.event_worker and self.event_worker.is_alive():
            self.event_worker.join(timeout=5)
        if self.file_worker and self.file_worker.is_alive():
            self.file_worker.join(timeout=5)
        self.subscription = None
        self._emit(
            "INFO", "Real-time event subscriptions and targeted file watcher stopped"
        )
