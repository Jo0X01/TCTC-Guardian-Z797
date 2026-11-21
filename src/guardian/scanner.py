from __future__ import annotations

import hashlib
import ipaddress
import json
import ntpath
import os
import platform
import re
import time
import uuid
try:
    import winreg
except ImportError:  # non-Windows development/test host
    winreg = None  # type: ignore[assignment]
from pathlib import Path
from typing import Any, Callable

from guardian.indicators import (
    EXECUTABLE_EXTENSIONS, SCRIPT_EXTENSIONS,
    contains_pe_header, is_temp_local_path, is_known_staging_path,
    known_sample_artifact, KNOWN_SAMPLE_ARTIFACTS,
)
from guardian.models import Finding, ScanReport, StageResult, utc_now
from guardian.eventlogs import parse_event_log_output_with_status, event_field
from guardian import windows
from guardian.memory import MemoryScanCancelled, scan_process_memory, select_memory_targets

EventCallback = Callable[[dict[str, Any]], None]


EVENT_LOG_CHANNELS = (
    ("Sysmon", "Microsoft-Windows-Sysmon/Operational"),
    ("Windows Security", "Security"),
    ("PowerShell", "Microsoft-Windows-PowerShell/Operational"),
    ("Task Scheduler", "Microsoft-Windows-TaskScheduler/Operational"),
    ("WMI Activity", "Microsoft-Windows-WMI-Activity/Operational"),
)

if winreg is not None:
    RUN_KEYS = [
        ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
else:
    RUN_KEYS = []


LAB_SIMULATION_MARKER = "TCTC_GUARDIAN_LAB_SIMULATION"
LAB_SIMULATION_PREFIX = "TCTC-Guardian-Lab-"

def _is_manifested_lab_canary(path: str, digest: str) -> bool:
    """Label only the exact canary recorded by the explicit safe-lab tool."""
    try:
        local = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
        manifest = local / "TCTC Guardian" / "Lab" / "safe-lab-manifest.json"
        if not manifest.is_file() or manifest.is_symlink():
            return False
        record = json.loads(manifest.read_text(encoding="utf-8"))
        if record.get("marker") != LAB_SIMULATION_MARKER:
            return False
        expected_path = os.path.normcase(os.path.abspath(str(record.get("canary_file", ""))))
        actual_path = os.path.normcase(os.path.abspath(path))
        return bool(expected_path and expected_path == actual_path and
                    str(record.get("sha256", "")).lower() == str(digest).lower() and
                    Path(path).name.lower().startswith(LAB_SIMULATION_PREFIX.lower()))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False


def _remote_ip_from_netstat_line(line: str) -> str | None:
    """Parse only the remote endpoint from a `netstat -ano` TCP/UDP row.

    Local endpoint addresses must never trigger an IOC match. Supports IPv4,
    bracketed IPv6 and IPv6 scope IDs; wildcard / listening rows are ignored.
    """
    parts = line.split()
    if len(parts) < 4 or parts[0].upper() not in {"TCP", "TCPV6", "UDP", "UDPV6"}:
        return None
    remote = parts[2].strip()
    if not remote or remote in {"*", "*:*", "0.0.0.0:0", "[::]:0"}:
        return None
    if remote.startswith("[") and "]" in remote:
        host = remote[1:remote.index("]")]
    else:
        # netstat uses the final colon to delimit the port, including IPv6 rows.
        host, sep, _port = remote.rpartition(":")
        if not sep:
            return None
    if "%" in host:
        host = host.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if address.is_unspecified or address.is_multicast:
        return None
    return address.compressed


class ScanCancelled(Exception):
    pass


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    """Hash a file incrementally; memory use stays bounded regardless of file size."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_emit(cb: EventCallback | None, event: dict[str, Any]) -> None:
    if cb:
        try:
            cb(event)
        except Exception:
            pass


class ScanEngine:
    STAGES = [
        ("processes", "Running processes", "Check active processes and unusual executable locations"),
        ("memory", "Live process memory", "Inspect private executable regions, mapped code integrity, thread starts and AMSI exports"),
        ("persistence", "Startup & persistence", "Review Run keys, services, Startup folders and scheduled tasks"),
        ("staging", "Staging folders & files", "Inspect the sample's Temp\\Local staging pattern and suspicious PE files"),
        ("network", "Network & DNS traces", "Compare configured threat indicators with DNS cache, Hosts and active connections"),
        ("eventlogs", "Z797 event history", "Review Sysmon, PowerShell, Security, Task Scheduler and WMI events containing sample evidence"),
        ("verification", "Final consistency check", "Summarize sensor coverage, permissions, and unresolved indicators"),
    ]

    def __init__(
        self, event_callback: EventCallback | None = None, cancel_event=None,
        c2_domains: list[str] | None = None, c2_ips: list[str] | None = None,
        related_campaign_ips: list[str] | None = None,
        c2_urls: list[str] | None = None, c2_ports: list[str] | None = None,
        custom_staging_roots: list[str] | None = None, event_log_record_limit: int = 5000,
        enabled_stages: set[str] | None = None, memory_settings: dict[str, Any] | None = None,
        evidence_dir: str | None = None, monitoring_mode: bool = False,
        staging_cache: dict[str, dict[str, Any]] | None = None,
    ):
        self.event_callback = event_callback
        self.cancel_event = cancel_event
        self.findings: list[Finding] = []
        self.process_inventory: dict[int, dict[str, Any]] = {}
        self.errors: list[dict[str, str]] = []
        self.report: ScanReport | None = None
        from .threat_profile import DEFAULT_THREAT_PROFILE
        domain_values = DEFAULT_THREAT_PROFILE["c2_domains"] if c2_domains is None else c2_domains
        self.c2_domains = tuple(dict.fromkeys(x.strip().lower() for x in domain_values if x.strip()))
        self.primary_domain = self.c2_domains[0] if self.c2_domains else ""
        ip_values = DEFAULT_THREAT_PROFILE["c2_ips"] if c2_ips is None else c2_ips
        self.c2_ips = tuple(dict.fromkeys(x.strip() for x in ip_values if x.strip()))
        # Sibling-campaign infrastructure is deliberately excluded: this tool is
        # limited to the locally analysed TCTC/Z797 sample.
        self.related_campaign_ips = ()
        url_values = DEFAULT_THREAT_PROFILE["c2_urls"] if c2_urls is None else c2_urls
        self.c2_urls = tuple(dict.fromkeys(x.strip().lower() for x in url_values if x.strip()))
        from urllib.parse import urlparse
        self.c2_paths = tuple(dict.fromkeys(urlparse(url).path.lower() for url in self.c2_urls if urlparse(url).path))
        self.c2_ports = ()
        import ntpath
        self.custom_staging_roots = []  # compatibility only; custom roots are intentionally unsupported
        self.event_log_record_limit = max(100, min(int(event_log_record_limit), 5000))
        self.telemetry_coverage: dict[str, dict[str, Any]] = {}
        self.scan_coverage: dict[str, dict[str, Any]] = {}
        self.enabled_stages = set(enabled_stages) if enabled_stages is not None else {x[0] for x in self.STAGES}
        self.memory_settings = dict(memory_settings or {})
        self.firewall_policy = str(self.memory_settings.get("firewall_policy", "Ask before blocking"))
        self.evidence_dir = evidence_dir
        self.monitoring_mode = bool(monitoring_mode)
        self.staging_cache = staging_cache if staging_cache is not None else {}
        self._staging_seen: set[str] = set()
        self.memory_coverage: list[str] = []
        self.persistence_stats: dict[str, Any] = {
            "runmru_values_inspected": 0, "services_enumerated": 0,
            "service_imagepaths_read": 0, "startup_roots_checked": 0,
            "startup_roots_found": 0, "startup_files_inspected": 0, "errors": [],
        }
        self._stage_warning = False

    def log(self, level: str, message: str, detail: str = "") -> None:
        if level in {"WARNING", "ERROR"}:
            self._stage_warning = True
        _safe_emit(self.event_callback, {"type": "log", "level": level, "message": message, "detail": detail, "time": utc_now()})

    def check_cancel(self) -> None:
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise ScanCancelled("Scan cancelled by user")

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        _safe_emit(self.event_callback, {"type": "finding", "finding": finding.to_dict()})

    def run(self) -> ScanReport:
        # One sample-specific investigation profile; there is no generic whole-drive scan mode.
        mode = "targeted"
        report = ScanReport(
            scan_id=uuid.uuid4().hex[:10], started_at=utc_now(), mode=mode,
            hostname=platform.node(), os_name=windows.format_os(),
        )
        self.report = report
        selected_stages = [stage for stage in self.STAGES if stage[0] in self.enabled_stages]
        total = len(selected_stages)
        selected_index = 0
        # Every planned stage is now represented, including checks the user disabled.
        # This prevents an absent stage from looking like a clean/empty check.
        for stage_id, name, description in self.STAGES:
            if stage_id not in self.enabled_stages:
                result = StageResult(stage_id, name, "skipped", "Disabled in Settings; this source was not queried.")
                report.stages.append(result)
                self.scan_coverage[stage_id] = {"status": "disabled", "reason": "Disabled in Settings; no data was queried."}
                if stage_id == "eventlogs":
                    self.telemetry_coverage = {
                        label: {"channel": channel, "status": "disabled", "records_returned": 0,
                                "records_inspected": 0, "limit_per_channel": self.event_log_record_limit,
                                "truncated": False, "matched_findings": 0,
                                "reason": "Historical event review is disabled in Settings; this channel was not queried."}
                        for label, channel in EVENT_LOG_CHANNELS
                    }
                continue
            if self.cancel_event is not None and self.cancel_event.is_set():
                report.cancelled = True
                break
            selected_index += 1
            result = StageResult(stage_id, name, "running", description)
            self._stage_warning = False
            report.stages.append(result)
            start = time.monotonic()
            _safe_emit(self.event_callback, {"type": "stage", "stage": result.to_dict(), "index": selected_index, "total": total})
            self.log("INFO", f"Started: {name}", description)
            before = len(self.findings)
            try:
                getattr(self, f"_scan_{stage_id}")()
                result.findings = len(self.findings) - before
                result.status = "warning" if result.findings or self._stage_warning else "completed"
                if stage_id == "verification":
                    result.message = f"Verification complete: {len(self.findings)} total finding(s), {len(self.errors)} check error(s)"
                    result.status = "warning" if self.findings or self.errors or self._stage_warning else "completed"
                elif result.findings:
                    result.message = f"{result.findings} finding(s)"
                elif self._stage_warning:
                    result.message = "Completed with coverage warnings"
                elif self.scan_coverage.get(stage_id, {}).get("status") in {"disabled", "unavailable", "unsupported", "no_targets"}:
                    result.status = "warning"
                    result.message = self.scan_coverage[stage_id].get("reason") or self.scan_coverage[stage_id].get("note") or "This source was not inspected."
                else:
                    result.message = "No indicator found in this check"
            except ScanCancelled:
                report.cancelled = True
                result.status = "cancelled"
                result.message = "Cancelled by user"
                result.duration_seconds = time.monotonic() - start
                _safe_emit(self.event_callback, {"type": "stage_done", "stage": result.to_dict(), "index": selected_index, "total": total})
                break
            except Exception as exc:
                result.status = "error"
                result.message = "This check could not be completed"
                result.error = f"{type(exc).__name__}: {exc}"
                self.errors.append({"stage": name, "message": result.error})
                report.errors.append({"stage": name, "message": result.error})
                self.log("ERROR", f"{name}: {result.message}", result.error)
            result.duration_seconds = round(time.monotonic() - start, 2)
            _safe_emit(self.event_callback, {"type": "stage_done", "stage": result.to_dict(), "index": selected_index, "total": total})
            self.log("SUCCESS" if result.status == "completed" else "WARNING" if result.status == "warning" else "ERROR",
                     f"Finished: {name} — {result.message}")
        report.findings = list(self.findings)
        report.coverage = dict(self.scan_coverage)
        report.coverage["event_logs"] = dict(self.telemetry_coverage)
        report.ended_at = utc_now()
        report.errors = list(self.errors)
        report.visibility_notes = [
            "This tool is limited to the locally analysed TCTC/Z797 sample, its recovered indicators and its two analysed Temp\\Local staging roots. It is not a general-purpose antivirus.",
            "A clean result means no configured indicator was found in the sources that were readable; it does not prove absence of compromise.",
            "Historical event-log coverage depends on channel availability, retention, permissions, and logging having been enabled before the incident. Only Sysmon, PowerShell 4103/4104, Windows process/persistence audit, Task Scheduler and WMI records containing Z797 indicators are relevant.",
            "The sample's dynamic Profile can provide URLs and payloads not embedded in the recovered core; this scanner cannot know unknown future values from static indicators alone.",
            "Live memory inspection is read-only and reports private executable regions, valid private PE headers, thread starts inside such regions, copy-on-write image pages and the sample-relevant AMSI stubs when readable.",
            "Private executable memory and copy-on-write pages can be legitimate (JIT, EDR, hotpatching and instrumentation); individual indicators are not proof of infection.",
            "APC queue state and past injections cannot be reconstructed reliably from a memory snapshot. Historical evidence requires telemetry that was enabled before the event.",
            "Continuous memory checks run only while the application remains open; this build is not a Windows service.",
            "Native API calls and memory-only behavior are not all visible through ordinary file, process and event-log inspection.",
        ]
        for skipped_stage in (stage for stage in self.STAGES if stage[0] not in self.enabled_stages):
            report.visibility_notes.append(f"{skipped_stage[1]} was disabled in Settings and was not queried during this investigation.")
        if "memory" not in self.enabled_stages:
            report.visibility_notes.append("Live process-memory inspection was not selected for this investigation; no conclusion about process memory can be drawn.")
        elif self.memory_coverage:
            report.visibility_notes.append(f"Memory coverage gaps: {len(self.memory_coverage)} process or API limitation(s). First gaps: " + " | ".join(self.memory_coverage[:8]))
        else:
            report.visibility_notes.append("The memory stage reported no access gaps. This does not mean every process or every memory technique is observable.")
        _safe_emit(self.event_callback, {"type": "scan_done", "report": report.to_dict()})
        return report

    def _scan_processes(self) -> None:
        if not windows.IS_WINDOWS:
            self.scan_coverage["processes"] = {"status": "unavailable", "reason": "Windows process inventory is available only on Windows."}
            self.log("WARNING", "Windows process inspection is unavailable on this platform")
            return
        processes = windows.list_processes()
        self.process_inventory = {int(p.get("pid", -1)): p for p in processes if int(p.get("pid", -1)) > 0}
        inaccessible = sum(1 for p in processes if not p.get("path"))
        self.log("INFO", f"Enumerated {len(processes)} processes")
        if inaccessible:
            self.log("WARNING", f"Executable path unavailable for {inaccessible} process(es)", "Protected processes or access restrictions can prevent image-path inspection.")
        self.scan_coverage["processes"] = {
            "status": "read_with_gaps" if inaccessible else "read",
            "processes_enumerated": len(processes),
            "image_paths_available": len(processes) - inaccessible,
            "image_paths_unavailable": inaccessible,
            "memory_target_allowlist": sorted({"runtimebroker.exe", "explorer.exe", "chrome.exe", "csc.exe (Temp\\Local only)"}),
        }
        total_processes = len(processes)
        for process_index, p in enumerate(processes, start=1):
            self.check_cancel()
            name = str(p.get("name", ""))
            if process_index == 1 or process_index % 10 == 0 or process_index == total_processes:
                _safe_emit(self.event_callback, {
                    "type": "current_task", "stage": "Running processes",
                    "current": f"{name or 'Unknown process'} · PID {p.get('pid', '?')}",
                    "detail": str(p.get("path", "Image path unavailable")) or "Image path unavailable",
                    "completed": process_index, "total": total_processes,
                })
            path = str(p.get("path", ""))
            if not path or not is_known_staging_path(path):
                continue
            try:
                st = os.stat(path, follow_symlinks=False)
                if not os.path.isfile(path) or Path(path).is_symlink():
                    continue
                digest = sha256_file(path)
                artifact = known_sample_artifact(digest, int(st.st_size))
            except OSError as exc:
                self.log("WARNING", "Could not verify a process image in the Z797 staging path", f"{path}: {exc}")
                continue
            if not artifact:
                # A Temp\\Local location or familiar process name is not by
                # itself proof that the process belongs to this infection.
                continue
            self.add(Finding(
                title="Exact Z797 payload is currently running",
                severity="Critical", confidence="High", category="Exact sample fingerprint",
                description=f"A live process image matches the recovered sample artifact '{artifact}' by SHA-256 and exact byte size. The process is currently executing from one of the analysed staging folders.",
                evidence=[f"PID: {p['pid']}", f"Parent PID: {p.get('ppid', 'unknown')}", f"Image: {path}", f"Exact sample artifact: {artifact}", f"SHA-256: {digest}", f"File size: {st.st_size:,} bytes"],
                path=path, sha256=digest, remediation="contain_exact_sample_process",
                metadata={"pid": int(p["pid"]), "process_path": path, "known_sample_artifact": artifact,
                          "hash_size_verified": True, "expected_size": int(st.st_size), "file_size": int(st.st_size),
                          "event_driven": False}, stage_id="processes"))

    def _scan_memory(self) -> None:
        if not windows.IS_WINDOWS:
            self.memory_coverage = ["Live memory APIs are unavailable on this operating system."]
            self.scan_coverage["memory"] = {"status": "unavailable", "reason": self.memory_coverage[0], "read_only": True}
            self.log("WARNING", "Live memory inspection is available only on Windows")
            return
        processes = list(self.process_inventory.values()) if self.process_inventory else windows.list_processes()
        memory_stats: dict[str, Any] = {}
        try:
            findings, coverage = scan_process_memory(
                processes, settings=self.memory_settings, evidence_dir=self.evidence_dir,
                cancel_event=self.cancel_event, progress=self.event_callback, stats_out=memory_stats,
            )
        except MemoryScanCancelled as exc:
            raise ScanCancelled(str(exc)) from exc
        self.memory_coverage = coverage
        status = str(memory_stats.get("status", "unknown"))
        if status == "no_targets":
            self.memory_coverage = coverage or ["No eligible TCTC target process was present; no process memory was opened."]
            self.log("WARNING", "No eligible TCTC target process was present", self.memory_coverage[0])
        self.scan_coverage["memory"] = {
            "status": status,
            "reason": (memory_coverage[0] if status in {"no_targets", "unsupported"} and memory_coverage else ""),
            "eligible_processes": int(memory_stats.get("processes_selected", 0) or 0),
            "eligible_process_names": sorted({str(x.get("process", "Unknown")) for x in memory_stats.get("process_details", [])}),
            "findings": len(findings),
            "coverage_gap_count": len(coverage),
            "coverage_gaps": list(coverage),
            "read_only": True,
            "inspection": memory_stats,
        }
        for item in findings:
            self.check_cancel()
            evidence = list(item.evidence)
            if item.rationale:
                evidence.insert(0, item.rationale)
            if item.evidence_file:
                evidence.append(f"Memory evidence: {item.evidence_file}")
            if item.sha256:
                evidence.append(f"SHA-256: {item.sha256}")
            # Memory-only indicators are investigative evidence, never a kill target.
            action = "none"
            self.add(Finding(
                title=item.title, severity=item.severity, confidence=item.confidence,
                category="Memory analysis", description=item.rationale or item.title,
                evidence=evidence, path=item.process_path, sha256=item.sha256,
                remediation=action,
                metadata={**item.to_dict(), "process_id": item.pid, "memory_indicator": item.indicator},
                stage_id="memory",
            ))
        if coverage:
            self.log("WARNING", f"Memory inspection had {len(coverage)} coverage gap(s)", "\n".join(coverage[:12]))
            if len(coverage) > 12:
                self.log("WARNING", f"{len(coverage) - 12} additional memory coverage gap(s) were recorded in the stage summary")
        self.log(
            "INFO",
            "Memory API work confirmed: "
            f"{memory_stats.get('processes_opened', 0)}/{memory_stats.get('processes_selected', 0)} process handles opened; "
            f"{memory_stats.get('regions_examined', 0)} VirtualQueryEx regions; "
            f"{memory_stats.get('remote_read_attempts', 0)} ReadProcessMemory calls / "
            f"{memory_stats.get('remote_bytes_read', 0):,} bytes; "
            f"{memory_stats.get('threads_enumerated', 0)} threads enumerated; "
            f"{len(findings)} finding(s), {len(coverage)} gap(s).",
        )

    def _scan_persistence(self) -> None:
        if not windows.IS_WINDOWS:
            self.scan_coverage["persistence"] = {"status": "unavailable", "reason": "Registry, service, startup and scheduled-task inspection requires Windows."}
            return
        registry_keys_opened = 0
        registry_values_inspected = 0
        registry_errors: list[str] = []
        self.persistence_stats = {
            "registry_keys_attempted": len(RUN_KEYS), "registry_keys_opened": 0,
            "registry_values_inspected": 0, "registry_keys_missing": 0,
            "runmru_values_inspected": 0, "services_enumerated": 0, "service_imagepaths_read": 0,
            "startup_roots_checked": 0, "startup_roots_found": 0, "startup_roots_missing": 0, "startup_files_inspected": 0,
            "scheduled_tasks_returned": 0, "scheduled_tasks_inspected": 0,
            "scheduled_tasks_query_succeeded": False,
            "errors": [],
        }
        for root_name, root, subkey in RUN_KEYS:
            self.check_cancel()
            try:
                with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)) as key:
                    registry_keys_opened += 1
                    self.persistence_stats["registry_keys_opened"] += 1
                    index = 0
                    while True:
                        try:
                            value_name, value_data, value_type = winreg.EnumValue(key, index)
                        except OSError as exc:
                            if getattr(exc, "winerror", None) not in (None, 259):
                                registry_errors.append(f"{root_name}\\{subkey} enumeration: {exc}")
                            break
                        index += 1
                        registry_values_inspected += 1
                        self.persistence_stats["registry_values_inspected"] += 1
                        text = str(value_data)
                        suspicious = self._has_z797_reference(text)
                        reason = "Startup command contains a Z797-specific domain, endpoint or exact analysed artifact name."
                        if suspicious:
                            self.add(Finding(
                                title="Run / RunOnce value launches the Z797 infection", severity="High" if self._matches_c2(text) else "Medium",
                                confidence="High" if self._matches_c2(text) else "Medium",
                                category="Persistence", description=reason,
                                evidence=[f"Registry: {root_name}\\{subkey}", f"Value: {value_name}", f"Command: {text}"],
                                path=f"{root_name}\\{subkey}\\{value_name}", remediation="remove_registry_value",
                                metadata={"root": root_name, "subkey": subkey, "value_name": value_name,
                                          "value_type": int(value_type), "value_data": text, "expected_value_data": text},
                                stage_id="persistence"))
            except FileNotFoundError:
                self.persistence_stats["registry_keys_missing"] += 1
                continue
            except PermissionError as exc:
                registry_errors.append(f"{root_name}\\{subkey}: {exc}")
                self.log("WARNING", f"Cannot read {root_name}\\{subkey}", str(exc))
            except OSError as exc:
                registry_errors.append(f"{root_name}\\{subkey}: {exc}")
                self.log("WARNING", f"Registry key could not be read: {subkey}", str(exc))

        # RunMRU can retain the command pasted into the Windows Run dialog by a
        # ClickFix victim. Read matching entries only; never delete this history.
        self._scan_run_mru()
        self._scan_service_paths()
        self._scan_startup_folders()
        self.log("INFO", "Reviewing scheduled task actions and launch paths")
        tasks, error = windows.query_scheduled_tasks()
        if not error:
            self.persistence_stats["scheduled_tasks_query_succeeded"] = True
            self.persistence_stats["scheduled_tasks_returned"] = len(tasks)
            self.log("INFO", f"Enumerated {len(tasks)} scheduled task record(s)")
        if error:
            self.persistence_stats["errors"].append("Scheduled Tasks: " + error)
            self.log("WARNING", "Scheduled Tasks could not be queried", error)
        for task_index, task in enumerate(tasks, start=1):
            self.check_cancel()
            self.persistence_stats["scheduled_tasks_inspected"] += 1
            if task_index == 1 or task_index % 50 == 0 or task_index == len(tasks):
                _safe_emit(self.event_callback, {
                    "type": "current_task", "stage": "Startup & persistence",
                    "current": f"Scheduled task {task_index}/{len(tasks)} · {task.get('name', 'Unknown task')}",
                    "detail": str(task.get("action", ""))[:500],
                    "completed": task_index, "total": len(tasks),
                })
            suspicious = self._has_z797_reference(task.get("action", ""))
            reason = "Scheduled task action contains a Z797-specific domain, endpoint or exact analysed artifact name."
            if suspicious:
                self.add(Finding(
                    title="Scheduled task references the Z797 infection", severity="High" if self._matches_c2(task["action"]) else "Medium",
                    confidence="High" if self._matches_c2(task["action"]) else "Medium",
                    category="Persistence", description=reason,
                    evidence=[f"Task: {task['name']}", f"Action: {task['action']}", f"Status: {task['status']}"],
                    path=task["action"], remediation="disable_task",
                    metadata={"task_name": task["name"], "task_action": task["action"],
                              "expected_task_action": task["action"], "task_status": task["status"]}, stage_id="persistence"))
        self.persistence_stats["registry_values_inspected"] = registry_values_inspected
        self.persistence_stats["registry_keys_opened"] = registry_keys_opened
        self.persistence_stats["errors"].extend(registry_errors)
        self.persistence_stats["registry_errors"] = len(registry_errors)
        self.persistence_stats["error_count"] = len(self.persistence_stats["errors"])
        if self.persistence_stats["errors"]:
            persistence_status = "read_with_gaps"
        else:
            persistence_status = "read"
        self.scan_coverage["persistence"] = {"status": persistence_status, **self.persistence_stats}
        self.log("INFO", "Persistence inspection counters: " + "; ".join(
            f"{key}={value}" for key, value in self.persistence_stats.items() if key != "errors"
        ))

    def _scan_run_mru(self) -> None:
        if not windows.IS_WINDOWS or winreg is None:
            return
        self.persistence_stats.setdefault("runmru_values_inspected", 0)
        self.persistence_stats.setdefault("errors", [])
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        try:
            access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, access) as key:
                index = 0
                while True:
                    self.check_cancel()
                    try:
                        value_name, value_data, value_type = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    index += 1
                    self.persistence_stats["runmru_values_inspected"] += 1
                    if str(value_name).lower() == "mrulist" or not isinstance(value_data, str):
                        continue
                    command = value_data.strip()
                    if not command:
                        continue
                    lowered = command.lower()
                    campaign_match = self._matches_c2(command) or any(
                        token in lowered for token in ("crandle.txt", "z797.ps1", "tctc.bba")
                    )
                    if not campaign_match:
                        continue
                    confidence = "High"
                    severity = "High"
                    reason = "Windows RunMRU contains an exact Z797 domain, endpoint or sample-artifact reference from the locally analysed chain."
                    self.add(Finding(
                        title="Windows Run dialog history contains a suspicious ClickFix command",
                        severity=severity, confidence=confidence, category="Initial access trace",
                        description=reason,
                        evidence=[f"Registry: HKCU\\{key_path}", f"Value: {value_name}", f"Command: {command}"],
                        path=f"HKCU\\{key_path}\\{value_name}", remediation="none",
                        metadata={"registry_key": key_path, "value_name": str(value_name), "value_type": int(value_type), "command": command, "evidence_only": True},
                        stage_id="persistence"))
        except FileNotFoundError:
            self.persistence_stats["runmru_key_missing"] = True
            return
        except PermissionError as exc:
            self.persistence_stats["errors"].append(f"RunMRU: {exc}")
            self.log("WARNING", "RunMRU history could not be read", str(exc))
        except OSError as exc:
            self.persistence_stats["errors"].append(f"RunMRU: {exc}")
            self.log("WARNING", "RunMRU history could not be read", str(exc))

    def _scan_service_paths(self) -> None:
        self.log("INFO", "Reviewing Windows service ImagePath and start type")
        self.persistence_stats.setdefault("services_enumerated", 0)
        self.persistence_stats.setdefault("service_imagepaths_read", 0)
        self.persistence_stats.setdefault("errors", [])
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
        except OSError as exc:
            self.persistence_stats["errors"].append(f"Services root: {exc}")
            self.log("WARNING", "Service registry could not be read", str(exc))
            return
        with root:
            i = 0
            while True:
                self.check_cancel()
                try:
                    service = winreg.EnumKey(root, i)
                except OSError as exc:
                    if getattr(exc, "winerror", None) not in (None, 259):
                        self.persistence_stats["errors"].append(f"Service enumeration index {i}: {exc}")
                    break
                i += 1
                self.persistence_stats["services_enumerated"] += 1
                try:
                    with winreg.OpenKey(root, service) as sk:
                        image, _ = winreg.QueryValueEx(sk, "ImagePath")
                        start, _ = winreg.QueryValueEx(sk, "Start")
                    self.persistence_stats["service_imagepaths_read"] += 1
                    text = str(image)
                    suspicious = self._has_z797_reference(text)
                    reason = "Service ImagePath contains a Z797-specific domain, endpoint or exact analysed artifact name."
                    if suspicious and int(start) in (0, 1, 2):
                        self.add(Finding(
                            title="Service ImagePath references a suspicious location", severity="High", confidence="High",
                            category="Persistence", description=f"{reason}. Service start type is system, automatic or boot-start.",
                            evidence=[f"Service: {service}", f"Start type: {start}", f"ImagePath: {text}"], path=text,
                            remediation="disable_service", metadata={"service_name": service, "image_path": text,
                                                                     "expected_image_path": text, "start_type": int(start)}, stage_id="persistence"))
                except OSError as exc:
                    self.persistence_stats["errors"].append(f"Service {service}: {exc}")
                    continue

    def _scan_startup_folders(self) -> None:
        self.persistence_stats.setdefault("startup_roots_checked", 0)
        self.persistence_stats.setdefault("startup_roots_found", 0)
        self.persistence_stats.setdefault("startup_files_inspected", 0)
        self.persistence_stats.setdefault("errors", [])
        candidates = []
        appdata = os.environ.get("APPDATA", "")
        programdata = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        if appdata:
            candidates.append(Path(appdata) / r"Microsoft\Windows\Start Menu\Programs\Startup")
        candidates.append(Path(programdata) / r"Microsoft\Windows\Start Menu\Programs\Startup")
        for folder in candidates:
            self.persistence_stats["startup_roots_checked"] += 1
            try:
                if not folder.is_dir():
                    self.persistence_stats["startup_roots_missing"] += 1
                    continue
                self.persistence_stats["startup_roots_found"] += 1
                for p in folder.iterdir():
                    self.check_cancel()
                    if p.is_file() and p.suffix.lower() in EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS:
                        self.persistence_stats["startup_files_inspected"] += 1
                        data = str(p)
                        st = p.stat()
                        digest = sha256_file(str(p))
                        known_artifact = known_sample_artifact(digest, int(st.st_size))
                        markers = self._scan_file_markers(str(p))
                        exact_name = p.name.lower() in {"crandle.txt", "z797.ps1", "tctc.bba"}
                        if not (known_artifact or markers or exact_name):
                            continue
                        actionable = bool(known_artifact or markers)
                        reason = (
                            "Startup item content matches a recovered Z797 artifact or contains an exact campaign IOC. "
                            "Guardian records the current hash and rechecks it before quarantine."
                            if actionable else
                            "Startup item uses an exact delivery filename from the analysed Z797 chain, but its content is not independently linked. Filename alone is not enough for automatic cleanup."
                        )
                        self.add(Finding(
                            title="Startup item references the Z797 infection", severity="High" if actionable else "Medium", confidence="High" if actionable else "Low",
                            category="Persistence", description=reason,
                            evidence=[f"Startup item: {p}", f"SHA-256: {digest}", f"Size: {st.st_size} bytes", *( ["Matched Z797 indicators: " + ", ".join(markers)] if markers else [] )],
                            path=str(p), sha256=digest, remediation="quarantine_file" if actionable else "none",
                            metadata={"file_path": str(p), "expected_size": int(st.st_size), "file_size": int(st.st_size), "matched_markers": markers, "known_sample_artifact": known_artifact, "evidence_only": not actionable, "startup_item": True}, stage_id="persistence"))
            except OSError as exc:
                self.persistence_stats["errors"].append(f"Startup folder {folder}: {exc}")
                self.log("WARNING", f"Could not enumerate Startup folder {folder}", str(exc))

    def _scan_staging(self) -> None:
        if not windows.IS_WINDOWS:
            self.scan_coverage["staging"] = {"status": "unavailable", "reason": "Targeted staging-file inspection requires Windows path configuration."}
            return
        temp = Path(os.environ.get("TEMP", os.environ.get("TMP", "")))
        windir = Path(os.environ.get("WINDIR", r"C:\Windows"))
        # Only the two exact Temp\\Local roots recovered from this sample are scanned.
        roots = ([temp / "Local"] if str(temp) else []) + [windir / "Temp" / "Local"]
        unique: list[Path] = []
        for p in roots:
            try:
                rp = p.resolve()
                if rp not in unique:
                    unique.append(rp)
            except OSError:
                pass
        scanned = 0
        inspected = 0
        unchanged = 0
        walk_errors: list[str] = []
        self._staging_seen = set()
        for root in unique:
            self.check_cancel()
            if not root.exists():
                self.log("INFO", f"Staging folder not present: {root}")
                continue
            if not root.is_dir():
                self.log("WARNING", f"Staging path exists but is not a directory: {root}")
                continue
            self.log("INFO", f"Inspecting staging directory: {root}")
            def on_walk_error(exc: OSError) -> None:
                walk_errors.append(str(exc)[:400])
                self.log("WARNING", "A staging directory could not be enumerated", str(exc))
            for current, dirs, files in os.walk(root, onerror=on_walk_error):
                dirs[:] = [d for d in dirs if d.lower() not in {"node_modules", ".git"}]
                for filename in files:
                    self.check_cancel()
                    scanned += 1
                    full = os.path.join(current, filename)
                    if scanned == 1 or scanned % 25 == 0:
                        _safe_emit(self.event_callback, {"type": "current_task", "stage": "Staging folders & files", "current": filename, "detail": full, "completed": scanned})
                    if scanned % 500 == 0:
                        self.log("INFO", f"Targeted staging progress: {scanned} file entries inspected")
                    did_inspect, skipped_unchanged = self._inspect_staging_candidate(full)
                    inspected += int(did_inspect)
                    unchanged += int(skipped_unchanged)
        self.log("INFO", f"Staging enumeration: {scanned} file(s); inspected {inspected}; unchanged skipped {unchanged}")

        if self.monitoring_mode:
            # Drop stale entries after a complete pass so deleted/renamed files
            # do not leave unbounded cache records across long tray sessions.
            for cached_path in tuple(self.staging_cache):
                if cached_path not in self._staging_seen:
                    self.staging_cache.pop(cached_path, None)
        self.scan_coverage["staging"] = {
            "status": "read_with_gaps" if walk_errors else "read",
            "roots": [str(root) for root in unique],
            "file_entries_enumerated": scanned,
            "files_inspected": inspected,
            "unchanged_files_skipped_from_rehash": unchanged,
            "enumeration_errors": walk_errors,
            "whole_drive_scan": False,
        }
        self.log("INFO", f"Staging file work: inspected {inspected}; unchanged skipped {unchanged}")

    def _inspect_staging_candidate(self, path: str) -> tuple[bool, bool]:
        """Use file metadata to avoid re-hashing unchanged files during monitoring only."""
        key = os.path.normcase(os.path.abspath(path))
        try:
            st = os.stat(path, follow_symlinks=False)
            state = (int(st.st_size), int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))),
                     int(getattr(st, "st_ctime_ns", int(st.st_ctime * 1e9))))
            self._staging_seen.add(key)
            cached = self.staging_cache.get(key) if self.monitoring_mode else None
            now = time.monotonic()
            # Re-hash unchanged items at least every 30 minutes as a backstop
            # against metadata timestamp manipulation by a local process.
            cache_fresh = bool(cached and now - float(cached.get("checked_at", 0.0)) < 1800)
            if self.monitoring_mode and cached and cached.get("state") == state and cache_fresh:
                # Findings must persist across monitoring cycles; only the expensive
                # file reads are skipped. Re-attach the cached evidence to this report.
                for item in cached.get("findings", []):
                    try:
                        self.findings.append(Finding(**item))
                    except (TypeError, ValueError):
                        continue
                return False, True
            before = len(self.findings)
            ok = self._inspect_staging_file(path)
            if self.monitoring_mode and ok:
                cached_findings = [item.to_dict() for item in self.findings[before:]
                                   if os.path.normcase(os.path.abspath(item.path)) == key]
                self.staging_cache[key] = {
                    "state": state, "checked_at": now, "findings": cached_findings,
                }
            elif self.monitoring_mode:
                self.staging_cache.pop(key, None)
            return True, False
        except OSError:
            if self.monitoring_mode:
                self.staging_cache.pop(key, None)
            ok = self._inspect_staging_file(path)
            return True, False

    def _inspect_staging_file(self, path: str) -> bool:
        """Inspect only exact sample artifacts or files carrying sample-specific IOCs."""
        try:
            if Path(path).is_symlink() or not is_known_staging_path(path):
                return True
            st = os.stat(path, follow_symlinks=False)
            if not os.path.isfile(path) or st.st_size <= 0:
                return True
            base = os.path.basename(path).lower()
            exact_name = base in {"crandle.txt", "z797.ps1", "tctc.bba"}
            digest = sha256_file(path)
            known_artifact = known_sample_artifact(digest, int(st.st_size))
            # Hash every file in the exact staging roots, but inspect content
            # only for script/text/shortcut formats. Unrelated browser/native
            # binaries and profile stores are not content-scanned.
            marker_extensions = SCRIPT_EXTENSIONS | {".txt", ".url", ".lnk", ".hta", ".xml", ".ini", ".json"}
            markers = self._scan_file_markers(path) if Path(path).suffix.lower() in marker_extensions else []
            if not (known_artifact or exact_name or markers):
                return True
            exact_hash = bool(known_artifact)
            lab_simulated = bool(markers and _is_manifested_lab_canary(path, digest))
            if lab_simulated:
                severity, confidence = "Info", "High"
                reason = ("This is the inert text canary created by TCTC Guardian's Safe Lab tool. "
                          "Its static IOC strings are test data, not an executed payload or proof of infection.")
            elif exact_hash:
                severity, confidence = "Critical", "High"
                reason = f"Exact SHA-256 and file-size match for a locally recovered Z797 artifact: {known_artifact}"
            elif markers:
                severity, confidence = "High", "High"
                reason = "The file contains an exact recovered Z797 C2 domain, URL or endpoint marker. The hash is recorded so the content can be revalidated before quarantine."
            else:
                severity, confidence = "Medium", "Medium"
                reason = "The exact staging filename used in the analysed Z797 delivery chain was found in the sample-specific Temp\\Local directory. Filename alone is not cryptographic proof."
            evidence = [reason, f"Size: {st.st_size:,} bytes", f"Last modified: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime))}", f"SHA-256: {digest}"]
            if markers:
                evidence.append("Matched Z797 indicators: " + ", ".join(markers))
            if lab_simulated:
                evidence.append("LAB ONLY: inert TXT canary; no malware code, network request, persistence, or memory modification.")
            self.add(Finding(
                title=("[LAB] Harmless Z797 indicator canary" if lab_simulated else
                       "Exact Z797 sample artifact found" if exact_hash else "Z797 delivery artifact / indicator found"),
                severity=severity, confidence=confidence,
                category=("Lab simulation evidence" if lab_simulated else
                          "Exact sample fingerprint" if exact_hash else "Z797 staging evidence"),
                description=reason, evidence=evidence, path=path, sha256=digest,
                remediation="quarantine_file" if (exact_hash or markers) else "none",
                metadata={"file_path": path, "known_sample_artifact": known_artifact,
                          "hash_size_verified": exact_hash, "expected_size": int(st.st_size),
                          "file_size": int(st.st_size), "sample_filename_match": exact_name,
                          "matched_markers": markers, "manual_review_required": not exact_hash and bool(markers),
                          "evidence_only": not (exact_hash or markers), "lab_simulated": lab_simulated},
                stage_id="staging"))
            return True
        except (PermissionError, OSError) as exc:
            self.log("WARNING", "Could not inspect a Z797 staging file", f"{path}: {exc}")
            return False

    def _scan_file_markers(self, path: str) -> list[str]:
        """Search the entire file for configured markers using bounded-memory streaming."""
        tokens = tuple(dict.fromkeys(self.c2_domains + self.c2_urls + self.c2_paths + ("/nfront.php", "/nback.php", "crandle.txt", "z797.ps1", "tctc.bba")))
        patterns: list[tuple[str, bytes]] = []
        for token in tokens:
            try:
                patterns.append((token, token.encode("ascii", errors="ignore").lower()))
                patterns.append((token, token.encode("utf-16le", errors="ignore").lower()))
            except Exception:
                continue
        patterns = [(label, pattern) for label, pattern in patterns if pattern]
        if not patterns:
            return []
        overlap = max(len(pattern) for _, pattern in patterns) - 1
        carry = b""
        found: set[str] = set()
        try:
            with open(path, "rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    block = (carry + chunk).lower()
                    for label, pattern in patterns:
                        if label not in found and pattern in block:
                            found.add(label)
                    carry = block[-overlap:] if overlap > 0 else b""
            return [token for token in tokens if token in found]
        except OSError:
            return []

    def _dns_evidence(self, output: str) -> list[str]:
        blocks = re.split(r"\n\s*\n", output)
        for block in blocks:
            if self._matches_c2(block):
                lines = [x.strip() for x in block.splitlines() if x.strip()]
                return ["DNS record details: " + " | ".join(lines[:6])[:600]] if lines else []
        return []

    def _has_z797_reference(self, value: str) -> bool:
        lowered = str(value or "").lower()
        return bool(
            any(x and x.lower() in lowered for x in (*self.c2_domains, *self.c2_urls, *self.c2_paths))
            or any(name in lowered for name in ("crandle.txt", "z797.ps1", "tctc.bba"))
        )

    def _matches_c2(self, value: str) -> bool:
        lowered = str(value).lower()
        return any(domain in lowered for domain in self.c2_domains)

    def _matched_campaign_domains(self, value: str) -> list[str]:
        lowered = str(value).lower()
        return [domain for domain in self.c2_domains if domain in lowered]

    def _scan_network(self) -> None:
        if not windows.IS_WINDOWS:
            self.scan_coverage["network"] = {"status": "unavailable", "reason": "DNS cache, Hosts and active endpoint inspection require Windows."}
            return
        network_coverage = {
            "status": "read", "dns_cache_read": False, "hosts_read": False,
            "netstat_read": False, "dns_lines": 0, "hosts_lines": 0,
            "hosts_matches": 0, "netstat_lines": 0, "endpoint_rows": 0,
            "campaign_ip_endpoint_rows": 0, "unattributed_campaign_ip_endpoints": 0,
            "configured_domains": list(self.c2_domains), "configured_ips": list(self.c2_ips),
            "matched_domains_in_dns": [], "resolved_campaign_domain_ips": [],
            "errors": [],
        }
        dns = ""
        configured_ips = list(self.c2_ips)
        resolved_ips: list[str] = []
        try:
            dns = windows.get_dns_cache()
            network_coverage["dns_cache_read"] = True
            network_coverage["dns_lines"] = len(dns.splitlines())
            if self._matches_c2(dns):
                block = next((b for b in re.split(r"\n\s*\n", dns) if self._matches_c2(b)), "")
                matched_domains = self._matched_campaign_domains(block or dns)
                network_coverage["matched_domains_in_dns"] = list(matched_domains)
                evidence = ["DNS cache contains: " + ", ".join(matched_domains)] + self._dns_evidence(dns)
                ipv4_pattern = r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"
                import ipaddress
                for candidate in re.findall(ipv4_pattern, block):
                    try:
                        ipaddress.IPv4Address(candidate)
                        if candidate not in resolved_ips:
                            resolved_ips.append(candidate)
                    except ipaddress.AddressValueError:
                        pass
                if resolved_ips:
                    evidence.append("Resolver-cache address(es): " + ", ".join(resolved_ips))
                self.add(Finding(
                    title="Unattributed historical DNS trace for a Z797 domain", severity="Low", confidence="Low",
                    category="Historical network context", description="The Windows DNS cache contains a domain recovered from the analysed Z797 chain. DNS cache data does not identify which application requested the lookup or prove that the malware made the request, so this is context only—not a confirmed infection finding.",
                    evidence=evidence + ["No originating process or request timestamp is available from this cache record.", "This trace cannot be cleaned safely by clearing the entire DNS cache."],
                    path="Windows DNS Client cache", remediation="none",
                    metadata={"domain": matched_domains[0] if matched_domains else "", "matched_domains": matched_domains, "resolved_ips": resolved_ips,
                              "context_only": True, "historical_only": True, "no_process_attribution": True}, stage_id="network"))
            else:
                self.log("SUCCESS", "No configured threat domain found in the current DNS cache")
        except Exception as exc:
            network_coverage["errors"].append(f"DNS cache: {exc}")
            self.log("WARNING", "DNS cache could not be inspected", str(exc))
        try:
            hosts = windows.get_hosts_text()
            network_coverage["hosts_read"] = True
            network_coverage["hosts_lines"] = len(hosts.splitlines())
            matching_lines = [(line.strip(), next((d for d in self.c2_domains if d in line.lower()), ""))
                              for line in hosts.splitlines() if self._matches_c2(line) and not line.lstrip().startswith("#")]
            network_coverage["hosts_matches"] = len(matching_lines)
            for line, matched_domain in matching_lines:
                if not matched_domain:
                    continue
                self.add(Finding(
                    title="Z797 controller / delivery domain mapped in Hosts file", severity="High", confidence="High",
                    category="Network indicator", description=f"The Hosts file redirects the exact Z797 domain {matched_domain}.",
                    evidence=[line, f"Matched Z797 domain: {matched_domain}"], path=os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "drivers", "etc", "hosts"),
                    remediation="remove_hosts_entry", metadata={"domain": matched_domain, "matched_domains": [matched_domain], "hosts_line": line}, stage_id="network"))
        except Exception as exc:
            network_coverage["errors"].append(f"Hosts file: {exc}")
            self.log("WARNING", "Hosts file could not be inspected", str(exc))
        try:
            self.log("INFO", "Inspecting active endpoints against confirmed Z797 delivery/C2 IPs")
            netstat = windows.get_netstat()
            network_coverage["netstat_read"] = True
            netstat_lines = netstat.splitlines()
            network_coverage["netstat_lines"] = len(netstat_lines)
            from .threat_profile import CONFIRMED_CAMPAIGN_IP_ROLES
            endpoint_rows: dict[str, list[str]] = {}
            for line in netstat_lines:
                remote_ip = _remote_ip_from_netstat_line(line)
                if remote_ip:
                    endpoint_rows.setdefault(remote_ip, []).append(line.strip())
            network_coverage["endpoint_rows"] = sum(len(rows) for rows in endpoint_rows.values())
            network_coverage["campaign_ip_endpoint_rows"] = sum(
                len(endpoint_rows.get(ip, [])) for ip in dict.fromkeys(configured_ips + resolved_ips)
            )
            network_coverage["resolved_campaign_domain_ips"] = list(resolved_ips)
            for ip in dict.fromkeys(configured_ips + resolved_ips):
                is_configured_ip = ip in configured_ips
                matching = endpoint_rows.get(ip, [])
                if matching:
                    correlated = []
                    for line in matching:
                        parts = line.split()
                        pid = int(parts[-1]) if parts and parts[-1].isdigit() else -1
                        process = self.process_inventory.get(pid)
                        if process and is_known_staging_path(str(process.get("path", ""))):
                            image_path = str(process.get("path", ""))
                            try:
                                image_stat = os.stat(image_path, follow_symlinks=False)
                                image_digest = sha256_file(image_path)
                                exact_artifact = known_sample_artifact(image_digest, int(image_stat.st_size))
                            except OSError:
                                exact_artifact = None
                                image_digest = ""
                                image_stat = None
                            if exact_artifact:
                                correlated.append((pid, process, line, image_digest, int(image_stat.st_size), exact_artifact))
                    if correlated:
                        for pid, process, line, image_digest, image_size, exact_artifact in correlated:
                            image = str(process.get("path", ""))
                            self.add(Finding(
                                title="Exact Z797 sample process connected to a campaign server", severity="Critical", confidence="High",
                                category="Network activity", description="A live process image matches a recovered Z797 artifact by exact SHA-256 and size, runs from an analysed staging path, and currently connects to a built-in campaign IP.",
                                evidence=[f"Exact artifact: {exact_artifact}", f"Process SHA-256: {image_digest}", f"Process size: {image_size}", f"Indicator source: {'Confirmed Z797 campaign IP' if is_configured_ip else 'Local DNS cache'}",
                                          f"Indicator role: {CONFIRMED_CAMPAIGN_IP_ROLES.get(ip, 'Address learned from configured campaign-domain DNS')}",
                                          f"Matched IP: {ip}", f"PID: {pid}", f"Image: {image}", line], path=image,
                                remediation=("block_network_ip" if is_configured_ip and self.firewall_policy != "Never change Firewall rules" else "none"),
                                metadata={"domain": self.primary_domain, "matched_domains": list(self.c2_domains), "ip": ip,
                                          "configured_ip": is_configured_ip, "pid": pid, "process_path": image,
                                          "process_sha256": image_digest, "expected_size": image_size,
                                          "known_sample_artifact": exact_artifact, "firewall_policy": self.firewall_policy}, stage_id="network"))
                    else:
                        # An IP-only endpoint is not a Z797 effect unless the owner is
                        # tied to an exact recovered payload. Shared/reused addresses
                        # are deliberately kept out of the Findings list.
                        network_coverage.setdefault("unattributed_campaign_ip_endpoints", 0)
                        network_coverage["unattributed_campaign_ip_endpoints"] += len(matching)
            if network_coverage.get("unattributed_campaign_ip_endpoints"):
                network_coverage.setdefault("notes", []).append(
                    f"{network_coverage['unattributed_campaign_ip_endpoints']} endpoint row(s) matched a campaign IP but had no exact Z797 process identity; they were not promoted to Findings."
                )
        except Exception as exc:
            network_coverage["errors"].append(f"Endpoint table: {exc}")
            self.log("WARNING", "Network endpoint table unavailable", str(exc))
        if network_coverage["errors"]:
            network_coverage["status"] = "read_with_gaps"
        self.scan_coverage["network"] = network_coverage
        self.log("INFO", "Network evidence was matched only against the built-in TCTC/Z797 sample profile; no C2 request was sent")

    def _scan_eventlogs(self) -> None:
        self.telemetry_coverage = {
            label: {"channel": channel, "status": "pending", "records_returned": 0,
                    "records_inspected": 0, "limit_per_channel": self.event_log_record_limit,
                    "truncated": False, "matched_findings": 0,
                    "reason": "Query has not completed."}
            for label, channel in EVENT_LOG_CHANNELS
        }
        if not windows.IS_WINDOWS:
            for label, channel in EVENT_LOG_CHANNELS:
                self.telemetry_coverage[label].update({
                    "status": "unavailable",
                    "reason": "Windows Event Log API is unavailable on this operating system; channel was not queried.",
                })
            self.scan_coverage["eventlogs"] = {
                "status": "unavailable", "channels_read": 0,
                "channels_unavailable": len(EVENT_LOG_CHANNELS),
                "channels_truncated": 0,
                "reason": "Windows Event Log history is available only on Windows.",
            }
            self.log("WARNING", "Windows Event Log history is available only on Windows")
            return

        # Query structured XML. /c asks for one additional record so a full
        # page can be reported as potentially truncated rather than silently
        # described as complete history.
        queries = [
            ("Microsoft-Windows-Sysmon/Operational",
             "*[System[(EventID=1 or EventID=2 or EventID=3 or EventID=4 or EventID=7 or EventID=8 or EventID=10 or EventID=11 or EventID=12 or EventID=13 or EventID=14 or EventID=16 or EventID=17 or EventID=18 or EventID=22 or EventID=23 or EventID=25 or EventID=26 or EventID=27 or EventID=29)]]",
             "Sysmon", True),
            ("Security", "*[System[(EventID=4688 or EventID=4697 or EventID=4698 or EventID=4702)]]", "Windows Security", True),
            ("Microsoft-Windows-PowerShell/Operational", "*[System[(EventID=4103 or EventID=4104)]]", "PowerShell", True),
            ("Microsoft-Windows-TaskScheduler/Operational", "*[System[(EventID=106 or EventID=140 or EventID=141 or EventID=200 or EventID=201)]]", "Task Scheduler", False),
            ("Microsoft-Windows-WMI-Activity/Operational", "*[System[(EventID=5857 or EventID=5858 or EventID=5859 or EventID=5860 or EventID=5861)]]", "WMI Activity", False),
        ]

        channel_records: dict[str, list[dict[str, Any]]] = {}
        matched_count = 0
        unavailable: list[str] = []
        truncated_channels: list[str] = []

        def field(record: dict[str, Any], *names: str) -> str:
            return event_field(record, *names)

        def normalize_pid(value: str) -> str:
            value = str(value or "").strip()
            if not value:
                return ""
            try:
                return str(int(value, 16) if value.lower().startswith("0x") else int(value, 10))
            except ValueError:
                return value

        def normalize_guid(value: str) -> str:
            return str(value or "").strip().strip("{}").lower()

        def basename(value: str) -> str:
            return ntpath.basename(str(value or "").replace("/", "\\")).lower()

        def sha_from_record(record: dict[str, Any]) -> str:
            hashes = field(record, "Hashes", "SHA256", "Sha256")
            match = re.search(r"(?i)(?:^|[,;\s])SHA256=([0-9a-f]{64})(?:$|[,;\s])", hashes)
            if match:
                return match.group(1).lower()
            match = re.fullmatch(r"(?i)[0-9a-f]{64}", hashes.strip())
            return match.group(0).lower() if match else ""

        def redact_excerpt(value: str, limit: int = 650) -> str:
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

        def record_values(record: dict[str, Any]) -> str:
            data = record.get("data", {})
            values = "\n".join(str(v) for v in data.values()) if isinstance(data, dict) else str(data)
            return values.lower()

        known_names = ("crandle.txt", "z797.ps1", "tctc.bba")

        def direct_campaign_marker(record: dict[str, Any]) -> tuple[int, list[str]]:
            """Return evidence strength and exact reasons; generic process names do not count."""
            values = record_values(record)
            digest = sha_from_record(record)
            reasons: list[str] = []
            if digest and digest in KNOWN_SAMPLE_ARTIFACTS:
                reasons.append("exact SHA-256 matches a locally recovered sample artifact")
                return 3, reasons
            for indicator in (*self.c2_domains, *self.c2_urls, *self.c2_paths):
                if indicator and indicator.lower() in values:
                    reasons.append(f"configured Z797 indicator: {indicator}")
            if reasons:
                return 3, reasons
            matched_names = [name for name in known_names if name in values]
            if matched_names:
                reasons.extend(f"sample-associated artifact name: {name}" for name in matched_names)
                return 2, reasons
            if "\\temp\\local\\" in values or "/temp/local/" in values:
                return 1, ["sample-observed Temp\\Local staging path (path alone is not attribution)"]
            return 0, []

        def is_watched_target(image: str) -> bool:
            target = basename(image)
            return target in {"runtimebroker.exe", "explorer.exe", "chrome.exe", "csc.exe"}

        def process_identity_matches(process_record: dict[str, Any] | None, image: str, pid: str) -> bool:
            # Event 8/10/25 attribution needs a complete ProcessCreate join:
            # ProcessGuid lookup is done by caller, then image and PID must both
            # be present and equal. Missing fields are not silently accepted.
            if not process_record or not image or not pid:
                return False
            recorded_image = field(process_record, "Image")
            if not recorded_image or ntpath.normcase(recorded_image) != ntpath.normcase(image):
                return False
            recorded_pid = normalize_pid(field(process_record, "ProcessId"))
            return bool(recorded_pid and recorded_pid == pid)

        def has_process_write_rights(value: str) -> bool:
            try:
                mask = int(value, 16) if str(value).lower().startswith("0x") else int(value or "0", 10)
            except (TypeError, ValueError):
                return False
            return bool(mask & (0x0002 | 0x0008 | 0x0020))

        def add_event_finding(
            record: dict[str, Any], *, title: str, severity: str, confidence: str,
            category: str, description: str, reasons: list[str], source_image: str = "",
            target_image: str = "", source_pid: str = "", target_pid: str = "",
            source_guid: str = "", target_guid: str = "", process_command: str = "",
            remediation: str = "none", extra: dict[str, Any] | None = None,
        ) -> None:
            nonlocal matched_count
            channel = str(record.get("channel") or (extra or {}).get("channel") or "Windows Event Log")
            event_id = str(record.get("event_id") or "unknown")
            timestamp = str(record.get("timestamp") or "Not supplied by provider")
            record_id = str(record.get("record_id") or "Not supplied")
            digest = sha_from_record(record)
            extra = dict(extra or {})
            lab_text = (record_values(record) + "\n" + str(process_command or "") + "\n" + str(extra.get("target_filename", ""))).lower()
            lab_simulated = bool(extra.get("lab_simulated") or (
                LAB_SIMULATION_MARKER.lower() in lab_text and LAB_SIMULATION_PREFIX.lower() in lab_text
            ))
            if lab_simulated:
                title = "[LAB] " + title
                severity, confidence = "Info", "High"
                category = "Lab simulation telemetry"
                description = ("Controlled benign test telemetry generated by TCTC Guardian Safe Lab. "
                               "The IOC strings were passed as inert text; no malware behavior or network request occurred.")
                remediation = "none"
            evidence = [
                f"Channel: {channel}", f"Provider: {record.get('provider') or 'Not supplied'}",
                f"Event ID: {event_id}", f"Timestamp (UTC): {timestamp}",
                f"Event record ID: {record_id}",
            ]
            if source_image:
                evidence.append(f"SourceImage: {source_image}")
            if target_image:
                evidence.append(f"TargetImage: {target_image}")
            if source_pid:
                evidence.append(f"Source PID: {source_pid}")
            if target_pid:
                evidence.append(f"Target PID: {target_pid}")
            if source_guid:
                evidence.append(f"Source Process GUID: {source_guid}")
            if target_guid:
                evidence.append(f"Target Process GUID: {target_guid}")
            if digest:
                evidence.append(f"SHA-256: {digest}")
            else:
                evidence.append(f"SHA-256: Not provided by Event ID {event_id} ({category}); this event is not a file-hash record")
            if process_command:
                evidence.append("Command / script excerpt: " + redact_excerpt(process_command, 650))
            evidence.extend(f"Assessment: {reason}" for reason in reasons[:5])
            excerpt_fields = record.get("data", {})
            if isinstance(excerpt_fields, dict):
                excerpt = " | ".join(f"{k}={redact_excerpt(str(v), 240)}" for k, v in list(excerpt_fields.items())[:8])
            else:
                excerpt = redact_excerpt(str(excerpt_fields))
            matched_count += 1
            self.add(Finding(
                title=title, severity=severity, confidence=confidence, category=category,
                description=description, evidence=evidence, path=target_image or source_image or channel,
                sha256=digest, remediation=remediation,
                metadata={
                    "channel": channel, "provider": record.get("provider", ""),
                    "event_id": event_id, "timestamp": timestamp, "record_id": record_id,
                    "source_image": source_image, "target_image": target_image,
                    "source_pid": source_pid, "target_pid": target_pid,
                    "source_process_guid": source_guid, "target_process_guid": target_guid,
                    "command_excerpt": redact_excerpt(process_command, 650),
                    "event_excerpt": excerpt, "historical": True,
                    **extra, "lab_simulated": lab_simulated,
                }, stage_id="eventlogs",
            ))

        for channel, query, label, required in queries:
            self.check_cancel()
            self.log("INFO", f"Querying {label} historical telemetry", f"Newest selected event records; per-channel cap {self.event_log_record_limit}")
            ok, output, error = windows.query_event_log(
                channel, query, count=self.event_log_record_limit + 1, timeout=45,
            )
            if not ok:
                lower_error = error.lower()
                no_matches = any(token in lower_error for token in ("no events were found", "no events match", "no matching events"))
                if no_matches:
                    channel_records[label] = []
                    self.telemetry_coverage[label] = {
                        "channel": channel, "status": "read", "records_returned": 0,
                        "records_inspected": 0, "limit_per_channel": self.event_log_record_limit,
                        "truncated": False, "matched_findings": 0, "format": "empty",
                        "reason": "The query succeeded but no matching events were retained in this channel.",
                    }
                    self.log("INFO", f"{label}: no matching historical events were retained")
                    continue
                missing = any(token in lower_error for token in (
                    "specified channel could not be found", "failed to open event query",
                    "the system cannot find the file specified", "channel not found", "no events were found",
                ))
                unavailable.append(label)
                self.telemetry_coverage[label] = {
                    "channel": channel, "status": "unavailable", "records_inspected": 0,
                    "limit_per_channel": self.event_log_record_limit, "truncated": False,
                    "reason": error.strip()[:500],
                }
                if label == "Sysmon" and missing:
                    self.log("WARNING", "Sysmon historical channel is unavailable", "Install / enable Sysmon and confirm the Microsoft-Windows-Sysmon/Operational channel exists. No historical Sysmon conclusion can be drawn.")
                elif required or not missing:
                    self.log("WARNING", f"{label} historical telemetry unavailable", error)
                else:
                    self.log("INFO", f"{label} optional channel is unavailable", error)
                continue

            records, parse_status = parse_event_log_output_with_status(output)
            for parsed_record in records:
                parsed_record.setdefault("channel", channel)
                parsed_record.setdefault("provider", label)
            if parse_status == "parse_error":
                self.telemetry_coverage[label] = {
                    "channel": channel, "status": "parse_error", "records_returned": 0,
                    "records_inspected": 0, "limit_per_channel": self.event_log_record_limit,
                    "truncated": False, "matched_findings": 0,
                    "reason": "The command succeeded, but its XML response could not be parsed; no historical conclusion was drawn.",
                }
                unavailable.append(label)
                self.log("WARNING", f"{label}: Event Log XML could not be parsed", "The query returned a malformed or incomplete XML response. This source is not counted as successfully inspected.")
                continue
            records_returned = len(records)
            truncated = records_returned > self.event_log_record_limit
            if truncated:
                records = records[:self.event_log_record_limit]
                truncated_channels.append(label)
                self.log("WARNING", f"{label}: result cap reached", f"More than {self.event_log_record_limit} selected event records exist; only the newest {self.event_log_record_limit} were inspected. The configured limit is capped at 5,000 per channel; review Event Viewer for older evidence.")
            channel_records[label] = records
            self.telemetry_coverage[label] = {
                "channel": channel, "status": "read", "records_returned": records_returned,
                "records_inspected": len(records), "limit_per_channel": self.event_log_record_limit,
                "truncated": truncated, "matched_findings": 0, "format": parse_status,
                "reason": "No matching events were returned." if not records else "",
                "event_ids": sorted({str(r.get("event_id") or "unknown") for r in records}),
            }
            self.log("INFO", f"{label}: inspected {len(records)} matching historical event(s)",
                     "Potentially truncated at configured per-channel cap." if truncated else "No record-cap truncation detected; availability still depends on retained and previously enabled Windows logging.")

        # Build the Sysmon ProcessCreate inventory first. Sysmon ProcessGuid is
        # stable across PID reuse and is the only accepted strong join for
        # retrospective process-access attribution.
        sysmon_records = channel_records.get("Sysmon", [])
        process_by_guid: dict[str, dict[str, Any]] = {}
        process_marker_by_guid: dict[str, tuple[int, list[str], dict[str, Any]]] = {}
        for record in sysmon_records:
            if str(record.get("event_id")) != "1":
                continue
            guid = normalize_guid(field(record, "ProcessGuid"))
            if not guid:
                continue
            process_by_guid[guid] = record
            strength, reasons = direct_campaign_marker(record)
            if strength:
                process_marker_by_guid[guid] = (strength, reasons, record)

        # Follow at most three parent edges. A child is attributed only when its
        # exact ParentProcessGuid points to a directly matched or already-linked
        # process; a shared process name or PID is never enough.
        for _ in range(3):
            changed = False
            for guid, record in process_by_guid.items():
                if guid in process_marker_by_guid:
                    continue
                parent_guid = normalize_guid(field(record, "ParentProcessGuid"))
                if parent_guid and parent_guid in process_marker_by_guid:
                    parent_strength, parent_reasons, _parent = process_marker_by_guid[parent_guid]
                    # Only propagate a meaningful campaign marker (exact IOC /
                    # recovered artifact), not a generic Temp\\Local path alone.
                    if parent_strength >= 2:
                        process_marker_by_guid[guid] = (
                            max(2, parent_strength - 1),
                            ["exact ParentProcessGuid lineage to a previously matched process", *parent_reasons[:2]],
                            record,
                        )
                        changed = True
            if not changed:
                break

        # Individual ProcessCreate records with direct campaign evidence and
        # low-confidence related-behavior context. Iterate all events, not only
        # ProcessGuid records, so older / reduced text exports remain reviewable.
        for record in sysmon_records:
            if str(record.get("event_id")) != "1":
                continue
            guid = normalize_guid(field(record, "ProcessGuid"))
            linked_marker = process_marker_by_guid.get(guid) if guid else None
            strength, reasons = direct_campaign_marker(record)
            if strength:
                image = field(record, "Image")
                command = field(record, "CommandLine")
                severity, confidence = ("High", "High") if strength == 3 else (("Medium", "Low") if strength == 2 else ("Low", "Low"))
                add_event_finding(
                    record, title="Process execution matches a recovered Z797 indicator",
                    severity=severity, confidence=confidence,
                    category="Campaign-linked process execution",
                    description="A Sysmon ProcessCreate record contains a locally curated Z797 indicator. This is historical evidence; verify the file and process context before response.",
                    reasons=reasons, source_image=image,
                    source_pid=normalize_pid(field(record, "ProcessId")), source_guid=guid,
                    process_command=command,
                )
                continue
            if linked_marker:
                # Descendant linkage is preserved for correlating Event 10/8,
                # but does not create a stand-alone alert on every child.
                continue
            image = field(record, "Image")
            command = field(record, "CommandLine")
            # Unattributed hidden PowerShell/download behavior is intentionally ignored.
            # This product reports only records carrying a recovered Z797 indicator.

        # Analyze each retained event with the correlated process identity.
        for record in sysmon_records:
            self.check_cancel()
            event_id = str(record.get("event_id") or "")
            data_text = record_values(record)
            source_image = field(record, "SourceImage", "Image")
            target_image = field(record, "TargetImage")
            source_pid = normalize_pid(field(record, "SourceProcessId", "ProcessId"))
            target_pid = normalize_pid(field(record, "TargetProcessId"))
            source_guid = normalize_guid(field(record, "SourceProcessGUID", "ProcessGuid"))
            target_guid = normalize_guid(field(record, "TargetProcessGUID"))
            command = field(record, "CommandLine")

            if event_id in {"3", "22"}:
                # Sysmon network-connect (3) and DNS-query (22) events are
                # matched against exact configured campaign infrastructure.
                host = field(record, "DestinationHostname", "QueryName", "Query")
                host = host.strip().lower().rstrip(".")
                ip_values = " ".join((field(record, "DestinationIp"), field(record, "QueryResults", "QueryResult")))
                observed_ips = set(re.findall(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])", ip_values))
                matched_domains = [domain for domain in self.c2_domains if host == domain or host.endswith("." + domain)]
                matched_ips = sorted(observed_ips.intersection(set(self.c2_ips)))
                if matched_domains or matched_ips:
                    process_record = process_by_guid.get(source_guid) if source_guid else None
                    marker = process_marker_by_guid.get(source_guid) if source_guid else None
                    identity_matches = process_identity_matches(process_record, source_image, source_pid)
                    correlated = bool(marker and marker[0] >= 2 and identity_matches)
                    severity = "High" if correlated and matched_domains else "Medium"
                    confidence = "High" if correlated and matched_domains else ("Medium" if matched_domains else "Low")
                    reasons = ([f"Exact configured campaign domain: {x}" for x in matched_domains] +
                               [f"Exact configured campaign IP: {x}" for x in matched_ips])
                    if correlated:
                        reasons.append("ProcessGuid / image / PID joined to a Z797-marked process lineage")
                    else:
                        reasons.append("Network IOC is present, but no exact source-process lineage was established")
                    add_event_finding(
                        record, title="Historical network / DNS event matches recovered campaign infrastructure",
                        severity=severity, confidence=confidence, category="Campaign network / DNS telemetry",
                        description="Sysmon recorded a connection or DNS query matching an exact configured campaign domain/IP. This is historical telemetry; a destination match alone does not prove payload execution or data theft.",
                        reasons=reasons, source_image=source_image, target_image=host or ", ".join(matched_ips),
                        source_pid=source_pid, source_guid=source_guid,
                        extra={"matched_domains": matched_domains, "matched_ips": matched_ips,
                               "process_guid_joined": correlated, "destination_port": field(record, "DestinationPort")},
                    )

            elif event_id in {"4", "16"}:
                # Sensor-health records are operational diagnostics, not malware
                # findings. They are handled by readiness/monitoring status.
                if event_id == "4" and "stop" in field(record, "State", "ServiceState").lower():
                    self.log("WARNING", "Historical Sysmon stop event found", "Sysmon telemetry may be incomplete for the period after this event.")
                elif event_id == "16":
                    self.log("INFO", "Historical Sysmon configuration change event found", field(record, "Configuration", "ConfigurationFile")[:500])

            elif event_id in {"12", "13", "14"}:
                target_object = field(record, "TargetObject", "NewName", "OldName")
                details = field(record, "Details", "EventType", "NewName", "OldName")
                combined = (target_object + " " + details + " " + source_image + " " + command).lower()
                autorun_target = any(token in target_object.lower() for token in (
                    "\\currentversion\\run", "\\currentversion\\runonce",
                    "\\services\\", "\\image file execution options\\",
                    "\\winlogon\\", "\\appinit_dlls", "\\startupapproved\\",
                ))
                marker = process_marker_by_guid.get(source_guid) if source_guid else None
                process_record = process_by_guid.get(source_guid) if source_guid else None
                identity_matches = process_identity_matches(process_record, source_image, source_pid) if process_record else False
                values_have_ioc = any(x and x.lower() in combined for x in (*self.c2_domains, *self.c2_urls, *self.c2_paths))
                values_have_artifact = any(name in combined for name in known_names)
                lineage_matches = bool(marker and marker[0] >= 2 and identity_matches)
                if autorun_target and (values_have_ioc or values_have_artifact or lineage_matches):
                    add_event_finding(
                        record, title="Historical registry persistence change matches Z797 indicators",
                        severity="High" if values_have_ioc else "Medium", confidence="High" if values_have_ioc else "Medium",
                        category="Registry persistence telemetry",
                        description="Sysmon recorded a Run/RunOnce, service, Winlogon, IFEO or related persistence registry change containing campaign/staging evidence or written by a correlated process. No registry value is changed automatically.",
                        reasons=(["Exact configured campaign IOC present in registry data"] if values_have_ioc else
                                 ["Registry persistence target and sample artifact/staging evidence match"] if values_have_artifact else
                                 ["Registry change actor joined to a Z797 ProcessGuid lineage"]),
                        source_image=source_image, target_image=target_object, source_pid=source_pid, source_guid=source_guid,
                        process_command=details or command,
                        extra={"registry_event_type": event_id, "registry_target": target_object, "process_guid_joined": lineage_matches},
                    )

            elif event_id in {"17", "18"}:
                pipe_name = field(record, "PipeName", "Pipe")
                process_record = process_by_guid.get(source_guid) if source_guid else None
                marker = process_marker_by_guid.get(source_guid) if source_guid else None
                identity_matches = process_identity_matches(process_record, source_image, source_pid) if process_record else False
                pipe_marker = any(name in pipe_name.lower() for name in known_names) or any(
                    indicator and indicator.lower() in pipe_name.lower() for indicator in (*self.c2_domains, *self.c2_paths)
                )
                if pipe_marker or (marker and marker[0] >= 2 and identity_matches):
                    add_event_finding(
                        record, title="Named-pipe activity linked to a Z797 process lineage",
                        severity="High" if pipe_marker else "Medium", confidence="High" if pipe_marker else "Medium",
                        category="Correlated named-pipe telemetry",
                        description="Sysmon recorded named-pipe creation/connection associated with an exact configured indicator or a source process joined to the Z797 process lineage. Pipe activity alone does not establish successful lateral movement.",
                        reasons=(["Named pipe contains an exact configured campaign marker"] if pipe_marker else
                                 ["ProcessGuid / image / PID joined to a Z797 process lineage"]),
                        source_image=source_image, target_image=pipe_name, source_pid=source_pid, source_guid=source_guid,
                        extra={"named_pipe_event": "created" if event_id == "17" else "connected", "process_guid_joined": bool(marker and identity_matches)},
                    )

            elif event_id in {"2", "23"}:
                target_file = field(record, "TargetFilename")
                normalized_path = target_file.replace("/", "\\").lower()
                digest = sha_from_record(record)
                matched_name = any(name in normalized_path for name in known_names)
                exact = bool(digest and digest in KNOWN_SAMPLE_ARTIFACTS)
                actor_record = process_by_guid.get(source_guid) if source_guid else None
                actor_marker = process_marker_by_guid.get(source_guid) if source_guid else None
                actor_identity = process_identity_matches(actor_record, source_image, source_pid) if actor_record else False
                actor_linked = bool(actor_marker and actor_marker[0] >= 2 and actor_identity)
                if exact or matched_name or actor_linked:
                    operation = "file creation-time change" if event_id == "2" else "file deletion"
                    add_event_finding(
                        record, title=f"Historical {operation} involving a Z797 sample artifact",
                        severity="High" if exact else "Medium",
                        confidence="High" if exact else "Medium",
                        category="Z797 file lifecycle telemetry",
                        description="Sysmon recorded a file lifecycle event for an exact recovered artifact, a campaign-specific delivery filename, or a source process joined to the Z797 lineage. Unrelated files in Temp\\Local are ignored.",
                        reasons=(["Exact recovered artifact SHA-256 match"] if exact else
                                 ["Known Z797 delivery artifact filename"] if matched_name else
                                 ["Source ProcessGuid / image / PID joined to the Z797 process lineage"]),
                        source_image=source_image, target_image=target_file, source_pid=source_pid, source_guid=source_guid,
                        process_command=command, extra={"file_event_kind": operation, "target_filename": target_file, "actor_process_joined": actor_linked},
                    )

            if event_id == "10" and is_watched_target(target_image):
                source_record = process_by_guid.get(source_guid) if source_guid else None
                marker = process_marker_by_guid.get(source_guid) if source_guid else None
                identity_matches = process_identity_matches(source_record, source_image, source_pid)
                access_raw = field(record, "GrantedAccess")
                write_rights = has_process_write_rights(access_raw)
                # The actor must be the SourceProcessGuid owner. A target name,
                # a target-side process lineage, or read-only VM access is not
                # sufficient to call this campaign-linked behavior.
                if marker and marker[0] >= 2 and identity_matches and write_rights:
                    strength, reasons, _ = marker
                    direct = direct_campaign_marker(source_record)[0] if source_record else 0
                    severity, confidence = ("High", "High") if direct == 3 else ("Medium", "Medium")
                    add_event_finding(
                        record, title="Campaign-linked process accessed a monitored Windows process",
                        severity=severity, confidence=confidence, category="Correlated ProcessAccess",
                        description="Sysmon Event ID 10 was joined by SourceProcessGuid to a ProcessCreate record with Z797 evidence. The target process name alone was not used for attribution.",
                        reasons=["SourceProcessGuid joined to Sysmon Event ID 1", *reasons],
                        source_image=source_image, target_image=target_image,
                        source_pid=source_pid, target_pid=target_pid,
                        source_guid=source_guid, target_guid=target_guid,
                        process_command=field(source_record, "CommandLine"),
                        extra={"source_guid_joined": True, "source_guid_image_match": True, "source_guid_pid_match": True, "access_mask": access_raw},
                    )

            elif event_id == "8" and is_watched_target(target_image):
                source_record = process_by_guid.get(source_guid) if source_guid else None
                marker = process_marker_by_guid.get(source_guid) if source_guid else None
                identity_matches = process_identity_matches(source_record, source_image, source_pid)
                if marker and marker[0] >= 2 and identity_matches:
                    strength, reasons, _ = marker
                    add_event_finding(
                        record, title="Campaign-linked source created a remote thread in a monitored process",
                        severity="High" if strength == 3 else "Medium", confidence="High" if strength == 3 else "Medium",
                        category="Correlated remote-thread telemetry",
                        description="Sysmon Event ID 8 is linked to a ProcessCreate record by SourceProcessGuid. This is strong behavioral evidence, but still requires review of the process and event timeline.",
                        reasons=["SourceProcessGuid joined to Sysmon Event ID 1", *reasons],
                        source_image=source_image, target_image=target_image,
                        source_pid=source_pid, target_pid=target_pid,
                        source_guid=source_guid, target_guid=target_guid,
                        extra={"source_guid_joined": True, "start_address": field(record, "StartAddress"), "start_module": field(record, "StartModule")},
                    )

            elif event_id == "29":
                target_file = field(record, "TargetFilename")
                digest = sha_from_record(record)
                normalized_target = target_file.replace("/", "\\").lower()
                known = bool(digest and digest in KNOWN_SAMPLE_ARTIFACTS)
                known_name = any(name in normalized_target for name in known_names)
                actor_record = process_by_guid.get(source_guid) if source_guid else None
                actor_marker = process_marker_by_guid.get(source_guid) if source_guid else None
                actor_identity = process_identity_matches(actor_record, source_image, source_pid) if actor_record else False
                actor_linked = bool(actor_marker and actor_marker[0] >= 2 and actor_identity)
                if known or known_name or actor_linked:
                    add_event_finding(
                        record, title="Executable file creation linked to the Z797 chain",
                        severity="High" if known or actor_linked else "Medium",
                        confidence="High" if known or actor_linked else "Medium",
                        category="Z797 PE creation telemetry",
                        description="Sysmon Event ID 29 identified an executable created under the analyzed staging pattern and the target name, hash, or creating process is linked to the recovered Z797 chain. Detect-only telemetry observes creation; it does not block it.",
                        reasons=(["SHA-256 matches a locally recovered sample artifact"] if known else
                                 ["Creating process joined to a Z797 ProcessGuid lineage"] if actor_linked else
                                 ["Known delivery artifact filename in the analyzed staging path"]),
                        source_image=source_image, source_pid=source_pid, source_guid=source_guid,
                        process_command=command, extra={"target_filename": target_file, "pe_detect_only": True, "actor_process_joined": actor_linked},
                    )

            elif event_id in {"11", "26", "27"}:
                target_file = field(record, "TargetFilename")
                normalized_path = target_file.replace("/", "\\").lower()
                digest = sha_from_record(record)
                exact = bool(digest and digest in KNOWN_SAMPLE_ARTIFACTS)
                known_name = any(name in normalized_path for name in known_names)
                actor_record = process_by_guid.get(source_guid) if source_guid else None
                actor_marker = process_marker_by_guid.get(source_guid) if source_guid else None
                actor_identity = process_identity_matches(actor_record, source_image, source_pid) if actor_record else False
                actor_linked = bool(actor_marker and actor_marker[0] >= 2 and actor_identity)
                if exact or known_name or actor_linked:
                    kind = {"11": "file created", "23": "file deleted", "26": "file delete detected", "27": "file blocked"}.get(event_id, "file event")
                    add_event_finding(
                        record, title=f"Z797 artifact {kind} telemetry",
                        severity="High" if exact or actor_linked else "Medium", confidence="High" if exact or actor_linked else "Medium",
                        category="Z797 file lifecycle telemetry",
                        description="A Sysmon file event references a recovered artifact, a known delivery filename, or a creator joined to the Z797 process lineage. Unrelated files in Temp\\Local are ignored.",
                        reasons=(["Exact recovered artifact SHA-256 match"] if exact else
                                 ["Creator process joined to a Z797 ProcessGuid lineage"] if actor_linked else
                                 ["Known Z797 delivery artifact filename"]),
                        source_image=source_image, target_image=target_file,
                        source_pid=source_pid, source_guid=source_guid,
                        process_command=command,
                        extra={"target_filename": target_file, "file_event_kind": kind, "block_status": "event 27 is historical block telemetry" if event_id == "27" else "not a block event", "actor_process_joined": actor_linked,
                               "lab_simulated": bool(actor_record and LAB_SIMULATION_MARKER.lower() in record_values(actor_record))},
                    )

            elif event_id == "25":
                image = field(record, "Image")
                process_guid = normalize_guid(field(record, "ProcessGuid"))
                marker = process_marker_by_guid.get(process_guid) if process_guid else None
                process_record = process_by_guid.get(process_guid) if process_guid else None
                tampered_pid = normalize_pid(field(record, "ProcessId"))
                identity_matches = process_identity_matches(process_record, image, tampered_pid)
                if is_watched_target(image):
                    if marker and marker[0] >= 2 and identity_matches:
                        strength, reasons, _ = marker
                        add_event_finding(
                            record, title="Process tampering telemetry linked to a Z797 process lineage",
                            severity="High" if strength == 3 else "Medium", confidence="High" if strength == 3 else "Medium",
                            category="Correlated process-tampering telemetry",
                            description="Sysmon Event ID 25 concerns a monitored process whose ProcessGuid is linked to a Z797-indicated process record.",
                            reasons=reasons, source_image=image, source_pid=normalize_pid(field(record, "ProcessId")), source_guid=process_guid,
                        )


        # PowerShell historical telemetry: these channels are queried only if
        # the provider retained Script Block / Module logging. They are not an
        # AMSI result feed and cannot show script blocks that were never logged.
        for record in channel_records.get("PowerShell", []):
            self.check_cancel()
            event_id = str(record.get("event_id") or "")
            if event_id not in {"4103", "4104"}:
                continue
            script_text = "\n".join(str(v) for v in (record.get("data", {}) or {}).values())
            lower = script_text.lower()
            has_ioc = any(x and x.lower() in lower for x in (*self.c2_domains, *self.c2_urls, *self.c2_paths))
            has_staging = any(name in lower for name in known_names)
            has_download = any(token in lower for token in ("invoke-webrequest", "downloadstring", "downloadfile", "start-bitstransfer", "curl.exe", "bitsadmin", "webclient", "http://", "https://"))
            if has_ioc and (has_download or has_staging):
                severity, confidence = "High", "High"
                title = "Historical PowerShell script contains a recovered Z797 IOC"
                description = "PowerShell 4103/4104 telemetry contains a locally configured Z797 domain/URL/path together with download or staging context. This is script telemetry, not a direct AMSI verdict."
                reasons = ["Exact configured Z797 indicator in PowerShell event", "Download or staging context present"]
            elif has_staging and has_download:
                severity, confidence = "Medium", "Medium"
                title = "PowerShell download of a known Z797 delivery artifact"
                description = "PowerShell Script Block / Module telemetry references one of the exact delivery filenames recovered from the Z797 chain together with download behavior. No confirmed C2 domain was present in this event."
                reasons = ["Download context", "Exact Z797 delivery filename", "Campaign attribution is based on the recovered filename and should be reviewed with its process chain"]
            else:
                # Generic hidden download behaviour is outside this product's
                # narrow TCTC/Z797 scope and must not create a Finding.
                continue
            pid = normalize_pid(str(record.get("execution_pid") or field(record, "ProcessId", "HostProcessId")))
            add_event_finding(
                record, title=title, severity=severity, confidence=confidence,
                category="PowerShell Script Block / Module telemetry", description=description,
                reasons=[f"PowerShell event type: {'Script Block (4104)' if event_id == '4104' else 'Module (4103)'}", *reasons],
                source_image=field(record, "HostApplication", "ApplicationName"), source_pid=pid,
                process_command=script_text,
                extra={"script_telemetry_kind": "Script Block (4104)" if event_id == "4104" else "Module (4103)", "amsi_result": False},
            )

        # Security process-creation and persistence telemetry only. Broad file
        # object-access auditing is deliberately outside this sample-specific profile.
        for record in channel_records.get("Windows Security", []):
            self.check_cancel()
            event_id = str(record.get("event_id") or "")
            source = field(record, "ProcessName", "Process Name", "NewProcessName", "CreatorProcessName")
            target = field(record, "ObjectName", "Object Name", "ProcessCommandLine")
            if event_id in {"4697", "4698", "4702"}:
                target_name = field(record, "ServiceName", "TaskName")
                details = field(record, "ServiceFileName", "ImagePath", "TaskContent", "ActionName", "TaskXml")
                combined = (target_name + " " + details).lower()
                has_ioc = any(x and x.lower() in combined for x in (*self.c2_domains, *self.c2_urls, *self.c2_paths))
                has_staging = any(name in combined for name in known_names)
                if has_ioc or has_staging:
                    add_event_finding(
                        record, title="Historical service / scheduled-task registration contains a Z797 reference",
                        severity="High" if has_ioc else "Medium",
                        confidence="High" if has_ioc else "Medium", category="Z797 persistence history",
                        description="Windows Security auditing recorded a service or scheduled-task registration/update whose target or command contains an exact configured Z797 indicator or a known delivery artifact name. This does not prove the task ran successfully.",
                        reasons=(["Exact configured campaign IOC in service/task data"] if has_ioc else
                                 ["Known Z797 delivery artifact name in service/task data"]),
                        target_image=target_name, process_command=details,
                        extra={"security_persistence_event": event_id, "campaign_attributed": has_ioc or has_staging},
                    )
            elif event_id == "4688":
                command = field(record, "CommandLine", "ProcessCommandLine")
                image = field(record, "NewProcessName", "NewProcessId")
                combined = (image + " " + command).lower()
                if any(x and x.lower() in combined for x in (*self.c2_domains, *self.c2_urls, *self.c2_paths)) or any(name in combined for name in known_names):
                    add_event_finding(
                        record, title="Windows process-creation audit contains a Z797 indicator",
                        severity="High", confidence="High", category="Windows process-creation audit",
                        description="Security Event ID 4688 records a process command line or image containing a locally curated Z797 indicator.",
                        reasons=["Confirmed campaign indicator in NewProcessName / CommandLine"],
                        source_image=image, source_pid=normalize_pid(field(record, "NewProcessId")),
                        target_image=field(record, "ParentProcessName", "CreatorProcessName"),
                        target_pid=normalize_pid(field(record, "ProcessId")), process_command=command,
                    )

        # Task Scheduler and WMI event channels are context sources; they are
        # never standalone attribution without an IOC or staging indicator.
        for label in ("Task Scheduler", "WMI Activity"):
            for record in channel_records.get(label, []):
                self.check_cancel()
                values = record_values(record)
                has_ioc = any(x and x.lower() in values for x in (*self.c2_domains, *self.c2_urls, *self.c2_paths))
                has_staging = any(name in values for name in known_names)
                if has_ioc or has_staging:
                    add_event_finding(
                        record, title=f"Z797-related configuration/activity in {label} history",
                        severity="High" if has_ioc else "Medium", confidence="High" if has_ioc else "Medium",
                        category=f"{label} historical telemetry",
                        description="The event contains a locally curated Z797 indicator or sample-associated staging path. Review the task/action or WMI client context before changing system configuration.",
                        reasons=["Exact Z797 indicator present"] if has_ioc else ["Sample-associated path/name present; no exact C2 indicator"],
                        source_image=field(record, "ClientProcessName", "ProcessName", "Image"),
                        source_pid=normalize_pid(field(record, "ClientProcessId", "ProcessId")),
                        process_command="\n".join(str(v) for v in (record.get("data", {}) or {}).values()),
                    )

        for label, coverage in self.telemetry_coverage.items():
            coverage["matched_findings"] = sum(
                1 for finding in self.findings
                if finding.stage_id == "eventlogs" and finding.metadata.get("channel") == coverage.get("channel")
            )
        read_channels = [name for name, info in self.telemetry_coverage.items() if info.get("status") == "read"]
        if read_channels:
            self.log("SUCCESS", "Historical event-log queries completed", ", ".join(
                f"{name}: {self.telemetry_coverage[name].get('records_inspected', 0)} records / {self.telemetry_coverage[name].get('matched_findings', 0)} findings"
                for name in read_channels
            ))
        if unavailable:
            self.log("WARNING", "Some historical telemetry sources were unavailable", ", ".join(unavailable))
        if truncated_channels:
            self.log("WARNING", "Some historical event-log results were capped", ", ".join(truncated_channels))
        if not read_channels:
            self.log("WARNING", "No selected event-log source could be queried", "This limits retrospective reconstruction; it does not mean no suspicious activity occurred.")
        powershell_coverage = self.telemetry_coverage.get("PowerShell", {})
        if powershell_coverage.get("status") == "read" and not channel_records.get("PowerShell"):
            self.log("WARNING", "No historical PowerShell 4103/4104 records were returned", "Script Block Logging (4104) and Module Logging (4103) must have been enabled when the activity occurred. These events are not a direct AMSI result feed.")
        elif powershell_coverage.get("status") in {"unavailable", "parse_error"}:
            self.log("WARNING", "Historical PowerShell telemetry could not be reviewed", "The PowerShell channel was unavailable or its response could not be parsed; no conclusion about prior script execution can be drawn.")

        read_count = sum(1 for item in self.telemetry_coverage.values() if item.get("status") == "read")
        unavailable_count = sum(1 for item in self.telemetry_coverage.values() if item.get("status") in {"unavailable", "parse_error"})
        pending_count = sum(1 for item in self.telemetry_coverage.values() if item.get("status") == "pending")
        truncated_count = sum(1 for item in self.telemetry_coverage.values() if item.get("truncated"))
        event_status = "read" if read_count == len(EVENT_LOG_CHANNELS) and not truncated_count else "read_with_gaps"
        if read_count == 0:
            event_status = "unavailable"
        self.scan_coverage["eventlogs"] = {
            "status": event_status, "channels_total": len(EVENT_LOG_CHANNELS),
            "channels_read": read_count, "channels_unavailable": unavailable_count,
            "channels_pending": pending_count, "channels_truncated": truncated_count,
            "records_inspected": sum(int(item.get("records_inspected", 0) or 0) for item in self.telemetry_coverage.values()),
            "records_returned": sum(int(item.get("records_returned", 0) or 0) for item in self.telemetry_coverage.values()),
            "matched_findings": matched_count,
        }
        if unavailable_count or pending_count or truncated_count:
            self.log("WARNING", "Historical event-log coverage is partial",
                     f"read={read_count}/{len(EVENT_LOG_CHANNELS)}; unavailable={unavailable_count}; pending={pending_count}; capped={truncated_count}")

    def _scan_verification(self) -> None:
        total = len(self.findings)
        errors = len(self.errors)
        admin = windows.is_admin()
        self.log("INFO", f"Verification summary: {total} indicator(s), {errors} check error(s), administrator={admin}")
        if not admin:
            self.log("WARNING", "Not running elevated", "Some registry hives, protected folders and event logs may be unreadable. Run as Administrator for broader coverage.")
        if not windows.IS_WINDOWS:
            self.log("WARNING", "This host is not Windows; only portable portions were available")
        self.log("INFO", "A zero-finding result is not a proof of full eradication")
