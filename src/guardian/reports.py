from __future__ import annotations

import html
import json
import os
from pathlib import Path
from typing import Any

from guardian import __version__
from guardian.models import ScanReport


def report_directory() -> Path:
    base = Path(os.environ.get("USERPROFILE", str(Path.home())))
    docs = base / "Documents"
    if not docs.exists():
        docs = base
    out = docs / "TCTC Guardian" / "Reports"
    out.mkdir(parents=True, exist_ok=True)
    return out


def save_report(report: ScanReport | dict[str, Any]) -> dict[str, str]:
    data = report.to_dict() if isinstance(report, ScanReport) else report
    out = report_directory()
    scan_id = str(data.get("scan_id", "scan"))
    stem = f"TCTC-Guardian-{scan_id}"
    json_path = out / f"{stem}.json"
    html_path = out / f"{stem}.html"
    data.setdefault("application", {"name": "TCTC Guardian Z797", "version": __version__})
    data.setdefault("credits", [
        {"name": "Python Software Foundation", "component": "Python runtime", "url": "https://www.python.org/"},
        {"name": "Qt for Python / PySide6", "component": "Desktop GUI and system tray; LGPLv3, GPLv3 or commercial terms depending on module and distribution", "url": "https://doc.qt.io/qtforpython-6/licenses.html"},
        {"name": "Microsoft", "component": "Windows APIs, Event Log, PowerShell and netstat"},
        {"name": "Microsoft Sysinternals", "component": "Optional Sysmon telemetry", "url": "https://learn.microsoft.com/sysinternals/downloads/sysmon"},
        {"name": "Nuitka", "component": "Optional executable build tool", "url": "https://nuitka.net/"},
    ])
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    html_path.write_text(render_html(data), encoding="utf-8")
    return {"json": str(json_path), "html": str(html_path), "directory": str(out)}


def render_html(data: dict[str, Any]) -> str:
    findings = data.get("findings", []) or []
    stages = data.get("stages", []) or []
    summary = data.get("summary", {}) or {}
    app = data.get("application", {}) or {}

    def esc(value: Any) -> str:
        return html.escape(str(value if value is not None else ""))

    def list_html(values: list[Any], fallback: str) -> str:
        if not values:
            return f"<li>{esc(fallback)}</li>"
        return "".join(f"<li>{esc(value)}</li>" for value in values)

    finding_rows: list[str] = []
    for finding in findings:
        evidence = "<br>".join(esc(item) for item in finding.get("evidence", []) or [])
        severity = str(finding.get("severity", "Info")).lower()
        remediation = finding.get("remediation_status") or str(finding.get("remediation", "none")).replace("_", " ")
        finding_rows.append(
            "<tr>"
            f"<td><span class='severity {esc(severity)}'>{esc(finding.get('severity', 'Info'))}</span></td>"
            f"<td><strong>{esc(finding.get('title'))}</strong><small>{esc(finding.get('category'))}</small></td>"
            f"<td>{esc(finding.get('confidence'))}</td>"
            f"<td class='path'>{esc(finding.get('path'))}<small>{evidence}</small></td>"
            f"<td>{esc(finding.get('description'))}</td>"
            f"<td>{esc(remediation)}</td></tr>"
        )
    if not finding_rows:
        finding_rows = ["<tr><td colspan='6' class='empty'>No configured indicators were identified in the sources that were inspected.</td></tr>"]

    stage_rows = "".join(
        "<tr>"
        f"<td><strong>{esc(stage.get('name'))}</strong></td>"
        f"<td><span class='stage {esc(stage.get('status', 'pending'))}'>{esc(stage.get('status'))}</span></td>"
        f"<td>{esc(stage.get('message'))}</td>"
        f"<td>{esc(stage.get('duration_seconds'))}s</td></tr>"
        for stage in stages
    ) or "<tr><td colspan='4' class='empty'>No stage data was recorded.</td></tr>"

    notes = list_html(data.get("visibility_notes", []) or [], "No additional visibility notes were recorded.")
    all_coverage = data.get("coverage", {}) or {}
    source_coverage = {k: v for k, v in all_coverage.items() if k != "event_logs" and isinstance(v, dict)}
    source_coverage_rows = []
    for label, item in source_coverage.items():
        details = []
        for key, value in item.items():
            if key == "status":
                continue
            if key == "inspection":
                rendered = "Detailed Windows API counters are shown in Live memory inspection below."
            elif isinstance(value, dict):
                rendered = f"{len(value)} field(s)"
            elif isinstance(value, list):
                rendered = ", ".join(str(x) for x in value[:8])
                if len(value) > 8:
                    rendered += f" (+{len(value) - 8} more)"
            else:
                rendered = str(value)
            details.append(f"{key.replace('_', ' ')}: {rendered}")
        source_coverage_rows.append(
            "<tr>"
            f"<td><strong>{esc(label.replace('_', ' ').title())}</strong></td>"
            f"<td>{esc(item.get('status', 'unknown'))}</td>"
            f"<td>{esc(' · '.join(details))}</td>"
            "</tr>"
        )
    if not source_coverage_rows:
        source_coverage_rows = ["<tr><td colspan='3' class='empty'>No additional source coverage counters were collected.</td></tr>"]
    coverage = all_coverage.get("event_logs", {}) or {}
    coverage_rows = []
    for label, item in coverage.items():
        status = item.get("status", "unknown")
        truncated = "Yes · newest records only" if item.get("truncated") else "No cap reached"
        returned = item.get("records_returned", item.get("records_inspected", 0))
        event_ids = ", ".join(str(x) for x in item.get("event_ids", []) or []) or "—"
        coverage_rows.append(
            "<tr>"
            f"<td><strong>{esc(label)}</strong><small>{esc(item.get('channel', ''))}</small></td>"
            f"<td>{esc(status)}</td>"
            f"<td>{esc(returned)}</td>"
            f"<td>{esc(item.get('records_inspected', 0))} / {esc(item.get('limit_per_channel', '—'))}</td>"
            f"<td>{esc(event_ids)}</td>"
            f"<td>{esc(truncated)}</td>"
            f"<td>{esc(item.get('matched_findings', 0))}</td>"
            f"<td>{esc(item.get('reason', ''))}</td>"
            "</tr>"
        )
    if not coverage_rows:
        coverage_rows = ["<tr><td colspan='8' class='empty'>No historical event-log coverage data was collected.</td></tr>"]
    errors = "".join(
        f"<li><strong>{esc(error.get('stage'))}:</strong> {esc(error.get('message'))}</li>"
        for error in (data.get("errors", []) or [])
    ) or "<li>No scan-stage errors were recorded.</li>"

    # The scanner's coverage counters are the source of truth. Older report
    # versions optionally supplied a separate diagnostics object; keep that as
    # a compatibility fallback without dumping raw local endpoints into reports.
    network = data.get("network_diagnostics", {}) or {}
    net_cov = all_coverage.get("network", {}) or {}
    known = network.get("known_server", {}) or {}
    resolution = network.get("dns_resolution", {}) or {}
    configured_domains = net_cov.get("configured_domains") or known.get("domains") or [known.get("domain", "benderoflight.com")]
    configured_ips = net_cov.get("configured_ips") or known.get("ips", [])
    network_fields = [
        ("DNS cache readable", net_cov.get("dns_cache_read", "not collected")),
        ("DNS cache lines", net_cov.get("dns_lines", "not collected")),
        ("Hosts file readable", net_cov.get("hosts_read", "not collected")),
        ("Hosts file lines", net_cov.get("hosts_lines", "not collected")),
        ("Z797 Hosts mappings", net_cov.get("hosts_matches", len(network.get("hosts_matches", []) or []))),
        ("netstat readable", net_cov.get("netstat_read", "not collected")),
        ("netstat text lines", net_cov.get("netstat_lines", "not collected")),
        ("Parsed active remote endpoint rows", net_cov.get("endpoint_rows", len(network.get("endpoints", []) or []))),
        ("Rows matching configured campaign IPs", net_cov.get("campaign_ip_endpoint_rows", "not collected")),
        ("Unattributed campaign-IP rows", net_cov.get("unattributed_campaign_ip_endpoints", "not collected")),
        ("Configured threat domains", configured_domains),
        ("Configured threat IPs", configured_ips),
        ("Configured URL paths", known.get("api_paths", ["/nfront.php", "/nback.php"])),
        ("Resolved campaign-domain addresses", net_cov.get("resolved_campaign_domain_ips", resolution.get("addresses", []))),
        ("Collection errors", net_cov.get("errors", network.get("errors", []))),
    ]
    network_rows = "".join(
        f"<tr><th>{esc(label)}</th><td>{esc(', '.join(map(str, value)) if isinstance(value, list) else value)}</td></tr>"
        for label, value in network_fields
    )

    memory = (all_coverage.get("memory", {}) or {}).get("inspection", {}) or {}
    memory_details = memory.get("process_details", []) if isinstance(memory, dict) else []
    memory_fields = [
        ("Memory inspection status", memory.get("status", (all_coverage.get("memory", {}) or {}).get("status", "not collected"))),
        ("Inspection depth", memory.get("inspection_depth", "not collected")),
        ("Checks enabled for this pass", memory.get("enabled_checks", {})),
        ("Eligible target processes", memory.get("processes_selected", 0)),
        ("Targets skipped by safety rule", memory.get("processes_skipped", 0)),
        ("Process handles opened", memory.get("processes_opened", 0)),
        ("Process handle failures", memory.get("process_open_failures", 0)),
        ("VirtualQueryEx calls", memory.get("virtual_query_calls", 0)),
        ("VirtualQueryEx successful region records", memory.get("virtual_query_successes", 0)),
        ("VirtualQueryEx failures / normal end-of-range", f"{memory.get('virtual_query_failures', 0)} / {memory.get('virtual_query_end_of_range', 0)}"),
        ("Virtual address regions examined", memory.get("regions_examined", 0)),
        ("Virtual region span (metadata sum; not bytes read)", memory.get("virtual_region_span_bytes", 0)),
        ("Committed regions", memory.get("committed_regions", 0)),
        ("Executable regions", memory.get("executable_regions", 0)),
        ("Private executable regions", memory.get("private_executable_regions", 0)),
        ("Image executable regions", memory.get("image_executable_regions", 0)),
        ("Manual-map header probes / bytes", f"{memory.get('manual_map_probe_calls', 0)} / {memory.get('manual_map_probe_bytes', 0)}"),
        ("ReadProcessMemory calls", memory.get("remote_read_attempts", 0)),
        ("Successful full reads", memory.get("remote_read_successes", 0)),
        ("Partial reads", memory.get("remote_read_partial", 0)),
        ("Failed reads", memory.get("remote_read_failures", 0)),
        ("Bytes read from process memory", memory.get("remote_bytes_read", 0)),
        ("Suspicious-region captures attempted / completed / failed", f"{memory.get('evidence_captures_attempted', 0)} / {memory.get('evidence_captures_completed', 0)} / {memory.get('evidence_capture_failures', 0)}"),
        ("Bytes saved as memory evidence", memory.get("evidence_capture_bytes", 0)),
        ("Processes eligible for thread-start correlation", memory.get("thread_scan_eligible_processes", 0)),
        ("Processes skipped for thread scan (no private executable regions)", memory.get("thread_scan_skipped_no_private_exec", 0)),
        ("Thread snapshots attempted / succeeded / failed", f"{memory.get('thread_snapshot_attempts', 0)} / {memory.get('thread_snapshot_successes', 0)} / {memory.get('thread_snapshot_failures', 0)}"),
        ("Threads enumerated", memory.get("threads_enumerated", 0)),
        ("Thread handles opened / failed", f"{memory.get('thread_open_attempts', 0)} / {memory.get('thread_open_failures', 0)}"),
        ("Thread start queries", memory.get("thread_start_query_attempts", 0)),
        ("Thread start queries successful / failed", f"{memory.get('thread_start_query_successes', 0)} / {memory.get('thread_start_query_failures', 0)}"),
        ("Working-set batches / pages", f"{memory.get('working_set_query_attempts', 0)} / {memory.get('working_set_pages_queried', 0)}"),
        ("Working-set batch failures / API unavailable", f"{memory.get('working_set_query_failures', 0)} / {memory.get('working_set_api_unavailable', 0)}"),
        ("Private image pages reported", memory.get("private_image_pages", 0)),
        ("Module snapshot attempts / successes / failures", f"{memory.get('module_snapshot_attempts', 0)} / {memory.get('module_snapshot_successes', 0)} / {memory.get('module_snapshot_failures', 0)}"),
        ("Modules enumerated", memory.get("modules_enumerated", 0)),
        ("AMSI module found / not loaded", f"{memory.get('amsi_module_found', 0)} / {memory.get('amsi_module_not_loaded', 0)}"),
        ("AMSI exports checked", memory.get("amsi_exports_checked", 0)),
        ("Scan duration", f"{memory.get('duration_seconds', 0)} seconds"),
        ("Scope", memory.get("scope_note", "Detailed memory counters were not recorded.")),
    ]
    def render_memory_value(value: Any) -> str:
        if isinstance(value, dict):
            return ", ".join(f"{key}={'on' if enabled else 'off'}" for key, enabled in value.items())
        if isinstance(value, list):
            return ", ".join(map(str, value))
        return str(value)

    memory_rows = "".join(
        f"<tr><th>{esc(label)}</th><td>{esc(render_memory_value(value))}</td></tr>" for label, value in memory_fields
    )
    memory_process_rows = []
    for item in memory_details:
        memory_process_rows.append(
            "<tr>"
            f"<td>{esc(item.get('process', 'Unknown'))} · PID {esc(item.get('pid', ''))}</td>"
            f"<td>{esc('opened' if item.get('open_succeeded') else item.get('skip_reason', 'not opened'))}</td>"
            f"<td>{esc(item.get('regions_examined', 0))}</td>"
            f"<td>{esc(item.get('executable_regions', 0))}</td>"
            f"<td>{esc(item.get('remote_read_attempts', 0))} / {esc(item.get('remote_bytes_read', 0))}</td>"
            f"<td>{esc(item.get('threads_enumerated', 0))} / {esc(item.get('thread_start_query_attempts', 0))}</td>"
            f"<td>{esc(item.get('findings', 0))}</td></tr>"
        )
    if not memory_process_rows:
        memory_process_rows = ["<tr><td colspan='7' class='empty'>No per-process memory work was recorded; check whether the stage was disabled, unsupported or had no eligible targets.</td></tr>"]

    credits = data.get("credits", []) or []
    credit_rows = "".join(
        f"<li><strong>{esc(item.get('name'))}</strong> — {esc(item.get('component'))}</li>"
        for item in credits
    ) or "<li>Third-party component details were not provided.</li>"

    cancelled = bool(data.get("cancelled"))
    error_count = int(summary.get("errors", len(data.get("errors", []) or [])) or 0)
    warning_count = sum(stage.get("status") in ("warning", "error", "skipped") for stage in stages)
    if cancelled:
        result_label, result_class = "Cancelled · partial results", "warning"
    elif error_count or warning_count:
        result_label, result_class = "Completed · coverage limitations", "warning"
    elif findings:
        result_label, result_class = "Review required", "danger"
    else:
        result_label, result_class = "No configured indicators detected", "success"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>TCTC Guardian Z797 — Targeted infection investigation</title>
<style>
:root{{--bg:#f3f6fa;--surface:#fff;--line:#e2e8f0;--text:#172438;--muted:#68788e;--blue:#2d63d8;--navy:#111c2c;--green:#16865d;--amber:#b9770e;--red:#c53d4a;}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px 'Segoe UI',Arial,sans-serif;line-height:1.55}}
main{{max-width:1320px;margin:32px auto;padding:0 24px}}header{{background:var(--navy);color:#fff;padding:30px 34px;border-radius:12px}}
.eyebrow{{color:#9db4d1;font-size:11px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase}}
h1{{font-size:28px;line-height:1.2;margin:8px 0 5px}}header p{{color:#b9c8da;margin:5px 0;font-size:13px}}header code{{color:#d4e4ff}}
.result{{display:inline-block;margin-top:14px;padding:7px 11px;border-radius:5px;font-size:12px;font-weight:700}}
.result.success{{background:#174a3a;color:#8de2bb}}.result.warning{{background:#55401c;color:#ffd37a}}.result.danger{{background:#5b2931;color:#ffadb3}}
.stats{{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;margin:16px 0 24px}}
.stat{{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:14px 16px}}
.stat strong{{display:block;font-size:26px;line-height:1.2}}.stat span{{display:block;color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase;margin-top:5px}}
h2{{font-size:17px;margin:25px 0 10px}}.sub{{color:var(--muted);font-size:12px;margin:-5px 0 10px}}
section{{background:var(--surface);border:1px solid var(--line);border-radius:9px;overflow:hidden}}
table{{border-collapse:collapse;width:100%}}th,td{{padding:11px 13px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;font-size:12px}}
thead th{{color:#5e6f85;font-size:10px;letter-spacing:.4px;background:#eef2f7}}tbody th{{width:200px;color:#607189;background:#f8fafc;font-weight:600}}
tr:last-child td,tr:last-child th{{border-bottom:0}}td strong{{display:block}}td small{{display:block;color:var(--muted);margin-top:3px;white-space:pre-wrap}}
.severity,.stage{{font-size:10px;font-weight:700;text-transform:uppercase;padding:4px 7px;border-radius:4px;white-space:nowrap}}
.critical,.high,.danger{{color:var(--red);background:#fcebed}}.medium,.warning{{color:var(--amber);background:#fff4df}}.low,.info{{color:var(--blue);background:#eaf1fc}}.success,.completed{{color:var(--green);background:#e7f6ef}}.pending,.cancelled,.skipped{{color:#65758a;background:#f1f4f8}}.error{{color:var(--red);background:#fcebed}}
.path,.mono{{font-family:Consolas,'Courier New',monospace;word-break:break-word}}.empty{{padding:25px;text-align:center;color:var(--muted)}}
.notice{{padding:13px 16px;background:#edf4ff;border-left:3px solid var(--blue);color:#405875;font-size:12px}}
ul{{margin:8px 0;padding-left:20px}}li{{margin:4px 0}}footer{{margin:24px 0 38px;color:var(--muted);font-size:11px}}
@media(max-width:800px){{.stats{{grid-template-columns:repeat(2,minmax(0,1fr))}}main{{padding:0 12px}}header{{padding:22px}}}}
</style></head><body><main>
<header><div class="eyebrow">TCTC Guardian Z797 · Version {esc(app.get('version', __version__))}</div>
<h1>Endpoint investigation report</h1>
<p>Scan ID: <code>{esc(data.get('scan_id'))}</code> · Mode: {esc(str(data.get('mode', 'unknown')).upper())}</p>
<p>Device: {esc(data.get('hostname'))} · Operating system: {esc(data.get('os_name'))}</p>
<p>Started: {esc(data.get('started_at'))} · Finished: {esc(data.get('ended_at'))}</p>
<span class="result {result_class}">{result_label}</span></header>
<div class="stats">
<div class="stat"><strong>{summary.get('critical', 0)}</strong><span>Critical</span></div>
<div class="stat"><strong>{summary.get('high', 0)}</strong><span>High</span></div>
<div class="stat"><strong>{summary.get('medium', 0)}</strong><span>Medium</span></div>
<div class="stat"><strong>{summary.get('low', 0)}</strong><span>Low / Info</span></div>
<div class="stat"><strong>{error_count}</strong><span>Check errors</span></div>
</div>
<h2>Investigation coverage</h2><p class="sub">The status reflects what each local check could access during this run.</p>
<section><table><thead><tr><th>Area</th><th>Status</th><th>Result / limitation</th><th>Duration</th></tr></thead><tbody>{stage_rows}</tbody></table></section>
<h2>Evidence & detections</h2><p class="sub">Review findings in context. A matching indicator is not, by itself, proof of successful compromise.</p>
<section><table><thead><tr><th>Severity</th><th>Indicator</th><th>Confidence</th><th>Location / evidence</th><th>Assessment</th><th>Response</th></tr></thead><tbody>{''.join(finding_rows)}</tbody></table></section>
<h2>Collection source details</h2><p class="sub">Counters below describe the actual targeted work completed. They do not imply full-disk or full-memory coverage.</p>
<section><table><thead><tr><th>Source</th><th>Status</th><th>Details</th></tr></thead><tbody>{''.join(source_coverage_rows)}</tbody></table></section>
<h2>Live memory inspection · actual API work</h2><p class="sub">These are runtime counters from the Windows API calls made by this scan. VirtualQueryEx enumerates memory-region metadata; ReadProcessMemory reads only targeted byte ranges. This is not a full byte-for-byte dump.</p>
<section><table><tbody>{memory_rows}</tbody></table></section>
<h3>Per-process memory work</h3><section><table><thead><tr><th>Process</th><th>Handle result</th><th>Regions walked</th><th>Executable regions</th><th>RPM calls / bytes</th><th>Threads / start queries</th><th>Findings</th></tr></thead><tbody>{''.join(memory_process_rows)}</tbody></table></section>
<h2>Historical event-log coverage</h2><p class="sub">Counts describe matching records returned during this scan. The default cap is 5,000 newest matching events per channel; a capped source is partial. Missing channels and disabled audit policies reduce historical visibility.</p>
<section><table><thead><tr><th>Channel</th><th>Status</th><th>Records returned</th><th>Records inspected / cap</th><th>Event IDs</th><th>Truncated?</th><th>Findings</th><th>Availability / parse reason</th></tr></thead><tbody>{''.join(coverage_rows)}</tbody></table></section>
<h2>Network & DNS snapshot</h2><p class="sub">Collected from local resolver configuration, hosts file and operating-system socket tables.</p>
<section><table><tbody>{network_rows}</tbody></table></section>
<h2>Current endpoint collection</h2><section><div style="padding:14px 18px">{esc(net_cov.get('endpoint_rows', len(network.get('endpoints', []) or [])))} parsed remote endpoint row(s) were counted. Raw local IPs, ports and PIDs are deliberately not copied into the report to reduce unnecessary disclosure. Only matches to the fixed Z797 indicator set are promoted to findings.</div></section>
<div class="notice" style="margin-top:14px">Safety policy: the known domain and API paths are static-analysis indicators only. No HTTP/API request was sent to the suspected server, and server availability was not tested.</div>
<h2>Errors & visibility limitations</h2><section><div style="padding:14px 18px"><strong>Check errors</strong><ul>{errors}</ul><strong>Visibility notes</strong><ul>{notes}</ul></div></section>
<h2>Credits & components</h2><section><div style="padding:14px 18px"><ul>{credit_rows}</ul><p class="sub">TCTC Guardian Z797 is an independent defensive utility and is not affiliated with Microsoft or the listed projects.</p></div></section>
<footer>Generated locally by TCTC Guardian Z797. A clean targeted scan is not proof of full eradication. Validate any suspected infection with trusted security tooling.</footer>
</main></body></html>"""
