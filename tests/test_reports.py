import unittest

from guardian.reports import render_html


def sample_report():
    return {
        "scan_id": "test-001",
        "mode": "targeted",
        "hostname": "TEST-PC",
        "os_name": "Windows 11",
        "started_at": "2026-11-21T12:00:00+01:00",
        "ended_at": "2026-11-21T12:01:00+01:00",
        "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0, "errors": 0},
        "stages": [{"name": "Process activity", "status": "completed", "message": "Completed", "duration_seconds": 1.2}],
        "findings": [{
            "title": "Suspicious file <script>", "severity": "Critical", "category": "Staging",
            "confidence": "High", "path": "C:/Temp/test.exe", "description": "Test payload marker",
            "evidence": ["SHA256 matches <sample>"], "remediation": "quarantine",
        }],
        "errors": [], "visibility_notes": [],
        "network_diagnostics": {
            "default_dns": ["1.1.1.1"], "default_gateway": ["192.0.2.1"],
            "known_server": {"domain": "benderoflight.com", "api_paths": ["/nfront.php", "/nback.php"]},
            "dns_resolution": {"status": "resolved", "addresses": ["198.51.100.9"]},
            "hosts_matches": [], "endpoints": ["TCP 127.0.0.1:1 127.0.0.1:2 ESTABLISHED 123"],
            "errors": [],
        },
    }


class ReportTests(unittest.TestCase):
    def test_report_has_full_sections_and_escapes_untrusted_text(self):
        rendered = render_html(sample_report())
        self.assertIn("Investigation coverage", rendered)
        self.assertIn("Evidence & detections", rendered)
        self.assertIn("Network & DNS snapshot", rendered)
        self.assertIn("Credits & components", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertNotIn("<script>", rendered)
        self.assertIn("No HTTP/API request was sent", rendered)


    def test_eventlog_coverage_distinguishes_returned_inspected_and_truncated_records(self):
        report = sample_report()
        report["coverage"] = {"processes": {"status": "read", "processes_enumerated": 145, "image_paths_unavailable": 3}, "memory": {"status": "read_with_gaps", "eligible_processes": 2, "coverage_gaps": ["access denied"]}, "persistence": {"status": "read", "registry_values_inspected": 22, "scheduled_tasks_returned": 180}, "network": {"status": "read_with_gaps", "dns_cache_read": True, "hosts_read": True, "errors": ["endpoint denied"]}, "event_logs": {
            "Sysmon": {
                "channel": "Microsoft-Windows-Sysmon/Operational", "status": "read",
                "records_returned": 2001, "records_inspected": 2000,
                "limit_per_channel": 2000, "truncated": True, "matched_findings": 3,
                "event_ids": ["1", "10", "29"], "reason": "More records may exist",
            },
            "PowerShell": {
                "channel": "Microsoft-Windows-PowerShell/Operational", "status": "unavailable",
                "records_inspected": 0, "limit_per_channel": 2000,
                "reason": "Channel not found",
            },
        }}
        rendered = render_html(report)
        self.assertIn("Records returned", rendered)
        self.assertIn("Records inspected / cap", rendered)
        self.assertIn("Event IDs", rendered)
        self.assertIn("2001", rendered)
        self.assertIn("2000", rendered)
        self.assertIn("1, 10, 29", rendered)
        self.assertIn("Yes · newest records only", rendered)
        self.assertIn("Channel not found", rendered)
        self.assertIn("Collection source details", rendered)
        self.assertIn("145", rendered)
        self.assertIn("read_with_gaps", rendered)
        self.assertIn("access denied", rendered)
        self.assertIn("scheduled tasks returned: 180", rendered)
        self.assertIn("180", rendered)
        self.assertIn("endpoint denied", rendered)
        self.assertIn("Collection source details", rendered)
        self.assertIn("145", rendered)
        self.assertIn("read_with_gaps", rendered)
        self.assertIn("access denied", rendered)

    def test_memory_report_shows_real_api_counters_and_explicit_scope(self):
        report = sample_report()
        report["coverage"] = {
            "memory": {
                "status": "read", "eligible_processes": 1,
                "inspection": {
                    "status": "read", "inspection_depth": "memory_map_enumerated_and_targeted_bytes_read",
                    "enabled_checks": {"private_executable_regions": True, "manual_map_pe_headers": True,
                                       "thread_start_correlation": False},
                    "processes_selected": 1, "processes_opened": 1,
                    "virtual_query_calls": 41, "virtual_query_successes": 40,
                    "regions_examined": 40, "virtual_region_span_bytes": 987654321,
                    "private_executable_regions": 2, "manual_map_probe_calls": 2,
                    "manual_map_probe_bytes": 8192, "remote_read_attempts": 3,
                    "remote_read_successes": 3, "remote_read_partial": 0,
                    "remote_read_failures": 0, "remote_bytes_read": 16384,
                    "thread_scan_eligible_processes": 1, "threads_enumerated": 8,
                    "thread_start_query_attempts": 8, "working_set_query_attempts": 2,
                    "working_set_pages_queried": 16, "modules_enumerated": 22,
                    "amsi_exports_checked": 2, "duration_seconds": 0.42,
                    "scope_note": "VirtualQueryEx region map plus targeted ReadProcessMemory probes; not a full memory dump.",
                    "process_details": [{"pid": 777, "process": "RuntimeBroker.exe", "open_succeeded": True,
                                         "regions_examined": 40, "executable_regions": 4,
                                         "remote_read_attempts": 3, "remote_bytes_read": 16384,
                                         "threads_enumerated": 8, "thread_start_query_attempts": 8,
                                         "findings": 0}],
                },
            },
        }
        rendered = render_html(report)
        self.assertIn("Live memory inspection · actual API work", rendered)
        self.assertIn("VirtualQueryEx calls", rendered)
        self.assertIn("41", rendered)
        self.assertIn("ReadProcessMemory calls", rendered)
        self.assertIn("Inspection depth", rendered)
        self.assertIn("manual_map_pe_headers=on", rendered)
        self.assertIn("thread_start_correlation=off", rendered)
        self.assertIn("16384", rendered)
        self.assertIn("RuntimeBroker.exe · PID 777", rendered)
        self.assertIn("not a full memory dump", rendered)

    def test_disabled_historical_channels_are_explicit_in_report(self):
        report = sample_report()
        report["stages"] = [{"name": "Z797 event history", "status": "skipped",
                             "message": "Disabled in Settings; this source was not queried.", "duration_seconds": 0}]
        report["coverage"] = {"event_logs": {
            name: {"channel": channel, "status": "disabled", "records_returned": 0,
                   "records_inspected": 0, "limit_per_channel": 5000,
                   "reason": "Historical event review is disabled in Settings; this channel was not queried."}
            for name, channel in [
                ("Sysmon", "Microsoft-Windows-Sysmon/Operational"),
                ("Windows Security", "Security"),
                ("PowerShell", "Microsoft-Windows-PowerShell/Operational"),
                ("Task Scheduler", "Microsoft-Windows-TaskScheduler/Operational"),
                ("WMI Activity", "Microsoft-Windows-WMI-Activity/Operational"),
            ]
        }}
        rendered = render_html(report)
        self.assertIn("Historical event-log coverage", rendered)
        self.assertIn("disabled", rendered)
        self.assertIn("was not queried", rendered)
        self.assertIn("skipped", rendered)

    def test_network_report_uses_scan_coverage_endpoint_counts_not_empty_diagnostics(self):
        report = sample_report()
        report["network_diagnostics"] = {}
        report["coverage"] = {"network": {
            "status": "read", "dns_cache_read": True, "dns_lines": 1687,
            "hosts_read": True, "hosts_lines": 27, "hosts_matches": 0,
            "netstat_read": True, "netstat_lines": 132, "endpoint_rows": 131,
            "campaign_ip_endpoint_rows": 0, "unattributed_campaign_ip_endpoints": 0,
            "configured_domains": ["benderoflight.com"], "configured_ips": ["93.94.52.29"],
            "resolved_campaign_domain_ips": [], "errors": [],
        }}
        rendered = render_html(report)
        self.assertIn("Parsed active remote endpoint rows", rendered)
        self.assertIn("131", rendered)
        self.assertIn("Raw local IPs, ports and PIDs are deliberately not copied", rendered)

    def test_clean_report_is_not_described_as_full_removal(self):
        report = sample_report()
        report["findings"] = []
        rendered = render_html(report)
        self.assertIn("No configured indicators detected", rendered)
        self.assertIn("not proof of full eradication", rendered)


if __name__ == "__main__":
    unittest.main()
