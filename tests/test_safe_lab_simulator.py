from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guardian.scanner import ScanEngine, _is_manifested_lab_canary


class SafeLabSimulatorTests(unittest.TestCase):
    def test_manifested_lab_canary_is_labelled_as_info_and_quarantinable(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            local = base / "localappdata"
            lab_dir = base / "Temp" / "Local" / "TCTC-Guardian-Lab-ab12cd34ef56"
            lab_dir.mkdir(parents=True)
            canary = lab_dir / "TCTC-Guardian-Lab-ab12cd34ef56.txt"
            content = (
                "TCTC_GUARDIAN_LAB_SIMULATION\n"
                "benderoflight.com\n/nfront.php\n/nback.php\n"
            ).encode()
            canary.write_bytes(content)
            digest = hashlib.sha256(content).hexdigest()
            manifest_dir = local / "TCTC Guardian" / "Lab"
            manifest_dir.mkdir(parents=True)
            (manifest_dir / "safe-lab-manifest.json").write_text(json.dumps({
                "marker": "TCTC_GUARDIAN_LAB_SIMULATION",
                "canary_file": str(canary),
                "sha256": digest,
            }), encoding="utf-8")

            with patch.dict(os.environ, {"LOCALAPPDATA": str(local)}):
                self.assertTrue(_is_manifested_lab_canary(str(canary), digest))
                engine = ScanEngine()
                with patch("guardian.scanner.is_known_staging_path", return_value=True):
                    self.assertTrue(engine._inspect_staging_file(str(canary)))

            self.assertEqual(len(engine.findings), 1)
            finding = engine.findings[0]
            self.assertEqual(finding.title, "[LAB] Harmless Z797 indicator canary")
            self.assertEqual(finding.severity, "Info")
            self.assertEqual(finding.category, "Lab simulation evidence")
            self.assertEqual(finding.remediation, "quarantine_file")
            self.assertTrue(finding.metadata.get("lab_simulated"))
            self.assertEqual(finding.sha256, digest)

    def test_manifest_hash_mismatch_is_not_labelled_as_lab(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            local = base / "localappdata"
            canary = base / "TCTC-Guardian-Lab-ab12cd34ef56.txt"
            canary.write_text("benderoflight.com /nfront.php", encoding="utf-8")
            manifest_dir = local / "TCTC Guardian" / "Lab"
            manifest_dir.mkdir(parents=True)
            (manifest_dir / "safe-lab-manifest.json").write_text(json.dumps({
                "marker": "TCTC_GUARDIAN_LAB_SIMULATION",
                "canary_file": str(canary),
                "sha256": "0" * 64,
            }), encoding="utf-8")
            with patch.dict(os.environ, {"LOCALAPPDATA": str(local)}):
                self.assertFalse(_is_manifested_lab_canary(str(canary), hashlib.sha256(canary.read_bytes()).hexdigest()))

    def test_sysmon_lab_process_and_file_events_are_labelled_as_lab_info(self):
        from xml.sax.saxutils import escape

        namespace = "http://schemas.microsoft.com/win/2004/08/events/event"
        process_guid = "{11111111-1111-1111-1111-111111111111}"
        lab_path = r"C:\Users\Demo\AppData\Local\Temp\Local\TCTC-Guardian-Lab-ab12cd34ef56\TCTC-Guardian-Lab-ab12cd34ef56.txt"

        def make_event(event_id: int, record_id: int, values: dict[str, str]) -> str:
            fields = "".join(f'<Data Name="{escape(k)}">{escape(v)}</Data>' for k, v in values.items())
            return (
                f'<Event xmlns="{namespace}"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>{event_id}</EventID>'
                f'<EventRecordID>{record_id}</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel>'
                f'<TimeCreated SystemTime="2026-11-21T19:00:00.000Z"/><Execution ProcessID="1000"/></System>'
                f'<EventData>{fields}</EventData></Event>'
            )

        process_event = make_event(1, 1, {
            "ProcessGuid": process_guid, "ProcessId": "1000",
            "Image": r"C:\Python\python.exe",
            "CommandLine": f'python.exe -c "TCTC_GUARDIAN_LAB_SIMULATION benderoflight.com /nfront.php {lab_path}"',
        })
        file_event = make_event(11, 2, {
            "ProcessGuid": process_guid, "ProcessId": "1000",
            "Image": r"C:\Python\python.exe", "TargetFilename": lab_path,
        })
        outputs = [
            (True, f"<Events>{process_event}{file_event}</Events>", ""),
            (True, "<Events />", ""), (True, "<Events />", ""),
            (True, "<Events />", ""), (True, "<Events />", ""),
        ]
        engine = ScanEngine(enabled_stages={"eventlogs"})
        with patch("guardian.scanner.windows.IS_WINDOWS", True), patch(
            "guardian.scanner.windows.query_event_log", side_effect=outputs
        ):
            engine._scan_eventlogs()

        self.assertEqual(len(engine.findings), 2)
        self.assertTrue(all(item.title.startswith("[LAB] ") for item in engine.findings))
        self.assertTrue(all(item.severity == "Info" for item in engine.findings))
        self.assertTrue(all(item.category == "Lab simulation telemetry" for item in engine.findings))
        self.assertTrue(all(item.metadata.get("lab_simulated") for item in engine.findings))


    def test_lab_uses_system_directory_cmd_not_comspec_and_serializes_child_image(self):
        from labs import safe_z797_lab

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            system_dir = base / "Windows" / "System32"
            system_dir.mkdir(parents=True)
            cmd = system_dir / "cmd.exe"
            cmd.write_bytes(b"mock cmd placeholder")
            temp_root = base / "Temp"
            temp_root.mkdir()
            local_app = base / "LocalAppData"
            local_app.mkdir()
            manifest_dir = local_app / "TCTC Guardian" / "Lab"
            manifest_dir.mkdir(parents=True)

            class FakeChild:
                pid = 4321
                returncode = 0

                @staticmethod
                def communicate(timeout=20):
                    return ("", "")

            with (
                patch.object(safe_z797_lab, "_staging_root", return_value=temp_root / "Local"),
                patch.object(safe_z797_lab, "_manifest_path", return_value=manifest_dir / "safe-lab-manifest.json"),
                patch.object(safe_z797_lab, "_system_command_processor", return_value=cmd),
                patch.object(safe_z797_lab.subprocess, "Popen", return_value=FakeChild()) as popen,
                patch.dict(os.environ, {"LOCALAPPDATA": str(local_app), "COMSPEC": str(base / "attacker.exe")} ),
            ):
                (temp_root / "Local").mkdir()
                record = safe_z797_lab.prepare(generate_process_event=True)

            self.assertTrue(popen.called)
            launched = popen.call_args.args[0]
            self.assertTrue(launched.startswith(f'"{cmd}" /d /c echo '))
            self.assertNotIn("attacker.exe", launched)
            self.assertEqual(record["child_image"], str(cmd))
            loaded = json.loads((manifest_dir / "safe-lab-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(loaded["child_image"], str(cmd))
            self.assertTrue(Path(record["canary_file"]).is_file())

    def test_lab_removes_partial_directory_when_child_process_fails(self):
        from labs import safe_z797_lab

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            temp_root = base / "Temp"
            temp_root.mkdir()
            local_app = base / "LocalAppData"
            manifest_dir = local_app / "TCTC Guardian" / "Lab"
            manifest_dir.mkdir(parents=True)
            cmd = base / "cmd.exe"
            cmd.write_bytes(b"mock")

            class FailedChild:
                pid = 9876
                returncode = 5

                @staticmethod
                def communicate(timeout=20):
                    return ("", "mock failure")

            staging = temp_root / "Local"
            staging.mkdir()
            with (
                patch.object(safe_z797_lab, "_staging_root", return_value=staging),
                patch.object(safe_z797_lab, "_manifest_path", return_value=manifest_dir / "safe-lab-manifest.json"),
                patch.object(safe_z797_lab, "_system_command_processor", return_value=cmd),
                patch.object(safe_z797_lab.subprocess, "Popen", return_value=FailedChild()),
                patch.dict(os.environ, {"LOCALAPPDATA": str(local_app)}),
                patch.object(safe_z797_lab, "uuid") as uuid_mock,
            ):
                uuid_mock.uuid4.return_value.hex = "ab12cd34ef56"
                with self.assertRaisesRegex(RuntimeError, "echo returned 5"):
                    safe_z797_lab.prepare(generate_process_event=True)

            self.assertFalse((staging / "TCTC-Guardian-Lab-ab12cd34ef56").exists())
            self.assertFalse((manifest_dir / "safe-lab-manifest.json").exists())


    def test_lab_terminates_hung_benign_cmd_process_and_removes_partial_directory(self):
        from labs import safe_z797_lab

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            staging = base / "Temp" / "Local"
            staging.mkdir(parents=True)
            local_app = base / "LocalAppData"
            manifest_dir = local_app / "TCTC Guardian" / "Lab"
            manifest_dir.mkdir(parents=True)
            cmd = base / "cmd.exe"
            cmd.write_bytes(b"mock")

            class HungChild:
                pid = 4444
                returncode = None
                killed = False

                def communicate(self, timeout=20):
                    if not self.killed:
                        raise safe_z797_lab.subprocess.TimeoutExpired("cmd.exe", timeout)
                    return ("", "")

                def kill(self):
                    self.killed = True
                    self.returncode = -9

            child = HungChild()
            with (
                patch.object(safe_z797_lab, "_staging_root", return_value=staging),
                patch.object(safe_z797_lab, "_manifest_path", return_value=manifest_dir / "safe-lab-manifest.json"),
                patch.object(safe_z797_lab, "_system_command_processor", return_value=cmd),
                patch.object(safe_z797_lab.subprocess, "Popen", return_value=child),
                patch.dict(os.environ, {"LOCALAPPDATA": str(local_app)}),
                patch.object(safe_z797_lab, "uuid") as uuid_mock,
            ):
                uuid_mock.uuid4.return_value.hex = "cd34ef56ab12"
                with self.assertRaisesRegex(RuntimeError, "timed out"):
                    safe_z797_lab.prepare(generate_process_event=True)

            self.assertTrue(child.killed)
            self.assertFalse((staging / "TCTC-Guardian-Lab-cd34ef56ab12").exists())
            self.assertFalse((manifest_dir / "safe-lab-manifest.json").exists())

    def test_system_command_processor_resolver_rejects_missing_or_symlinked_cmd(self):
        from labs.safe_z797_lab import _resolve_system_command_processor

        with tempfile.TemporaryDirectory() as td:
            system_dir = Path(td) / "System32"
            system_dir.mkdir()
            self.assertIsNone(_resolve_system_command_processor(system_dir))
            cmd = system_dir / "cmd.exe"
            cmd.write_bytes(b"mock")
            self.assertEqual(_resolve_system_command_processor(system_dir), cmd.resolve())

    def test_simulator_source_has_no_network_or_remote_process_api(self):
        source = (Path(__file__).parents[1] / "labs" / "safe_z797_lab.py").read_text(encoding="utf-8")
        forbidden = (
            "import socket", "import requests", "urllib.request", "WriteProcessMemory",
            "VirtualAllocEx", "CreateRemoteThread", "QueueUserAPC", "NtCreateThreadEx",
            "OpenProcess", "winreg", "SetWindowsHookEx", "AmsiScanBuffer",
            "os.environ.get(\"COMSPEC\")",
        )
        for token in forbidden:
            self.assertNotIn(token, source)
        self.assertIn("TCTC_GUARDIAN_LAB_SIMULATION", source)


if __name__ == "__main__":
    unittest.main()
