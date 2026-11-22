from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guardian import sysmon_setup
from guardian import resource_paths
from guardian.realtime import sysmon_readiness


class SysmonBootstrapTests(unittest.TestCase):
    def test_readiness_requires_running_service_and_operational_channel(self):
        calls = []

        def fake(args, timeout=10):
            calls.append(args)
            if args[:2] == ["sc.exe", "query"]:
                if args[2] == "Sysmon64":
                    return 0, "STATE : 4 RUNNING", ""
                return 1060, "", "service not found"
            return 0, "channel config", ""

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "TCTC Guardian Z797"
            root.mkdir()
            config = root / "Sysmon-TCTC-Z797.xml"
            config.write_text("<Sysmon><EventFiltering><FileExecutableDetected /></EventFiltering></Sysmon>", encoding="utf-8")
            binary = root / "Sysmon64.exe"
            binary.write_bytes(b"signed sysmon fixture")
            marker = {
                "ServiceName": "Sysmon64", "BinaryPath": str(binary), "ConfigPath": str(config),
                "ConfigSha256": hashlib.sha256(config.read_bytes()).hexdigest(), "BlockPeCreation": False,
            }
            (root / "sysmon-install.json").write_text(json.dumps(marker), encoding="utf-8")
            with patch.dict(os.environ, {"PROGRAMDATA": td}), patch("guardian.realtime.windows.IS_WINDOWS", True), patch(
                "guardian.realtime.windows.run_command", side_effect=fake
            ):
                ready, detail = sysmon_readiness()
        self.assertTrue(ready)
        self.assertIn("Sysmon64", detail)
        self.assertIn("detect-only", detail)
        self.assertTrue(any(call[0] == "wevtutil.exe" for call in calls))

    def test_readiness_rejects_an_existing_pe_block_policy(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "TCTC Guardian Z797"
            root.mkdir()
            config = root / "Sysmon-TCTC-Z797.xml"
            config.write_text(
                "<Sysmon><EventFiltering><FileExecutableDetected /><FileBlockExecutable /></EventFiltering></Sysmon>",
                encoding="utf-8",
            )
            binary = root / "Sysmon64.exe"
            binary.write_bytes(b"signed sysmon fixture")
            marker = {
                "ServiceName": "Sysmon64", "BinaryPath": str(binary), "ConfigPath": str(config),
                "ConfigSha256": hashlib.sha256(config.read_bytes()).hexdigest(), "BlockPeCreation": True,
            }
            (root / "sysmon-install.json").write_text(json.dumps(marker), encoding="utf-8")
            def fake(args, timeout=10):
                if args[:2] == ["sc.exe", "query"]:
                    return (0, "STATE : 4 RUNNING", "") if args[2] == "Sysmon64" else (1060, "", "not found")
                return 0, "channel", ""
            with patch.dict(os.environ, {"PROGRAMDATA": td}), patch("guardian.realtime.windows.IS_WINDOWS", True), patch(
                "guardian.realtime.windows.run_command", side_effect=fake
            ):
                ready, detail = sysmon_readiness()
        self.assertFalse(ready)
        self.assertIn("detect-only", detail)
        self.assertIn("PE creation blocking must be disabled", detail)

    def test_guardian_owned_legacy_block_marker_is_not_considered_intact(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "TCTC Guardian Z797"
            root.mkdir()
            config = root / "Sysmon-TCTC-Z797.xml"
            config.write_text("<Sysmon><FileBlockExecutable /></Sysmon>", encoding="utf-8")
            binary = root / "Sysmon64.exe"
            binary.write_bytes(b"signed sysmon fixture")
            marker = {
                "ServiceName": "Sysmon64", "BinaryPath": str(binary), "ConfigPath": str(config),
                "ConfigSha256": hashlib.sha256(config.read_bytes()).hexdigest(), "BlockPeCreation": True,
            }
            (root / "sysmon-install.json").write_text(json.dumps(marker), encoding="utf-8")
            with patch.dict(os.environ, {"PROGRAMDATA": td}):
                intact = sysmon_setup._guardian_marker_is_intact(["Sysmon64"])
        self.assertFalse(intact)

    def test_readiness_fails_closed_when_service_missing(self):
        with patch("guardian.realtime.windows.IS_WINDOWS", True), patch(
            "guardian.realtime.windows.run_command", return_value=(1060, "", "service not found")
        ):
            ready, detail = sysmon_readiness()
        self.assertFalse(ready)
        self.assertIn("No running Sysmon service", detail)

    def test_application_version_is_updated_for_python_native_release(self):
        from guardian import __version__
        self.assertEqual(__version__, "1.0.0")

    def test_authenticode_organization_lookup_uses_organization_name_oid(self):
        calls = []

        class FakeCrypt32:
            @staticmethod
            def CertGetNameStringW(cert_ptr, name_type, flags, type_parameter, buffer, size):
                oid = __import__("ctypes").cast(type_parameter, __import__("ctypes").c_char_p).value.decode("ascii")
                calls.append((name_type, oid, buffer is None))
                if buffer is None:
                    return len("Microsoft Corporation") + 1
                buffer.value = "Microsoft Corporation"
                return len(buffer.value) + 1

        organization = sysmon_setup._certificate_organization_name(FakeCrypt32(), None)
        self.assertEqual(organization, "Microsoft Corporation")
        self.assertEqual(calls, [(3, "2.5.4.10", True), (3, "2.5.4.10", False)])

    def test_windows10_22h2_x64_is_accepted_in_compatibility_mode(self):
        supported, detail = sysmon_setup._evaluate_sysmon_windows_support(
            19045, "Windows 10 Home", "AMD64"
        )
        self.assertTrue(supported)
        self.assertIn("Windows 10 22H2", detail)
        self.assertIn("Sysmon 15.22", detail)
        self.assertIn("Microsoft", detail)

    def test_windows10_pre_22h2_is_rejected(self):
        supported, detail = sysmon_setup._evaluate_sysmon_windows_support(
            19044, "Windows 10 Pro", "AMD64"
        )
        self.assertFalse(supported)
        self.assertIn("19045", detail)

    def test_windows10_x86_is_not_claimed_as_validated(self):
        supported, detail = sysmon_setup._evaluate_sysmon_windows_support(
            19045, "Windows 10 Home", "x86"
        )
        self.assertFalse(supported)
        self.assertIn("x64", detail)

    def test_windows11_remains_supported(self):
        supported, detail = sysmon_setup._evaluate_sysmon_windows_support(
            26300, "Windows 10 Home", "AMD64"
        )
        self.assertTrue(supported)
        self.assertIn("Windows 11", detail)

    def test_windows_server_2019_remains_supported(self):
        supported, detail = sysmon_setup._evaluate_sysmon_windows_support(
            17763, "Windows Server 2019 Standard", "AMD64"
        )
        self.assertTrue(supported)

    def test_win10_sysmon_payload_accepts_pinned_15_22_hashes(self):
        with patch.object(
            sysmon_setup,
            "_bootstrap_sha256",
            side_effect=[
                sysmon_setup.SYSMON_WIN10_22H2_ARCHIVE_SHA256,
                sysmon_setup.SYSMON_WIN10_22H2_BINARY_SHA256["Sysmon64.exe"],
            ],
        ):
            sysmon_setup._validate_win10_sysmon_payload(
                Path("Sysmon.zip"),
                Path("Sysmon64.exe"),
                "Sysmon64.exe",
            )

    def test_win10_sysmon_payload_rejects_changed_archive(self):
        with patch.object(
            sysmon_setup,
            "_bootstrap_sha256",
            side_effect=[
                "0" * 64,
                sysmon_setup.SYSMON_WIN10_22H2_BINARY_SHA256["Sysmon64.exe"],
            ],
        ):
            with self.assertRaisesRegex(RuntimeError, "pinned Windows 10"):
                sysmon_setup._validate_win10_sysmon_payload(
                    Path("Sysmon.zip"),
                    Path("Sysmon64.exe"),
                    "Sysmon64.exe",
                )

    def test_win10_sysmon_payload_rejects_changed_binary(self):
        with patch.object(
            sysmon_setup,
            "_bootstrap_sha256",
            side_effect=[
                sysmon_setup.SYSMON_WIN10_22H2_ARCHIVE_SHA256,
                "0" * 64,
            ],
        ):
            with self.assertRaisesRegex(RuntimeError, "SHA-256"):
                sysmon_setup._validate_win10_sysmon_payload(
                    Path("Sysmon.zip"),
                    Path("Sysmon64.exe"),
                    "Sysmon64.exe",
                )
    def test_windows_11_build_is_not_mislabeled_from_legacy_registry_product_name(self):
        self.assertEqual(
            sysmon_setup._display_windows_product_name("Windows 10 Home", 26300),
            "Windows 11 Home",
        )

    def test_sysmon_setup_is_python_native_and_has_no_powershell_dependency(self):
        source = (Path(__file__).resolve().parents[1] / "src" / "guardian" / "sysmon_setup.py").read_text(encoding="utf-8")
        lowered = source.lower()
        self.assertIn("urllib.request", source)
        self.assertIn("winverifytrust", lowered)
        self.assertIn("certgetnamestringw", lowered)
        self.assertIn("dism.exe", lowered)
        self.assertIn('"-accepteula", "-i"', source)
        self.assertIn('["-c", str(config_target)]', source)
        self.assertNotIn("powershell.exe", lowered)
        self.assertNotIn("Setup-Sysmon.ps1", source)
        self.assertNotIn("Get-WindowsOptionalFeature", source)

    def test_sysmon_stderr_does_not_turn_successful_native_command_into_failure(self):
        with patch.object(sysmon_setup, "_run_process", return_value=(0, "", "Sysmon64.exe : status text")):
            stdout, stderr = sysmon_setup._sysmon_command(Path("Sysmon64.exe"), ["-s"])
        self.assertEqual(stdout, "")
        self.assertIn("status text", stderr)

    def test_sysmon_command_logs_both_streams_but_uses_exit_code(self):
        with patch.object(sysmon_setup, "_run_process", return_value=(0, "schema output", "informational stderr")), patch.object(
            sysmon_setup.LOG, "info"
        ) as log_info:
            sysmon_setup._sysmon_command(Path("Sysmon64.exe"), ["-s"])
        self.assertGreaterEqual(log_info.call_count, 2)

    def test_nonzero_native_exit_code_is_reported_even_when_stderr_is_present(self):
        with patch.object(sysmon_setup, "_run_process", return_value=(5, "", "real Sysmon failure")):
            with self.assertRaisesRegex(RuntimeError, "exit code 5"):
                sysmon_setup._sysmon_command(Path("Sysmon64.exe"), ["-s"])

    def test_dism_feature_detection_does_not_use_powershell(self):
        with tempfile.TemporaryDirectory() as td:
            dism = Path(td) / "System32" / "dism.exe"
            dism.parent.mkdir()
            dism.write_bytes(b"fixture")
            with patch.dict(os.environ, {"WINDIR": td}), patch.object(
                sysmon_setup, "_run_process", return_value=(0, "State : Enabled\n", "")
            ) as run:
                self.assertTrue(sysmon_setup._windows_builtin_sysmon_enabled())
        self.assertEqual(run.call_args.args[0][0], str(dism))
        self.assertIn("/FeatureName:Sysmon", run.call_args.args[0])

    def test_new_install_applies_detect_only_policy_and_records_marker(self):
        with tempfile.TemporaryDirectory() as td:
            config = Path(td) / "Sysmon-TCTC-Z797.xml"
            config.write_text("<Sysmon><EventFiltering><FileExecutableDetected /></EventFiltering></Sysmon>", encoding="utf-8")
            with patch.dict(os.environ, {"PROGRAMDATA": td}), patch.object(
                sysmon_setup, "_service_running", return_value=True
            ), patch.object(sysmon_setup, "_sysmon_command", return_value=("", "")) as run_sysmon, patch.object(
                sysmon_setup, "_run_process", return_value=(0, "channel", "")
            ):
                service, target, _version = sysmon_setup._apply_detect_only_policy(
                    Path("Sysmon64.exe"), config, [], False, False, "Microsoft Corporation", "test-source"
                )
            self.assertEqual(service, "Sysmon64")
            self.assertTrue(target.is_file())
            self.assertEqual(target.parent, Path(td) / "TCTC Guardian Z797")
            install_args = run_sysmon.call_args.args[1]
            self.assertEqual(install_args[0], "-accepteula")
            self.assertEqual(install_args[1], "-i")
            marker = json.loads((Path(td) / "TCTC Guardian Z797" / "sysmon-install.json").read_text(encoding="utf-8"))
            self.assertFalse(marker["BlockPeCreation"])
            self.assertEqual(marker["ConfigVariant"], "detect-only")
            self.assertEqual(marker["BinarySigner"], "Microsoft Corporation")

    def test_bootstrap_refuses_a_default_xml_that_enables_blocking(self):
        with tempfile.TemporaryDirectory() as td:
            config = Path(td) / "Sysmon-TCTC-Z797.xml"
            config.write_text("<Sysmon><EventFiltering><FileExecutableDetected /><FileBlockExecutable /></EventFiltering></Sysmon>", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "unexpectedly enables PE creation blocking"):
                sysmon_setup._apply_detect_only_policy(
                    Path("Sysmon64.exe"), config, [], False, False, "Microsoft Corporation", "test-source"
                )

    def test_external_configuration_is_backed_up_before_replacement(self):
        with tempfile.TemporaryDirectory() as td:
            config = Path(td) / "Sysmon-TCTC-Z797.xml"
            config.write_text("<Sysmon><EventFiltering><FileExecutableDetected /></EventFiltering></Sysmon>", encoding="utf-8")
            calls = []

            def fake_sysmon(executable, args, timeout=180):
                calls.append(list(args))
                if args == ["-c"]:
                    return "<Sysmon schemaversion='4.90' />", ""
                return "updated", ""

            with patch.dict(os.environ, {"PROGRAMDATA": td}), patch.object(
                sysmon_setup, "_service_running", return_value=True
            ), patch.object(sysmon_setup, "_sysmon_command", side_effect=fake_sysmon), patch.object(
                sysmon_setup, "_run_process", return_value=(0, "channel", "")
            ):
                sysmon_setup._apply_detect_only_policy(
                    Path("Sysmon64.exe"), config, ["Sysmon64"], True, False,
                    "Microsoft Corporation", "existing-test",
                )
            self.assertEqual(calls[0], ["-c"])
            self.assertEqual(calls[1][0], "-c")
            backups = list((Path(td) / "TCTC Guardian Z797" / "Backups").glob("Sysmon-current-config-*.txt"))
            self.assertEqual(len(backups), 1)
            self.assertIn("schemaversion", backups[0].read_text(encoding="utf-8"))

    def test_service_binary_path_parser_handles_quoted_paths(self):
        with patch.object(sysmon_setup, "_run_process", return_value=(0, 'BINARY_PATH_NAME : "C:\\Program Files\\Sysmon\\Sysmon64.exe" -service', "")):
            result = sysmon_setup._service_binary_path("Sysmon64")
        self.assertIn("Program Files", str(result))
        self.assertIn("Sysmon64.exe", str(result))

    def test_source_layout_download_uses_config_next_to_src_entrypoint(self):
        with tempfile.TemporaryDirectory() as td:
            app_dir = Path(td) / "src"
            app_dir.mkdir()
            (app_dir / "Sysmon-TCTC-Z797.xml").write_text(
                "<Sysmon><FileExecutableDetected /></Sysmon>", encoding="utf-8"
            )
            program_files = Path(td) / "ProgramFiles"

            def download(archive):
                Path(archive).write_bytes(b"mock sysmon zip")

            def extract(_archive, _member, destination):
                Path(destination).write_bytes(b"mock sysmon executable")

            with patch.dict(os.environ, {"ProgramW6432": str(program_files)}), \
                patch.object(sysmon_setup, "_expected_binary_name", return_value="Sysmon64.exe"), \
                patch.object(sysmon_setup, "_download_sysmon_archive", side_effect=download), \
                patch.object(sysmon_setup, "_validate_sysmon_archive", return_value="Sysmon64.exe"), \
                patch.object(sysmon_setup, "_extract_sysmon_binary", side_effect=extract), \
                patch.object(sysmon_setup, "_verify_microsoft_authenticode", return_value="Microsoft Corporation"):
                executable, signer, source = sysmon_setup._locate_or_download_binary(
                    app_dir, [], False
                )

            self.assertTrue(executable.is_file())
            self.assertEqual(executable, program_files / "TCTC Guardian Z797" / "Sysmon" / "Sysmon64.exe")
            self.assertEqual(signer, "Microsoft Corporation")
            self.assertIn("download.sysinternals.com", source)

    def test_run_launcher_does_not_require_a_separate_sysmon_installer(self):
        root = Path(__file__).resolve().parents[1]
        launcher = (root / "scripts" / "Run-TCTC-Guardian.bat").read_text(encoding="utf-8")
        self.assertNotIn("Install-Sysmon.bat", launcher)
        self.assertIn("application itself", launcher)
        self.assertIn(r"%PROJECT_ROOT%\src\main.py", launcher)


    def test_application_directory_uses_nuitka_onefile_runtime_for_bundled_policy(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runtime = root / "onefile-runtime"
            executable_dir = root / "bin"

            runtime.mkdir()
            executable_dir.mkdir()

            config = runtime / "Sysmon-TCTC-Z797.xml"
            config.write_text("<Sysmon />", encoding="utf-8")

            executable = executable_dir / "TCTC-Guardian-Z797.exe"

            compiled = type(
                "Compiled",
                (),
                {"python_runtime_dir": str(runtime)},
            )()

            with patch.object(
                resource_paths,
                "__compiled__",
                compiled,
                create=True,
            ), patch.object(
                sysmon_setup.sys,
                "argv",
                [str(executable)],
            ):
                result = sysmon_setup._application_directory()

            self.assertEqual(result.resolve(), runtime.resolve())
            self.assertTrue(
                (result / "Sysmon-TCTC-Z797.xml").is_file()
            )

if __name__ == "__main__":
    unittest.main()
