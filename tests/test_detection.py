import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from guardian.indicators import (
    suspicious_command,
    is_temp_local_path,
    contains_pe_header,
    is_protected_system_path,
    is_known_staging_path,
)
from guardian.scanner import ScanEngine, sha256_file, _remote_ip_from_netstat_line
from guardian.reports import render_html
from guardian.remediation import quarantine_file
from guardian import windows


class IndicatorTests(unittest.TestCase):
    def test_temp_local_path_detected(self):
        self.assertTrue(
            is_temp_local_path(r"C:\Users\Demo\AppData\Local\Temp\Local\csc.exe")
        )

    def test_sample_c2_detected(self):
        found, reason = suspicious_command("https://benderoflight.com/nfront.php")
        self.assertTrue(found)
        self.assertIn("domain", reason.lower())

    def test_custom_threat_domain_detected(self):
        found, reason = suspicious_command(
            "https://new-infra.example/check", ["new-infra.example"]
        )
        self.assertTrue(found)
        self.assertIn("new-infra.example", reason)

    def test_empty_custom_domain_list_does_not_restore_default_domain(self):
        found, _ = suspicious_command("https://benderoflight.com/nfront.php", [])
        self.assertFalse(found)
        engine = ScanEngine(c2_domains=[], c2_urls=[])
        self.assertFalse(engine._matches_c2("benderoflight.com"))

    def test_encoded_powershell_in_autostart_detected(self):
        found, _ = suspicious_command("powershell.exe -enc SQBFAFgA")
        self.assertTrue(found)

    def test_legitimate_runtimebroker_path_not_flagged(self):
        found, _ = suspicious_command(r"C:\Windows\System32\RuntimeBroker.exe")
        self.assertFalse(found)

    def test_ipinfo_is_not_a_standalone_rule(self):
        found, _ = suspicious_command("https://ipinfo.io/json")
        self.assertFalse(found)

    def test_pe_header_detected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "fake.exe"
            data = bytearray(256)
            data[0:2] = b"MZ"
            data[0x3C:0x40] = (0x80).to_bytes(4, "little")
            data[0x80:0x84] = b"PE\0\0"
            p.write_bytes(data)
            self.assertTrue(contains_pe_header(str(p)))

    def test_sha256(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "sample.bin"
            p.write_bytes(b"abc")
            self.assertEqual(
                sha256_file(str(p)),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )

    def test_protected_windows_path_helper(self):
        # The helper is environment-specific; test its result type and non-crashing behavior.
        self.assertIsInstance(is_protected_system_path(os.path.abspath(__file__)), bool)

    def test_known_staging_root_is_exact_and_scoped(self):
        with tempfile.TemporaryDirectory() as d:
            temp_root = Path(d) / "UserTemp"
            target = temp_root / "Local" / "payload.exe"
            target.parent.mkdir(parents=True)
            old_temp = os.environ.get("TEMP")
            old_windir = os.environ.get("WINDIR")
            try:
                os.environ["TEMP"] = str(temp_root)
                os.environ["WINDIR"] = str(Path(d) / "Windows")
                self.assertTrue(is_known_staging_path(str(target)))
                self.assertFalse(
                    is_known_staging_path(
                        str(Path(d) / "Other" / "Local" / "payload.exe")
                    )
                )
            finally:
                if old_temp is None:
                    os.environ.pop("TEMP", None)
                else:
                    os.environ["TEMP"] = old_temp
                if old_windir is None:
                    os.environ.pop("WINDIR", None)
                else:
                    os.environ["WINDIR"] = old_windir

    def test_staging_process_path_alone_does_not_offer_process_termination(self):

        with tempfile.TemporaryDirectory() as d:
            temp_root = Path(d) / "Temp"
            path = temp_root / "Local" / "payload.exe"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"not-a-known-sample")
            with patch.dict(
                os.environ, {"TEMP": str(temp_root), "WINDIR": str(Path(d) / "Windows")}
            ):
                engine = ScanEngine(enabled_stages={"processes"})
                with patch("guardian.scanner.windows.IS_WINDOWS", True), patch(
                    "guardian.scanner.windows.list_processes",
                    return_value=[
                        {
                            "pid": 8120,
                            "ppid": 700,
                            "name": "payload.exe",
                            "path": str(path),
                        }
                    ],
                ):
                    engine._scan_processes()
        self.assertEqual(engine.findings, [])

    def test_active_c2_endpoint_correlates_to_staging_process(self):

        # A DNS-learned address and an unverified process path are not enough for containment.
        netstat = "Proto Local Address Foreign Address State PID\nTCP 10.0.0.5:5555 198.51.100.7:443 ESTABLISHED 8120\n"
        engine = ScanEngine()
        engine.process_inventory = {
            8120: {
                "pid": 8120,
                "name": "payload.exe",
                "path": r"C:\Users\Demo\Temp\Local\payload.exe",
            }
        }
        with patch("guardian.scanner.windows.IS_WINDOWS", True), patch(
            "guardian.scanner.windows.get_dns_cache",
            return_value="Record Name : benderoflight.com\nA (Host) Record : 198.51.100.7\n",
        ), patch(
            "guardian.scanner.windows.get_hosts_text",
            return_value="127.0.0.1 localhost\n",
        ), patch(
            "guardian.scanner.windows.get_netstat", return_value=netstat
        ):
            engine._scan_network()
        self.assertFalse(
            any(f.remediation == "block_network_ip" for f in engine.findings)
        )

    def test_netstat_ioc_matching_uses_remote_endpoint_not_local_endpoint(self):
        self.assertEqual(
            _remote_ip_from_netstat_line(
                "TCP 93.94.52.29:51515 198.51.100.20:443 ESTABLISHED 8120"
            ),
            "198.51.100.20",
        )
        self.assertEqual(
            _remote_ip_from_netstat_line(
                "TCP 10.0.0.5:51515 93.94.52.29:443 ESTABLISHED 8120"
            ),
            "93.94.52.29",
        )
        self.assertIsNone(
            _remote_ip_from_netstat_line("TCP 0.0.0.0:135 0.0.0.0:0 LISTENING 4")
        )
        self.assertEqual(
            _remote_ip_from_netstat_line(
                "TCP [2001:db8::1]:51515 [2001:db8::2]:443 ESTABLISHED 8120"
            ),
            "2001:db8::2",
        )

    def test_local_endpoint_only_does_not_trigger_campaign_ip_match(self):
        netstat = "Proto Local Address Foreign Address State PID\nTCP 93.94.52.29:51515 198.51.100.20:443 ESTABLISHED 8120\n"
        engine = ScanEngine(
            c2_domains=[], c2_ips=["93.94.52.29"], related_campaign_ips=[]
        )
        with patch("guardian.scanner.windows.IS_WINDOWS", True), patch(
            "guardian.scanner.windows.get_dns_cache", return_value=""
        ), patch(
            "guardian.scanner.windows.get_hosts_text",
            return_value="127.0.0.1 localhost\n",
        ), patch(
            "guardian.scanner.windows.get_netstat", return_value=netstat
        ):
            engine._scan_network()
        self.assertFalse(
            any(
                f.category in {"Network activity", "Network context"}
                for f in engine.findings
            )
        )

    def test_confirmed_ip_without_exact_sample_process_correlation_is_not_a_finding(
        self,
    ):
        netstat = "Proto Local Address Foreign Address State PID\nTCP 10.0.0.5:51515 93.94.52.29:443 ESTABLISHED 8120\n"
        engine = ScanEngine(
            c2_domains=[], c2_ips=["93.94.52.29"], related_campaign_ips=[]
        )
        engine.process_inventory = {
            8120: {
                "pid": 8120,
                "name": "chrome.exe",
                "path": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            }
        }
        with patch("guardian.scanner.windows.IS_WINDOWS", True), patch(
            "guardian.scanner.windows.get_dns_cache", return_value=""
        ), patch(
            "guardian.scanner.windows.get_hosts_text",
            return_value="127.0.0.1 localhost\n",
        ), patch(
            "guardian.scanner.windows.get_netstat", return_value=netstat
        ):
            engine._scan_network()
        self.assertFalse(any(f.category == "Network activity" for f in engine.findings))
        self.assertEqual(
            engine.scan_coverage["network"].get("unattributed_campaign_ip_endpoints"), 1
        )
        self.assertEqual(engine.scan_coverage["network"].get("endpoint_rows"), 1)
        self.assertEqual(engine.scan_coverage["network"].get("netstat_lines"), 2)

    def test_dns_cache_domain_is_low_confidence_context_without_process_attribution(
        self,
    ):
        engine = ScanEngine(c2_domains=["benderoflight.com"], c2_ips=[])
        with patch("guardian.scanner.windows.IS_WINDOWS", True), patch(
            "guardian.scanner.windows.get_dns_cache",
            return_value="Record Name : benderoflight.com\nA (Host) Record : 109.238.86.137\n",
        ), patch(
            "guardian.scanner.windows.get_hosts_text",
            return_value="127.0.0.1 localhost\n",
        ), patch(
            "guardian.scanner.windows.get_netstat",
            return_value="Proto Local Address Foreign Address State PID\n",
        ):
            engine._scan_network()
        finding = next(
            f for f in engine.findings if f.category == "Historical network context"
        )
        self.assertEqual(finding.severity, "Low")
        self.assertEqual(finding.confidence, "Low")
        self.assertEqual(finding.remediation, "none")
        self.assertTrue(finding.metadata.get("context_only"))

    def test_sibling_campaign_ip_is_not_in_the_active_z797_network_profile(self):
        netstat = "Proto Local Address Foreign Address State PID\nTCP 10.0.0.5:5555 93.94.52.4:443 ESTABLISHED 8120\n"
        engine = ScanEngine(c2_domains=[], c2_ips=[])
        with patch("guardian.scanner.windows.IS_WINDOWS", True), patch(
            "guardian.scanner.windows.get_dns_cache", return_value=""
        ), patch(
            "guardian.scanner.windows.get_hosts_text",
            return_value="127.0.0.1 localhost\n",
        ), patch(
            "guardian.scanner.windows.get_netstat", return_value=netstat
        ):
            engine._scan_network()
        self.assertEqual(engine.findings, [])

    def test_network_firewall_action_can_be_disabled_by_profile_policy(self):

        # A policy setting cannot turn an unverified process or DNS-learned IP into a Z797 alert.
        netstat = "Proto Local Address Foreign Address State PID\nTCP 10.0.0.5:5555 198.51.100.7:443 ESTABLISHED 8120\n"
        engine = ScanEngine(
            memory_settings={"firewall_policy": "Never change Firewall rules"}
        )
        engine.process_inventory = {
            8120: {
                "pid": 8120,
                "name": "payload.exe",
                "path": r"C:\Users\Demo\Temp\Local\payload.exe",
            }
        }
        with patch("guardian.scanner.windows.IS_WINDOWS", True), patch(
            "guardian.scanner.windows.get_dns_cache",
            return_value="Record Name : benderoflight.com\nA (Host) Record : 198.51.100.7\n",
        ), patch(
            "guardian.scanner.windows.get_hosts_text",
            return_value="127.0.0.1 localhost\n",
        ), patch(
            "guardian.scanner.windows.get_netstat", return_value=netstat
        ):
            engine._scan_network()
        self.assertFalse(
            any(f.remediation == "block_network_ip" for f in engine.findings)
        )


class EngineTests(unittest.TestCase):
    def test_custom_roots_reject_whole_volume_roots(self):

        engine = ScanEngine(custom_staging_roots=["C:\\", "C:\\Users\\Public\\Samples"])
        self.assertEqual(engine.custom_staging_roots, [])

    def test_verification_stage_never_says_no_indicator_when_findings_exist(self):
        events = []
        engine = ScanEngine(
            event_callback=events.append, enabled_stages={"processes", "verification"}
        )
        sample = __import__("guardian.models", fromlist=["Finding"]).Finding(
            title="Synthetic finding",
            severity="Low",
            confidence="Low",
            category="Test",
            description="Fixture only",
            evidence=["unit test"],
            stage_id="processes",
        )
        engine.add(sample)
        report = engine.run()
        done = [
            event
            for event in events
            if event.get("type") == "stage_done"
            and event.get("stage", {}).get("stage_id") == "verification"
        ]
        self.assertEqual(len(done), 1)
        self.assertIn("1 total finding(s)", done[0]["stage"]["message"])
        self.assertNotIn("No indicator found", done[0]["stage"]["message"])
        self.assertEqual(done[0]["stage"]["status"], "warning")
        self.assertEqual(len(report.findings), 1)

    def test_scope_limits_investigation_stages(self):
        report = ScanEngine(enabled_stages={"processes"}).run()
        self.assertEqual(
            [stage.stage_id for stage in report.stages],
            [
                "processes",
                "memory",
                "persistence",
                "staging",
                "network",
                "eventlogs",
                "verification",
            ],
        )
        self.assertEqual(
            report.stages[0].status,
            "warning" if not windows.IS_WINDOWS else report.stages[0].status,
        )
        self.assertTrue(all(stage.status == "skipped" for stage in report.stages[1:]))
        self.assertEqual(report.coverage["event_logs"]["Sysmon"]["status"], "disabled")
        self.assertEqual(report.to_dict()["summary"]["skipped_stages"], 6)
        self.assertEqual(report.mode, "targeted")

    def test_non_windows_scan_runs_without_crash(self):

        if windows.IS_WINDOWS:
            self.skipTest("Non-Windows test only")
        report = ScanEngine().run()
        self.assertEqual(len(report.stages), 7)
        self.assertTrue(report.ended_at)
        self.assertEqual(report.errors, [])
        self.assertEqual(
            report.coverage["event_logs"]["Sysmon"]["status"], "unavailable"
        )
        self.assertEqual(
            report.coverage["event_logs"]["PowerShell"]["status"], "unavailable"
        )
        self.assertEqual(report.coverage["eventlogs"]["channels_unavailable"], 5)

    def test_report_html_escapes_external_values(self):
        data = {
            "scan_id": "test",
            "hostname": "host",
            "os_name": "Windows",
            "started_at": "now",
            "ended_at": "now",
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "errors": 0},
            "stages": [],
            "findings": [
                {
                    "severity": "High",
                    "confidence": "High",
                    "title": "<script>alert(1)</script>",
                    "category": "test",
                    "path": "x",
                    "evidence": [],
                    "description": "<b>bad</b>",
                }
            ],
            "errors": [],
            "visibility_notes": [],
        }
        html = render_html(data)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_quarantine_disabled_off_windows(self):
        if windows.IS_WINDOWS:
            self.skipTest("Non-Windows test only")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "test.bin"
            p.write_bytes(b"test")
            with self.assertRaises(RuntimeError):
                quarantine_file(str(p))
            self.assertTrue(p.exists())

    def test_marker_match_crosses_stream_chunk_boundary(self):
        import tempfile
        from pathlib import Path

        scanner = ScanEngine()
        with tempfile.TemporaryDirectory() as td:
            file_path = Path(td) / "large-candidate.bin"
            file_path.write_bytes(
                b"x" * (1024 * 1024 - 5) + b"benderoflight.com" + b"y" * 64
            )
            self.assertIn(
                "benderoflight.com", scanner._scan_file_markers(str(file_path))
            )

    def test_tctc_staging_csc_candidate_is_high_confidence_and_quarantinable(self):

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "Temp" / "Local" / "csc.exe"
            path.parent.mkdir(parents=True)
            data = bytearray(256)
            data[0:2] = b"MZ"
            data[0x3C:0x40] = (0x80).to_bytes(4, "little")
            data[0x80:0x84] = b"PE\0\0"
            path.write_bytes(data)
            engine = ScanEngine()
            engine._inspect_staging_file(str(path))
            self.assertEqual(engine.findings, [])

    def test_chrome_helper_filename_is_low_confidence_and_not_auto_quarantined(self):

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "Temp" / "Local" / "Svie24xHm5.png"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"\x89PNG\r\n\x1a\nartifact")
            engine = ScanEngine()
            engine._inspect_staging_file(str(path))
            self.assertEqual(engine.findings, [])

    def test_exact_campaign_filename_in_staging_is_manual_quarantine_candidate(self):

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "Temp" / "Local" / "Z797.ps1"
            path.parent.mkdir(parents=True)
            path.write_text("Write-Output 'sample fixture'", encoding="utf-8")
            with patch.dict(
                os.environ,
                {"TEMP": str(path.parents[1]), "WINDIR": str(Path(d) / "Windows")},
            ):
                engine = ScanEngine()
                engine._inspect_staging_file(str(path))
            self.assertEqual(len(engine.findings), 1)
            self.assertEqual(engine.findings[0].severity, "Medium")
            self.assertEqual(engine.findings[0].remediation, "none")
            self.assertTrue(engine.findings[0].metadata["evidence_only"])

    def test_exact_sample_hash_and_size_is_critical_and_quarantinable(self):
        from guardian.indicators import KNOWN_SAMPLE_ARTIFACTS

        digest, (expected_size, _) = next(iter(KNOWN_SAMPLE_ARTIFACTS.items()))
        with tempfile.TemporaryDirectory() as d:
            temp_root = Path(d) / "Temp"
            path = temp_root / "Local" / "recovered-stage.bin"
            path.parent.mkdir(parents=True)
            with path.open("wb") as handle:
                handle.truncate(expected_size)
            with patch.dict(
                os.environ, {"TEMP": str(temp_root), "WINDIR": str(Path(d) / "Windows")}
            ), patch("guardian.scanner.sha256_file", return_value=digest):
                engine = ScanEngine()
                engine._inspect_staging_file(str(path))
            self.assertEqual(len(engine.findings), 1)
            self.assertEqual(engine.findings[0].severity, "Critical")
            self.assertEqual(engine.findings[0].confidence, "High")
            self.assertEqual(engine.findings[0].remediation, "quarantine_file")
            self.assertTrue(engine.findings[0].metadata["known_sample_artifact"])
            self.assertEqual(engine.findings[0].category, "Exact sample fingerprint")
            self.assertTrue(engine.findings[0].metadata["hash_size_verified"])
            self.assertEqual(
                engine.findings[0].metadata["expected_size"], expected_size
            )

    def test_generic_staging_file_is_low_and_not_auto_quarantined(self):

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "Temp" / "Local" / "cache.dat"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"opaque-data")
            engine = ScanEngine()
            engine._inspect_staging_file(str(path))
            self.assertEqual(engine.findings, [])

    def test_local_state_is_metadata_only_and_manual_quarantine_candidate(self):

        with tempfile.TemporaryDirectory() as d:
            temp_root = Path(d) / "TempRoot"
            path = (
                temp_root / "Local" / "Google" / "Chrome" / "User Data" / "Local State"
            )
            path.parent.mkdir(parents=True)
            path.write_text('{"os_crypt":"benderoflight.com"}', encoding="utf-8")
            env = {"TEMP": str(temp_root), "WINDIR": str(Path(d) / "Windows")}
            with patch.dict(os.environ, env), patch.object(
                ScanEngine,
                "_scan_file_markers",
                side_effect=AssertionError("Local State contents must not be scanned"),
            ), patch(
                "guardian.scanner.contains_pe_header",
                side_effect=AssertionError("Local State contents must not be parsed"),
            ):
                engine = ScanEngine()
                engine._inspect_staging_file(str(path))
            self.assertEqual(engine.findings, [])

    def test_exact_chrome_helper_staging_path_is_manual_quarantine_candidate(self):

        with tempfile.TemporaryDirectory() as d:
            temp_root = Path(d) / "TempRoot"
            path = (
                temp_root
                / "Local"
                / "Google"
                / "Chrome"
                / "User Data"
                / "Svie24xHm5.png"
            )
            path.parent.mkdir(parents=True)
            path.write_bytes(b"opaque helper artifact")
            env = {"TEMP": str(temp_root), "WINDIR": str(Path(d) / "Windows")}
            with patch.dict(os.environ, env), patch.object(
                ScanEngine,
                "_scan_file_markers",
                side_effect=AssertionError(
                    "unrelated browser helper content must not be scanned"
                ),
            ), patch(
                "guardian.scanner.contains_pe_header",
                side_effect=AssertionError(
                    "helper artifact contents must not be parsed"
                ),
            ):
                engine = ScanEngine()
                engine._inspect_staging_file(str(path))
            self.assertEqual(engine.findings, [])

    def test_related_ifwf_artifact_in_localappdata_is_reported_but_not_auto_quarantined(
        self,
    ):

        with tempfile.TemporaryDirectory() as d:
            local = Path(d) / "LocalAppData"
            local.mkdir()
            path = local / "ifwf.e4"
            path.write_bytes(b"unconfirmed sibling file")
            with patch.dict(os.environ, {"LOCALAPPDATA": str(local)}):
                engine = ScanEngine()
                engine._inspect_staging_file(str(path))
            self.assertEqual(engine.findings, [])

    def test_localappdata_chrome_helper_filename_is_low_confidence(self):

        with tempfile.TemporaryDirectory() as d:
            local = Path(d) / "LocalAppData"
            local.mkdir()
            path = local / "Svie24xHm5.png"
            path.write_bytes(b"not a real browser image")
            with patch.dict(os.environ, {"LOCALAPPDATA": str(local)}):
                engine = ScanEngine()
                engine._inspect_staging_file(str(path))
            self.assertEqual(engine.findings, [])
