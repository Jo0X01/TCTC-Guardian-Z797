import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guardian.indicators import KNOWN_SAMPLE_ARTIFACTS
from guardian.remediation import contain_exact_sample_process, _terminate_exact_sample_process, remediate_finding


class ExactSampleContainmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_temp = os.environ.get("TEMP")
        os.environ["TEMP"] = self.temp.name
        self.stage = Path(self.temp.name) / "Local"
        self.stage.mkdir()
        self.path = self.stage / "stage3.exe"
        self.digest, (self.size, self.label) = next(iter(KNOWN_SAMPLE_ARTIFACTS.items()))
        with self.path.open("wb") as handle:
            handle.truncate(self.size)

    def tearDown(self):
        if self.old_temp is None:
            os.environ.pop("TEMP", None)
        else:
            os.environ["TEMP"] = self.old_temp
        self.temp.cleanup()

    def test_stops_only_the_sysmon_correlated_pid_then_quarantines(self):
        with patch("guardian.remediation.windows.IS_WINDOWS", True), \
             patch("guardian.remediation._terminate_exact_sample_process", return_value="stopped PID 101") as terminate, \
             patch("guardian.remediation.quarantine_file", return_value={"quarantine_path": "Q\\stage3.exe"}) as quarantine:
            result = contain_exact_sample_process(101, str(self.path), self.digest, self.size)
        terminate.assert_called_once_with(101, str(self.path), self.digest, self.size, allow_missing_file=False)
        quarantine.assert_called_once_with(str(self.path), self.digest, self.size)
        self.assertTrue(result["process_stopped"])
        self.assertTrue(result["quarantined"])

    def test_sysmon_exact_hash_event_can_stop_process_if_file_was_already_quarantined(self):
        self.path.unlink()
        with patch("guardian.remediation.windows.IS_WINDOWS", True), \
             patch("guardian.remediation._terminate_exact_sample_process", return_value="stopped PID 101") as terminate, \
             patch("guardian.remediation.read_quarantine_index", return_value=[{"original_path": str(self.path), "sha256": self.digest, "quarantine_path": str(Path(self.temp.name) / "quarantined.exe")}]) as index, \
             patch("guardian.remediation.quarantine_file") as quarantine:
            (Path(self.temp.name) / "quarantined.exe").write_bytes(b"quarantined")
            result = contain_exact_sample_process(101, str(self.path), self.digest, self.size, allow_missing_file=True)
        terminate.assert_called_once_with(101, str(self.path), self.digest, self.size, allow_missing_file=True)
        quarantine.assert_not_called()
        index.assert_called_once()
        self.assertTrue(result["process_stopped"])
        self.assertTrue(result["image_already_absent"])
        self.assertTrue(result["quarantined"])

    def test_legacy_path_only_terminate_action_is_fail_closed(self):
        with self.assertRaisesRegex(RuntimeError, "Generic path-only process termination is disabled"):
            remediate_finding({
                "remediation": "terminate_process",
                "path": str(self.path),
                "metadata": {"pid": 101, "process_path": str(self.path)},
            }, user_confirmed=True)

    def test_missing_file_without_live_verified_event_is_refused(self):
        self.path.unlink()
        with patch("guardian.remediation.windows.IS_WINDOWS", True):
            with self.assertRaises(RuntimeError):
                _terminate_exact_sample_process(101, str(self.path), self.digest, self.size, allow_missing_file=False)

    def test_missing_image_without_quarantine_record_is_reported_as_partial(self):
        self.path.unlink()
        with patch("guardian.remediation.windows.IS_WINDOWS", True), \
             patch("guardian.remediation._terminate_exact_sample_process", return_value="stopped PID 101"), \
             patch("guardian.remediation.read_quarantine_index", return_value=[]):
            result = contain_exact_sample_process(101, str(self.path), self.digest, self.size, allow_missing_file=True)
        self.assertTrue(result["process_stopped"])
        self.assertFalse(result["quarantined"])
        self.assertIn("no matching quarantine record", result["message"])

    def test_missing_file_live_sysmon_event_uses_pinned_process_handle_and_path_check(self):
        self.path.unlink()
        class Fn:
            def __init__(self, callback):
                self.callback = callback
            def __call__(self, *args):
                return self.callback(*args)
        image_path = str(self.path)
        class FakeKernel32:
            def __init__(self):
                self.OpenProcess = Fn(lambda *args: 0x1234)
                def query(handle, flags, buffer, size_ptr):
                    buffer.value = image_path
                    return 1
                self.QueryFullProcessImageNameW = Fn(query)
                self.TerminateProcess = Fn(lambda *args: 1)
                self.WaitForSingleObject = Fn(lambda *args: 0)
                self.CloseHandle = Fn(lambda *args: 1)
        fake = FakeKernel32()
        with patch("guardian.remediation.windows.IS_WINDOWS", True), \
             patch("guardian.remediation.ctypes.WinDLL", return_value=fake, create=True):
            result = _terminate_exact_sample_process(101, str(self.path), self.digest, self.size, allow_missing_file=True)
        self.assertIn("Stopped exact TCTC sample process PID 101", result)


if __name__ == "__main__":
    unittest.main()
