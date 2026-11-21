import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guardian import remediation
from guardian.remediation import remediate_finding


class CampaignFileRemediationScopeTests(unittest.TestCase):
    def test_campaign_marker_file_in_exact_staging_root_can_be_quarantined_after_revalidation(self):
        with tempfile.TemporaryDirectory() as td:
            temp_root = Path(td) / "Temp"
            file_path = temp_root / "Local" / "script.ps1"
            file_path.parent.mkdir(parents=True)
            file_path.write_text("Invoke-WebRequest https://benderoflight.com/nfront.php", encoding="utf-8")
            digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
            finding = {
                "title": "Z797-related script",
                "path": str(file_path),
                "sha256": digest,
                "remediation": "quarantine_file",
                "metadata": {"file_path": str(file_path), "expected_size": file_path.stat().st_size},
            }
            with patch.dict(os.environ, {"TEMP": str(temp_root), "WINDIR": str(Path(td) / "Windows")}):
                with patch("guardian.remediation.windows.IS_WINDOWS", True), patch(
                    "guardian.remediation.quarantine_file",
                    return_value={"quarantine_path": "Q\\script.ps1"},
                ) as quarantine:
                    result = remediate_finding(finding, user_confirmed=True)
            quarantine.assert_called_once_with(str(file_path), digest, file_path.stat().st_size)
            self.assertEqual(result["status"], "success")

    def test_filename_and_matching_old_hash_without_current_campaign_content_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            temp_root = Path(td) / "Temp"
            file_path = temp_root / "Local" / "z797.ps1"
            file_path.parent.mkdir(parents=True)
            file_path.write_text("Write-Output 'ordinary text'", encoding="utf-8")
            digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
            finding = {
                "path": str(file_path), "sha256": digest, "remediation": "quarantine_file",
                "metadata": {"file_path": str(file_path), "expected_size": file_path.stat().st_size},
            }
            with patch.dict(os.environ, {"TEMP": str(temp_root), "WINDIR": str(Path(td) / "Windows")}):
                with patch("guardian.remediation.windows.IS_WINDOWS", True), patch("guardian.remediation.quarantine_file") as quarantine:
                    with self.assertRaisesRegex(RuntimeError, "no exact recovered Z797 hash or embedded campaign indicator"):
                        remediate_finding(finding, user_confirmed=True)
            quarantine.assert_not_called()

    def test_changed_file_is_refused_before_quarantine(self):
        with tempfile.TemporaryDirectory() as td:
            temp_root = Path(td) / "Temp"
            file_path = temp_root / "Local" / "script.ps1"
            file_path.parent.mkdir(parents=True)
            file_path.write_text("benderoflight.com", encoding="utf-8")
            old_digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
            old_size = file_path.stat().st_size
            file_path.write_text("changed content", encoding="utf-8")
            finding = {
                "path": str(file_path), "sha256": old_digest, "remediation": "quarantine_file",
                "metadata": {"file_path": str(file_path), "expected_size": old_size},
            }
            with patch.dict(os.environ, {"TEMP": str(temp_root), "WINDIR": str(Path(td) / "Windows")}):
                with patch("guardian.remediation.windows.IS_WINDOWS", True), patch("guardian.remediation.quarantine_file") as quarantine:
                    with self.assertRaisesRegex(RuntimeError, "File identity changed"):
                        remediate_finding(finding, user_confirmed=True)
            quarantine.assert_not_called()

    def test_unrelated_file_outside_approved_roots_is_refused_even_with_campaign_marker(self):
        with tempfile.TemporaryDirectory() as td:
            file_path = Path(td) / "Documents" / "my-script.ps1"
            file_path.parent.mkdir(parents=True)
            file_path.write_text("benderoflight.com", encoding="utf-8")
            digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
            finding = {
                "path": str(file_path), "sha256": digest, "remediation": "quarantine_file",
                "metadata": {"file_path": str(file_path), "expected_size": file_path.stat().st_size},
            }
            with patch("guardian.remediation.windows.IS_WINDOWS", True), patch("guardian.remediation.quarantine_file") as quarantine:
                with self.assertRaisesRegex(RuntimeError, "limited to the two analysed"):
                    remediate_finding(finding, user_confirmed=True)
            quarantine.assert_not_called()

    def test_no_user_confirmation_means_no_cleanup(self):
        with self.assertRaisesRegex(RuntimeError, "user confirmation"):
            remediate_finding({"remediation": "remove_registry_value", "metadata": {}}, user_confirmed=False)


if __name__ == "__main__":
    unittest.main()
