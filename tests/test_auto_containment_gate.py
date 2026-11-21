import os
import tempfile
import unittest
from pathlib import Path
from guardian.indicators import KNOWN_SAMPLE_ARTIFACTS
from guardian.containment_policy import is_exact_sample_auto_containment_candidate


class ExactAutoContainmentGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_temp = os.environ.get("TEMP")
        os.environ["TEMP"] = self.temp.name
        self.stage = Path(self.temp.name) / "Local"
        self.stage.mkdir()
        self.digest, (self.size, self.label) = next(iter(KNOWN_SAMPLE_ARTIFACTS.items()))
        self.finding = {
            "category": "Exact sample fingerprint", "severity": "Critical", "confidence": "High",
            "path": str(self.stage / "artifact.exe"), "sha256": self.digest,
            "remediation": "contain_exact_sample_process",
            "metadata": {"event_driven": True, "hash_size_verified": True, "expected_size": self.size},
        }

    def tearDown(self):
        if self.old_temp is None:
            os.environ.pop("TEMP", None)
        else:
            os.environ["TEMP"] = self.old_temp
        self.temp.cleanup()

    def test_exact_live_known_artifact_in_sample_staging_passes(self):
        self.assertTrue(is_exact_sample_auto_containment_candidate(self.finding))

    def test_filename_or_heuristic_without_exact_hash_does_not_pass(self):
        item = dict(self.finding); item["sha256"] = ""
        self.assertFalse(is_exact_sample_auto_containment_candidate(item))

    def test_wrong_size_does_not_pass(self):
        item = {**self.finding, "metadata": {**self.finding["metadata"], "expected_size": self.size + 1}}
        self.assertFalse(is_exact_sample_auto_containment_candidate(item))

    def test_non_event_scan_finding_does_not_auto_contain(self):
        item = {**self.finding, "metadata": {**self.finding["metadata"], "event_driven": False}}
        self.assertFalse(is_exact_sample_auto_containment_candidate(item))

    def test_file_outside_exact_staging_boundary_does_not_pass(self):
        item = {**self.finding, "path": str(Path(self.temp.name) / "Downloads" / "artifact.exe")}
        self.assertFalse(is_exact_sample_auto_containment_candidate(item))

    def test_periodic_inventory_can_pass_only_with_exact_sample_hash_and_size(self):
        item = {**self.finding, "metadata": {**self.finding["metadata"], "event_driven": False}}
        self.assertTrue(is_exact_sample_auto_containment_candidate(item, require_event_driven=False))
        self.assertFalse(is_exact_sample_auto_containment_candidate(item, require_event_driven=True))


if __name__ == "__main__":
    unittest.main()
