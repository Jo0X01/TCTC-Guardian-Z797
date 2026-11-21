from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from guardian.scanner import ScanEngine
from guardian.models import Finding


class StagingMonitorCacheTests(unittest.TestCase):
    def test_monitor_cache_skips_unchanged_and_rechecks_modified_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "staged.bin"
            path.write_bytes(b"first")
            cache = {}
            engine = ScanEngine(monitoring_mode=True, staging_cache=cache)
            def add_finding(candidate: str) -> bool:
                engine.findings.append(Finding(
                    title="cached test evidence", severity="High", confidence="High",
                    category="test", description="fixture", path=candidate,
                ))
                return True
            with patch.object(engine, "_inspect_staging_file", side_effect=add_finding) as inspect:
                self.assertEqual(engine._inspect_staging_candidate(str(path)), (True, False))
                cached_id = engine.findings[0].finding_id
                engine.findings.clear()  # a new report/monitor cycle has an empty finding list
                self.assertEqual(engine._inspect_staging_candidate(str(path)), (False, True))
                self.assertEqual(len(engine.findings), 1)
                self.assertEqual(engine.findings[0].finding_id, cached_id)
                path.write_bytes(b"modified-and-longer")
                self.assertEqual(engine._inspect_staging_candidate(str(path)), (True, False))
                self.assertEqual(inspect.call_count, 2)

    def test_monitor_does_not_cache_failed_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "staged.bin"
            path.write_bytes(b"first")
            cache = {}
            engine = ScanEngine(monitoring_mode=True, staging_cache=cache)
            with patch.object(engine, "_inspect_staging_file", return_value=False) as inspect:
                engine._inspect_staging_candidate(str(path))
                engine._inspect_staging_candidate(str(path))
                self.assertEqual(inspect.call_count, 2)
                self.assertEqual(cache, {})

    def test_monitor_rechecks_unchanged_files_after_cache_age_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "staged.bin"
            path.write_bytes(b"first")
            cache = {}
            engine = ScanEngine(monitoring_mode=True, staging_cache=cache)
            with patch.object(engine, "_inspect_staging_file", return_value=True) as inspect:
                engine._inspect_staging_candidate(str(path))
                key = next(iter(cache))
                cache[key]["checked_at"] = time.monotonic() - 1801
                self.assertEqual(engine._inspect_staging_candidate(str(path)), (True, False))
                self.assertEqual(inspect.call_count, 2)

    def test_manual_scan_ignores_monitor_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "staged.bin"
            path.write_bytes(b"first")
            cache = {}
            engine = ScanEngine(monitoring_mode=False, staging_cache=cache)
            with patch.object(engine, "_inspect_staging_file", return_value=True) as inspect:
                engine._inspect_staging_candidate(str(path))
                engine._inspect_staging_candidate(str(path))
                self.assertEqual(inspect.call_count, 2)
                self.assertEqual(cache, {})


if __name__ == "__main__":
    unittest.main()
