import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guardian.remediation import permanently_delete_quarantined_file


class PermanentQuarantineDeleteTests(unittest.TestCase):
    def _fixture(self, root: Path, contents: bytes = b"quarantined-evidence"):
        quarantine = root / "Quarantine"
        backups = root / "Backups"
        quarantine.mkdir(parents=True)
        backups.mkdir(parents=True)
        qid = "0123456789abcdef0123456789abcdef"
        payload = quarantine / f"{qid}_sample.bin"
        payload.write_bytes(contents)
        record = {
            "id": qid,
            "original_path": r"C:\Users\Demo\AppData\Local\Temp\Local\sample.bin",
            "quarantine_path": str(payload),
            "sha256": hashlib.sha256(contents).hexdigest(),
            "restored": False,
            "permanently_deleted": False,
        }
        (quarantine / "index.json").write_text(json.dumps([record]), encoding="utf-8")
        (quarantine / f"{qid}.json").write_text(json.dumps(record), encoding="utf-8")
        return quarantine, backups, qid, payload

    def test_permanent_delete_requires_verified_quarantine_file_and_keeps_tombstone(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            quarantine, backups, qid, payload = self._fixture(root)
            with patch("guardian.remediation.APP_DIR", root), \
                 patch("guardian.remediation.QUARANTINE_DIR", quarantine), \
                 patch("guardian.remediation.BACKUP_DIR", backups):
                message = permanently_delete_quarantined_file(qid)
                self.assertFalse(payload.exists())
                index = json.loads((quarantine / "index.json").read_text(encoding="utf-8"))
                self.assertTrue(index[0]["permanently_deleted"])
                self.assertIn("Permanently deleted", message)

    def test_hash_mismatch_refuses_deletion(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            quarantine, backups, qid, payload = self._fixture(root)
            record_path = quarantine / "index.json"
            record = json.loads(record_path.read_text(encoding="utf-8"))[0]
            record["sha256"] = "0" * 64
            record_path.write_text(json.dumps([record]), encoding="utf-8")
            with patch("guardian.remediation.APP_DIR", root), \
                 patch("guardian.remediation.QUARANTINE_DIR", quarantine), \
                 patch("guardian.remediation.BACKUP_DIR", backups):
                with self.assertRaisesRegex(RuntimeError, "hash"):
                    permanently_delete_quarantined_file(qid)
            self.assertTrue(payload.exists())

    def test_restored_file_cannot_be_deleted_from_quarantine(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            quarantine, backups, qid, payload = self._fixture(root)
            record_path = quarantine / "index.json"
            record = json.loads(record_path.read_text(encoding="utf-8"))[0]
            record["restored"] = True
            record_path.write_text(json.dumps([record]), encoding="utf-8")
            with patch("guardian.remediation.APP_DIR", root), \
                 patch("guardian.remediation.QUARANTINE_DIR", quarantine), \
                 patch("guardian.remediation.BACKUP_DIR", backups):
                with self.assertRaisesRegex(RuntimeError, "restored"):
                    permanently_delete_quarantined_file(qid)
            self.assertTrue(payload.exists())


if __name__ == "__main__":
    unittest.main()
