from __future__ import annotations

import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from guardian import sysmon_setup


class FakeResponse(io.BytesIO):
    def __init__(self, payload: bytes, *, url: str = sysmon_setup.SYSMON_DOWNLOAD_URL):
        super().__init__(payload)
        self.status = 200
        self.headers = {"Content-Length": str(len(payload))}
        self._url = url

    def geturl(self):
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def make_test_archive(*, member_name: str = "Sysmon64.exe") -> bytes:
    data = os.urandom(160 * 1024)
    padding = os.urandom(440 * 1024)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(member_name, data)
        archive.writestr("package-check.dat", padding)
    return stream.getvalue()


class SysmonDownloadTests(unittest.TestCase):
    def test_download_uses_only_official_https_endpoint_and_checks_final_host(self):
        payload = make_test_archive()
        with tempfile.TemporaryDirectory() as td, patch("guardian.sysmon_setup.time.sleep"):
            destination = Path(td) / "Sysmon.zip"
            sysmon_setup._download_sysmon_archive(destination, opener=lambda *_a, **_k: FakeResponse(payload))
            self.assertEqual(destination.read_bytes(), payload)

    def test_download_rejects_redirect_to_an_unapproved_host(self):
        payload = make_test_archive()
        with tempfile.TemporaryDirectory() as td, patch("guardian.sysmon_setup.time.sleep"):
            destination = Path(td) / "Sysmon.zip"
            with self.assertRaisesRegex(RuntimeError, "unapproved host"):
                sysmon_setup._download_sysmon_archive(
                    destination,
                    opener=lambda *_a, **_k: FakeResponse(payload, url="https://example.invalid/Sysmon.zip"),
                )
            self.assertFalse(destination.exists())

    def test_archive_requires_the_native_executable_for_detected_architecture(self):
        with tempfile.TemporaryDirectory() as td:
            archive = Path(td) / "Sysmon.zip"
            archive.write_bytes(make_test_archive())
            with patch("guardian.sysmon_setup._expected_binary_name", return_value="Sysmon64.exe"):
                member = sysmon_setup._validate_sysmon_archive(archive)
            self.assertEqual(member, "Sysmon64.exe")

    def test_archive_rejects_path_traversal_entries(self):
        with tempfile.TemporaryDirectory() as td:
            archive = Path(td) / "Sysmon.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as output:
                output.writestr("../evil.exe", os.urandom(150 * 1024))
                output.writestr("padding.bin", os.urandom(500 * 1024))
            with patch("guardian.sysmon_setup._expected_binary_name", return_value="Sysmon64.exe"):
                with self.assertRaisesRegex(RuntimeError, "unsafe path"):
                    sysmon_setup._validate_sysmon_archive(archive)

    def test_archive_rejects_zip_bomb_before_crc_decompression(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = Path(td) / "Sysmon.zip"
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
                for name in ("large-a.bin", "large-b.bin"):
                    with archive.open(name, "w") as member:
                        for _ in range(101):
                            member.write(b"\0" * (1024 * 1024))
                archive.writestr("padding.bin", os.urandom(520 * 1024))
            self.assertLess(archive_path.stat().st_size, sysmon_setup.MAX_ARCHIVE_BYTES)
            with patch("guardian.sysmon_setup._expected_binary_name", return_value="Sysmon64.exe"):
                with self.assertRaisesRegex(RuntimeError, "uncompressed safety limit"):
                    sysmon_setup._validate_sysmon_archive(archive_path)

    def test_archive_rejects_encrypted_entries_before_extraction(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = Path(td) / "Sysmon.zip"
            archive_path.write_bytes(make_test_archive())
            payload = bytearray(archive_path.read_bytes())
            local_header = payload.find(b"PK\x03\x04")
            central_header = payload.find(b"PK\x01\x02")
            self.assertGreaterEqual(local_header, 0)
            self.assertGreaterEqual(central_header, 0)
            local_flags = int.from_bytes(payload[local_header + 6:local_header + 8], "little") | 1
            central_flags = int.from_bytes(payload[central_header + 8:central_header + 10], "little") | 1
            payload[local_header + 6:local_header + 8] = local_flags.to_bytes(2, "little")
            payload[central_header + 8:central_header + 10] = central_flags.to_bytes(2, "little")
            archive_path.write_bytes(payload)
            with patch("guardian.sysmon_setup._expected_binary_name", return_value="Sysmon64.exe"):
                with self.assertRaisesRegex(RuntimeError, "encrypted entry"):
                    sysmon_setup._validate_sysmon_archive(archive_path)

    def test_extracts_only_selected_executable_and_checks_exact_size(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = Path(td) / "Sysmon.zip"
            payload = os.urandom(150 * 1024)
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("Sysmon64.exe", payload)
                archive.writestr("padding.bin", os.urandom(500 * 1024))
            destination = Path(td) / "out" / "Sysmon64.exe"
            sysmon_setup._extract_sysmon_binary(archive_path, "Sysmon64.exe", destination)
            self.assertEqual(destination.read_bytes(), payload)
            self.assertFalse(destination.with_suffix(".exe.partial").exists())

    def test_architecture_selection_supports_x64_arm64_and_x86(self):
        with patch.dict(os.environ, {"PROCESSOR_ARCHITEW6432": "ARM64"}, clear=False):
            self.assertEqual(sysmon_setup._expected_binary_name(), "Sysmon64a.exe")
        with patch.dict(os.environ, {"PROCESSOR_ARCHITEW6432": "AMD64"}, clear=False):
            self.assertEqual(sysmon_setup._expected_binary_name(), "Sysmon64.exe")
        with patch.dict(os.environ, {"PROCESSOR_ARCHITEW6432": "x86"}, clear=False):
            self.assertEqual(sysmon_setup._expected_binary_name(), "Sysmon.exe")


if __name__ == "__main__":
    unittest.main()
