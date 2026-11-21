from __future__ import annotations

import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from guardian import sysmon_setup


SCHEMA_EVENT_29 = '''<?xml version="1.0" encoding="UTF-16"?>
<instrumentationManifest>
  <events>
    <event name="SYSMONEVENT_FILE_EXE_DETECTED" value="29"
           template="File Executable Detected" ruleName="FileExecutableDetected" />
  </events>
</instrumentationManifest>'''


class SysmonOutputDecodingTests(unittest.TestCase):
    def test_decodes_utf16le_without_bom_used_by_redirected_sysmon_schema(self):
        raw = SCHEMA_EVENT_29.encode("utf-16-le")
        decoded = sysmon_setup._decode_native_output(raw)
        self.assertIn('ruleName="FileExecutableDetected"', decoded)
        self.assertTrue(sysmon_setup._schema_supports_file_executable_detected(decoded))

    def test_decodes_utf16le_with_bom(self):
        raw = SCHEMA_EVENT_29.encode("utf-16")
        decoded = sysmon_setup._decode_native_output(raw)
        self.assertIn("SYSMONEVENT_FILE_EXE_DETECTED", decoded)

    def test_decodes_utf16be_without_bom(self):
        raw = SCHEMA_EVENT_29.encode("utf-16-be")
        decoded = sysmon_setup._decode_native_output(raw)
        self.assertIn("FileExecutableDetected", decoded)

    def test_preserves_utf8_process_output(self):
        text = "Sysmon setup completed — Microsoft Corporation"
        self.assertEqual(sysmon_setup._decode_native_output(text.encode("utf-8")), text)

    def test_native_process_runner_decodes_both_streams_as_bytes(self):
        stdout = SCHEMA_EVENT_29.encode("utf-16-le")
        stderr = "informational status".encode("utf-8")
        with patch.object(
            sysmon_setup.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr),
        ) as run:
            code, out, err = sysmon_setup._run_process(["Sysmon64.exe", "-s"])
        self.assertEqual(code, 0)
        self.assertTrue(sysmon_setup._schema_supports_file_executable_detected(out))
        self.assertEqual(err, "informational status")
        self.assertFalse(run.call_args.kwargs.get("text", False))

    def test_schema_accepts_event_29_from_sysmon_manifest_with_command_banner(self):
        output = "Sysmon64.exe : status\n" + SCHEMA_EVENT_29
        self.assertTrue(sysmon_setup._schema_supports_file_executable_detected(output))

    def test_schema_rejects_event_27_only(self):
        output = '''<instrumentationManifest><events>
          <event name="SYSMONEVENT_FILE_BLOCK_EXECUTABLE" value="27"
                 template="File Block Executable" ruleName="FileBlockExecutable" />
        </events></instrumentationManifest>'''
        self.assertFalse(sysmon_setup._schema_supports_file_executable_detected(output))

    def test_schema_rejects_event_29_without_file_executable_identity(self):
        output = '''<instrumentationManifest><events>
          <event name="SYSMONEVENT_OTHER" value="29" template="Other" ruleName="Other" />
        </events></instrumentationManifest>'''
        self.assertFalse(sysmon_setup._schema_supports_file_executable_detected(output))

    def test_schema_parser_removes_nul_padding_before_validation(self):
        output = "\x00".join(SCHEMA_EVENT_29)
        self.assertTrue(sysmon_setup._schema_supports_file_executable_detected(output))


if __name__ == "__main__":
    unittest.main()
