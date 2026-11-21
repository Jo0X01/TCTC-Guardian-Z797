import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guardian.memory import (
    MemoryFinding,
    _looks_like_mapped_pe,
    _private_exec_should_raise_finding,
    _capture_region,
    create_full_process_dump,
    scan_process_memory,
    _windows_path_key,
    _inspect_process_image_identity,
    _thread_start_addresses,
    _query_private_image_pages,
    _image_modules,
    _inspect_amsi_exports,
    select_memory_targets,
)
from guardian.scanner import ScanEngine
from guardian import windows


class MemoryParsingTests(unittest.TestCase):
    def test_rejects_non_pe_memory(self):
        self.assertFalse(_looks_like_mapped_pe(b"not a PE image" + b"\x00" * 512))

    def test_generic_private_executable_region_is_not_an_alert(self):
        self.assertFalse(_private_exec_should_raise_finding(b"\x90" * 4096))

    def test_private_executable_region_with_valid_pe_is_a_finding_candidate(self):
        header = bytearray(0x300)
        header[:2] = b"MZ"
        struct.pack_into("<I", header, 0x3C, 0x80)
        header[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<HH", header, 0x84, 0x8664, 3)
        struct.pack_into("<H", header, 0x94, 0xF0)
        self.assertTrue(_private_exec_should_raise_finding(bytes(header)))
        self.assertFalse(_private_exec_should_raise_finding(bytes(header), manual_map_enabled=False))

    def test_accepts_minimal_valid_pe_headers(self):
        header = bytearray(0x300)
        header[:2] = b"MZ"
        struct.pack_into("<I", header, 0x3C, 0x80)
        header[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<HH", header, 0x84, 0x8664, 3)
        struct.pack_into("<H", header, 0x94, 0xF0)
        self.assertTrue(_looks_like_mapped_pe(bytes(header)))

    def test_rejects_bad_machine_type(self):
        header = bytearray(0x300)
        header[:2] = b"MZ"
        struct.pack_into("<I", header, 0x3C, 0x80)
        header[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<HH", header, 0x84, 0xFFFF, 3)
        struct.pack_into("<H", header, 0x94, 0xF0)
        self.assertFalse(_looks_like_mapped_pe(bytes(header)))

    def test_windows_image_path_normalization_handles_prefix_and_slashes(self):
        self.assertEqual(_windows_path_key(r"\\?\C:\Windows\System32\RuntimeBroker.exe"),
                         _windows_path_key(r"c:/windows/system32/runtimebroker.exe"))

    def test_process_image_identity_mismatch_is_low_confidence_only(self):
        import ctypes
        header = bytearray(0x300)
        header[:2] = b"MZ"
        struct.pack_into("<I", header, 0x3C, 0x80)
        header[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<HH", header, 0x84, 0x8664, 2)
        struct.pack_into("<H", header, 0x94, 0xF0)
        class FakeKernel:
            pass
        with patch("guardian.memory._image_modules", return_value=[{"path": r"C:\Windows\System32\sample.exe", "base": 0x100000, "size": 0x1000}]), \
             patch("guardian.memory._read_remote", return_value=bytes(header)), \
             patch("guardian.memory.Path.is_file", return_value=True):
            findings = _inspect_process_image_identity(FakeKernel(), object(), 777, "sample.exe", r"C:\Temp\sample.exe")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].indicator, "process_image_identity_mismatch")
        self.assertEqual(findings[0].confidence, "Low")

    def test_memory_finding_serializes_region_metadata(self):
        finding = MemoryFinding(
            pid=42, process_name="RuntimeBroker.exe", process_path=r"C:\Windows\System32\RuntimeBroker.exe",
            indicator="private_executable_region", title="Private executable memory region",
            severity="Medium", confidence="Low", base_address=0x12345000,
            region_size=4096, protection=0x20, memory_type=0x20000, state=0x1000,
        )
        data = finding.to_dict()
        self.assertEqual(data["base_address"], "0x12345000")
        self.assertEqual(data["region_size"], 4096)
        self.assertEqual(data["protection"], "0x20")

    def test_full_dump_requires_per_action_consent(self):
        ok, message = create_full_process_dump(9000, "not-created.dmp", user_consented=False)
        self.assertFalse(ok)
        self.assertIn("consent", message.lower())

    def test_region_capture_does_not_delete_preexisting_evidence_on_name_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base, size, pid = 0x12340000, 4096, 77
            existing = root / f"sample_{pid}_{base:016X}_{size:X}_STAMP_123.mem"
            existing.write_bytes(b"keep this original evidence")
            with patch("guardian.memory._utc_stamp", return_value="STAMP"), patch("guardian.memory.time.time_ns", return_value=123):
                path, digest, complete, note = _capture_region(object(), None, pid, "sample", base, size, root)
            self.assertFalse(complete)
            self.assertEqual(path, "")
            self.assertEqual(existing.read_bytes(), b"keep this original evidence")

    def test_memory_metadata_includes_capture_time(self):
        finding = MemoryFinding(
            pid=42, process_name="RuntimeBroker.exe", process_path="C:/Windows/System32/RuntimeBroker.exe",
            indicator="manual_mapped_pe", title="Mapped PE", severity="High", confidence="High",
            capture_complete=True, captured_at="20261121T012300Z",
        )
        self.assertEqual(finding.to_dict()["captured_at"], "20261121T012300Z")

    def test_memory_allowlist_only_selects_sample_process_targets(self):
        processes = [
            {"pid": 1, "name": "RuntimeBroker.exe", "path": r"C:\Windows\System32\RuntimeBroker.exe"},
            {"pid": 2, "name": "explorer.exe", "path": r"C:\Windows\explorer.exe"},
            {"pid": 3, "name": "chrome.exe", "path": r"C:\Program Files\Google\Chrome\Application\chrome.exe"},
            {"pid": 4, "name": "notepad.exe", "path": r"C:\Windows\System32\notepad.exe"},
            {"pid": 5, "name": "csc.exe", "path": r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"},
            {"pid": 6, "name": "csc.exe", "path": r"C:\Users\Demo\AppData\Local\Temp\Local\csc.exe"},
            {"pid": 7, "name": "csc.exe", "path": r"C:\Users\Demo\Downloads\csc.exe"},
        ]
        selected = select_memory_targets(processes)
        self.assertEqual([p["pid"] for p in selected], [1, 2, 3, 6])

    def test_csc_memory_scope_requires_exact_temp_local_path(self):
        processes = [
            {"pid": 10, "name": "csc.exe", "path": r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"},
            {"pid": 11, "name": "csc.exe", "path": r"C:\Users\Demo\Downloads\csc.exe"},
            {"pid": 12, "name": "csc.exe", "path": r"C:\Users\Demo\AppData\Local\Temp\Local\csc.exe"},
        ]
        self.assertEqual([p["pid"] for p in select_memory_targets(processes)], [12])

    def test_imported_profile_cannot_expand_memory_allowlist(self):
        processes = [
            {"pid": 1, "name": "RuntimeBroker.exe", "path": r"C:\Windows\System32\RuntimeBroker.exe"},
            {"pid": 2, "name": "notepad.exe", "path": r"C:\Windows\System32\notepad.exe"},
        ]
        self.assertEqual([p["pid"] for p in select_memory_targets(processes, {"memory_process_include": ["notepad.exe"]})], [])
        self.assertEqual([p["pid"] for p in select_memory_targets(processes, {"memory_process_include": []})], [1])

    def test_memory_scanner_reports_windows_requirement_offline(self):
        with patch("guardian.memory.IS_WINDOWS", False):
            findings, coverage = scan_process_memory([{"pid": 500, "name": "sample.exe", "path": ""}])
        self.assertEqual(findings, [])
        self.assertTrue(any("Windows" in item for item in coverage))

    def test_mocked_windows_scan_opens_process_before_querying_wow64_and_captures_manual_pe(self):
        import ctypes
        import guardian.memory as memory

        class Api:
            def __init__(self, callback):
                self.callback = callback
                self.argtypes = None
                self.restype = None
            def __call__(self, *args):
                return self.callback(*args)

        # Small benign in-memory PE header fixture; it is never executed.
        region = bytearray(0x1000)
        region[:2] = b"MZ"
        struct.pack_into("<I", region, 0x3C, 0x80)
        region[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<HH", region, 0x84, 0x8664, 2)
        struct.pack_into("<H", region, 0x94, 0xF0)

        def get_system_info(ptr):
            info = ptr._obj
            info.lpMaximumApplicationAddress = 0x11000
            info.dwPageSize = 0x1000

        def wow64(handle, out):
            self.assertEqual(handle, 0x55)
            ctypes.cast(out, ctypes.POINTER(ctypes.c_int))[0] = 0
            return 1

        def query_memory(handle, address, out, _size):
            mbi = out._obj
            mbi.BaseAddress = 0x10000
            mbi.AllocationBase = 0x10000
            mbi.AllocationProtect = 0x20
            mbi.PartitionId = 0
            mbi.RegionSize = 0x1000
            mbi.State = memory.MEM_COMMIT
            mbi.Protect = 0x20
            mbi.Type = memory.MEM_PRIVATE
            return ctypes.sizeof(mbi)

        def read_memory(_handle, address, buffer, size, bytes_read):
            offset = int(address.value if hasattr(address, "value") else address) - 0x10000
            data = bytes(region[offset:offset + size])
            ctypes.memmove(buffer, data, len(data))
            ctypes.cast(bytes_read, ctypes.POINTER(ctypes.c_size_t))[0] = len(data)
            return 1

        api = type("FakeKernel32", (), {})()
        api.GetSystemInfo = Api(get_system_info)
        def open_process(access, inherit, pid):
            self.assertEqual(access, memory.PROCESS_QUERY_INFORMATION | memory.PROCESS_QUERY_LIMITED_INFORMATION | memory.PROCESS_VM_READ)
            self.assertFalse(inherit)
            self.assertEqual(pid, 9001)
            return 0x55
        api.OpenProcess = Api(open_process)
        api.IsWow64Process = Api(wow64)
        api.VirtualQueryEx = Api(query_memory)
        api.ReadProcessMemory = Api(read_memory)
        api.CloseHandle = Api(lambda *_args: 1)

        progress_events = []
        with tempfile.TemporaryDirectory() as directory, \
             patch("guardian.memory.IS_WINDOWS", True), \
             patch("guardian.memory.ctypes.WinDLL", return_value=api, create=True):
            actual_api_work = {}
            findings, coverage = scan_process_memory(
                [{"pid": 9001, "name": "RuntimeBroker.exe", "path": r"C:\Windows\System32\RuntimeBroker.exe"}],
                settings={"memory_private_exec": True, "memory_manual_map": True,
                          "memory_thread_start": False, "memory_integrity": False,
                          "memory_image_identity": False, "memory_capture_regions": True},
                evidence_dir=directory, progress=progress_events.append, stats_out=actual_api_work,
            )
            mapped = next(item for item in findings if item.indicator == "manual_mapped_pe")
            starts = [e for e in progress_events if e.get("type") == "memory_process_start"]
            done = [e for e in progress_events if e.get("type") == "memory_process_done"]
            self.assertEqual(starts[0]["process_index"], 1)
            self.assertEqual(starts[0]["process_total"], 1)
            self.assertEqual(done[0]["process_index"], 1)
            self.assertTrue(mapped.capture_complete)
            self.assertEqual(len(mapped.sha256), 64)
            self.assertTrue(Path(mapped.evidence_file).is_file())
            self.assertEqual(Path(mapped.evidence_file).read_bytes(), bytes(region))
            self.assertTrue(Path(mapped.metadata_file).is_file())
            sidecar = __import__("json").loads(Path(mapped.metadata_file).read_text(encoding="utf-8"))
            self.assertEqual(sidecar["sha256"], mapped.sha256)
            self.assertEqual(sidecar["pid"], 9001)
            self.assertEqual(coverage, [])
            # These counters increment only around the calls made to the fake
            # Win32 API surface above; they prevent a cosmetic status-only scan.
            self.assertEqual(actual_api_work["processes_selected"], 1)
            self.assertEqual(actual_api_work["processes_opened"], 1)
            self.assertFalse(hasattr(api, "WriteProcessMemory"))
            self.assertFalse(hasattr(api, "VirtualProtectEx"))
            self.assertFalse(hasattr(api, "CreateRemoteThread"))
            self.assertEqual(actual_api_work["virtual_query_calls"], 1)
            self.assertEqual(actual_api_work["virtual_query_successes"], 1)
            self.assertEqual(actual_api_work["regions_examined"], 1)
            self.assertEqual(actual_api_work["private_executable_regions"], 1)
            self.assertGreaterEqual(actual_api_work["manual_map_probe_calls"], 1)
            self.assertGreaterEqual(actual_api_work["remote_read_attempts"], 2)
            self.assertGreaterEqual(actual_api_work["remote_bytes_read"], 0x1000)
            self.assertEqual(actual_api_work["status"], "read")
            self.assertEqual(actual_api_work["inspection_depth"], "memory_map_enumerated_and_targeted_bytes_read")
            self.assertTrue(actual_api_work["enabled_checks"]["manual_map_pe_headers"])
            self.assertEqual(actual_api_work["process_details"][0]["pid"], 9001)

    def test_toolhelp_thread_snapshot_and_ntqueryinformationthread_are_called_and_counted(self):
        import ctypes
        import guardian.memory as memory

        class Api:
            def __init__(self, callback):
                self.callback = callback
                self.argtypes = None
                self.restype = None
            def __call__(self, *args):
                return self.callback(*args)

        kernel32 = type("FakeKernel32", (), {})()
        kernel32.CreateToolhelp32Snapshot = Api(lambda *_args: 0x88)

        def thread_first(_snapshot, out):
            entry = out._obj
            entry.th32ThreadID = 4321
            entry.th32OwnerProcessID = 9003
            return 1

        kernel32.Thread32First = Api(thread_first)
        kernel32.Thread32Next = Api(lambda *_args: 0)
        kernel32.OpenThread = Api(lambda *_args: 0x99)
        kernel32.CloseHandle = Api(lambda *_args: 1)
        ntdll = type("FakeNtdll", (), {})()

        def query_thread(_handle, info_class, out, out_size, _return_length):
            self.assertEqual(info_class, 9)
            self.assertEqual(out_size, ctypes.sizeof(ctypes.c_void_p))
            ctypes.cast(out, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.c_void_p(0x12345000)
            return 0

        ntdll.NtQueryInformationThread = Api(query_thread)
        stats = {}
        with patch("guardian.memory.ctypes.WinDLL", side_effect=lambda name, **_kw: ntdll if name == "ntdll" else kernel32, create=True):
            starts, warnings = _thread_start_addresses(9003, kernel32, stats)

        self.assertEqual(starts, [(4321, 0x12345000)])
        self.assertEqual(warnings, [])
        self.assertEqual(stats["thread_snapshot_attempts"], 1)
        self.assertEqual(stats["thread_snapshot_successes"], 1)
        self.assertEqual(stats["threads_enumerated"], 1)
        self.assertEqual(stats["thread_open_attempts"], 1)
        self.assertEqual(stats["thread_start_query_attempts"], 1)
        self.assertEqual(stats["thread_start_query_successes"], 1)

    def test_queryworkingsetex_checks_image_pages_and_counts_private_pages(self):
        import guardian.memory as memory

        class Api:
            def __init__(self, callback):
                self.callback = callback
                self.argtypes = None
                self.restype = None
            def __call__(self, *args):
                return self.callback(*args)

        kernel32 = type("FakeKernel32", (), {})()

        def query_working_set(_process, info_ptr, _size):
            batch = info_ptr._obj
            for entry in batch:
                entry.VirtualAttributes = 1  # Valid=1, Shared=0 => private resident page.
            return 1

        kernel32.QueryWorkingSetEx = Api(query_working_set)
        stats = {}
        pages = _query_private_image_pages(kernel32, object(), 0x10000, 0x2000, 0x1000, stats)
        self.assertEqual(pages, [0x10000, 0x11000])
        self.assertEqual(stats["working_set_query_attempts"], 1)
        self.assertEqual(stats["working_set_query_successes"], 1)
        self.assertEqual(stats["working_set_pages_queried"], 2)
        self.assertEqual(stats["working_set_valid_pages"], 2)
        self.assertEqual(stats["private_image_pages"], 2)

    def test_toolhelp_module_snapshot_enumerates_module_path_and_base(self):
        import ctypes
        from guardian.memory import _image_modules

        class Api:
            def __init__(self, callback):
                self.callback = callback
                self.argtypes = None
                self.restype = None
            def __call__(self, *args):
                return self.callback(*args)

        kernel32 = type("FakeKernel32", (), {})()
        kernel32.CreateToolhelp32Snapshot = Api(lambda *_args: 0x88)

        def module_first(_snapshot, out):
            entry = out._obj
            entry.th32ProcessID = 9004
            entry.modBaseAddr = ctypes.cast(ctypes.c_void_p(0x7FFB0000), ctypes.POINTER(ctypes.c_byte))
            entry.modBaseSize = 0x20000
            entry.szModule = "amsi.dll"
            entry.szExePath = r"C:\Windows\System32\amsi.dll"
            return 1

        kernel32.Module32FirstW = Api(module_first)
        kernel32.Module32NextW = Api(lambda *_args: 0)
        kernel32.CloseHandle = Api(lambda *_args: 1)
        stats = {}
        modules = _image_modules(9004, kernel32, stats)
        self.assertEqual(len(modules), 1)
        self.assertEqual(modules[0]["name"], "amsi.dll")
        self.assertEqual(modules[0]["base"], 0x7FFB0000)
        self.assertEqual(stats["module_snapshot_attempts"], 1)
        self.assertEqual(stats["module_snapshot_successes"], 1)
        self.assertEqual(stats["modules_enumerated"], 1)

    def test_amsi_export_check_reads_only_known_export_addresses(self):
        import guardian.memory as memory

        live_stub = b"\x31\xC0\xC3" + b"\x90" * 13
        with patch("guardian.memory._image_modules", return_value=[
                 {"name": "amsi.dll", "path": r"C:\Windows\System32\amsi.dll", "base": 0x70000000}
             ]), \
             patch("guardian.memory._pe_export_file_offset", side_effect=[(0x1234, b"\x90" * 16), (0x2345, b"\x90" * 16)]), \
             patch("guardian.memory._read_remote", return_value=live_stub) as read_remote:
            stats = {}
            findings = _inspect_amsi_exports(object(), object(), 9005, stats)

        self.assertEqual([item.indicator for item in findings], ["amsi_export_stub", "amsi_export_stub"])
        self.assertEqual(stats["amsi_module_found"], 1)
        self.assertEqual(stats["amsi_exports_checked"], 2)
        self.assertEqual(read_remote.call_count, 2)
        self.assertEqual(read_remote.call_args_list[0].args[2:4], (0x70001234, 16))
        self.assertEqual(read_remote.call_args_list[1].args[2:4], (0x70002345, 16))

    def test_memory_scan_does_not_report_success_when_virtualqueryex_returns_no_regions(self):
        import ctypes
        import guardian.memory as memory

        class Api:
            def __init__(self, callback):
                self.callback = callback
                self.argtypes = None
                self.restype = None
            def __call__(self, *args):
                return self.callback(*args)

        def get_system_info(ptr):
            info = ptr._obj
            info.lpMaximumApplicationAddress = 0x10000
            info.dwPageSize = 0x1000

        def wow64(_handle, out):
            ctypes.cast(out, ctypes.POINTER(ctypes.c_int))[0] = 0
            return 1

        api = type("FakeKernel32", (), {})()
        api.GetSystemInfo = Api(get_system_info)
        api.OpenProcess = Api(lambda *_args: 0x55)
        api.IsWow64Process = Api(wow64)
        api.VirtualQueryEx = Api(lambda *_args: self.fail("VirtualQueryEx should not run for an empty address range"))
        api.ReadProcessMemory = Api(lambda *_args: self.fail("ReadProcessMemory must not run without an enumerated region"))
        api.CloseHandle = Api(lambda *_args: 1)

        with patch("guardian.memory.IS_WINDOWS", True), \
             patch("guardian.memory.ctypes.WinDLL", return_value=api, create=True):
            stats = {}
            findings, coverage = scan_process_memory(
                [{"pid": 9002, "name": "RuntimeBroker.exe", "path": r"C:\Windows\System32\RuntimeBroker.exe"}],
                settings={"memory_thread_start": False, "memory_integrity": False,
                          "memory_image_identity": False, "memory_capture_regions": False},
                stats_out=stats,
            )

        self.assertEqual(findings, [])
        self.assertEqual(stats["processes_opened"], 1)
        self.assertEqual(stats["regions_examined"], 0)
        self.assertEqual(stats["status"], "read_with_gaps")
        self.assertEqual(stats["inspection_depth"], "no_memory_regions_enumerated")
        self.assertTrue(any("no virtual-memory regions" in item for item in coverage))


class MemoryEngineIntegrationTests(unittest.TestCase):
    def test_memory_stage_is_present_and_optional(self):
        engine = ScanEngine(enabled_stages={"processes"})
        self.assertNotIn("memory", [stage[0] for stage in engine.STAGES if stage[0] in engine.enabled_stages])
        self.assertIn("memory", {stage[0] for stage in engine.STAGES})

    def test_memory_finding_maps_into_regular_evidence_pipeline(self):
        from guardian.memory import MemoryFinding
        sample = MemoryFinding(
            pid=777, process_name="RuntimeBroker.exe", process_path=r"C:\Windows\System32\RuntimeBroker.exe",
            indicator="manual_mapped_pe", title="PE image found in private executable memory",
            severity="High", confidence="High", base_address=0x100000, region_size=8192,
            evidence_file="C:/evidence/region.mem", sha256="a" * 64, capture_complete=True,
            rationale="A mapped PE was found and a thread starts inside the region.",
            evidence=["Thread ID: 888"],
        )
        engine = ScanEngine(enabled_stages={"memory"})
        with patch("guardian.scanner.windows.IS_WINDOWS", True), \
             patch("guardian.scanner.windows.list_processes", return_value=[{"pid": 777, "name": "RuntimeBroker.exe", "path": sample.process_path}]), \
             patch("guardian.scanner.scan_process_memory", return_value=([sample], [])):
            engine._scan_memory()
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].category, "Memory analysis")
        self.assertEqual(engine.findings[0].remediation, "none")
        self.assertEqual(engine.findings[0].metadata["pid"], 777)


if __name__ == "__main__":
    unittest.main()
