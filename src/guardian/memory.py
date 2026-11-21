from __future__ import annotations

"""Read-only Windows process-memory inspection for TCTC Guardian.

This module never writes to a target process, changes page protections, queues
threads/APCs, or patches memory. It collects observable memory-map evidence,
checks a small set of sample-relevant indicators, and optionally captures
suspicious executable regions to local evidence storage.
"""

import ctypes
import hashlib
import json
import os
import re
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

IS_WINDOWS = os.name == "nt"

# Process access rights: query information + read process memory only.
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
THREAD_QUERY_INFORMATION = 0x0040
THREAD_QUERY_LIMITED_INFORMATION = 0x0800

TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
EXECUTE_PROTECTIONS = {0x10, 0x20, 0x40, 0x80}

# Memory inspection is intentionally limited to processes observed in the analysed
# TCTC execution paths. Imported profiles cannot widen this allow-list.
MEMORY_TARGET_PROCESSES = frozenset({
    "runtimebroker.exe", "explorer.exe", "chrome.exe", "csc.exe",
})

_READ_CHUNK = 1024 * 1024


@dataclass
class MemoryFinding:
    pid: int
    process_name: str
    process_path: str
    indicator: str
    title: str
    severity: str
    confidence: str
    base_address: int = 0
    region_size: int = 0
    protection: int = 0
    memory_type: int = 0
    state: int = 0
    thread_id: int | None = None
    thread_start: int | None = None
    evidence_file: str = ""
    metadata_file: str = ""
    sha256: str = ""
    capture_complete: bool = False
    captured_at: str = ""
    rationale: str = ""
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "process_path": self.process_path,
            "indicator": self.indicator,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "base_address": f"0x{self.base_address:X}" if self.base_address else "",
            "region_size": self.region_size,
            "protection": f"0x{self.protection:X}" if self.protection else "",
            "memory_type": self.memory_type,
            "state": self.state,
            "thread_id": self.thread_id,
            "thread_start": f"0x{self.thread_start:X}" if self.thread_start else "",
            "evidence_file": self.evidence_file,
            "metadata_file": self.metadata_file,
            "sha256": self.sha256,
            "capture_complete": self.capture_complete,
            "captured_at": self.captured_at,
            "rationale": self.rationale,
            "evidence": list(self.evidence),
        }


@dataclass
class ProcessMemoryResult:
    pid: int
    process_name: str
    process_path: str
    findings: list[MemoryFinding] = field(default_factory=list)
    regions_examined: int = 0
    executable_regions: int = 0
    inaccessible_reason: str = ""
    warnings: list[str] = field(default_factory=list)


class MemoryScanCancelled(Exception):
    pass


def _cancelled(cancel_event: Any) -> bool:
    return bool(cancel_event is not None and cancel_event.is_set())


def select_memory_targets(processes: list[dict[str, Any]], settings: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Return only sample-relevant processes; profiles cannot broaden the set."""
    cfg = dict(settings or {})
    configured = {str(x).strip().lower() for x in cfg.get("memory_process_include", []) if str(x).strip()}
    allowed = MEMORY_TARGET_PROCESSES.intersection(configured) if configured else MEMORY_TARGET_PROCESSES
    selected: list[dict[str, Any]] = []
    for process in processes:
        name = str(process.get("name", "")).strip().lower()
        if name not in allowed:
            continue
        # csc.exe is eligible only when the image itself is staged in the
        # sample-specific Temp\Local tree. The genuine Framework compiler is
        # not a memory target merely because its basename is csc.exe.
        if name == "csc.exe":
            path = str(process.get("path", "")).replace("/", "\\").lower()
            if "\\temp\\local\\" not in path:
                continue
        selected.append(process)
    return selected


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value or "process")[:80] or "process"


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _is_executable(protect: int) -> bool:
    base = protect & 0xFF
    return base in EXECUTE_PROTECTIONS and not (protect & PAGE_GUARD)


def _bump(stats: dict[str, Any] | None, key: str, amount: int = 1) -> None:
    if stats is not None:
        stats[key] = int(stats.get(key, 0) or 0) + amount


def _read_remote(kernel32: Any, process: Any, address: int, size: int,
                 stats: dict[str, Any] | None = None) -> bytes:
    """Perform one real ReadProcessMemory call and account for its result."""
    if size <= 0:
        return b""
    _bump(stats, "remote_read_attempts")
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(process, ctypes.c_void_p(address), buf, size, ctypes.byref(read))
    count = int(read.value or 0)
    if count:
        _bump(stats, "remote_bytes_read", count)
    if ok and count == size:
        _bump(stats, "remote_read_successes")
    elif count:
        _bump(stats, "remote_read_partial")
    else:
        _bump(stats, "remote_read_failures")
    return buf.raw[:count]


def _looks_like_mapped_pe(prefix: bytes) -> bool:
    """Return true only for a minimally valid in-memory PE header."""
    if len(prefix) < 0x100 or prefix[:2] != b"MZ":
        return False
    try:
        e_lfanew = struct.unpack_from("<I", prefix, 0x3C)[0]
        if e_lfanew < 0x40 or e_lfanew + 0x18 > len(prefix) or e_lfanew > 0x1000:
            return False
        if prefix[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return False
        machine, sections = struct.unpack_from("<HH", prefix, e_lfanew + 4)
        optional_size = struct.unpack_from("<H", prefix, e_lfanew + 20)[0]
        if machine not in {0x14C, 0x8664, 0xAA64}:
            return False
        if not (1 <= sections <= 96) or optional_size < 0x60:
            return False
        return True
    except (struct.error, ValueError):
        return False


def _private_exec_should_raise_finding(prefix: bytes, *, manual_map_enabled: bool = True) -> bool:
    """Suppress generic MEM_PRIVATE executable noise unless a PE maps cleanly."""
    return bool(manual_map_enabled and _looks_like_mapped_pe(prefix))


def _system_max_address(kernel32: Any) -> tuple[int, int]:
    class SYSTEM_INFO(ctypes.Structure):
        _fields_ = [
            ("wProcessorArchitecture", ctypes.c_ushort),
            ("wReserved", ctypes.c_ushort),
            ("dwPageSize", ctypes.c_ulong),
            ("lpMinimumApplicationAddress", ctypes.c_void_p),
            ("lpMaximumApplicationAddress", ctypes.c_void_p),
            ("dwActiveProcessorMask", ctypes.c_size_t),
            ("dwNumberOfProcessors", ctypes.c_ulong),
            ("dwProcessorType", ctypes.c_ulong),
            ("dwAllocationGranularity", ctypes.c_ulong),
            ("wProcessorLevel", ctypes.c_ushort),
            ("wProcessorRevision", ctypes.c_ushort),
        ]
    info = SYSTEM_INFO()
    kernel32.GetSystemInfo(ctypes.byref(info))
    return int(info.lpMaximumApplicationAddress or 0x7FFFFFFEFFFF), int(info.dwPageSize or 0x1000)


def _enumerate_threads(pid: int, kernel32: Any, stats: dict[str, Any] | None = None) -> list[int]:
    class THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
            ("th32ThreadID", ctypes.c_ulong), ("th32OwnerProcessID", ctypes.c_ulong),
            ("tpBasePri", ctypes.c_long), ("tpDeltaPri", ctypes.c_long),
            ("dwFlags", ctypes.c_ulong),
        ]

    kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.Thread32First.argtypes = [ctypes.c_void_p, ctypes.POINTER(THREADENTRY32)]
    kernel32.Thread32First.restype = ctypes.c_int
    kernel32.Thread32Next.argtypes = [ctypes.c_void_p, ctypes.POINTER(THREADENTRY32)]
    kernel32.Thread32Next.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int

    _bump(stats, "thread_snapshot_attempts")
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        _bump(stats, "thread_snapshot_failures")
        return []
    _bump(stats, "thread_snapshot_successes")
    tids: list[int] = []
    try:
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(entry)
        ok = kernel32.Thread32First(snap, ctypes.byref(entry))
        while ok:
            if int(entry.th32OwnerProcessID) == int(pid):
                tids.append(int(entry.th32ThreadID))
                _bump(stats, "threads_enumerated")
            ok = kernel32.Thread32Next(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return tids


def _thread_start_addresses(pid: int, kernel32: Any, stats: dict[str, Any] | None = None) -> tuple[list[tuple[int, int]], list[str]]:
    """Read thread start addresses using NtQueryInformationThread (class 9)."""
    if not hasattr(ctypes, "WinDLL"):
        return [], ["Thread start-address inspection requires Windows"]
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    query = ntdll.NtQueryInformationThread
    query.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
    query.restype = ctypes.c_long
    kernel32.OpenThread.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel32.OpenThread.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    addresses: list[tuple[int, int]] = []
    warnings: list[str] = []
    snapshot_failures_before = int((stats or {}).get("thread_snapshot_failures", 0))
    open_failures_before = int((stats or {}).get("thread_open_failures", 0))
    query_failures_before = int((stats or {}).get("thread_start_query_failures", 0))
    tids = _enumerate_threads(pid, kernel32, stats)
    for tid in tids:
        _bump(stats, "thread_open_attempts")
        hthread = kernel32.OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, False, tid)
        if not hthread:
            _bump(stats, "thread_open_failures")
            continue
        try:
            start = ctypes.c_void_p()
            _bump(stats, "thread_start_query_attempts")
            status = query(hthread, 9, ctypes.byref(start), ctypes.sizeof(start), None)
            if status >= 0 and start.value:
                addresses.append((tid, int(start.value)))
                _bump(stats, "thread_start_query_successes")
            else:
                _bump(stats, "thread_start_query_failures")
        finally:
            kernel32.CloseHandle(hthread)
    if stats is not None:
        if int(stats.get("thread_snapshot_failures", 0)) > snapshot_failures_before:
            warnings.append("Thread snapshot could not be collected; thread-start correlation was unavailable.")
        open_failed = int(stats.get("thread_open_failures", 0)) - open_failures_before
        if open_failed:
            warnings.append(f"Could not open {open_failed} enumerated thread handle(s) for start-address inspection.")
        query_failed = int(stats.get("thread_start_query_failures", 0)) - query_failures_before
        if query_failed:
            warnings.append(f"NtQueryInformationThread failed for {query_failed} thread(s); their start addresses were not verified.")
    return addresses, warnings


def _capture_region(kernel32: Any, process: Any, pid: int, process_name: str,
                    base: int, size: int, evidence_root: Path, cancel_event: Any = None,
                    stats: dict[str, Any] | None = None) -> tuple[str, str, bool, str]:
    """Stream a suspicious region to disk without allocating it all in memory."""
    evidence_root.mkdir(parents=True, exist_ok=True)
    filename = f"{_safe_name(process_name)}_{pid}_{base:016X}_{size:X}_{_utc_stamp()}_{time.time_ns()}.mem"
    destination = evidence_root / filename
    digest = hashlib.sha256()
    total = 0
    created = False
    try:
        with destination.open("xb") as out:
            created = True
            offset = 0
            while offset < size:
                if _cancelled(cancel_event):
                    raise MemoryScanCancelled("Memory capture cancelled by user")
                requested = min(_READ_CHUNK, size - offset)
                data = _read_remote(kernel32, process, base + offset, requested, stats)
                if not data:
                    raise OSError(f"ReadProcessMemory stopped at offset 0x{offset:X}")
                out.write(data)
                digest.update(data)
                total += len(data)
                offset += len(data)
                if len(data) < requested:
                    raise OSError(f"Partial region read at offset 0x{offset:X}")
        return str(destination), digest.hexdigest(), True, f"Captured {total:,} bytes"
    except MemoryScanCancelled:
        if created:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    except Exception as exc:
        if created:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
        return "", "", False, f"Region capture incomplete: {type(exc).__name__}: {exc}"



def _query_private_image_pages(kernel32: Any, process: Any, base: int, size: int, page_size: int,
                               stats: dict[str, Any] | None = None) -> list[int]:
    """Return executable MEM_IMAGE pages that are resident but no longer shared.

    QueryWorkingSetEx's Shared bit is an indicator of copy-on-write/private
    residency, not proof of malicious patching. It is deliberately reported
    with low confidence and must be correlated with other evidence.
    """
    class WORKING_SET_EX_INFORMATION(ctypes.Structure):
        _fields_ = [("VirtualAddress", ctypes.c_void_p), ("VirtualAttributes", ctypes.c_size_t)]

    query = getattr(kernel32, "QueryWorkingSetEx", None)
    if query is None and hasattr(ctypes, "WinDLL"):
        try:
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            query = psapi.QueryWorkingSetEx
        except Exception:
            _bump(stats, "working_set_api_unavailable")
            return []
    if query is None:
        _bump(stats, "working_set_api_unavailable")
        return []
    query.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    query.restype = ctypes.c_int
    private_pages: list[int] = []
    batch_size = 512
    address = base
    end = base + size
    while address < end:
        count = min(batch_size, (end - address + page_size - 1) // page_size)
        _bump(stats, "working_set_query_attempts")
        _bump(stats, "working_set_pages_queried", count)
        batch = (WORKING_SET_EX_INFORMATION * count)()
        for index in range(count):
            batch[index].VirtualAddress = ctypes.c_void_p(address + index * page_size)
        if query(process, ctypes.byref(batch), ctypes.sizeof(batch)):
            _bump(stats, "working_set_query_successes")
            for index in range(count):
                attributes = int(batch[index].VirtualAttributes)
                valid = attributes & 1
                shared = (attributes >> 15) & 1
                if valid:
                    _bump(stats, "working_set_valid_pages")
                if valid and not shared:
                    private_pages.append(address + index * page_size)
                    _bump(stats, "private_image_pages")
        else:
            _bump(stats, "working_set_query_failures")
        address += count * page_size
    return private_pages

def _image_modules(pid: int, kernel32: Any, stats: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    class MODULEENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_ulong), ("th32ModuleID", ctypes.c_ulong),
            ("th32ProcessID", ctypes.c_ulong), ("GlblcntUsage", ctypes.c_ulong),
            ("ProccntUsage", ctypes.c_ulong), ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
            ("modBaseSize", ctypes.c_ulong), ("hModule", ctypes.c_void_p),
            ("szModule", ctypes.c_wchar * 256), ("szExePath", ctypes.c_wchar * 260),
        ]
    kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.Module32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32FirstW.restype = ctypes.c_int
    kernel32.Module32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32NextW.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    _bump(stats, "module_snapshot_attempts")
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if not snap or snap == INVALID_HANDLE_VALUE:
        _bump(stats, "module_snapshot_failures")
        return []
    _bump(stats, "module_snapshot_successes")
    modules: list[dict[str, Any]] = []
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = kernel32.Module32FirstW(snap, ctypes.byref(entry))
        while ok:
            modules.append({"name": str(entry.szModule), "path": str(entry.szExePath),
                            # modBaseAddr is a remote-process virtual address, not a
                            # pointer that may safely be dereferenced in this process.
                            "base": int(ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0),
                            "size": int(entry.modBaseSize)})
            _bump(stats, "modules_enumerated")
            ok = kernel32.Module32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return modules


def _windows_path_key(value: str) -> str:
    """Normalize common Win32 path spellings for same-image comparisons."""
    import ntpath
    value = str(value or "").replace("/", "\\")
    if value.startswith("\\\\?\\"):
        value = value[4:]
    return ntpath.normcase(ntpath.normpath(value)) if value else ""


def _inspect_process_image_identity(kernel32: Any, process: Any, pid: int,
                                    process_name: str, process_path: str,
                                    stats: dict[str, Any] | None = None) -> list[MemoryFinding]:
    """Report cautious hints when the mapped main image and its disk path disagree.

    This is not a definitive Process Ghosting detector. It uses module snapshots
    and file visibility only; image-section telemetry is required for proof.
    """
    modules = _image_modules(pid, kernel32, stats)
    main_module = next((m for m in modules if str(m.get("path", "")).lower().endswith(".exe")), None)
    if not main_module:
        return []
    module_path = str(main_module.get("path", ""))
    module_base = int(main_module.get("base", 0) or 0)
    if not module_path or not module_base:
        return []
    image_header = _read_remote(kernel32, process, module_base, 4096, stats)
    valid_image = _looks_like_mapped_pe(image_header)
    if not valid_image:
        return []

    same_path = bool(process_path and _windows_path_key(process_path) == _windows_path_key(module_path))
    module_file_missing = not Path(module_path).is_file()
    process_file_missing = bool(process_path and not Path(process_path).is_file())
    if same_path and not module_file_missing and not process_file_missing:
        return []
    if not same_path:
        title = "Process image path differs from mapped main module"
        rationale = (
            "The process inventory path and the main executable module path do not normalize to the same location. "
            "This can be caused by path aliases or legitimate loaders; it is a low-confidence image-identity anomaly, not proof of Process Ghosting."
        )
    else:
        title = "Mapped process image is no longer present at its recorded path"
        rationale = (
            "A valid PE image remains mapped, but the recorded executable path is not currently visible as a file. "
            "Self-deleting applications and update/installer workflows can do this legitimately; Process Ghosting cannot be confirmed from this snapshot alone."
        )
    return [MemoryFinding(
        pid=pid, process_name=process_name, process_path=process_path,
        indicator="process_image_identity_mismatch", title=title,
        severity="Low", confidence="Low", base_address=module_base,
        region_size=int(main_module.get("size", 0) or 0), memory_type=MEM_IMAGE,
        state=MEM_COMMIT, rationale=rationale,
        evidence=[f"PID: {pid}", f"Process inventory path: {process_path or 'Unavailable'}",
                  f"Mapped module path: {module_path}", f"Mapped base: 0x{module_base:X}",
                  f"Valid in-memory PE header: {valid_image}",
                  f"Process path exists: {not process_file_missing}",
                  f"Module path exists: {not module_file_missing}",
                  "Detection source: Toolhelp module snapshot + read-only in-memory PE header check"],
    )]


def _pe_export_file_offset(path: str, wanted: str) -> tuple[int, bytes] | None:
    """Return (RVA, first file-backed bytes) for one PE export, without loading it."""
    try:
        data = Path(path).read_bytes()
        if len(data) < 0x100 or data[:2] != b"MZ":
            return None
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            return None
        sections_count = struct.unpack_from("<H", data, pe + 6)[0]
        opt_size = struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        data_dir = opt + (112 if magic == 0x20B else 96)
        export_rva, export_size = struct.unpack_from("<II", data, data_dir)
        if not export_rva or not export_size:
            return None
        sections_off = opt + opt_size
        sections: list[tuple[int, int, int, int]] = []
        for i in range(sections_count):
            off = sections_off + i * 40
            virtual_size, virtual_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
            sections.append((virtual_addr, max(virtual_size, raw_size), raw_ptr, raw_size))
        def rva_to_off(rva: int) -> int | None:
            for va, span, raw, raw_size in sections:
                if va <= rva < va + span and rva - va < raw_size:
                    return raw + (rva - va)
            return None
        exp_off = rva_to_off(export_rva)
        if exp_off is None or exp_off + 40 > len(data):
            return None
        number_functions = struct.unpack_from("<I", data, exp_off + 20)[0]
        number_names = struct.unpack_from("<I", data, exp_off + 24)[0]
        functions_rva = struct.unpack_from("<I", data, exp_off + 28)[0]
        names_rva = struct.unpack_from("<I", data, exp_off + 32)[0]
        ordinals_rva = struct.unpack_from("<I", data, exp_off + 36)[0]
        functions_off, names_off, ordinals_off = map(rva_to_off, (functions_rva, names_rva, ordinals_rva))
        if None in (functions_off, names_off, ordinals_off):
            return None
        for index in range(number_names):
            name_rva = struct.unpack_from("<I", data, names_off + index * 4)[0]
            name_off = rva_to_off(name_rva)
            if name_off is None:
                continue
            end = data.find(b"\0", name_off, min(name_off + 256, len(data)))
            if end < 0 or data[name_off:end].decode("ascii", "ignore") != wanted:
                continue
            ordinal = struct.unpack_from("<H", data, ordinals_off + index * 2)[0]
            if ordinal >= number_functions:
                return None
            func_rva = struct.unpack_from("<I", data, functions_off + ordinal * 4)[0]
            func_off = rva_to_off(func_rva)
            if func_off is None:
                return None
            return func_rva, data[func_off:func_off + 16]
    except (OSError, ValueError, struct.error, IndexError):
        return None
    return None


def _inspect_amsi_exports(kernel32: Any, process: Any, pid: int,
                          stats: dict[str, Any] | None = None) -> list[MemoryFinding]:
    findings: list[MemoryFinding] = []
    modules = _image_modules(pid, kernel32, stats)
    amsi = next((m for m in modules if str(m.get("name", "")).lower() == "amsi.dll"), None)
    if not amsi or not amsi.get("path") or not amsi.get("base"):
        _bump(stats, "amsi_module_not_loaded")
        return findings
    _bump(stats, "amsi_module_found")
    for export_name in ("AmsiScanBuffer", "AmsiScanString"):
        exported = _pe_export_file_offset(str(amsi["path"]), export_name)
        if not exported:
            continue
        rva, disk_prefix = exported
        _bump(stats, "amsi_exports_checked")
        remote = _read_remote(kernel32, process, int(amsi["base"]) + rva, 16, stats)
        if len(remote) < 3:
            continue
        if remote[:3] in (b"\x31\xC0\xC3", b"\x33\xC0\xC3"):
            findings.append(MemoryFinding(
                pid=pid, process_name="", process_path="", indicator="amsi_export_stub",
                title=f"AMSI export appears patched: {export_name}", severity="High", confidence="Medium",
                base_address=int(amsi["base"]) + rva, region_size=len(remote),
                rationale="The live export begins with an xor-eax/ret stub matching the AMSI bypass pattern recovered from the investigated sample. This is strong evidence of tampering, but another security product or test tool may also patch AMSI.",
                evidence=[f"Module: {amsi['path']}", f"Export: {export_name}",
                          f"Live bytes: {remote[:8].hex(' ')}", f"On-disk bytes: {disk_prefix[:8].hex(' ')}"],
            ))
    return findings


def scan_process_memory(processes: list[dict[str, Any]], settings: dict[str, Any] | None = None,
                        evidence_dir: str | os.PathLike[str] | None = None,
                        cancel_event: Any = None,
                        progress: Callable[[dict[str, Any]], None] | None = None,
                        stats_out: dict[str, Any] | None = None) -> tuple[list[MemoryFinding], list[str]]:
    """Inspect accessible processes read-only and return findings + coverage gaps."""
    cfg = dict(settings or {})
    scan_started = time.monotonic()
    scope_note = (
        "Actual read-only API path: OpenProcess with query/read-only rights; VirtualQueryEx walks the target process virtual address map; "
        "ReadProcessMemory reads the first up-to-4096 bytes of each eligible private executable region plus selected module/AMSI headers "
        "and any explicitly captured suspicious region; QueryWorkingSetEx checks resident executable image pages; Toolhelp snapshots "
        "enumerate threads/modules; NtQueryInformationThread reads thread start addresses. VirtualQueryEx enumerates region metadata, "
        "not region contents. This is not a byte-for-byte scan of all memory or all processes."
    )
    stats: dict[str, Any] = {
        "method": "OpenProcess + VirtualQueryEx + targeted ReadProcessMemory + Toolhelp thread/module snapshots + QueryWorkingSetEx",
        "read_only_access_mask": "PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ",
        "enabled_checks": {
            "private_executable_regions": bool(cfg.get("memory_private_exec", True)),
            "manual_map_pe_headers": bool(cfg.get("memory_manual_map", True)),
            "thread_start_correlation": bool(cfg.get("memory_thread_start", True)),
            "working_set_image_integrity": bool(cfg.get("memory_integrity", True)),
            "mapped_image_identity": bool(cfg.get("memory_image_identity", True)),
            "suspicious_region_capture": bool(cfg.get("memory_capture_regions", True)),
        },
        "processes_selected": 0, "processes_opened": 0, "process_open_failures": 0, "processes_skipped": 0,
        "virtual_query_calls": 0, "virtual_query_successes": 0, "virtual_query_failures": 0, "virtual_query_end_of_range": 0,
        "regions_examined": 0, "virtual_region_span_bytes": 0,
        "committed_regions": 0, "executable_regions": 0,
        "private_executable_regions": 0, "image_executable_regions": 0,
        "manual_map_probe_calls": 0, "manual_map_probe_bytes": 0,
        "remote_read_attempts": 0, "remote_read_successes": 0, "remote_read_partial": 0,
        "remote_read_failures": 0, "remote_bytes_read": 0,
        "evidence_captures_attempted": 0, "evidence_captures_completed": 0,
        "evidence_capture_failures": 0, "evidence_capture_bytes": 0,
        "thread_scan_eligible_processes": 0, "thread_scan_skipped_no_private_exec": 0,
        "thread_snapshot_attempts": 0, "thread_snapshot_successes": 0, "thread_snapshot_failures": 0,
        "threads_enumerated": 0, "thread_open_attempts": 0, "thread_open_failures": 0,
        "thread_start_query_attempts": 0, "thread_start_query_successes": 0, "thread_start_query_failures": 0,
        "module_snapshot_attempts": 0, "module_snapshot_successes": 0, "module_snapshot_failures": 0,
        "modules_enumerated": 0, "working_set_query_attempts": 0, "working_set_query_successes": 0,
        "working_set_query_failures": 0, "working_set_api_unavailable": 0,
        "working_set_pages_queried": 0, "working_set_valid_pages": 0, "private_image_pages": 0,
        "amsi_module_found": 0, "amsi_module_not_loaded": 0, "amsi_exports_checked": 0,
        "process_details": [],
    }
    if not IS_WINDOWS:
        stats["status"] = "unsupported"
        stats["inspection_depth"] = "windows_apis_unavailable"
        stats["scope_note"] = scope_note
        if stats_out is not None:
            stats_out.update(stats)
        return [], ["Live process memory inspection is available only on Windows."]
    if not hasattr(ctypes, "WinDLL"):
        stats["status"] = "unsupported"
        stats["inspection_depth"] = "windows_apis_unavailable"
        stats["scope_note"] = scope_note
        if stats_out is not None:
            stats_out.update(stats)
        return [], ["Windows API bindings are unavailable in this Python runtime."]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel32.ReadProcessMemory.restype = ctypes.c_int

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", ctypes.c_ulong),
            ("PartitionId", ctypes.c_ushort),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.c_ulong),
            ("Protect", ctypes.c_ulong),
            ("Type", ctypes.c_ulong),
        ]

    max_address, page_size = _system_max_address(kernel32)
    kernel32.IsWow64Process.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    kernel32.IsWow64Process.restype = ctypes.c_int
    evidence_root = Path(evidence_dir) if evidence_dir else Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TCTC Guardian" / "evidence" / "memory"
    all_findings: list[MemoryFinding] = []
    coverage: list[str] = []
    capture_regions = bool(cfg.get("memory_capture_regions", True))
    target_processes = select_memory_targets(processes, cfg)
    if not target_processes:
        stats["status"] = "no_targets"
        stats["inspection_depth"] = "no_eligible_target_process"
        stats["duration_seconds"] = round(time.monotonic() - scan_started, 3)
        stats["scope_note"] = scope_note
        if stats_out is not None:
            stats_out.update(stats)
        return [], ["No eligible TCTC-target process was found in the memory allow-list (RuntimeBroker.exe, explorer.exe, chrome.exe, and csc.exe only from Temp\\Local). Other processes were deliberately not inspected."]

    stats["processes_selected"] = len(target_processes)
    process_total = len(target_processes)
    for process_index, proc in enumerate(target_processes, start=1):
        if _cancelled(cancel_event):
            raise MemoryScanCancelled("Memory investigation cancelled")
        pid = int(proc.get("pid", 0) or 0)
        name = str(proc.get("name", "Unknown"))
        path = str(proc.get("path", ""))
        if progress:
            progress({"type": "memory_process_start", "pid": pid, "process": name, "path": path,
                      "process_index": process_index, "process_total": process_total})
        if pid <= 4 or pid == os.getpid():
            _bump(stats, "processes_skipped")
            stats["process_details"].append({"pid": pid, "process": name, "process_path": path,
                                             "findings": 0, "open_succeeded": False,
                                             "skip_reason": "System/current process safety exclusion"})
            if progress:
                progress({"type": "memory_process_done", "pid": pid, "process": name, "findings": 0,
                          "skipped": True, "skip_reason": "System/current process safety exclusion",
                          "process_index": process_index, "process_total": process_total})
            continue
        proc_stats_before = {k: v for k, v in stats.items() if isinstance(v, int)}
        working_set_failures_before = int(stats.get("working_set_query_failures", 0))
        working_set_unavailable_before = int(stats.get("working_set_api_unavailable", 0))
        read_failures_before = int(stats.get("remote_read_failures", 0))
        read_partial_before = int(stats.get("remote_read_partial", 0))
        module_failures_before = int(stats.get("module_snapshot_failures", 0))
        handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
        if not handle:
            _bump(stats, "process_open_failures")
            err = ctypes.get_last_error()
            coverage.append(f"{name} (PID {pid}): process memory is not readable (Windows error {err}).")
            per_process = {k: int(stats.get(k, 0) or 0) - proc_stats_before.get(k, 0) for k in stats if isinstance(stats.get(k), int)}
            per_process.update({"pid": pid, "process": name, "process_path": path, "findings": 0,
                                "open_succeeded": False, "skip_reason": f"OpenProcess denied (Windows error {err})"})
            stats["process_details"].append(per_process)
            if progress:
                progress({"type": "memory_process_done", "pid": pid, "process": name, "findings": 0,
                          "stats": per_process, "skipped": True, "process_index": process_index, "process_total": process_total})
            continue
        _bump(stats, "processes_opened")
        proc_findings: list[MemoryFinding] = []
        executable_private: list[tuple[int, int, int]] = []
        executable_findings: dict[int, MemoryFinding] = {}
        try:
            process_max_address = max_address
            if ctypes.sizeof(ctypes.c_void_p) == 8:
                is_wow64 = ctypes.c_int(0)
                if kernel32.IsWow64Process(handle, ctypes.byref(is_wow64)) and is_wow64.value:
                    process_max_address = min(process_max_address, 0x7FFEFFFF)
            address = 0x10000
            regions = 0
            exec_regions = 0
            query_successes_before = int(stats.get("virtual_query_successes", 0))
            while address < process_max_address:
                if _cancelled(cancel_event):
                    raise MemoryScanCancelled("Memory investigation cancelled")
                mbi = MEMORY_BASIC_INFORMATION()
                _bump(stats, "virtual_query_calls")
                returned = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
                if not returned:
                    error = ctypes.get_last_error()
                    if error in (0, 87):  # ERROR_INVALID_PARAMETER at the end of the user address range is expected.
                        _bump(stats, "virtual_query_end_of_range")
                    else:
                        _bump(stats, "virtual_query_failures")
                        coverage.append(f"{name} (PID {pid}): VirtualQueryEx stopped at 0x{address:X} (Windows error {error}); remaining address space was not inspected.")
                    break
                _bump(stats, "virtual_query_successes")
                _bump(stats, "regions_examined")
                base = int(mbi.BaseAddress or 0)
                size = int(mbi.RegionSize or 0)
                if size <= 0:
                    address += page_size
                    continue
                regions += 1
                _bump(stats, "virtual_region_span_bytes", size)
                if int(mbi.State) == MEM_COMMIT:
                    _bump(stats, "committed_regions")
                if mbi.State == MEM_COMMIT and _is_executable(int(mbi.Protect)):
                    exec_regions += 1
                    _bump(stats, "executable_regions")
                    if int(mbi.Type) == MEM_IMAGE:
                        _bump(stats, "image_executable_regions")
                    if int(mbi.Type) == MEM_IMAGE and cfg.get("memory_integrity", True):
                        private_pages = _query_private_image_pages(kernel32, handle, base, size, page_size, stats)
                        if private_pages:
                            proc_findings.append(MemoryFinding(
                                pid, name, path, "image_page_cow",
                                "Executable image contains private copy-on-write pages", "Low", "Low",
                                base, size, int(mbi.Protect), int(mbi.Type), int(mbi.State),
                                rationale="QueryWorkingSetEx reports one or more resident image pages as private rather than shared. This can result from legitimate hotpatching, security software, instrumentation or normal loader behavior; it is not proof of malicious modification.",
                                evidence=[f"PID: {pid}", f"Module image region: 0x{base:X}",
                                          f"Region size: {size:,} bytes", f"Private resident executable pages: {len(private_pages)}",
                                          "Sample page addresses: " + ", ".join(f"0x{x:X}" for x in private_pages[:12]),
                                          "Detection source: QueryWorkingSetEx (Shared bit)"]
                            ))
                    if int(mbi.Type) == MEM_PRIVATE and (cfg.get("memory_private_exec", True) or cfg.get("memory_manual_map", True)):
                        executable_private.append((base, size, int(mbi.Protect)))
                        _bump(stats, "private_executable_regions")
                        if cfg.get("memory_manual_map", True):
                            probe_size = min(4096, size)
                            _bump(stats, "manual_map_probe_calls")
                            prefix = _read_remote(kernel32, handle, base, probe_size, stats)
                            _bump(stats, "manual_map_probe_bytes", len(prefix))
                        else:
                            prefix = b""
                        is_manual = _private_exec_should_raise_finding(
                            prefix, manual_map_enabled=bool(cfg.get("memory_manual_map", True))
                        )
                        # A raw executable MEM_PRIVATE region is telemetry, not an
                        # alert. It remains eligible for later thread-start correlation.
                        # Only a minimally valid in-memory PE creates a standalone finding.
                        if is_manual:
                            finding = MemoryFinding(
                                pid, name, path, "manual_mapped_pe",
                                "PE image found in private executable memory", "High", "Medium",
                                base, size, int(mbi.Protect), int(mbi.Type), int(mbi.State),
                                rationale="A minimally valid PE header was found inside a MEM_PRIVATE executable region. This is consistent with manual mapping; correlate with thread starts, process lineage and network/file evidence.",
                                evidence=[f"PID: {pid}", f"Process: {name}", f"Image: {path or 'Unavailable'}",
                                          f"Base: 0x{base:X}", f"Size: {size:,} bytes",
                                          f"Protection: 0x{int(mbi.Protect):X}", "Type: MEM_PRIVATE",
                                          "Detection source: VirtualQueryEx + ReadProcessMemory"]
                            )
                            proc_findings.append(finding)
                            executable_findings[base] = finding
                address = max(address + page_size, base + size)
                if progress and regions % 512 == 0:
                    progress({"type": "memory_progress", "pid": pid, "process": name, "regions": regions, "findings": len(proc_findings)})
            query_successes_for_process = int(stats.get("virtual_query_successes", 0)) - query_successes_before
            if regions == 0 or query_successes_for_process == 0:
                coverage.append(
                    f"{name} (PID {pid}): no virtual-memory regions were returned by VirtualQueryEx; "
                    "the process memory map was not inspected."
                )
            # Correlate thread entry points with executable private regions.
            if cfg.get("memory_thread_start", True) and executable_private:
                _bump(stats, "thread_scan_eligible_processes")
                starts, thread_warnings = _thread_start_addresses(pid, kernel32, stats)
                for warning in thread_warnings:
                    coverage.append(f"{name} (PID {pid}): {warning}")
                for tid, start in starts:
                    match = next((r for r in executable_private if r[0] <= start < r[0] + r[1]), None)
                    if match:
                        base, size, protect = match
                        correlated = next((f for f in proc_findings if f.base_address == base), None)
                        if correlated:
                            correlated.thread_id = tid
                            correlated.thread_start = start
                            correlated.confidence = "High" if correlated.indicator == "manual_mapped_pe" else "Medium"
                            correlated.severity = "High" if correlated.indicator == "manual_mapped_pe" else "Medium"
                            correlated.evidence.extend([f"Thread ID: {tid}", f"Thread start: 0x{start:X}",
                                                        "A thread entry point falls inside this private executable region."])
                        else:
                            thread_finding = MemoryFinding(
                                pid, name, path, "thread_start_in_private_exec",
                                "Thread starts inside private executable memory", "High", "Medium",
                                base, size, protect, MEM_PRIVATE, MEM_COMMIT, tid, start,
                                rationale="The thread start address falls inside a private executable region. This is a useful injection indicator, but legitimate runtime/JIT activity must still be considered.",
                                evidence=[f"PID: {pid}", f"Thread ID: {tid}", f"Thread start: 0x{start:X}", f"Region base: 0x{base:X}", f"Region size: {size:,} bytes"]
                            )
                            proc_findings.append(thread_finding)
                            executable_findings[base] = thread_finding
            elif cfg.get("memory_thread_start", True):
                _bump(stats, "thread_scan_skipped_no_private_exec")
            # Preserve only regions with a stronger, actionable signal. Capturing
            # every JIT/browser executable allocation can produce huge volumes of
            # low-value and privacy-sensitive data.
            if capture_regions:
                for base, finding in executable_findings.items():
                    if finding.indicator != "manual_mapped_pe" and finding.thread_start is None:
                        continue
                    region = next((r for r in executable_private if r[0] == base), None)
                    if not region:
                        continue
                    _, region_size, _ = region
                    _bump(stats, "evidence_captures_attempted")
                    captured, digest, complete, note = _capture_region(
                        kernel32, handle, pid, name, base, region_size, evidence_root, cancel_event, stats
                    )
                    if complete:
                        _bump(stats, "evidence_captures_completed")
                        _bump(stats, "evidence_capture_bytes", region_size)
                    else:
                        _bump(stats, "evidence_capture_failures")
                    finding.evidence_file = captured
                    finding.sha256 = digest
                    finding.capture_complete = complete
                    finding.captured_at = _utc_stamp() if complete else ""
                    finding.evidence.append(note)
                    if complete:
                        sidecar = Path(captured).with_suffix(".json")
                        metadata = {
                            "schema_version": 1,
                            "captured_at_utc": finding.captured_at,
                            "pid": finding.pid,
                            "process_name": finding.process_name,
                            "process_path": finding.process_path,
                            "indicator": finding.indicator,
                            "title": finding.title,
                            "severity": finding.severity,
                            "confidence": finding.confidence,
                            "base_address": f"0x{finding.base_address:X}",
                            "region_size": finding.region_size,
                            "protection": f"0x{finding.protection:X}",
                            "memory_type": finding.memory_type,
                            "state": finding.state,
                            "thread_id": finding.thread_id,
                            "thread_start": f"0x{finding.thread_start:X}" if finding.thread_start else "",
                            "sha256": digest,
                            "rationale": finding.rationale,
                            "evidence": list(finding.evidence),
                        }
                        try:
                            with sidecar.open("x", encoding="utf-8") as metadata_stream:
                                json.dump(metadata, metadata_stream, indent=2, ensure_ascii=False)
                            finding.metadata_file = str(sidecar)
                            finding.evidence.append(f"Metadata: {sidecar}")
                            finding.evidence.append(f"Captured at (UTC): {finding.captured_at}")
                            finding.evidence.append(f"SHA-256: {digest}")
                        except OSError as exc:
                            finding.capture_complete = False
                            finding.evidence.append(f"Metadata sidecar could not be saved: {type(exc).__name__}: {exc}")
            # Compare process inventory identity with the mapped main image. This is
            # only a low-confidence Process Ghosting hint; it is never auto-remediated.
            if cfg.get("memory_image_identity", True):
                try:
                    for f in _inspect_process_image_identity(kernel32, handle, pid, name, path, stats):
                        proc_findings.append(f)
                except Exception as exc:
                    coverage.append(f"{name} (PID {pid}): mapped image identity check unavailable: {type(exc).__name__}: {exc}")
            # Sample-specific AMSI patch check. It reads known exports only.
            if cfg.get("memory_integrity", True):
                try:
                    for f in _inspect_amsi_exports(kernel32, handle, pid, stats):
                        f.process_name = name
                        f.process_path = path
                        proc_findings.append(f)
                except Exception as exc:
                    coverage.append(f"{name} (PID {pid}): AMSI export inspection unavailable: {type(exc).__name__}: {exc}")
        except MemoryScanCancelled:
            raise
        except Exception as exc:
            coverage.append(f"{name} (PID {pid}): memory inspection error: {type(exc).__name__}: {exc}")
        finally:
            kernel32.CloseHandle(handle)
        working_set_failures = int(stats.get("working_set_query_failures", 0)) - working_set_failures_before
        if working_set_failures:
            coverage.append(f"{name} (PID {pid}): QueryWorkingSetEx failed for {working_set_failures} batch(es); copy-on-write page checks were incomplete.")
        working_set_unavailable = int(stats.get("working_set_api_unavailable", 0)) - working_set_unavailable_before
        if working_set_unavailable:
            coverage.append(f"{name} (PID {pid}): QueryWorkingSetEx is unavailable; copy-on-write page checks were skipped.")
        read_failures = int(stats.get("remote_read_failures", 0)) - read_failures_before
        read_partial = int(stats.get("remote_read_partial", 0)) - read_partial_before
        if read_failures or read_partial:
            coverage.append(f"{name} (PID {pid}): ReadProcessMemory had {read_failures} failed and {read_partial} partial read(s); affected bytes were not fully inspected.")
        module_failures = int(stats.get("module_snapshot_failures", 0)) - module_failures_before
        if module_failures:
            coverage.append(f"{name} (PID {pid}): Toolhelp module snapshot failed; mapped-image identity / AMSI module checks may be incomplete.")
        numeric_after = {k: v for k, v in stats.items() if isinstance(v, int)}
        per_process = {k: numeric_after.get(k, 0) - proc_stats_before.get(k, 0) for k in numeric_after}
        per_process.update({"pid": pid, "process": name, "process_path": path, "findings": len(proc_findings), "open_succeeded": True})
        stats["process_details"].append(per_process)
        all_findings.extend(proc_findings)
        if progress:
            progress({"type": "memory_process_done", "pid": pid, "process": name, "findings": len(proc_findings),
                      "stats": per_process, "process_index": process_index, "process_total": process_total})

    stats["status"] = "read_with_gaps" if coverage else "read"
    stats["finding_count"] = len(all_findings)
    stats["duration_seconds"] = round(time.monotonic() - scan_started, 3)
    stats["coverage_gap_count"] = len(coverage)
    if stats["regions_examined"] <= 0:
        stats["inspection_depth"] = "no_memory_regions_enumerated"
    elif stats["remote_bytes_read"] > 0:
        stats["inspection_depth"] = "memory_map_enumerated_and_targeted_bytes_read"
    elif stats["remote_read_attempts"] > 0:
        stats["inspection_depth"] = "memory_map_enumerated_but_targeted_reads_failed_or_were_partial"
    else:
        stats["inspection_depth"] = "memory_map_metadata_only_no_targeted_byte_reads"
    stats["scope_note"] = scope_note
    if stats_out is not None:
        stats_out.update(stats)
    if progress:
        progress({"type": "memory_scan_summary", "stats": {k: v for k, v in stats.items() if k != "process_details"},
                  "process_details": list(stats["process_details"])})
    return all_findings, coverage


def terminate_process_after_evidence(pid: int, expected_image_path: str, evidence_file: str, *, expected_sha256: str = "", user_confirmed: bool = False) -> tuple[bool, str]:
    """Stop a confirmed compromised process only after evidence was captured.

    This terminates the whole process; Windows does not provide a universally
    safe way to stop one arbitrary injected region while leaving the process
    in a consistent state. The action is manual-confirmation only.
    """
    if not user_confirmed:
        return False, "Explicit user confirmation is required."
    if not IS_WINDOWS or not hasattr(ctypes, "WinDLL"):
        return False, "Process containment is available only on Windows."
    if int(pid) <= 4 or int(pid) == os.getpid():
        return False, "Refusing to terminate a system or current process."
    if not evidence_file or not Path(evidence_file).is_file():
        return False, "Refusing containment because the suspicious memory evidence file is missing."
    if not expected_sha256:
        return False, "Refusing containment because the captured memory evidence hash is missing."
    try:
        actual_sha256 = hashlib.sha256()
        with Path(evidence_file).open("rb") as evidence_stream:
            for chunk in iter(lambda: evidence_stream.read(_READ_CHUNK), b""):
                actual_sha256.update(chunk)
        if actual_sha256.hexdigest().lower() != expected_sha256.lower():
            return False, "Refusing containment because the captured memory evidence hash changed after inspection."
    except OSError as exc:
        return False, f"Could not verify memory evidence before containment: {exc}"
    critical_names = {"csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "smss.exe", "system", "registry"}
    if Path(expected_image_path or "").name.lower() in critical_names:
        return False, "Refusing to terminate a Windows-critical process."
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PROCESS_TERMINATE = 0x0001
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong)]
    kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int
    kernel32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    kernel32.TerminateProcess.restype = ctypes.c_int
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    kernel32.WaitForSingleObject.restype = ctypes.c_ulong
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        return False, f"OpenProcess failed with Windows error {ctypes.get_last_error()}"
    try:
        size = ctypes.c_ulong(32768)
        actual = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(handle, 0, actual, ctypes.byref(size)):
            return False, f"Could not verify the process image path (Windows error {ctypes.get_last_error()})."
        expected = os.path.normcase(os.path.abspath(expected_image_path or ""))
        observed = os.path.normcase(os.path.abspath(actual.value))
        if not expected or expected != observed:
            return False, "The PID no longer maps to the image path recorded in the evidence. Refusing action to avoid PID-reuse mistakes."
        if not kernel32.TerminateProcess(handle, 0xD15):
            return False, f"TerminateProcess failed with Windows error {ctypes.get_last_error()}"
        wait_result = kernel32.WaitForSingleObject(handle, 5000)
        if wait_result == 0x102:
            return True, f"Termination was requested for PID {pid}; Windows did not signal process exit within five seconds. Verify the process state before continuing."
        return True, f"Process PID {pid} exited after its memory evidence had been preserved. Restart the affected application or Windows component only from a trusted source."
    finally:
        kernel32.CloseHandle(handle)


def create_full_process_dump(pid: int, output_path: str | os.PathLike[str], *,
                             expected_image_path: str = "", user_consented: bool = False) -> tuple[bool, str]:
    """Create an optional full-memory minidump; explicit per-action consent is mandatory."""
    if not user_consented:
        return False, "A full process dump requires explicit user consent for this process."
    if not IS_WINDOWS or not hasattr(ctypes, "WinDLL"):
        return False, "Full process dumps are available only on Windows."
    if int(pid) <= 4 or int(pid) == os.getpid():
        return False, "System and current-process dumps are not supported by this action."
    if not expected_image_path:
        return False, "The selected process image path is required to protect against PID reuse."
    if Path(expected_image_path).name.lower() in {"csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "smss.exe", "system", "registry"}:
        return False, "Full dumps of Windows-critical processes are blocked by this tool."
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong)]
    kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, int(pid))
    if not process:
        return False, f"OpenProcess failed with Windows error {ctypes.get_last_error()}"
    target = Path(output_path)
    created = False
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        dbghelp = ctypes.WinDLL("Dbghelp", use_last_error=True)
        dbghelp.MiniDumpWriteDump.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        dbghelp.MiniDumpWriteDump.restype = ctypes.c_int
        size = ctypes.c_ulong(32768)
        actual = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(process, 0, actual, ctypes.byref(size)):
            return False, f"Could not verify process image path (Windows error {ctypes.get_last_error()})."
        if os.path.normcase(os.path.abspath(actual.value)) != os.path.normcase(os.path.abspath(expected_image_path)):
            return False, "The PID no longer maps to the selected image path. Refusing to dump a different process."
        with target.open("xb") as stream:
            created = True
            # MiniDumpWithFullMemory = 0x2. This can contain passwords, tokens,
            # browser data and other private information from the target process.
            ok = dbghelp.MiniDumpWriteDump(process, int(pid), ctypes.c_void_p(msvcrt_get_osfhandle(stream.fileno())), 0x2, None, None, None)
            if not ok:
                target.unlink(missing_ok=True)
                return False, f"MiniDumpWriteDump failed with Windows error {ctypes.get_last_error()}"
        digest = hashlib.sha256()
        with target.open("rb") as stream:
            for chunk in iter(lambda: stream.read(_READ_CHUNK), b""):
                digest.update(chunk)
        return True, f"Full process dump saved to {target}; SHA-256: {digest.hexdigest()}"
    except Exception as exc:
        if created:
            target.unlink(missing_ok=True)
        return False, f"Dump failed: {type(exc).__name__}: {exc}"
    finally:
        kernel32.CloseHandle(process)


def msvcrt_get_osfhandle(fd: int) -> int:
    import msvcrt
    return int(msvcrt.get_osfhandle(fd))
