from __future__ import annotations

import csv
import ctypes
import io
import os
import platform
import subprocess
from typing import Any
import sys

IS_WINDOWS = os.name == "nt"


def is_admin() -> bool:
    if not IS_WINDOWS:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """Request UAC elevation by relaunching the current script or frozen EXE."""
    if not IS_WINDOWS:
        return False
    if getattr(sys, "frozen", False):
        executable = sys.executable
        args = sys.argv[1:]
    else:
        executable = sys.executable
        script = os.path.abspath(sys.argv[0])
        args = [script, *sys.argv[1:]]
    parameters = subprocess.list2cmdline(args)
    shell32 = ctypes.windll.shell32
    shell32.ShellExecuteW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    shell32.ShellExecuteW.restype = ctypes.c_void_p
    result = shell32.ShellExecuteW(
        None, "runas", executable, parameters, os.getcwd(), 1
    )
    return bool(result and int(result) > 32)


def _windows_version_tuple() -> tuple[int, int, int] | None:
    """Read the real NT version tuple; platform.release() may be compatibility-shimmed."""
    if not IS_WINDOWS or not hasattr(ctypes, "WinDLL"):
        return None

    class OSVERSIONINFOEXW(ctypes.Structure):
        _fields_ = [
            ("dwOSVersionInfoSize", ctypes.c_ulong),
            ("dwMajorVersion", ctypes.c_ulong),
            ("dwMinorVersion", ctypes.c_ulong),
            ("dwBuildNumber", ctypes.c_ulong),
            ("dwPlatformId", ctypes.c_ulong),
            ("szCSDVersion", ctypes.c_wchar * 128),
            ("wServicePackMajor", ctypes.c_ushort),
            ("wServicePackMinor", ctypes.c_ushort),
            ("wSuiteMask", ctypes.c_ushort),
            ("wProductType", ctypes.c_ubyte),
            ("wReserved", ctypes.c_ubyte),
        ]

    try:
        ntdll = ctypes.WinDLL("ntdll")
        rtl_get_version = ntdll.RtlGetVersion
        rtl_get_version.argtypes = [ctypes.POINTER(OSVERSIONINFOEXW)]
        rtl_get_version.restype = ctypes.c_long
        info = OSVERSIONINFOEXW()
        info.dwOSVersionInfoSize = ctypes.sizeof(info)
        status = int(rtl_get_version(ctypes.byref(info)))
        if status != 0:
            return None
        return (
            int(info.dwMajorVersion),
            int(info.dwMinorVersion),
            int(info.dwBuildNumber),
        )
    except Exception:
        return None


def format_os() -> str:
    """Return the kernel-reported Windows marketing name, build and architecture."""
    version = _windows_version_tuple()
    architecture = platform.machine() or "Unknown architecture"
    if version:
        major, minor, build = version
        if major == 10 and minor == 0:
            name = "Windows 11" if build >= 22000 else "Windows 10"
        elif major == 6 and minor == 3:
            name = "Windows 8.1"
        elif major == 6 and minor == 2:
            name = "Windows 8"
        elif major == 6 and minor == 1:
            name = "Windows 7"
        else:
            name = f"Windows {major}.{minor}"
        return f"{name} · Build {build} / {architecture}"
    return f"{platform.system()} {platform.release()} / {architecture}"


def windows_version() -> str:
    return format_os()


def run_command(args: list[str], timeout: int = 20) -> tuple[int, str, str]:
    try:
        cp = subprocess.run(
            args,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            shell=False,
        )
        return cp.returncode, cp.stdout or "", cp.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return (
            124,
            (exc.stdout or "") if isinstance(exc.stdout, str) else "",
            f"Timed out after {timeout}s",
        )
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except Exception as exc:
        return 1, "", f"{type(exc).__name__}: {exc}"


STARTUP_TASK_NAME = "TCTC Guardian - User Startup"


def configure_startup_task(enabled: bool, *, start_monitoring: bool = False) -> str:
    """Register or remove a per-user logon task that runs the app elevated.

    The task uses the current user's highest available token. No password is
    stored in the task definition. The application still checks its own UAC
    state and refuses to continue if it is not elevated.
    """
    if not IS_WINDOWS:
        raise RuntimeError("Windows startup registration is available only on Windows.")
    import sys

    if enabled:
        if getattr(sys, "frozen", False):
            executable = sys.executable
            arguments = (
                ["--start-monitoring", "--start-hidden"] if start_monitoring else []
            )
        else:
            executable = sys.executable
            script = os.path.abspath(sys.argv[0])
            arguments = [script] + (
                ["--start-monitoring", "--start-hidden"] if start_monitoring else []
            )
        launch = subprocess.list2cmdline([executable, *arguments])
        code, out, err = run_command(
            [
                "schtasks",
                "/Create",
                "/SC",
                "ONLOGON",
                "/TN",
                STARTUP_TASK_NAME,
                "/TR",
                launch,
                "/RL",
                "HIGHEST",
                "/F",
            ],
            timeout=30,
        )
        if code != 0:
            raise RuntimeError(
                err.strip() or out.strip() or f"schtasks exited with code {code}"
            )
        return "Windows logon task registered with the highest available privileges."

    query_code, _query_out, _query_err = run_command(
        ["schtasks", "/Query", "/TN", STARTUP_TASK_NAME], timeout=15
    )
    if query_code != 0:
        return "No Windows logon task was registered."
    code, out, err = run_command(
        ["schtasks", "/Delete", "/TN", STARTUP_TASK_NAME, "/F"], timeout=20
    )
    if code != 0:
        raise RuntimeError(
            err.strip() or out.strip() or f"schtasks exited with code {code}"
        )
    return "Windows logon task removed."


def list_processes() -> list[dict[str, Any]]:
    """Enumerate processes using Toolhelp + QueryFullProcessImageNameW."""
    if not IS_WINDOWS:
        return []

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_ulong),
            ("cntUsage", ctypes.c_ulong),
            ("th32ProcessID", ctypes.c_ulong),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", ctypes.c_ulong),
            ("cntThreads", ctypes.c_ulong),
            ("th32ParentProcessID", ctypes.c_ulong),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.c_ulong),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.Process32FirstW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(PROCESSENTRY32W),
    ]
    kernel32.Process32FirstW.restype = ctypes.c_int
    kernel32.Process32NextW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(PROCESSENTRY32W),
    ]
    kernel32.Process32NextW.restype = ctypes.c_int
    kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.QueryFullProcessImageNameW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int

    TH32CS_SNAPPROCESS = 0x00000002
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())

    results: list[dict[str, Any]] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            pid = int(entry.th32ProcessID)
            path = ""
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                try:
                    size = ctypes.c_ulong(32768)
                    buf = ctypes.create_unicode_buffer(size.value)
                    if kernel32.QueryFullProcessImageNameW(
                        handle, 0, buf, ctypes.byref(size)
                    ):
                        path = buf.value
                finally:
                    kernel32.CloseHandle(handle)
            results.append(
                {
                    "pid": pid,
                    "ppid": int(entry.th32ParentProcessID),
                    "name": entry.szExeFile,
                    "path": path,
                }
            )
            ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return results


def get_netstat() -> str:
    if not IS_WINDOWS:
        return ""
    code, out, err = run_command(["netstat", "-ano"], timeout=15)
    if code != 0 and not out:
        raise RuntimeError(err or "netstat failed")
    return out


def get_dns_cache() -> str:
    if not IS_WINDOWS:
        return ""
    code, out, err = run_command(["ipconfig", "/displaydns"], timeout=20)
    if code != 0 and not out:
        raise RuntimeError(err or "Could not read DNS cache")
    return out


def get_hosts_text() -> str:
    if not IS_WINDOWS:
        return ""
    path = os.path.join(
        os.environ.get("WINDIR", r"C:\Windows"), "System32", "drivers", "etc", "hosts"
    )
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError as exc:
        raise RuntimeError(f"Cannot read hosts file: {exc}") from exc


def _decode_eventlog_bytes(value: bytes) -> str:
    """Decode wevtutil XML output without assuming the active console codepage."""
    if not value:
        return ""
    if value.startswith((b"\xff\xfe", b"\xfe\xff")):
        return value.decode("utf-16", errors="replace")
    if value.count(b"\x00") > max(2, len(value) // 20):
        try:
            return value.decode("utf-16-le", errors="replace")
        except UnicodeError:
            pass
    try:
        return value.decode("utf-8-sig")
    except UnicodeDecodeError:
        return value.decode("mbcs" if IS_WINDOWS else "latin-1", errors="replace")


def query_event_log(
    channel: str, query: str, count: int = 2000, timeout: int = 40
) -> tuple[bool, str, str]:
    """Query matching historical events as structured XML (newest first).

    The caller should request one record above its display limit to detect a
    potentially truncated channel. Output is captured as bytes because Windows
    Event Log providers can emit Unicode independent of the console codepage.
    """
    if not IS_WINDOWS:
        return False, "", "Windows Event Log is only available on Windows"
    safe_count = max(1, min(int(count), 5001))
    args = [
        "wevtutil.exe",
        "qe",
        channel,
        f"/q:{query}",
        "/rd:true",
        f"/c:{safe_count}",
        "/f:xml",
    ]
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        out = _decode_eventlog_bytes(completed.stdout or b"")
        err = _decode_eventlog_bytes(completed.stderr or b"")
        if completed.returncode != 0:
            return (
                False,
                out,
                err.strip() or f"wevtutil exited with code {completed.returncode}",
            )
        return True, out, ""
    except subprocess.TimeoutExpired:
        return False, "", f"Timed out after {timeout}s"
    except FileNotFoundError as exc:
        return False, "", str(exc)
    except Exception as exc:
        return False, "", f"{type(exc).__name__}: {exc}"


def query_scheduled_tasks() -> tuple[list[dict[str, str]], str]:
    if not IS_WINDOWS:
        return [], "Scheduled Tasks are only available on Windows"
    code, out, err = run_command(["schtasks", "/query", "/fo", "CSV", "/v"], timeout=35)
    if code != 0:
        return [], err.strip() or f"schtasks exited with code {code}"
    try:
        rows = list(csv.DictReader(io.StringIO(out)))
    except Exception as exc:
        return [], f"Could not parse scheduled task output: {exc}"
    normalized = []
    for row in rows:
        clean = {
            str(k or "").strip().lower(): str(v or "").strip() for k, v in row.items()
        }
        name = next((v for k, v in clean.items() if k in {"taskname", "task name"}), "")
        action = next(
            (
                v
                for k, v in clean.items()
                if k in {"task to run", "actions", "task action"}
            ),
            "",
        )
        status = next(
            (v for k, v in clean.items() if k in {"status", "scheduled task state"}), ""
        )
        if name:
            normalized.append({"name": name, "action": action, "status": status})
    return normalized, ""
