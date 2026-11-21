from __future__ import annotations

import base64
import csv
import ctypes
import io
import json
import re
import os
import ntpath
import shutil
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

try:
    import winreg
except ImportError:  # non-Windows test host
    winreg = None  # type: ignore[assignment]

from guardian.indicators import KNOWN_SAMPLE_ARTIFACTS, is_protected_system_path, is_temp_local_path, is_known_staging_path
from guardian import windows
from guardian.threat_profile import DEFAULT_THREAT_PROFILE

def _preferred_app_dir() -> Path:
    # Per-user storage avoids a permission boundary between elevated and standard launches.
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TCTC Guardian"

APP_DIR = _preferred_app_dir()
QUARANTINE_DIR = APP_DIR / "Quarantine"
BACKUP_DIR = APP_DIR / "Backups"


def _json_safe_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"kind": "bytes", "base64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return {"kind": "plain", "value": value}
    return {"kind": "repr", "value": repr(value)}


def _json_restore_value(value: dict[str, Any]) -> Any:
    if value.get("kind") == "bytes":
        return base64.b64decode(value["base64"])
    return value.get("value")


def backup_directory() -> Path:
    ensure_storage()
    return BACKUP_DIR


def ensure_storage() -> None:
    global APP_DIR, QUARANTINE_DIR, BACKUP_DIR
    try:
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        fallback = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TCTC Guardian"
        APP_DIR = fallback
        QUARANTINE_DIR = APP_DIR / "Quarantine"
        BACKUP_DIR = APP_DIR / "Backups"
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def read_quarantine_index() -> list[dict[str, Any]]:
    ensure_storage()
    index = QUARANTINE_DIR / "index.json"
    if not index.exists():
        return []
    try:
        data = json.loads(index.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _write_quarantine_index(items: list[dict[str, Any]]) -> None:
    ensure_storage()
    target = QUARANTINE_DIR / "index.json"
    temp = target.with_suffix(".tmp")
    temp.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(temp, target)


def quarantine_file(source: str, expected_hash: str = "", expected_size: int | None = None) -> dict[str, Any]:
    if not windows.IS_WINDOWS:
        raise RuntimeError("Quarantine is supported on Windows only")
    source_path = Path(source)
    if not source_path.exists() or not source_path.is_file():
        raise FileNotFoundError(f"File no longer exists: {source}")
    source_stat = source_path.lstat()
    reparse = bool(getattr(source_stat, "st_file_attributes", 0) & 0x400)
    if source_path.is_symlink() or reparse:
        raise RuntimeError("Refusing to quarantine a symbolic link or reparse-point file")
    resolved = source_path.resolve(strict=True)
    if is_protected_system_path(str(resolved)) and not is_known_staging_path(str(resolved)):
        raise RuntimeError("Refusing to quarantine a file under protected Windows or Program Files locations, except the specifically analyzed Temp\\Local staging path")
    stat = resolved.stat()
    if expected_size is not None and int(stat.st_size) != int(expected_size):
        raise RuntimeError("File size changed since the exact sample verification; refusing quarantine")
    digest_before = _sha256(str(resolved))
    if expected_hash and digest_before.lower() != expected_hash.lower():
        raise RuntimeError("File contents changed since the scan; run a new scan before remediation")
    ensure_storage()
    qid = uuid.uuid4().hex
    dest = QUARANTINE_DIR / f"{qid}_{resolved.name}"
    metadata_path = QUARANTINE_DIR / f"{qid}.json"
    moved = False
    try:
        # Same-volume rename is atomic. Cross-volume copy verifies bytes before source removal.
        try:
            os.replace(str(resolved), str(dest))
            moved = True
        except OSError:
            shutil.copy2(str(resolved), str(dest))
            digest_copy = _sha256(str(dest))
            if digest_copy != digest_before:
                dest.unlink(missing_ok=True)
                raise RuntimeError("Quarantine copy verification failed; original file was not removed")
            try:
                resolved.unlink()
            except Exception:
                dest.unlink(missing_ok=True)
                raise
            moved = True
        digest_after = _sha256(str(dest))
        if digest_after != digest_before:
            if not resolved.exists():
                shutil.move(str(dest), str(resolved))
            raise RuntimeError("Quarantined file hash changed during transfer; original path was restored when possible")
        record = {
            "id": qid, "original_path": str(resolved), "quarantine_path": str(dest),
            "sha256": digest_before, "size": stat.st_size, "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "restored": False,
        }
        metadata_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
        items = read_quarantine_index()
        items.append(record)
        _write_quarantine_index(items)
        return record
    except Exception:
        # Roll back a move if the evidence index could not be committed.
        if moved and dest.exists() and not resolved.exists():
            try:
                resolved.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(dest), str(resolved))
            except Exception:
                pass
        metadata_path.unlink(missing_ok=True)
        raise


def permanently_delete_quarantined_file(record_id: str) -> str:
    """Permanently delete one verified file from this application's quarantine.

    The file must remain inside QUARANTINE_DIR and match the SHA-256 recorded
    when it was quarantined. The index keeps a tombstone for the audit trail.
    """
    if not record_id or not re.fullmatch(r"[0-9a-fA-F]{32}", str(record_id)):
        raise RuntimeError("Invalid quarantine record identifier")
    items = read_quarantine_index()
    record = next((x for x in items if x.get("id") == record_id), None)
    if not record:
        raise FileNotFoundError("Quarantine record was not found")
    if record.get("restored"):
        raise RuntimeError("A restored file is no longer in quarantine")
    if record.get("permanently_deleted"):
        raise RuntimeError("This quarantine item was already permanently deleted")

    ensure_storage()
    root = QUARANTINE_DIR.resolve(strict=True)
    candidate = Path(str(record.get("quarantine_path", "")))
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError("The quarantined file is missing")
    stat = candidate.lstat()
    if candidate.is_symlink() or bool(getattr(stat, "st_file_attributes", 0) & 0x400):
        raise RuntimeError("Refusing to delete a symbolic link or reparse-point file")
    resolved = candidate.resolve(strict=True)
    if not _is_relative_to(resolved, root):
        raise RuntimeError("Refusing to delete a file outside the application's quarantine directory")
    expected = str(record.get("sha256", "")).lower()
    if not expected or _sha256(str(resolved)).lower() != expected:
        raise RuntimeError("Quarantine file hash does not match its record; refusing permanent deletion")

    resolved.unlink()
    record["permanently_deleted"] = True
    record["permanently_deleted_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _write_quarantine_index(items)
    metadata_path = QUARANTINE_DIR / f"{record_id}.json"
    try:
        metadata_path.unlink(missing_ok=True)
    except OSError:
        pass
    return f"Permanently deleted the verified quarantined file: {Path(record.get('original_path', resolved.name)).name}"


def _sha256(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _z797_markers_in(value: Any) -> set[str]:
    text = str(value or "").lower().replace("\\", "/")
    markers = set()
    for token in [
        *DEFAULT_THREAT_PROFILE["c2_domains"],
        *DEFAULT_THREAT_PROFILE["c2_urls"],
        "crandle.txt", "z797.ps1", "tctc.bba", "/nfront.php", "/nback.php",
    ]:
        normalized = str(token).lower().replace("\\", "/")
        if normalized and normalized in text:
            markers.add(normalized)
    return markers


def _require_z797_marker(value: Any, what: str) -> set[str]:
    markers = _z797_markers_in(value)
    if not markers:
        raise RuntimeError(f"{what} no longer contains a built-in TCTC/Z797 indicator; refusing to modify it")
    return markers



def _file_contains_z797_marker(path: str) -> bool:
    """Stream a current file for built-in campaign markers without loading it all into RAM."""
    tokens = [
        *DEFAULT_THREAT_PROFILE.get("c2_domains", []),
        *DEFAULT_THREAT_PROFILE.get("c2_urls", []),
        "crandle.txt", "z797.ps1", "tctc.bba", "/nfront.php", "/nback.php",
    ]
    patterns: list[bytes] = []
    for token in tokens:
        raw = str(token).lower().encode("utf-8", errors="ignore")
        if raw:
            patterns.extend((raw, token.encode("utf-16le", errors="ignore").lower()))
    if not patterns:
        return False
    overlap = max(map(len, patterns)) - 1
    carry = b""
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(256 * 1024)
            if not chunk:
                return False
            data = (carry + chunk).lower()
            if any(pattern in data for pattern in patterns):
                return True
            carry = data[-overlap:] if overlap > 0 else b""


def _is_approved_startup_file(path: str) -> bool:
    text = "/" + os.path.abspath(path).replace("\\", "/").lower().strip("/") + "/"
    # Both per-user AppData\Roaming and ProgramData Startup directories end
    # in this canonical segment. Match a directory boundary, not a filename.
    return "/microsoft/windows/start menu/programs/startup/" in text

def remove_registry_value(meta: dict[str, Any]) -> dict[str, Any]:
    if not windows.IS_WINDOWS or winreg is None:
        raise RuntimeError("Registry remediation is available on Windows only")
    root_map = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    root_name = str(meta.get("root", ""))
    subkey = str(meta.get("subkey", ""))
    value_name = str(meta.get("value_name", ""))
    if root_name not in root_map or "CurrentVersion\\Run" not in subkey:
        raise RuntimeError("Refusing to modify a registry path outside the approved Run/RunOnce locations")
    root = root_map[root_name]
    with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
        data, value_type = winreg.QueryValueEx(key, value_name)
        expected = str(meta.get("expected_value_data", meta.get("value_data", "")))
        current_text = str(data)
        if current_text != expected:
            raise RuntimeError("The Run / RunOnce value changed since the scan; re-scan before cleanup")
        _require_z797_marker(current_text, "Registry value")
        backup = {
            "type": "registry_value", "root": root_name, "subkey": subkey,
            "value_name": value_name, "value_type": int(value_type), "value_data": _json_safe_value(data),
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        ensure_storage()
        backup_file = BACKUP_DIR / f"registry_{uuid.uuid4().hex}.json"
        backup_file.write_text(json.dumps(backup, indent=2, ensure_ascii=False), encoding="utf-8")
        winreg.DeleteValue(key, value_name)
    return {"backup": str(backup_file), "removed": f"{root_name}\\{subkey}\\{value_name}"}


def restore_registry_backup(backup_path: str) -> str:
    if not windows.IS_WINDOWS or winreg is None:
        raise RuntimeError("Registry restore is available on Windows only")
    backup = json.loads(Path(backup_path).read_text(encoding="utf-8"))
    if backup.get("type") != "registry_value":
        raise RuntimeError("Unsupported backup type")
    root_map = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    root_name, subkey = backup["root"], backup["subkey"]
    if root_name not in root_map or "CurrentVersion\\Run" not in subkey:
        raise RuntimeError("Backup registry path is outside the approved locations")
    with winreg.CreateKeyEx(root_map[root_name], subkey, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, backup["value_name"], 0, int(backup["value_type"]), _json_restore_value(backup["value_data"]))
    return f"Restored {root_name}\\{subkey}\\{backup['value_name']}"


def set_task_enabled(task_name: str, enabled: bool) -> str:
    if not windows.IS_WINDOWS:
        raise RuntimeError("Scheduled task changes are supported on Windows only")
    if not task_name.strip():
        raise RuntimeError("Invalid scheduled task name")
    action = "/enable" if enabled else "/disable"
    code, out, err = windows.run_command(["schtasks", "/change", "/tn", task_name, action], timeout=25)
    if code != 0:
        raise RuntimeError(err.strip() or out.strip() or f"schtasks exited with code {code}")
    return f"{'Enabled' if enabled else 'Disabled'} scheduled task: {task_name}"


def terminate_suspicious_process(pid: int, image_path: str) -> str:
    if not windows.IS_WINDOWS:
        raise RuntimeError("Process termination is supported on Windows only")
    if not is_known_staging_path(image_path):
        raise RuntimeError("Refusing to terminate a process outside the two analyzed Temp\\Local staging roots")
    if pid <= 4:
        raise RuntimeError("Refusing to terminate a protected system PID")
    current = next((p for p in windows.list_processes() if int(p.get("pid", -1)) == int(pid)), None)
    if current is None:
        raise RuntimeError("The process has already exited; nothing to terminate")
    current_path = str(current.get("path", ""))
    if os.path.normcase(os.path.abspath(current_path)) != os.path.normcase(os.path.abspath(image_path)):
        raise RuntimeError("The PID now maps to a different image path; refusing to terminate it")
    code, out, err = windows.run_command(["taskkill", "/PID", str(int(pid)), "/F"], timeout=15)
    if code != 0:
        raise RuntimeError(err.strip() or out.strip() or f"taskkill exited with code {code}")
    return f"Stopped process PID {pid} ({image_path})"



def _terminate_exact_sample_process(pid: int, image_path: str, expected_sha256: str, expected_size: int, *, allow_missing_file: bool = False) -> str:
    """Terminate only a live process whose image path and on-disk PE are an exact recovered artifact.

    The process handle pins the process object, avoiding a taskkill PID-reuse race.
    This intentionally refuses paths outside the analyzed Temp\\Local staging roots.
    """
    if not windows.IS_WINDOWS:
        raise RuntimeError("Exact process containment is supported on Windows only")
    digest = str(expected_sha256 or "").lower()
    known = KNOWN_SAMPLE_ARTIFACTS.get(digest)
    if not known or int(known[0]) != int(expected_size):
        raise RuntimeError("Refusing process termination: SHA-256 and expected byte size are not an exact recovered TCTC artifact")
    if int(pid) <= 4 or not is_known_staging_path(image_path):
        raise RuntimeError("Refusing process termination outside the analyzed staging path or for a protected PID")
    candidate = Path(image_path)
    if candidate.is_symlink():
        raise RuntimeError("Refusing to terminate through a symbolic-link image path")
    candidate_stat = candidate.lstat() if candidate.exists() else None
    if candidate_stat is None:
        if not allow_missing_file:
            raise RuntimeError("The exact sample image is no longer available for on-disk verification")
    else:
        if not candidate.is_file() or bool(getattr(candidate_stat, "st_file_attributes", 0) & 0x400):
            raise RuntimeError("The exact sample image is not a regular file or is a reparse point")
        if candidate.stat().st_size != int(expected_size) or _sha256(str(candidate)).lower() != digest:
            raise RuntimeError("The live image path no longer matches the exact sample SHA-256 and size")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PROCESS_TERMINATE = 0x0001
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong)]
    kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int
    kernel32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    kernel32.TerminateProcess.restype = ctypes.c_int
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int

    handle = kernel32.OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        current = next((row for row in windows.list_processes() if int(row.get("pid", -1)) == int(pid)), None)
        if current is None:
            return f"Exact sample process PID {pid} had already exited; verified file will still be quarantined"
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        size = ctypes.c_ulong(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        current_path = buffer.value
        if os.path.normcase(os.path.abspath(current_path)) != os.path.normcase(os.path.abspath(image_path)):
            raise RuntimeError("PID now belongs to a different image; refusing termination")
        if not kernel32.TerminateProcess(handle, 0xE797):
            raise ctypes.WinError(ctypes.get_last_error())
        kernel32.WaitForSingleObject(handle, 5000)
        return f"Stopped exact TCTC sample process PID {pid}: {current_path}"
    finally:
        kernel32.CloseHandle(handle)


def contain_exact_sample_process(
    pid: int, image_path: str, expected_sha256: str, expected_size: int, *, allow_missing_file: bool = False
) -> dict[str, Any]:
    """Stop only the PID tied to an exact Sysmon process-create image event.

    If the file was already quarantined/deleted after Sysmon hashed it, the
    event's exact known SHA-256 + expected size plus a pinned PID/image-path
    check are sufficient to stop that specific process. No other process is
    selected by name or path.
    """
    stop_message = _terminate_exact_sample_process(
        pid, image_path, expected_sha256, expected_size, allow_missing_file=allow_missing_file
    )
    candidate = Path(image_path)
    if not candidate.exists():
        original = os.path.normcase(os.path.abspath(str(candidate)))
        prior_record = next((item for item in read_quarantine_index()
                             if os.path.normcase(os.path.abspath(str(item.get("original_path", "")))) == original
                             and str(item.get("sha256", "")).lower() == str(expected_sha256).lower()
                             and Path(str(item.get("quarantine_path", ""))).is_file()), None)
        return {"process_stopped": True, "quarantined": bool(prior_record), "image_already_absent": True,
                "record": prior_record,
                "message": stop_message + ("; verified prior quarantine record found" if prior_record else "; image is absent but no matching quarantine record exists; verify cleanup evidence")}
    try:
        record = quarantine_file(image_path, expected_sha256, expected_size)
        return {"process_stopped": True, "quarantined": True, "message": stop_message + f"; image quarantined to {record['quarantine_path']}", "record": record}
    except Exception as exc:
        return {"process_stopped": True, "quarantined": False, "message": stop_message + f"; quarantine failed and needs review: {type(exc).__name__}: {exc}"}




def _save_action_backup(record: dict[str, Any], prefix: str) -> Path:
    ensure_storage()
    path = BACKUP_DIR / f"{prefix}_{uuid.uuid4().hex}.json"
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def disable_service(service_name: str, previous_start: int, image_path: str) -> str:
    if not windows.IS_WINDOWS or winreg is None:
        raise RuntimeError("Service remediation is available on Windows only")
    if not service_name or not all(c.isalnum() or c in "_.-" for c in service_name):
        raise RuntimeError("Invalid service name")
    subkey = rf"SYSTEM\CurrentControlSet\Services\{service_name}"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
        current_image, _ = winreg.QueryValueEx(key, "ImagePath")
        current_start, _ = winreg.QueryValueEx(key, "Start")
        expected_image = str(image_path or "").strip()
        if not expected_image or str(current_image).strip().lower() != expected_image.lower():
            raise RuntimeError("Service ImagePath changed since the scan; refusing to modify it")
        if int(current_start) != int(previous_start):
            raise RuntimeError("Service start mode changed since the scan; re-scan before cleanup")
        _require_z797_marker(current_image, "Service ImagePath")
        backup = {"type": "service", "service_name": service_name, "image_path": str(current_image), "start_type": int(current_start)}
        backup_path = _save_action_backup(backup, "service")
        winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 4)  # SERVICE_DISABLED
    # Stop only after the persistent start setting is disabled; failure is reported, not hidden.
    code, out, err = windows.run_command(["sc.exe", "stop", service_name], timeout=20)
    if code != 0 and "1062" not in (out + err):
        return f"Disabled service start; stop request returned: {(err or out).strip()} | backup: {backup_path}"
    return f"Disabled and requested stop for service {service_name}; backup: {backup_path}"


def remove_hosts_entry(domain: str, expected_line: str) -> str:
    if not windows.IS_WINDOWS:
        raise RuntimeError("Hosts-file remediation is available on Windows only")
    known_domains = {str(x).lower() for x in DEFAULT_THREAT_PROFILE["c2_domains"]}
    if str(domain).lower() not in known_domains or str(domain).lower() not in str(expected_line).lower():
        raise RuntimeError("Only an exact Hosts mapping for a built-in Z797 domain can be removed")
    hosts = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    original = hosts.read_bytes()
    text = original.decode("utf-8", errors="replace")
    lines = text.splitlines(keepends=True)
    matched = [line for line in lines if domain.lower() in line.lower() and line.strip() == expected_line.strip()]
    if not matched:
        raise RuntimeError("The exact hosts-file line has changed or no longer exists; refusing to edit")
    backup_path = _save_action_backup({"type": "hosts_file", "path": str(hosts), "backup_file": ""}, "hosts")
    binary_backup = backup_path.with_suffix(".bin")
    binary_backup.write_bytes(original)
    filtered = [line for line in lines if not (domain.lower() in line.lower() and line.strip() == expected_line.strip())]
    temp = hosts.with_name("hosts.tctc.tmp")
    temp.write_text("".join(filtered), encoding="utf-8", newline="")
    try:
        os.replace(temp, hosts)
    except Exception:
        temp.unlink(missing_ok=True)
        raise
    return f"Removed exact hosts mapping; original file backup: {binary_backup}"


def block_remote_ip_with_backup(remote_ip: str) -> str:
    """Add a narrowly-scoped outbound Windows Firewall block and save rollback data."""
    if not windows.IS_WINDOWS:
        raise RuntimeError("Windows Firewall actions are available only on Windows")
    import hashlib
    import ipaddress
    address = ipaddress.ip_address(str(remote_ip).strip())
    if str(address) not in {str(x) for x in DEFAULT_THREAT_PROFILE["c2_ips"]}:
        raise RuntimeError("Only a built-in, confirmed TCTC/Z797 campaign IP can receive a Guardian Firewall rule")
    if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local:
        raise RuntimeError("Refusing to block a non-routable special-purpose address")
    name = "TCTC Guardian - Block - " + hashlib.sha256(str(address).encode("ascii")).hexdigest()[:16]
    # A rule name derived from the exact address lets the user remove only the
    # rule created by this app, without touching pre-existing Firewall policy.
    code, out, err = windows.run_command([
        "netsh", "advfirewall", "firewall", "show", "rule", f"name={name}",
    ], timeout=15)
    if code == 0 and name.lower() in out.lower():
        return f"The TCTC Guardian outbound block rule already exists for {address}."
    code, out, err = windows.run_command([
        "netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
        "dir=out", "action=block", f"remoteip={address}", "enable=yes", "profile=any",
    ], timeout=20)
    if code != 0:
        raise RuntimeError(err.strip() or out.strip() or f"netsh exited with code {code}")
    verify_code, verify_out, verify_err = windows.run_command([
        "netsh", "advfirewall", "firewall", "show", "rule", f"name={name}",
    ], timeout=15)
    if verify_code != 0 or name.lower() not in verify_out.lower():
        windows.run_command(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"], timeout=15)
        raise RuntimeError("Windows did not confirm the new Firewall rule; the attempted rule was rolled back.")
    backup = {"type": "firewall_rule", "rule_name": name, "remote_ip": str(address),
              "direction": "out", "action": "block", "created_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    try:
        backup_path = _save_action_backup(backup, "firewall")
    except Exception:
        windows.run_command(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"], timeout=15)
        raise
    return f"Blocked outbound traffic to {address}; rollback record: {backup_path}"


def remove_guardian_firewall_rule(rule_name: str) -> str:
    if not windows.IS_WINDOWS:
        raise RuntimeError("Windows Firewall actions are available only on Windows")
    if not re.fullmatch(r"TCTC Guardian - Block - [0-9a-f]{16}", str(rule_name)):
        raise RuntimeError("Refusing to remove a Firewall rule not created by TCTC Guardian")
    code, out, err = windows.run_command([
        "netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}",
    ], timeout=20)
    if code != 0:
        raise RuntimeError(err.strip() or out.strip() or f"netsh exited with code {code}")
    return f"Removed TCTC Guardian Firewall rule: {rule_name}"


def _task_xml_action(xml_text: str) -> str:
    try:
        root = ET.fromstring(xml_text.lstrip("\ufeff"))
    except ET.ParseError as exc:
        raise RuntimeError(f"Scheduled task XML could not be parsed: {exc}") from exc
    values: list[str] = []
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1].lower()
        if tag in {"command", "arguments", "workingdirectory"} and element.text:
            values.append(element.text.strip())
    return " ".join(values).strip()


def _normal_action(value: str) -> str:
    return " ".join(str(value or "").replace('"', "").lower().split())


def disable_task_with_backup(task_name: str, expected_action: str) -> str:
    if not windows.IS_WINDOWS:
        raise RuntimeError("Scheduled task remediation is available on Windows only")
    if not task_name or not expected_action:
        raise RuntimeError("Missing scheduled task name or recorded action")
    expected_markers = _require_z797_marker(expected_action, "Recorded scheduled-task action")
    code, xml_out, err = windows.run_command(["schtasks", "/query", "/tn", task_name, "/xml"], timeout=20)
    if code != 0:
        raise RuntimeError(err.strip() or xml_out.strip() or "Could not query scheduled task XML")
    current_action = _task_xml_action(xml_out)
    current_markers = _require_z797_marker(current_action, "Current scheduled-task action")
    if not (expected_markers & current_markers):
        raise RuntimeError("The task action no longer contains the same Z797 indicator as the scan; refusing to disable it")
    # Also require the executable component to remain identical where it can be parsed.
    expected_norm = _normal_action(expected_action)
    current_norm = _normal_action(current_action)
    expected_exe = ntpath.basename(expected_norm.split(" ", 1)[0])
    current_exe = ntpath.basename(current_norm.split(" ", 1)[0])
    if expected_exe and current_exe and expected_exe != current_exe:
        raise RuntimeError("The scheduled-task executable changed since the scan; refusing to disable it")

    code, out, err = windows.run_command(["schtasks", "/query", "/tn", task_name, "/fo", "CSV", "/v"], timeout=20)
    if code != 0:
        raise RuntimeError(err.strip() or out.strip() or "Could not query scheduled task state")
    rows = list(csv.DictReader(io.StringIO(out)))
    state_values = " ".join(str(v) for row in rows[:1] for k, v in row.items()
                             if k and ("state" in k.lower() or "status" in k.lower())).lower()
    state_text = state_values or out.lower()
    disabled_tokens = ("disabled", "deaktiviert", "deshabilitado", "désactivé", "معطل")
    enabled_tokens = ("enabled", "ready", "running", "queued", "bereit", "habilitado", "activé")
    was_disabled = any(token in state_text for token in disabled_tokens)
    state_known_enabled = any(token in state_text for token in enabled_tokens)
    if not was_disabled and not state_known_enabled:
        raise RuntimeError("Could not determine the task's current enabled state safely; no change was made")
    backup_path = _save_action_backup({
        "type": "scheduled_task", "task_name": task_name, "was_disabled": was_disabled,
        "expected_action": expected_action, "current_action": current_action,
        "query_output": out,
    }, "task")
    if was_disabled:
        return f"Task was already disabled; state recorded: {backup_path}"
    result = set_task_enabled(task_name, False)
    return result + f"; action and state backup: {backup_path}"


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def restore_action_backup(backup_path: str) -> str:
    path = Path(backup_path).resolve(strict=True)
    allowed_roots = [backup_directory().resolve(strict=True)]
    program_data = os.environ.get("PROGRAMDATA")
    if program_data:
        legacy = Path(program_data) / "TCTC Guardian" / "Backups"
        if legacy.exists():
            allowed_roots.append(legacy.resolve())
    if not any(_is_relative_to(path, root) for root in allowed_roots):
        raise RuntimeError("Select a backup created inside a TCTC Guardian Backups folder")
    data = json.loads(path.read_text(encoding="utf-8"))
    kind = data.get("type")
    if kind == "registry_value":
        return restore_registry_backup(backup_path)
    if kind == "scheduled_task":
        if data.get("was_disabled"):
            return f"Task {data.get('task_name')} was already disabled; original state preserved"
        return set_task_enabled(str(data.get("task_name", "")), True)
    if kind == "service":
        if not windows.IS_WINDOWS or winreg is None:
            raise RuntimeError("Service restore is available on Windows only")
        service_name = str(data.get("service_name", ""))
        if not service_name or not all(c.isalnum() or c in "_.-" for c in service_name):
            raise RuntimeError("Invalid service name in backup")
        subkey = rf"SYSTEM\CurrentControlSet\Services\{service_name}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
            current_image, _ = winreg.QueryValueEx(key, "ImagePath")
            if str(current_image).strip().lower() != str(data.get("image_path", "")).strip().lower():
                raise RuntimeError("Service ImagePath changed since the backup; refusing to restore its start mode")
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, int(data["start_type"]))
        return f"Restored service start type for {data['service_name']}"
    if kind == "firewall_rule":
        return remove_guardian_firewall_rule(str(data.get("rule_name", "")))
    if kind == "hosts_file":
        backup_bin = path.with_suffix(".bin")
        if not backup_bin.exists():
            raise FileNotFoundError("Hosts backup data is missing")
        target = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
        recorded_target = Path(data.get("path", "")).resolve()
        if recorded_target != target.resolve():
            raise RuntimeError("Hosts backup target does not match the real Windows hosts file")
        restore_temp = target.with_name("hosts.tctc.restore.tmp")
        restore_temp.write_bytes(backup_bin.read_bytes())
        os.replace(restore_temp, target)
        return f"Restored hosts file from {backup_bin}"
    raise RuntimeError(f"Unsupported backup type: {kind}")


def remediate_finding(finding: dict[str, Any], *, user_confirmed: bool = False) -> dict[str, Any]:
    action = str(finding.get("remediation", "none"))
    meta = finding.get("metadata") or {}
    allowed = {
        "quarantine_file", "contain_exact_sample_process", "remove_registry_value",
        "disable_task", "disable_service", "remove_hosts_entry", "block_network_ip",
    }
    if action not in allowed:
        if action == "terminate_process":
            raise RuntimeError("Generic path-only process termination is disabled; only an exact recovered Z797 hash and size can be contained")
        raise RuntimeError("No campaign-specific cleanup action is defined for this finding")
    if not user_confirmed:
        raise RuntimeError("A user confirmation is required before changing files, persistence or Firewall rules")

    if action == "quarantine_file":
        source = str(meta.get("file_path") or finding.get("path", ""))
        expected_hash = str(finding.get("sha256", "")).lower()
        expected_size = int(meta.get("expected_size", meta.get("file_size", 0)) or 0)
        if not source or not expected_hash or len(expected_hash) != 64 or expected_size <= 0:
            raise RuntimeError("The finding has no complete SHA-256 / size identity; re-scan before cleanup")
        if not (is_known_staging_path(source) or _is_approved_startup_file(source)):
            raise RuntimeError("File quarantine is limited to the two analysed Temp\\Local roots or the Windows Startup folders")
        current = Path(source)
        if not current.is_file() or current.is_symlink():
            raise RuntimeError("The recorded file is no longer a regular file; re-scan before cleanup")
        stat = current.stat()
        if int(stat.st_size) != expected_size or _sha256(str(current)).lower() != expected_hash:
            raise RuntimeError("File identity changed since the finding was created; run a new scan before remediation")
        exact = KNOWN_SAMPLE_ARTIFACTS.get(expected_hash)
        exact_hash_match = bool(exact and int(exact[0]) == expected_size)
        marker_match = _file_contains_z797_marker(str(current))
        if not (exact_hash_match or marker_match):
            raise RuntimeError("The current file has no exact recovered Z797 hash or embedded campaign indicator; filename alone is not enough to quarantine")
        result = quarantine_file(source, expected_hash, expected_size)
        return {"action": action, "status": "success", "message": f"Quarantined to {result['quarantine_path']}", "record": result}
    if action == "remove_registry_value":
        result = remove_registry_value(meta)
        return {"action": action, "status": "success", "message": f"Removed Z797 autostart value; backup saved to {result['backup']}", "record": result}
    if action == "disable_task":
        result = disable_task_with_backup(str(meta.get("task_name", "")), str(meta.get("expected_task_action", meta.get("task_action", ""))))
        return {"action": action, "status": "success", "message": result}
    if action == "disable_service":
        result = disable_service(str(meta.get("service_name", "")), int(meta.get("start_type", 2)), str(meta.get("expected_image_path", meta.get("image_path", ""))))
        status = "partial" if "stop request returned:" in result.lower() else "success"
        return {"action": action, "status": status, "message": result}
    if action == "remove_hosts_entry":
        result = remove_hosts_entry(str(meta.get("domain", "")), str(meta.get("hosts_line", "")))
        return {"action": action, "status": "success", "message": result}
    if action == "block_network_ip":
        if not bool(meta.get("configured_ip")):
            raise RuntimeError("The destination was not a built-in confirmed Z797 IP; Firewall response is refused")
        expected_digest = str(meta.get("process_sha256", "")).lower()
        expected_size = int(meta.get("expected_size", 0) or 0)
        if not expected_digest or expected_digest not in KNOWN_SAMPLE_ARTIFACTS:
            raise RuntimeError("The connecting process is not tied to an exact recovered Z797 artifact; Firewall response is refused")
        if int(KNOWN_SAMPLE_ARTIFACTS[expected_digest][0]) != expected_size:
            raise RuntimeError("The recorded process size does not match the recovered Z797 artifact; Firewall response is refused")
        pid = int(meta.get("pid", 0) or 0)
        current = next((p for p in windows.list_processes() if int(p.get("pid", -1)) == pid), None)
        if current is None or pid <= 4:
            raise RuntimeError("The original connecting process is no longer present; re-scan before creating a Firewall rule")
        current_path = str(current.get("path", ""))
        recorded_path = str(meta.get("process_path", ""))
        if not current_path or os.path.normcase(os.path.abspath(current_path)) != os.path.normcase(os.path.abspath(recorded_path)):
            raise RuntimeError("The PID no longer maps to the recorded process image; refusing Firewall response")
        if not is_known_staging_path(current_path) or not Path(current_path).is_file():
            raise RuntimeError("The current image is no longer in the analysed staging area; refusing Firewall response")
        stat = Path(current_path).stat()
        if stat.st_size != expected_size or _sha256(current_path).lower() != expected_digest:
            raise RuntimeError("The live process image no longer matches the exact recovered Z797 file; refusing Firewall response")
        result = block_remote_ip_with_backup(str(meta.get("ip", "")))
        return {"action": action, "status": "success", "message": result}
    if action == "contain_exact_sample_process":
        result = contain_exact_sample_process(
            int(meta.get("pid", 0)), str(finding.get("path", "")),
            str(finding.get("sha256", "")), int(meta.get("expected_size", 0) or 0),
            allow_missing_file=bool(meta.get("event_driven") and meta.get("hash_size_verified")),
        )
        return {"action": action, "status": "success" if result.get("quarantined") else "partial", **result}
    raise RuntimeError("Unsupported campaign-specific cleanup action")


def restore_quarantined_file(record_id: str) -> str:
    items = read_quarantine_index()
    record = next((x for x in items if x.get("id") == record_id), None)
    if not record:
        raise FileNotFoundError("Quarantine record was not found")
    if record.get("restored"):
        raise RuntimeError("This file has already been restored")
    qpath = Path(record["quarantine_path"])
    original = Path(record["original_path"])
    if not qpath.exists():
        raise FileNotFoundError(f"Quarantined file is missing: {qpath}")
    if original.exists():
        raise FileExistsError(f"Original path already exists; refusing to overwrite: {original}")
    if is_protected_system_path(str(original)) and not is_known_staging_path(str(original)):
        raise RuntimeError("Refusing to restore a quarantined file into a protected Windows or Program Files path, except the analyzed Temp\\Local staging path")
    original.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(qpath), str(original))
    if record.get("sha256") and _sha256(str(original)) != record["sha256"]:
        shutil.move(str(original), str(qpath))
        raise RuntimeError("Restored file hash did not match quarantine metadata")
    record["restored"] = True
    record["restored_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _write_quarantine_index(items)
    return f"Restored file to {original}"
