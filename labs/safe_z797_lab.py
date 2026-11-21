from __future__ import annotations

"""Create/remove a harmless TCTC Guardian validation canary.

This is NOT a malware simulator. It writes one inert text file under the exact
Temp\\Local staging root and optionally starts the trusted Windows cmd.exe
from the system directory to emit a harmless ProcessCreate event and, when safe, write that file.
The command line contains static campaign IOC strings so Sysmon ProcessCreate telemetry can be exercised. No network, remote
process access, injection, AMSI changes, persistence, service/task changes, or
security-control changes are performed.
"""

import argparse
import ctypes
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LAB_PREFIX = "TCTC-Guardian-Lab-"
LAB_MARKER = "TCTC_GUARDIAN_LAB_SIMULATION"
STATIC_TEXT = (
    f"{LAB_MARKER}\n"
    "This is an inert text canary created by TCTC Guardian's safe lab tool.\n"
    "Static indicators for parser validation only (no request is sent):\n"
    "benderoflight.com\n"
    "/nfront.php\n"
    "/nback.php\n"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _local_app_data() -> Path:
    value = os.environ.get("LOCALAPPDATA")
    if value:
        return Path(value)
    return Path.home() / "AppData" / "Local"



def _resolve_system_command_processor(system_directory: str | Path) -> Path | None:
    """Resolve cmd.exe only from the Windows system directory returned by Win32."""
    try:
        system_root = Path(system_directory).resolve(strict=True)
        candidate = system_root / "cmd.exe"
        if not candidate.is_file() or candidate.is_symlink():
            return None
        resolved = candidate.resolve(strict=True)
        if resolved.parent != system_root or resolved.name.casefold() != "cmd.exe":
            return None
        return resolved
    except (OSError, RuntimeError, ValueError):
        return None


def _system_command_processor() -> Path | None:
    """Get the trusted system command interpreter without trusting COMSPEC."""
    if os.name != "nt" or not hasattr(ctypes, "WinDLL"):
        return None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_system_directory = kernel32.GetSystemDirectoryW
        get_system_directory.argtypes = [wintypes.LPWSTR, wintypes.UINT]
        get_system_directory.restype = wintypes.UINT
        buffer = ctypes.create_unicode_buffer(32768)
        length = int(get_system_directory(buffer, len(buffer)))
        if length == 0 or length >= len(buffer):
            return None
        return _resolve_system_command_processor(buffer.value)
    except (AttributeError, OSError, TypeError, ValueError):
        return None

def _staging_root() -> Path:
    # Match Guardian's user Temp\\Local root, not Windows\\Temp\\Local.
    temp_root = Path(tempfile.gettempdir()).resolve()
    root = temp_root / "Local"
    if root.exists() and root.is_symlink():
        raise RuntimeError("Refusing to use a Temp\\Local root that is a symbolic link.")
    root.mkdir(parents=True, exist_ok=True)
    resolved = root.resolve(strict=True)
    if resolved.parent != temp_root or resolved.name.lower() != "local":
        raise RuntimeError("Resolved staging path is not the expected user Temp\\Local directory.")
    return resolved


def _manifest_path() -> Path:
    root = _local_app_data() / "TCTC Guardian" / "Lab"
    root.mkdir(parents=True, exist_ok=True)
    return root / "safe-lab-manifest.json"


def _load_manifest() -> dict[str, Any]:
    path = _manifest_path()
    if not path.exists():
        raise FileNotFoundError("No safe-lab manifest exists. Run the prepare command first.")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("marker") != LAB_MARKER:
        raise RuntimeError("Lab manifest marker is invalid; refusing cleanup.")
    return data


def prepare(*, generate_process_event: bool = True) -> dict[str, Any]:
    root = _staging_root()
    manifest_path = _manifest_path()
    if manifest_path.exists():
        try:
            existing = json.loads(manifest_path.read_text(encoding="utf-8"))
            existing_dir = Path(str(existing.get("staging_directory", "")))
            if existing.get("marker") == LAB_MARKER and existing_dir.exists():
                raise RuntimeError("A previous Safe Lab directory still exists. Run Cleanup-Safe-Z797-Lab.bat before preparing another test.")
        except json.JSONDecodeError:
            raise RuntimeError("The previous Safe Lab manifest is unreadable. Review it manually; refusing to overwrite it.")
    lab_id = uuid.uuid4().hex[:12]
    lab_dir = root / f"{LAB_PREFIX}{lab_id}"
    lab_dir.mkdir(parents=False, exist_ok=False)
    canary = lab_dir / f"{LAB_PREFIX}{lab_id}.txt"

    # The file is inert UTF-8 text and is never executed. On Windows, when the
    # path is safe to quote for cmd.exe, the echo command itself creates it so
    # Sysmon can observe both ProcessCreate (1) and FileCreate (11).
    child_pid: int | None = None
    child_image = ""
    child_generated = False
    command_processor = _system_command_processor() if generate_process_event else None
    cmd_unsafe = any(ch in str(canary) for ch in '&|<>^()%!"')
    try:
        if generate_process_event and command_processor is not None:
            one_line = f"{LAB_MARKER} benderoflight.com /nfront.php /nback.php {LAB_PREFIX}{lab_id}"
            if cmd_unsafe:
                # Avoid shell metacharacters in unusual profile paths. The canary is
                # still written by Python; cmd only emits a harmless event marker.
                canary.write_text(STATIC_TEXT, encoding="utf-8")
                command_text = f"echo {one_line}"
            else:
                command_text = f'echo {one_line} > "{canary}"'
            raw_command_line = f'"{command_processor}" /d /c {command_text}'
            child = subprocess.Popen(
                raw_command_line, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                stdin=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            child_pid = int(child.pid)
            try:
                stdout, stderr = child.communicate(timeout=20)
            except subprocess.TimeoutExpired as exc:
                child.kill()
                child.communicate()
                raise RuntimeError("The harmless cmd.exe echo timed out and was terminated.") from exc
            if child.returncode != 0:
                raise RuntimeError(f"The harmless cmd.exe echo returned {child.returncode}: {(stderr or stdout).strip()[:300]}")
            child_image = str(command_processor)
            child_generated = True
            if not canary.is_file():
                # Keep the harmless staging canary usable even if cmd redirection
                # behaves differently on a localized or customized Windows setup.
                canary.write_text(STATIC_TEXT, encoding="utf-8")
        else:
            canary.write_text(STATIC_TEXT, encoding="utf-8")
    except Exception:
        # Never leave a half-created test directory behind when process telemetry fails.
        if lab_dir.exists() and not lab_dir.is_symlink():
            shutil.rmtree(lab_dir, ignore_errors=True)
        raise
    record = {
        "marker": LAB_MARKER,
        "lab_id": lab_id,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "staging_directory": str(lab_dir),
        "canary_file": str(canary),
        "sha256": sha256_file(canary),
        "size": canary.stat().st_size,
        "child_process_generated": child_generated,
        "child_image": child_image,
        "child_pid": child_pid,
        "network_requests": 0,
        "persistence_changes": 0,
        "remote_process_operations": 0,
        "memory_modifications": 0,
    }
    manifest_tmp = manifest_path.with_suffix(".tmp")
    try:
        manifest_tmp.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(manifest_tmp, manifest_path)
    except Exception:
        manifest_tmp.unlink(missing_ok=True)
        if lab_dir.exists() and not lab_dir.is_symlink():
            shutil.rmtree(lab_dir, ignore_errors=True)
        raise
    return record


def status() -> dict[str, Any]:
    record = _load_manifest()
    canary = Path(str(record["canary_file"]))
    exists = canary.is_file() and not canary.is_symlink()
    result = dict(record)
    result["canary_exists"] = exists
    if exists:
        result["current_sha256"] = sha256_file(canary)
        result["hash_matches_manifest"] = result["current_sha256"] == record.get("sha256")
    else:
        result["note"] = "The canary may have been quarantined by Guardian or removed already."
    return result


def cleanup() -> dict[str, Any]:
    record = _load_manifest()
    root = _staging_root()
    candidate = Path(str(record.get("staging_directory", "")))
    if candidate.is_symlink():
        raise RuntimeError("Refusing to clean a symbolic-link lab directory.")
    resolved = candidate.resolve(strict=False)
    lab_id = str(record.get("lab_id", ""))
    if (not re.fullmatch(r"[0-9a-f]{12}", lab_id) or resolved.parent != root
            or resolved.name != f"{LAB_PREFIX}{lab_id}"):
        raise RuntimeError("Manifest path is outside the expected dedicated lab directory; refusing cleanup.")
    removed = False
    if resolved.exists():
        # Remove only this one UUID-named directory created by this tool.
        shutil.rmtree(resolved)
        removed = True
    manifest_path = _manifest_path()
    manifest_path.unlink(missing_ok=True)
    return {
        "cleaned": True,
        "lab_directory_removed": removed,
        "directory": str(resolved),
        "note": "Sysmon historical records are intentionally not deleted. Quarantined files remain in Guardian's Quarantine until restored or removed there.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe, inert Z797 validation canary for TCTC Guardian")
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare", help="Create a harmless Temp\\Local canary and optional benign child-process telemetry")
    prep.add_argument("--no-process-event", action="store_true", help="Write the canary directly; do not start a child process")
    sub.add_parser("status", help="Show whether the canary still exists and whether its hash is unchanged")
    sub.add_parser("cleanup", help="Remove only this tool's dedicated lab directory and manifest")
    args = parser.parse_args()

    try:
        if args.command == "prepare":
            result = prepare(generate_process_event=not args.no_process_event)
            print("SAFE LAB CANARY CREATED")
            print(json.dumps(result, indent=2, ensure_ascii=False))
            print("\nNext: run TCTC Guardian Scan. The canary should appear as [LAB] evidence.")
            print("No network requests, persistence changes, remote-process operations, or memory modifications were performed.")
        elif args.command == "status":
            print(json.dumps(status(), indent=2, ensure_ascii=False))
        elif args.command == "cleanup":
            print(json.dumps(cleanup(), indent=2, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(f"SAFE LAB ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
