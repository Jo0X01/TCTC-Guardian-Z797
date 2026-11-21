from __future__ import annotations

import os
import re
from pathlib import Path

C2_DOMAIN = "benderoflight.com"
C2_PATHS = ("/nfront.php", "/nback.php")
LOW_CONFIDENCE_CONTEXT = ("ipinfo.io",)
STAGING_RELATIVE = "Local"

SUSPICIOUS_TOKENS = (
    "AmsiScanBuffer",
    "AmsiScanString",
)

# Exact SHA-256 + byte-size pairs recovered from the locally analysed artifact set.
# These are sample-specific indicators, not family-wide signatures.
KNOWN_SAMPLE_ARTIFACTS: dict[str, tuple[int, str]] = {
    "077c93f044b590a017771ced5067e8adde18d629598ea545496904dafcfd8e22": (8147456, "Recovered outer PE"),
    "c34719ff34d037eedc4338655d844734a7451c00250a56c8cba8f807f92bcafb": (8178288, "Raw tctc.bba delivery artifact"),
    "ce9263eec902131910d6ff69b33f2d61f09707dadb7818c11de46d97fa441169": (8328272, "Recovered stage-2 shellcode artifact"),
    "30a16519c20df8f6d7fd8e127c5e2ba688b074eb723c60ed88e36b1da3cc1b12": (8324608, "Recovered stage-3 PE artifact"),
    "a10e4fbff548ea2839db1cac5faaa3316b950cc9f8a2cf82658b1a9ad7eb9089": (494080, "Recovered inner controller PE"),
    "4dd38c86f35b68702d47d3bb90c8dc694e9b85d179b0825fb1aea05d3e60a335": (736768, "Recovered encrypted 42.bin task artifact"),
    "4a5e0ed88529761af8e86afcf2b969217a7345abe2c467523d036bb5126ca644": (736768, "Recovered decrypted 42.bin PE artifact"),
}


def known_sample_artifact(digest: str, size: int) -> str | None:
    """Return an exact sample-artifact label only when both hash and size match."""
    record = KNOWN_SAMPLE_ARTIFACTS.get(str(digest).lower())
    if record is None or int(size) != record[0]:
        return None
    return record[1]

EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx"}
SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf"}


def normalized(value: str) -> str:
    return value.replace("/", "\\").lower()


def is_temp_local_path(value: str) -> bool:
    p = normalized(value)
    return "\\temp\\local\\" in p or p.endswith("\\temp\\local")


def is_known_staging_path(value: str) -> bool:
    r"""Return true only under the two exact Temp\Local roots used by the sample."""
    candidate = os.path.normcase(os.path.abspath(value))
    temp = os.environ.get("TEMP") or os.environ.get("TMP")
    windir = os.environ.get("WINDIR", r"C:\Windows")
    roots = []
    if temp:
        roots.append(os.path.join(temp, "Local"))
    roots.append(os.path.join(windir, "Temp", "Local"))
    for root in roots:
        normalized_root = os.path.normcase(os.path.abspath(root))
        try:
            if os.path.commonpath([candidate, normalized_root]) == normalized_root and candidate != normalized_root:
                return True
        except ValueError:
            continue
    return False


def suspicious_command(value: str, domains: tuple[str, ...] | list[str] | None = None) -> tuple[bool, str]:
    p = normalized(value)
    source_domains = (C2_DOMAIN,) if domains is None else domains
    configured_domains = tuple(x.strip().lower() for x in source_domains if x.strip())
    matched = next((domain for domain in configured_domains if domain in p), None)
    if matched:
        return True, f"Contains a configured threat domain: {matched}"
    if is_temp_local_path(value):
        return True, "References the sample's Temp\\Local staging pattern"
    if re.search(r"\bpowershell(?:\.exe)?\b.*(?:\s-enc\s|\s-encodedcommand\s)", p):
        return True, "Encoded PowerShell command in an autostart location"
    if any(x in p for x in ("mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe")) and any(
        marker in p for marker in ("\\appdata\\", "\\temp\\", "\\downloads\\")
    ):
        return True, "Script host or DLL launcher references a user-writable location"
    return False, ""


def is_under(path: str, parent: str) -> bool:
    try:
        Path(path).resolve().relative_to(Path(parent).resolve())
        return True
    except Exception:
        return False


def is_protected_system_path(path: str) -> bool:
    p = normalized(os.path.abspath(path))
    windows = normalized(os.environ.get("WINDIR", r"C:\Windows"))
    pf = normalized(os.environ.get("ProgramFiles", r"C:\Program Files"))
    pf86 = normalized(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    protected_roots = [windows, pf, pf86]
    return any(p == root or p.startswith(root + "\\") for root in protected_roots if root)


def contains_pe_header(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
            if len(head) < 64 or head[:2] != b"MZ":
                return False
            pe_offset = int.from_bytes(head[0x3C:0x40], "little")
            if pe_offset < 0x40 or pe_offset + 4 > len(head):
                f.seek(pe_offset)
                signature = f.read(4)
            else:
                signature = head[pe_offset:pe_offset + 4]
            return signature == b"PE\0\0"
    except (OSError, ValueError, OverflowError):
        return False
