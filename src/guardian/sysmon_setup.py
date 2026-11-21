from __future__ import annotations

"""Python-native Microsoft Sysmon bootstrap. No PowerShell host is used."""

import ctypes
import hashlib
import json
import locale
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid
import zipfile
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable
from urllib.parse import urlsplit

from guardian import windows
from guardian.realtime import sysmon_readiness

LOG = logging.getLogger(__name__)
SYSMON_DOWNLOAD_URL = "https://download.sysinternals.com/files/Sysmon.zip"
SYSMON_DOWNLOAD_HOST = "download.sysinternals.com"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_SERVICE_NAMES = ("Sysmon64", "Sysmon")
CERT_NAME_ATTR_TYPE = 3  # CertGetNameStringW: pvTypePara is an X.500 attribute OID.
OID_ORGANIZATION_NAME = "2.5.4.10"  # szOID_ORGANIZATION_NAME (O)
MIN_ARCHIVE_BYTES = 512 * 1024
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 100
MAX_UNCOMPRESSED_ARCHIVE_BYTES = 200 * 1024 * 1024
MIN_EXE_BYTES = 100 * 1024
MAX_EXE_BYTES = 100 * 1024 * 1024
DOWNLOAD_ATTEMPTS = 3


def _application_directory() -> Path:
    try:
        return Path(sys.argv[0]).resolve().parent
    except Exception:
        return Path.cwd()


def _program_data_directory() -> Path:
    return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "TCTC Guardian Z797"


def _log_directory() -> Path:
    return (
        Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
        / "TCTC Guardian Z797"
        / "Logs"
    )


def _decode_native_output(payload: bytes | str | None) -> str:
    """Decode redirected Windows process output, including UTF-16LE Sysmon XML.

    Native Windows tools do not all use UTF-8 when stdout/stderr is redirected.
    Sysmon's ``-s`` schema output is commonly UTF-16LE without a BOM; decoding it
    as UTF-8 leaves NUL bytes between every ASCII character and breaks searches.
    """
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    if not payload:
        return ""
    if payload.startswith(b"\xff\xfe"):
        return payload.decode("utf-16", "replace")
    if payload.startswith(b"\xfe\xff"):
        return payload.decode("utf-16", "replace")
    if payload.startswith(b"\xef\xbb\xbf"):
        return payload.decode("utf-8-sig", "replace")

    sample = payload[:8192]
    if len(sample) >= 8:
        even_count = max(1, len(sample[0::2]))
        odd_count = max(1, len(sample[1::2]))
        even_nuls = sample[0::2].count(0) / even_count
        odd_nuls = sample[1::2].count(0) / odd_count
        # ASCII-heavy UTF-16 text has NUL bytes in the odd positions (LE),
        # or even positions (BE). Require a clear skew to avoid misclassifying
        # arbitrary binary / ANSI output.
        if odd_nuls >= 0.20 and odd_nuls >= (even_nuls * 2.5):
            return payload.decode("utf-16-le", "replace").lstrip("\ufeff")
        if even_nuls >= 0.20 and even_nuls >= (odd_nuls * 2.5):
            return payload.decode("utf-16-be", "replace").lstrip("\ufeff")

    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        preferred = locale.getpreferredencoding(False) or "mbcs"
        try:
            return payload.decode(preferred, "replace")
        except (LookupError, UnicodeError):
            return payload.decode("cp1252", "replace")


def _run_process(args: list[str], *, timeout: int = 60) -> tuple[int, str, str]:
    """Run a native executable and decode its output using Windows-aware rules."""
    try:
        result = subprocess.run(
            [str(x) for x in args],
            capture_output=True,
            text=False,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            shell=False,
            stdin=subprocess.DEVNULL,
        )
        return (
            result.returncode,
            _decode_native_output(result.stdout),
            _decode_native_output(result.stderr),
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _decode_native_output(exc.stdout)
        stderr = _decode_native_output(exc.stderr)
        return 124, stdout, (stderr + f"\nTimed out after {timeout} seconds.").strip()
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except Exception as exc:
        return 1, "", f"{type(exc).__name__}: {exc}"


def _schema_supports_file_executable_detected(schema_output: str) -> bool:
    """Confirm Sysmon event 29 from the schema manifest, not a fragile text token.

    Sysmon's manifest identifies this event internally as
    ``SYSMONEVENT_FILE_EXE_DETECTED`` and exposes ``FileExecutableDetected`` as
    its rule name. Output may be prefixed by the executable name and may contain
    wide-character NULs if supplied by a test or an older caller.
    """
    import xml.etree.ElementTree as ET

    text = str(schema_output or "").replace("\x00", "")
    # Drop any command-line banner before the XML declaration/root element.
    starts = [
        pos
        for marker in ("<?xml", "<instrumentationManifest", "<manifest")
        if (pos := text.casefold().find(marker.casefold())) >= 0
    ]
    if starts:
        text = text[min(starts) :]
    try:
        root = ET.fromstring(text)
        for node in root.iter():
            if node.tag.rsplit("}", 1)[-1].casefold() != "event":
                continue
            attrs = {
                str(key).casefold(): str(value) for key, value in node.attrib.items()
            }
            if attrs.get("value", "").strip() != "29":
                continue
            event_identity = " ".join(
                attrs.get(key, "") for key in ("name", "rulename", "template")
            ).casefold()
            compact_identity = re.sub(r"[^a-z0-9]+", "", event_identity)
            if (
                "fileexecutabledetected" in compact_identity
                or "sysmoneventfileexedetected" in compact_identity
            ):
                return True
    except (ET.ParseError, ValueError):
        pass

    # Fallback for truncated / banner-prefixed manifests: the rule name and
    # event ID must occur on the SAME event element, not elsewhere in the XML.
    for tag in re.findall(r"<event\b[^>]*>", text, flags=re.IGNORECASE):
        value = re.search(r"\bvalue\s*=\s*['\"]29['\"]", tag, flags=re.IGNORECASE)
        identity = re.search(
            r"(?:\bname|\brulename|\btemplate)\s*=\s*['\"]([^'\"]+)['\"]",
            tag,
            flags=re.IGNORECASE,
        )
        if value and identity:
            compact = re.sub(r"[^a-z0-9]+", "", tag.casefold())
            if (
                "fileexecutabledetected" in compact
                or "sysmoneventfileexedetected" in compact
            ):
                return True
    return False


def _registered_sysmon_services() -> list[str]:
    services = []
    for name in SYSMON_SERVICE_NAMES:
        code, _out, _err = _run_process(["sc.exe", "query", name], timeout=10)
        if code == 0:
            services.append(name)
    return services


def _service_query(name: str) -> str:
    code, out, err = _run_process(["sc.exe", "query", name], timeout=10)
    return f"{out}\n{err}" if code == 0 else ""


def _service_running(name: str) -> bool:
    return bool(re.search(r"\bSTATE\s*:\s*4\s+RUNNING\b", _service_query(name), re.I))


def _service_binary_path(name: str) -> Path | None:
    code, out, err = _run_process(["sc.exe", "qc", name], timeout=10)
    if code != 0:
        return None
    match = re.search(r"BINARY_PATH_NAME\s*:\s*(.+)", out + "\n" + err, re.I)
    if not match:
        return None
    raw = match.group(1).strip()
    quoted = re.match(r'^"([^\"]+\.exe)"', raw, re.I)
    unquoted = re.match(r"^(.+?\.exe)(?:\s|$)", raw, re.I)
    candidate = (
        quoted.group(1)
        if quoted
        else (unquoted.group(1).strip('"') if unquoted else "")
    )
    if not candidate:
        return None
    try:
        return Path(os.path.expandvars(candidate)).resolve()
    except Exception:
        return Path(candidate)


def _guardian_marker() -> tuple[dict[str, Any] | None, Path]:
    marker_path = _program_data_directory() / "sysmon-install.json"
    try:
        obj = json.loads(marker_path.read_text(encoding="utf-8-sig"))
        if isinstance(obj, dict):
            return obj, marker_path
    except Exception:
        pass
    return None, marker_path


def _guardian_marker_is_intact(services: list[str]) -> bool:
    marker, _path = _guardian_marker()
    if not marker:
        return False
    try:
        config = Path(str(marker.get("ConfigPath", "")))
        binary = Path(str(marker.get("BinaryPath", "")))
        digest = str(marker.get("ConfigSha256", "")).lower()
        service = str(marker.get("ServiceName", ""))
        config_bytes = config.read_bytes()
        config_text = config_bytes.decode("utf-8-sig", "replace")
        return (
            config.is_file()
            and binary.is_file()
            and service in services
            and len(digest) == 64
            and marker.get("BlockPeCreation") is False
            and "<FileBlockExecutable" not in config_text
            and hashlib.sha256(config_bytes).hexdigest() == digest
        )
    except Exception:
        return False


def _windows_builtin_sysmon_enabled() -> bool:
    """Query optional feature through DISM directly, not PowerShell."""
    dism = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "dism.exe"
    if not dism.is_file():
        return False
    code, out, err = _run_process(
        [str(dism), "/Online", "/Get-FeatureInfo", "/FeatureName:Sysmon", "/English"],
        timeout=90,
    )
    if code != 0:
        combined = f"{out}\n{err}".lower()
        if (
            "0x800f080c" not in combined
            and "feature name sysmon is unknown" not in combined
        ):
            LOG.info(
                "DISM could not query the built-in Sysmon feature: %s",
                (err or out).strip()[-1000:],
            )
        return False
    match = re.search(r"^\s*State\s*:\s*(.+?)\s*$", out, re.I | re.M)
    return bool(match and match.group(1).strip().lower() == "enabled")


def _is_supported_windows() -> tuple[bool, str]:
    if not windows.IS_WINDOWS:
        return False, "Sysmon setup is available only on Windows."
    try:
        build = int(sys.getwindowsversion().build)
    except Exception:
        build = 0
    product_name = ""
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        ) as key:
            product_name, _kind = winreg.QueryValueEx(key, "ProductName")
    except Exception:
        pass
    display_name = _display_windows_product_name(product_name, build)
    is_server = "server" in str(display_name).lower()
    minimum = 17763 if is_server else 22000
    if build < minimum:
        required = (
            "Windows Server 2019 or newer" if is_server else "Windows 11 or newer"
        )
        return (
            False,
            f"This Sysmon release requires {required}. Detected build {build} ({display_name or 'Windows'}).",
        )
    return True, f"Supported Windows build {build} ({display_name or 'Windows'})."


def _display_windows_product_name(product_name: str, build: int) -> str:
    """Windows 11 can retain a legacy 'Windows 10' ProductName registry value."""
    value = str(product_name or "").strip()
    if build >= 22000 and value.casefold().startswith("windows 10"):
        return "Windows 11" + value[len("Windows 10") :]
    return value


def _expected_binary_name() -> str:
    arch = (
        os.environ.get("PROCESSOR_ARCHITEW6432") or platform.machine() or ""
    ).lower()
    if arch in {"arm64", "aarch64"}:
        return "Sysmon64a.exe"
    if arch in {"amd64", "x86_64", "x64"}:
        return "Sysmon64.exe"
    return "Sysmon.exe"


def _download_sysmon_archive(
    destination: Path, *, opener: Callable[..., Any] | None = None
) -> None:
    """Download over HTTPS using Python urllib (Windows registry proxy support)."""
    source = urlsplit(SYSMON_DOWNLOAD_URL)
    if source.scheme != "https" or source.hostname != SYSMON_DOWNLOAD_HOST:
        raise RuntimeError(
            "The configured Sysmon URL is not Microsoft's official HTTPS endpoint."
        )
    open_url = opener or urllib.request.urlopen
    failures: list[str] = []
    destination.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        digest = hashlib.sha256()
        total = 0
        try:
            request = urllib.request.Request(
                SYSMON_DOWNLOAD_URL,
                headers={
                    "User-Agent": "TCTC-Guardian-Z797/1.0.0",
                    "Accept": "application/zip,application/octet-stream",
                },
            )
            with open_url(request, timeout=60) as response:
                final = urlsplit(response.geturl())
                if final.scheme != "https" or final.hostname != SYSMON_DOWNLOAD_HOST:
                    raise RuntimeError(
                        f"Microsoft download redirected to an unapproved host: {final.hostname or 'unknown'}"
                    )
                status = getattr(response, "status", 200)
                if status != 200:
                    raise RuntimeError(f"Microsoft download returned HTTP {status}.")
                size_header = response.headers.get("Content-Length")
                expected = (
                    int(size_header) if size_header and size_header.isdigit() else None
                )
                if (
                    expected is not None
                    and not MIN_ARCHIVE_BYTES <= expected <= MAX_ARCHIVE_BYTES
                ):
                    raise RuntimeError(f"Unexpected Sysmon ZIP size: {expected} bytes.")
                with destination.open("wb") as output:
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > MAX_ARCHIVE_BYTES:
                            raise RuntimeError(
                                "Sysmon download exceeded the 100 MB safety limit."
                            )
                        digest.update(chunk)
                        output.write(chunk)
                if expected is not None and expected != total:
                    raise RuntimeError(
                        f"Incomplete download: expected {expected} bytes, received {total}."
                    )
            if not MIN_ARCHIVE_BYTES <= total <= MAX_ARCHIVE_BYTES:
                raise RuntimeError(
                    f"The downloaded Sysmon archive has an invalid size ({total} bytes)."
                )
            _validate_sysmon_archive(destination)
            LOG.info(
                "Sysmon ZIP downloaded (%d bytes; SHA-256 %s).",
                total,
                digest.hexdigest(),
            )
            return
        except Exception as exc:
            failures.append(f"attempt {attempt}: {type(exc).__name__}: {exc}")
            destination.unlink(missing_ok=True)
            if attempt < DOWNLOAD_ATTEMPTS:
                time.sleep(attempt * 1.5)
    raise RuntimeError(
        "Unable to download and validate Microsoft's Sysmon ZIP. Check internet/proxy/firewall access to "
        f"{SYSMON_DOWNLOAD_HOST}. Details: {' | '.join(failures)}"
    )


def _validate_sysmon_archive(archive_path: Path) -> str:
    if (
        not archive_path.is_file()
        or not MIN_ARCHIVE_BYTES <= archive_path.stat().st_size <= MAX_ARCHIVE_BYTES
    ):
        raise RuntimeError("The Sysmon archive is missing or has an invalid size.")
    expected = _expected_binary_name().lower()
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_ARCHIVE_ENTRIES:
                raise RuntimeError(
                    f"The Sysmon ZIP contains an unexpected number of entries ({len(infos)})."
                )
            uncompressed_total = sum(info.file_size for info in infos)
            if uncompressed_total > MAX_UNCOMPRESSED_ARCHIVE_BYTES:
                raise RuntimeError(
                    "The Sysmon ZIP exceeds the 200 MB uncompressed safety limit."
                )
            candidates: dict[str, zipfile.ZipInfo] = {}
            for info in infos:
                normalized = info.filename.replace("\\", "/")
                member = PurePosixPath(normalized)
                if (
                    member.is_absolute()
                    or ".." in member.parts
                    or (member.parts and ":" in member.parts[0])
                    or "\x00" in normalized
                ):
                    raise RuntimeError("The Sysmon ZIP contains an unsafe path entry.")
                if info.flag_bits & 0x1:
                    raise RuntimeError(
                        "The Sysmon ZIP contains an encrypted entry and cannot be safely validated."
                    )
                if info.is_dir():
                    continue
                if (
                    member.name.lower()
                    in {"sysmon.exe", "sysmon64.exe", "sysmon64a.exe"}
                    and MIN_EXE_BYTES <= info.file_size <= MAX_EXE_BYTES
                ):
                    key = member.name.lower()
                    if key in candidates:
                        raise RuntimeError(
                            f"The Sysmon ZIP contains duplicate {member.name} entries."
                        )
                    candidates[key] = info
            if expected not in candidates:
                raise RuntimeError(
                    f"The official ZIP does not contain {_expected_binary_name()}; found: {', '.join(sorted(candidates)) or 'no valid executables'}."
                )
            bad = archive.testzip()
            if bad:
                raise RuntimeError(f"Sysmon ZIP CRC validation failed at {bad}.")
            return candidates[expected].filename
    except zipfile.BadZipFile as exc:
        raise RuntimeError(
            f"The Microsoft Sysmon download is not a valid ZIP: {exc}"
        ) from exc


def _extract_sysmon_binary(
    archive_path: Path, member_name: str, destination: Path
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path, "r") as archive:
        info = archive.getinfo(member_name)
        if not MIN_EXE_BYTES <= info.file_size <= MAX_EXE_BYTES:
            raise RuntimeError("The selected Sysmon executable has an invalid size.")
        temp = destination.with_suffix(destination.suffix + ".partial")
        try:
            with archive.open(info) as source, temp.open("wb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
            if temp.stat().st_size != info.file_size:
                raise RuntimeError(
                    "Extracted Sysmon executable size does not match its ZIP entry."
                )
            temp.replace(destination)
        finally:
            temp.unlink(missing_ok=True)


# WinTrust structures used to validate Authenticode and inspect the signer.
class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(_GUID)),
    ]


class _WINTRUST_UNION(ctypes.Union):
    _fields_ = [
        ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
        ("pCatalog", ctypes.c_void_p),
        ("pBlob", ctypes.c_void_p),
        ("pSgnr", ctypes.c_void_p),
        ("pCert", ctypes.c_void_p),
    ]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("u", _WINTRUST_UNION),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


class _CERT_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("dwCertEncodingType", wintypes.DWORD),
        ("pbCertEncoded", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCertEncoded", wintypes.DWORD),
        ("pCertInfo", ctypes.c_void_p),
        ("hCertStore", ctypes.c_void_p),
    ]


class _CRYPT_PROVIDER_CERT(ctypes.Structure):
    # Full SDK layout is required because pasCertChain is an array of these structures.
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pCert", ctypes.POINTER(_CERT_CONTEXT)),
        ("fCommercial", wintypes.BOOL),
        ("fTrustedRoot", wintypes.BOOL),
        ("fSelfSigned", wintypes.BOOL),
        ("fTestCert", wintypes.BOOL),
        ("dwRevokedReason", wintypes.DWORD),
        ("dwConfidence", wintypes.DWORD),
        ("dwError", wintypes.DWORD),
        ("pTrustListContext", ctypes.c_void_p),
        ("fTrustListSignerCert", wintypes.BOOL),
        ("pCtlContext", ctypes.c_void_p),
        ("dwCtlError", wintypes.DWORD),
        ("fIsCyclic", wintypes.BOOL),
        ("pChainElement", ctypes.c_void_p),
    ]


class _CRYPT_PROVIDER_SIGNER(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("sftVerifyAsOf", _FILETIME),
        ("csCertChain", wintypes.DWORD),
        ("pasCertChain", ctypes.POINTER(_CRYPT_PROVIDER_CERT)),
        ("dwSignerType", wintypes.DWORD),
        ("psSigner", ctypes.c_void_p),
        ("dwError", wintypes.DWORD),
        ("csCounterSigners", wintypes.DWORD),
        ("pasCounterSigners", ctypes.c_void_p),
        ("pChainContext", ctypes.c_void_p),
    ]


def _guid_from_string(value: str) -> _GUID:
    parsed = uuid.UUID(value)
    return _GUID(
        parsed.time_low,
        parsed.time_mid,
        parsed.time_hi_version,
        (ctypes.c_ubyte * 8)(*parsed.bytes[8:]),
    )


def _certificate_organization_name(crypt32: Any, cert_ptr: Any) -> str:
    """Read the X.500 organizationName attribute from a signer certificate."""
    # CryptoAPI OIDs are narrow ASCII strings even when the output API is W.
    oid_parameter = ctypes.c_char_p(OID_ORGANIZATION_NAME.encode("ascii"))
    oid_pointer = ctypes.cast(oid_parameter, ctypes.c_void_p)
    required = int(
        crypt32.CertGetNameStringW(
            cert_ptr, CERT_NAME_ATTR_TYPE, 0, oid_pointer, None, 0
        )
    )
    if not 1 < required < 4096:
        return ""
    buffer = ctypes.create_unicode_buffer(required)
    written = int(
        crypt32.CertGetNameStringW(
            cert_ptr, CERT_NAME_ATTR_TYPE, 0, oid_pointer, buffer, required
        )
    )
    if written <= 1:
        return ""
    return buffer.value.strip()


def _verify_microsoft_authenticode(path: Path) -> str:
    """Require a trusted Authenticode signature whose signer organization is Microsoft."""
    if not windows.IS_WINDOWS:
        raise RuntimeError(
            "Authenticode verification requires the Windows trust provider."
        )
    wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    wintrust.WinVerifyTrust.argtypes = [
        wintypes.HWND,
        ctypes.POINTER(_GUID),
        ctypes.POINTER(_WINTRUST_DATA),
    ]
    wintrust.WinVerifyTrust.restype = ctypes.c_long
    wintrust.WTHelperProvDataFromStateData.argtypes = [wintypes.HANDLE]
    wintrust.WTHelperProvDataFromStateData.restype = ctypes.c_void_p
    wintrust.WTHelperGetProvSignerFromChain.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    wintrust.WTHelperGetProvSignerFromChain.restype = ctypes.POINTER(
        _CRYPT_PROVIDER_SIGNER
    )
    crypt32.CertGetNameStringW.argtypes = [
        ctypes.POINTER(_CERT_CONTEXT),
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    crypt32.CertGetNameStringW.restype = wintypes.DWORD

    action = _guid_from_string("00AAC56B-CD44-11d0-8CC2-00C04FC295EE")
    file_info = _WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(file_info)
    file_info.pcwszFilePath = str(path.resolve())
    data = _WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(data)
    data.dwUIChoice = 2  # WTD_UI_NONE
    data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
    data.dwUnionChoice = 1  # WTD_CHOICE_FILE
    data.u.pFile = ctypes.pointer(file_info)
    data.dwStateAction = 1  # WTD_STATEACTION_VERIFY
    data.dwProvFlags = 0

    status = int(
        wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
    )
    try:
        if status != 0:
            raise RuntimeError(
                f"Windows Authenticode validation failed with status 0x{status & 0xFFFFFFFF:08X}."
            )
        provider_data = wintrust.WTHelperProvDataFromStateData(data.hWVTStateData)
        if not provider_data:
            raise RuntimeError(
                "Windows validated the signature but signer details were unavailable."
            )
        publishers: list[str] = []
        for index in range(4):
            signer_ptr = wintrust.WTHelperGetProvSignerFromChain(
                provider_data, index, False, 0
            )
            if not signer_ptr:
                break
            signer = signer_ptr.contents
            if not signer.csCertChain or not signer.pasCertChain:
                continue
            cert_ptr = signer.pasCertChain[0].pCert
            if not cert_ptr:
                continue
            organization = _certificate_organization_name(crypt32, cert_ptr)
            if organization:
                publishers.append(organization)
        for publisher in publishers:
            if publisher.casefold() == "microsoft corporation":
                return publisher
        raise RuntimeError(
            "The Authenticode signature is valid, but the signer is not Microsoft Corporation. "
            f"Observed signer organization(s): {', '.join(publishers) or 'unavailable'}."
        )
    finally:
        data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))


def _sysmon_command(
    executable: Path, args: list[str], *, timeout: int = 180
) -> tuple[str, str]:
    code, stdout, stderr = _run_process([str(executable), *args], timeout=timeout)
    combined = "\n".join(x for x in (stdout, stderr) if x).strip()
    command_label = f"{executable.name} {' '.join(args)}"
    if stdout.strip():
        LOG.info(
            "Sysmon command output (%s): %s", command_label, stdout.strip()[-3000:]
        )
    if stderr.strip():
        LOG.info(
            "Sysmon command stderr (%s; exit code %s): %s",
            command_label,
            code,
            stderr.strip()[-3000:],
        )
    if code != 0:
        raise RuntimeError(
            f"Sysmon command {command_label} returned exit code {code}. "
            f"Output: {combined[-5000:]}"
        )
    # Sysmon writes some informational output to stderr. A zero exit code is
    # authoritative; stderr is retained for diagnostics and is not an exception.
    return stdout, stderr


def _write_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    try:
        with temporary.open("wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _backup_external_configuration(executable: Path) -> Path:
    stdout, stderr = _sysmon_command(executable, ["-c"], timeout=60)
    text = "\n".join(part for part in (stdout, stderr) if part).strip()
    if not text:
        raise RuntimeError(
            "Sysmon returned an empty configuration dump; refusing to replace the external policy without a backup."
        )
    backup_dir = _program_data_directory() / "Backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup = (
        backup_dir
        / f"Sysmon-current-config-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
    )
    _write_atomic(backup, (text + "\n").encode("utf-8", "replace"))
    LOG.warning("Backed up external Sysmon configuration to %s", backup)
    return backup


def _locate_or_download_binary(
    app_dir: Path, services: list[str], built_in_enabled: bool
) -> tuple[Path, str, str]:
    """Return the signed Sysmon executable, its signer and its installation source."""
    system_root = Path(os.environ.get("WINDIR", r"C:\Windows"))
    built_in = system_root / "System32" / "Sysmon.exe"
    if built_in_enabled:
        for service in services:
            service_path = _service_binary_path(service)
            if (
                service_path
                and str(service_path.resolve()).casefold()
                != str(built_in.resolve()).casefold()
            ):
                raise RuntimeError(
                    "The Windows built-in Sysmon feature is enabled while a standalone Sysmon service is registered. "
                    "Microsoft does not support running both. No existing service was changed."
                )
        if not built_in.is_file():
            raise RuntimeError(
                "The built-in Sysmon feature is enabled, but Windows\\System32\\Sysmon.exe is missing. Repair the Windows optional feature first."
            )
        return (
            built_in,
            _verify_microsoft_authenticode(built_in),
            "Windows built-in Sysmon optional feature",
        )

    if services:
        if len(services) != 1:
            raise RuntimeError(
                "Both Sysmon and Sysmon64 services are registered. Resolve this conflicting installation manually before continuing."
            )
        marker, _marker_path = _guardian_marker()
        marker_binary = Path(str(marker.get("BinaryPath", ""))) if marker else None
        candidate = (
            marker_binary
            if marker_binary and marker_binary.is_file()
            else _service_binary_path(services[0])
        )
        if not candidate or not candidate.is_file():
            raise RuntimeError(
                f"The existing {services[0]} service is registered, but its executable path could not be verified. No new copy was installed."
            )
        return (
            candidate,
            _verify_microsoft_authenticode(candidate),
            "Existing Microsoft Sysmon installation",
        )

    config_source = app_dir / "Sysmon-TCTC-Z797.xml"
    if not config_source.is_file():
        raise RuntimeError(
            f"The bundled detect-only Sysmon policy is missing: {config_source}"
        )
    program_files = (
        os.environ.get("ProgramW6432")
        or os.environ.get("ProgramFiles")
        or r"C:\Program Files"
    )
    install_root = Path(program_files) / "TCTC Guardian Z797" / "Sysmon"
    install_root.mkdir(parents=True, exist_ok=True)
    expected_name = _expected_binary_name()
    temp_root = Path(tempfile.mkdtemp(prefix="TCTC-Sysmon-"))
    try:
        archive = temp_root / "Sysmon.zip"
        LOG.info("Downloading official Sysmon package from %s", SYSMON_DOWNLOAD_URL)
        _download_sysmon_archive(archive)
        member = _validate_sysmon_archive(archive)
        downloaded = temp_root / expected_name
        _extract_sysmon_binary(archive, member, downloaded)
        signer = _verify_microsoft_authenticode(downloaded)
        target = install_root / expected_name
        staged = install_root / (expected_name + ".new")
        try:
            shutil.copy2(downloaded, staged)
            staged_signer = _verify_microsoft_authenticode(staged)
            if staged_signer.casefold() != signer.casefold():
                raise RuntimeError(
                    "The Sysmon signer changed during installation staging."
                )
            staged.replace(target)
        finally:
            staged.unlink(missing_ok=True)
        return target, _verify_microsoft_authenticode(target), SYSMON_DOWNLOAD_URL
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def _set_progress(progress: Any, label: str, QApplication: Any) -> None:
    try:
        progress.setLabelText(label)
        QApplication.processEvents()
    except Exception:
        pass


def _ask(
    parent: Any,
    QMessageBox: Any,
    *,
    title: str,
    text: str,
    informative: str,
    affirmative: str,
    negative: str = "Cancel",
    warning: bool = False,
) -> bool:
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setText(text)
    box.setInformativeText(informative)
    box.setStandardButtons(
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
    )
    box.setDefaultButton(QMessageBox.StandardButton.No)
    box.button(QMessageBox.StandardButton.Yes).setText(affirmative)
    box.button(QMessageBox.StandardButton.No).setText(negative)
    box.setIcon(QMessageBox.Icon.Warning if warning else QMessageBox.Icon.Information)
    return box.exec() == QMessageBox.StandardButton.Yes


def _apply_detect_only_policy(
    executable: Path,
    config_source: Path,
    services: list[str],
    allow_replacement: bool,
    marker_intact: bool,
    signer: str,
    install_source: str,
) -> tuple[str, Path, str]:
    """Install or update the targeted policy; PE creation blocking is forbidden here."""
    config_text = config_source.read_text(encoding="utf-8-sig")
    if "<FileExecutableDetected" not in config_text:
        raise RuntimeError(
            "The bundled Sysmon XML is missing the required PE-creation detection rule."
        )
    if re.search(r"<FileBlockExecutable\b", config_text, re.IGNORECASE):
        raise RuntimeError(
            "The default Sysmon XML unexpectedly enables PE creation blocking; refusing to install it."
        )

    program_data = _program_data_directory()
    config_target = program_data / "Sysmon-TCTC-Z797.xml"
    marker, marker_path = _guardian_marker()
    if services and not marker_intact:
        if not allow_replacement:
            raise RuntimeError(
                "The existing Sysmon configuration is externally managed and replacement was not approved."
            )
        _backup_external_configuration(executable)

    if services:
        # A stopped pre-existing service must be started before its driver can
        # accept a configuration update. Do not stop/uninstall a service.
        if not _service_running(services[0]):
            start_code, start_out, start_err = _run_process(
                ["sc.exe", "start", services[0]], timeout=30
            )
            if start_code != 0 and not _service_running(services[0]):
                raise RuntimeError(
                    f"Could not start the existing Sysmon service before updating its configuration: {(start_err or start_out).strip()}"
                )

    _write_atomic(config_target, config_source.read_bytes())
    if services:
        LOG.info(
            "Applying the TCTC Guardian detect-only policy to existing Sysmon service %s.",
            services[0],
        )
        _sysmon_command(executable, ["-c", str(config_target)], timeout=180)
    else:
        LOG.info(
            "Installing Sysmon service and driver with the detect-only TCTC Guardian policy."
        )
        _sysmon_command(
            executable, ["-accepteula", "-i", str(config_target)], timeout=240
        )

    service_name = ""
    started = time.monotonic()
    while time.monotonic() - started < 30:
        for candidate in SYSMON_SERVICE_NAMES:
            if _service_running(candidate):
                service_name = candidate
                break
        if service_name:
            break
        time.sleep(1)
    if not service_name:
        details = "; ".join(
            f"{name}: {_service_query(name).strip() or 'not present'}"
            for name in SYSMON_SERVICE_NAMES
        )
        raise RuntimeError(
            f"Sysmon did not reach the Running state within 30 seconds. {details}"
        )

    channel_code, channel_out, channel_err = _run_process(
        ["wevtutil.exe", "gl", SYSMON_CHANNEL], timeout=25
    )
    if channel_code != 0:
        raise RuntimeError(
            f"The Sysmon Operational event channel is unavailable: {(channel_err or channel_out).strip()}"
        )

    digest = hashlib.sha256(config_target.read_bytes()).hexdigest()
    # The CLI schema output is not a product version; do not mislabel file size
    # as a version number in the readiness marker.
    binary_version = "unknown"
    marker_data = {
        "InstalledAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ServiceName": service_name,
        "BinaryPath": str(executable.resolve()),
        "BinaryVersion": binary_version,
        "BinarySigner": signer,
        "ConfigPath": str(config_target.resolve()),
        "ConfigSha256": digest,
        "BlockPeCreation": False,
        "ConfigVariant": "detect-only",
        "InstallSource": install_source,
    }
    _write_atomic(
        marker_path,
        (json.dumps(marker_data, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
    )
    return service_name, config_target, binary_version


def _run_in_worker(
    work: Callable[[Callable[[str], None]], Any], progress: Any, QApplication: Any
) -> Any:
    """Run blocking network/native operations off the Qt thread while pumping UI events."""
    state: dict[str, Any] = {"done": False, "value": None, "error": None}
    current_stage = [""]

    def set_stage(label: str) -> None:
        current_stage[0] = str(label)

    def run() -> None:
        try:
            state["value"] = work(set_stage)
        except BaseException as exc:
            state["error"] = exc
        finally:
            state["done"] = True

    worker = threading.Thread(target=run, name="TCTC-Sysmon-Bootstrap", daemon=True)
    worker.start()
    shown = None
    while not state["done"]:
        QApplication.processEvents()
        if current_stage[0] and current_stage[0] != shown:
            try:
                progress.setLabelText(current_stage[0])
            except Exception:
                pass
            shown = current_stage[0]
        worker.join(0.08)
    worker.join()
    if state["error"] is not None:
        raise state["error"]
    return state["value"]


def ensure_sysmon_ready(
    parent: Any, QMessageBox: Any, QProgressDialog: Any, QApplication: Any
) -> bool:
    """Ensure a trusted Sysmon sensor is installed and configured from Python."""
    if not windows.IS_WINDOWS:
        return False
    ready, detail = sysmon_readiness()
    if ready:
        LOG.info("Sysmon readiness check passed: %s", detail)
        return True

    supported, support_detail = _is_supported_windows()
    if not supported:
        QMessageBox.critical(parent, "Unsupported Windows version", support_detail)
        LOG.error("Sysmon setup is not supported: %s", support_detail)
        return False

    app_dir = _application_directory()
    config_source = app_dir / "Sysmon-TCTC-Z797.xml"
    if not config_source.is_file():
        message = f"The bundled detect-only Sysmon policy is missing:\n{config_source}"
        QMessageBox.critical(parent, "Sysmon policy missing", message)
        LOG.error(message)
        return False

    services = _registered_sysmon_services()
    marker_intact = _guardian_marker_is_intact(services)
    allow_replacement = False
    if services and not marker_intact:
        allow_replacement = _ask(
            parent,
            QMessageBox,
            title="Existing Sysmon configuration",
            text="Sysmon is already installed with a configuration not verified as managed by TCTC Guardian.",
            informative=(
                "Guardian can export a backup of the active configuration, then apply its targeted "
                "Z797 detect-only policy. This may replace settings managed by another security "
                "product or administrator, or disable an older PE-block policy. Continue only when "
                "authorized. No PE files will be blocked by the policy installed by this release."
            ),
            affirmative="Back up and configure",
            negative="Leave unchanged",
            warning=True,
        )
        if not allow_replacement:
            LOG.warning(
                "User declined replacing an externally managed Sysmon configuration."
            )
            QMessageBox.information(
                parent,
                "Sysmon was left unchanged",
                "Guardian will open, but continuous monitoring remains unavailable until Sysmon is configured.",
            )
            return False

    log_dir = _log_directory()
    setup_log = log_dir / "sysmon-setup.log"
    progress = None
    setup_handler = None
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        setup_handler = logging.FileHandler(
            setup_log, mode="a", encoding="utf-8", delay=True
        )
        setup_handler.setLevel(logging.INFO)
        setup_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        )
        LOG.addHandler(setup_handler)

        progress = QProgressDialog(
            "Checking the Windows Sysmon feature…", "", 0, 0, parent
        )
        progress.setWindowTitle("Setting up protection")
        progress.setCancelButton(None)
        progress.setMinimumDuration(0)
        progress.setAutoClose(False)
        progress.setAutoReset(False)
        progress.show()
        QApplication.processEvents()

        LOG.info(
            "Starting Python-native Sysmon setup. Initial readiness: %s; %s",
            detail,
            support_detail,
        )
        # DISM can take several seconds, so query it off the GUI thread.
        built_in_enabled = _run_in_worker(
            lambda set_stage: (
                set_stage("Checking the Windows built-in Sysmon feature…")
                or _windows_builtin_sysmon_enabled()
            ),
            progress,
            QApplication,
        )
        progress.close()
        progress = None

        accept_license = not services and not built_in_enabled
        if accept_license:
            agreed = _ask(
                parent,
                QMessageBox,
                title="Microsoft Sysmon license",
                text="TCTC Guardian needs Microsoft Sysmon for continuous monitoring.",
                informative=(
                    "The application will download Sysmon only from Microsoft's official Sysinternals HTTPS site, "
                    "validate the ZIP, verify the Microsoft Authenticode signature with Windows security APIs, "
                    "install it, and apply the targeted Z797 policy. The default is DETECT-ONLY: executable-file "
                    "creation will be detected, never blocked. By selecting Agree & Install, you accept the "
                    "Microsoft Sysinternals license terms. "
                    '<br><a href="https://learn.microsoft.com/en-us/sysinternals/license-terms">Review Microsoft license terms</a>'
                ),
                affirmative="Agree & Install",
                negative="Cancel",
            )
            if not agreed:
                LOG.info(
                    "Sysmon installation cancelled because the user did not accept the license."
                )
                QMessageBox.information(
                    parent,
                    "Sysmon was not installed",
                    "Guardian will open, but continuous monitoring cannot start until Sysmon is installed.",
                )
                return False

        progress = QProgressDialog("Preparing Microsoft Sysmon…", "", 0, 0, parent)
        progress.setWindowTitle("Setting up protection")
        progress.setCancelButton(None)
        progress.setMinimumDuration(0)
        progress.setAutoClose(False)
        progress.setAutoReset(False)
        progress.show()
        QApplication.processEvents()
        setup_started = time.monotonic()

        def perform_setup(
            set_stage: Callable[[str], None],
        ) -> tuple[str, Path, str, str]:
            set_stage("Selecting the Microsoft Sysmon binary…")
            executable, signer, install_source = _locate_or_download_binary(
                app_dir, services, built_in_enabled
            )
            LOG.info(
                "Selected Sysmon executable %s; signer=%s; source=%s",
                executable,
                signer,
                install_source,
            )

            set_stage("Checking Sysmon schema support…")
            schema_out, schema_err = _sysmon_command(executable, ["-s"], timeout=90)
            schema = f"{schema_out}\n{schema_err}"
            if not _schema_supports_file_executable_detected(schema):
                # Keep diagnostics actionable without dumping a multi-megabyte manifest.
                schema_preview = re.sub(
                    r"\s+", " ", schema.replace("\x00", " ")
                ).strip()[:1200]
                LOG.error(
                    "Sysmon schema check did not find Event 29. Decoded output preview: %s",
                    schema_preview,
                )
                raise RuntimeError(
                    "The selected Sysmon binary did not confirm the required PE-creation detection event (Event 29). "
                    "The schema output could not be decoded or did not contain the expected event metadata. "
                    "No Sysmon configuration was changed."
                )
            LOG.info(
                "Sysmon schema supports FileExecutableDetected. PE creation blocking stays disabled."
            )

            set_stage("Applying the detect-only monitoring policy…")
            service_name, config_target, binary_version = _apply_detect_only_policy(
                executable,
                config_source,
                services,
                allow_replacement,
                marker_intact,
                signer,
                install_source,
            )
            return service_name, config_target, binary_version, signer

        service_name, config_target, binary_version, signer = _run_in_worker(
            perform_setup, progress, QApplication
        )
        LOG.info(
            "Sysmon setup metadata: service=%s config=%s binary=%s signer=%s",
            service_name,
            config_target,
            binary_version,
            signer,
        )
        verified, verified_detail = sysmon_readiness()
        if not verified:
            raise RuntimeError(
                f"Sysmon setup completed but readiness verification failed: {verified_detail}"
            )
        LOG.info("Python-native Sysmon setup completed: %s", verified_detail)
        LOG.info(
            "Sysmon setup duration: %.1f seconds", time.monotonic() - setup_started
        )
        QMessageBox.information(
            parent,
            "Protection sensor ready",
            "Microsoft Sysmon is installed and verified.\n\n"
            "PE creation mode: DETECT-ONLY. No files will be blocked.\n"
            f"Service: {service_name}\nEvent channel: {SYSMON_CHANNEL}\n\nSetup log: {setup_log}",
        )
        return True
    except Exception as exc:
        LOG.exception("Python-native Sysmon setup failed")
        try:
            with setup_log.open("a", encoding="utf-8", errors="replace") as output:
                output.write(
                    f"\n[{datetime.now(timezone.utc).isoformat()}] ERROR: {type(exc).__name__}: {exc}\n"
                )
        except Exception:
            pass
        QMessageBox.critical(
            parent,
            "Sysmon setup failed",
            f"TCTC Guardian could not prepare its monitoring sensor.\n\n{exc}\n\n"
            f"Detailed log: {setup_log}\n\nThe application will open for manual investigation, but continuous monitoring remains unavailable.",
        )
        return False
    finally:
        if progress is not None:
            try:
                progress.close()
            except Exception:
                pass
        if setup_handler is not None:
            try:
                LOG.removeHandler(setup_handler)
                setup_handler.close()
            except Exception:
                pass
