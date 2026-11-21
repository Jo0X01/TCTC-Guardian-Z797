from __future__ import annotations

"""User settings for the narrowly-scoped TCTC/Z797 guardian."""

import copy
import json
import os
from pathlib import Path
from typing import Any

from guardian.threat_profile import DEFAULT_THREAT_PROFILE

APP_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TCTC Guardian Z797"
SETTINGS_PATH = APP_DIR / "settings.json"

# Only settings consumed by the scanner, monitor, or remediation policy are exposed.
DEFAULT_SETTINGS: dict[str, Any] = {
    "monitoring_enabled": True,
    "monitoring_start_with_windows": False,
    "monitoring_notifications": True,
    "monitoring_interval_minutes": 5,
    "monitor_processes": True,
    "monitor_memory": True,
    "monitor_network": True,
    "monitor_files": True,
    "monitor_persistence": True,
    "monitor_eventlogs": True,
    "memory_process_include": ["runtimebroker.exe", "explorer.exe", "chrome.exe", "csc.exe"],
    "memory_evidence_dir": "",
    "memory_private_exec": True,
    "memory_manual_map": True,
    "memory_thread_start": True,
    "memory_integrity": True,
    "memory_image_identity": True,
    "memory_capture_regions": True,
    "auto_contain_exact_sample": True,
    "firewall_policy": "Ask before blocking",
    "event_log_record_limit": 5000,
    "settings_schema_version": 4,
    # Profile values are immutable and intentionally not presented as user options.
    "c2_domains": list(DEFAULT_THREAT_PROFILE["c2_domains"]),
    "c2_ips": list(DEFAULT_THREAT_PROFILE["c2_ips"]),
    "c2_urls": list(DEFAULT_THREAT_PROFILE["c2_urls"]),
}

_MEMORY_TARGETS = {"runtimebroker.exe", "explorer.exe", "chrome.exe", "csc.exe"}
_FIREWALL_POLICIES = {"Ask before blocking", "Never change Firewall rules"}


def read_settings() -> dict[str, Any]:
    settings = copy.deepcopy(DEFAULT_SETTINGS)
    legacy = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TCTC Guardian" / "settings.json"
    source = SETTINGS_PATH if SETTINGS_PATH.exists() else legacy
    try:
        raw = json.loads(source.read_text(encoding="utf-8")) if source.exists() else {}
        if isinstance(raw, dict):
            old_schema = int(raw.get("settings_schema_version", 0) or 0)
            settings.update({key: value for key, value in raw.items() if key in DEFAULT_SETTINGS})
            # Earlier internal builds used smaller defaults; migrate only known legacy defaults.
            if old_schema < 3 and int(raw.get("event_log_record_limit", 250) or 250) in {250, 2000}:
                settings["event_log_record_limit"] = 5000
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass

    # Immutable, sample-specific IOC scope; old custom or sibling-campaign values are ignored.
    for key in ("c2_domains", "c2_ips", "c2_urls"):
        settings[key] = list(DEFAULT_THREAT_PROFILE[key])

    policy = str(settings.get("firewall_policy", "Ask before blocking"))
    if policy not in _FIREWALL_POLICIES:
        policy = "Ask before blocking"
    settings["firewall_policy"] = policy
    try:
        settings["monitoring_interval_minutes"] = max(1, min(60, int(settings.get("monitoring_interval_minutes", 5))))
    except (TypeError, ValueError):
        settings["monitoring_interval_minutes"] = 5
    try:
        settings["event_log_record_limit"] = max(100, min(5000, int(settings.get("event_log_record_limit", 5000))))
    except (TypeError, ValueError):
        settings["event_log_record_limit"] = 5000
    settings["memory_process_include"] = [
        str(x).lower() for x in settings.get("memory_process_include", [])
        if str(x).lower() in _MEMORY_TARGETS
    ] or list(DEFAULT_SETTINGS["memory_process_include"])
    settings["settings_schema_version"] = 4
    return settings


def write_settings(settings: dict[str, Any]) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    payload = {key: settings.get(key, value) for key, value in DEFAULT_SETTINGS.items()}
    # Never persist user-added indicators or arbitrary roots.
    for key in ("c2_domains", "c2_ips", "c2_urls"):
        payload[key] = list(DEFAULT_THREAT_PROFILE[key])
    payload["settings_schema_version"] = 4
    temp = SETTINGS_PATH.with_suffix(".tmp")
    temp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(temp, SETTINGS_PATH)


def enabled_stages(settings: dict[str, Any], *, monitoring: bool = False) -> set[str]:
    mapping = {
        "monitor_processes": "processes",
        "monitor_memory": "memory",
        "monitor_persistence": "persistence",
        "monitor_files": "staging",
        "monitor_network": "network",
        "monitor_eventlogs": "eventlogs",
    }
    selected = {stage for key, stage in mapping.items() if settings.get(key, True)}
    selected.add("verification")
    if "memory" in selected:
        selected.add("processes")
    return selected


def engine_args(
    settings: dict[str, Any], *, monitoring: bool = False,
    staging_cache: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    args = {
        "c2_domains": list(DEFAULT_THREAT_PROFILE["c2_domains"]),
        "c2_ips": list(DEFAULT_THREAT_PROFILE["c2_ips"]),
        "c2_urls": list(DEFAULT_THREAT_PROFILE["c2_urls"]),
        "event_log_record_limit": int(settings.get("event_log_record_limit", 5000)),
        "enabled_stages": enabled_stages(settings, monitoring=monitoring),
        "memory_settings": {
            key: settings.get(key) for key in (
                "memory_process_include", "memory_capture_regions", "memory_private_exec",
                "memory_manual_map", "memory_thread_start", "memory_integrity", "memory_image_identity",
                "firewall_policy",
            )
        },
        "evidence_dir": settings.get("memory_evidence_dir") or None,
    }
    if monitoring:
        args["monitoring_mode"] = True
        args["staging_cache"] = staging_cache if staging_cache is not None else {}
    return args
