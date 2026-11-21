from __future__ import annotations

"""Fail-closed policy for automatic containment of exact Z797 artifacts."""

from typing import Any

from guardian.indicators import KNOWN_SAMPLE_ARTIFACTS, is_known_staging_path


def is_exact_sample_auto_containment_candidate(
    finding: dict[str, Any], *, require_event_driven: bool = True
) -> bool:
    """Fail-closed gate for automatic containment of recovered sample artifacts.

    Realtime events require event_driven=True. A periodic monitor inventory may
    set require_event_driven=False, but still needs the exact hash/size/category
    and the exact analyzed Temp\\Local staging boundary.
    """
    meta = finding.get("metadata") or {}
    digest = str(finding.get("sha256", "")).lower()
    known = KNOWN_SAMPLE_ARTIFACTS.get(digest)
    if not known or not bool(meta.get("hash_size_verified")):
        return False
    if require_event_driven and not bool(meta.get("event_driven")):
        return False
    if finding.get("category") != "Exact sample fingerprint":
        return False
    if finding.get("severity") != "Critical" or finding.get("confidence") != "High":
        return False
    if finding.get("remediation") not in {
        "quarantine_file",
        "contain_exact_sample_process",
    }:
        return False
    try:
        if int(meta.get("expected_size", 0)) != int(known[0]):
            return False
        return is_known_staging_path(str(finding.get("path", "")))
    except (TypeError, ValueError, OSError):
        return False
