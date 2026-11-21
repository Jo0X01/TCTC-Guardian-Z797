from __future__ import annotations

"""Built-in indicators recovered from the specific TCTC/Z797 sample chain.

Only these domains, URLs and IPs are used by Guardian. Indicators from sibling
ClickFix/LegionLoader/ROMULUS reports are intentionally not imported.
"""

CONFIRMED_CAMPAIGN_DOMAINS: tuple[str, ...] = (
    "benderoflight.com",   # recovered controller domain
    "survivomatic.com",    # recovered task-download host
    "ruthaiv.com",         # recovered task-download host
)

CONFIRMED_CAMPAIGN_IPS: tuple[str, ...] = (
    "93.94.52.29",         # initial ClickFix delivery host
    "109.238.86.137",      # observed TLS destination associated with benderoflight.com /nfront.php
)

CONFIRMED_CAMPAIGN_IP_ROLES: dict[str, str] = {
    "93.94.52.29": "Initial ClickFix delivery server for crandle.txt and Z797.ps1.",
    "109.238.86.137": "Observed in the locally recovered PCAP as a TLS destination associated with benderoflight.com /nfront.php. IP-only matches are not attributed to Z797 without process identity.",
}

CONFIRMED_CAMPAIGN_URLS: tuple[str, ...] = (
    "https://benderoflight.com/nfront.php",
    "https://benderoflight.com/nback.php",
)

DEFAULT_THREAT_PROFILE = {
    "c2_domains": list(CONFIRMED_CAMPAIGN_DOMAINS),
    "c2_ips": list(CONFIRMED_CAMPAIGN_IPS),
    "c2_urls": list(CONFIRMED_CAMPAIGN_URLS),
}


def merge_default_indicators(_settings: dict) -> dict:
    """Return only the immutable IOCs recovered from this exact sample chain."""
    return {key: list(value) for key, value in DEFAULT_THREAT_PROFILE.items()}
