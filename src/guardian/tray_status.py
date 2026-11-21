"""Human-readable System Tray protection state; intentionally Qt-independent."""

from __future__ import annotations


def tray_status_details(active: bool) -> dict[str, str]:
    if active:
        return {
            "color": "#22c55e",
            "menu_text": "Monitoring: ON · protection active",
            "tooltip": "TCTC Guardian Z797\nMonitoring: ACTIVE\nThe app is running in the system tray.",
        }
    return {
        "color": "#ef4444",
        "menu_text": "Monitoring: OFF · app is still running, protection paused",
        "tooltip": "TCTC Guardian Z797\nMonitoring: STOPPED\nThe app is still running, but continuous checks are paused.",
    }
