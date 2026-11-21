from __future__ import annotations

"""Small Qt runtime adjustments made before the GUI framework is imported."""

import os


_QT_ICC_FILTER = "qt.gui.icc.warning=false"


def configure_qt_logging_environment() -> None:
    """Filter only Qt's noisy ICC-profile warnings.

    Qt rejects an invalid/unsupported display or image ICC profile and falls
    back to its normal color handling. Guardian's interface uses explicit RGB
    colors, so these repeated parser warnings add no actionable information.
    All other Qt warnings and errors remain visible.
    """
    current = os.environ.get("QT_LOGGING_RULES", "")
    rules = [
        line.strip()
        for line in current.replace(";", "\n").splitlines()
        if line.strip() and not line.strip().startswith("qt.gui.icc.warning=")
    ]
    rules.append(_QT_ICC_FILTER)
    os.environ["QT_LOGGING_RULES"] = "\n".join(rules)
