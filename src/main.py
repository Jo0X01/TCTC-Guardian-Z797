from __future__ import annotations

import argparse
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from guardian.windows import is_admin, relaunch_as_admin


def configure_logging() -> None:
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TCTC Guardian Z797" / "Logs"
    try:
        base.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(base / "guardian.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        logging.basicConfig(level=logging.INFO, handlers=[handler], format="%(asctime)s %(levelname)s %(message)s")
    except Exception:
        logging.basicConfig(level=logging.INFO)


def main() -> int:
    parser = argparse.ArgumentParser(description="TCTC Guardian Z797 targeted Windows investigation utility")
    parser.add_argument("--self-check", action="store_true", help="Check imports and indicator rules without scanning the host")
    parser.add_argument("--start-monitoring", action="store_true", help="Start configured continuous monitoring after launch")
    parser.add_argument("--start-hidden", action="store_true", help="Start minimized to the system tray")
    args = parser.parse_args()
    configure_logging()
    if args.self_check:
        from guardian.indicators import suspicious_command, is_temp_local_path
        from guardian.memory import select_memory_targets
        assert is_temp_local_path(r"C:\Users\Demo\AppData\Local\Temp\Local\x.exe")
        assert suspicious_command(r"C:\Users\Demo\AppData\Local\Temp\Local\csc.exe")[0]
        assert not suspicious_command(r"C:\Windows\System32\RuntimeBroker.exe")[0]
        selected = select_memory_targets([
            {"name": "RuntimeBroker.exe", "path": r"C:\Windows\System32\RuntimeBroker.exe"},
            {"name": "notepad.exe", "path": r"C:\Windows\System32\notepad.exe"},
        ], {})
        assert len(selected) == 1 and selected[0]["name"].lower() == "runtimebroker.exe"
        print("TCTC Guardian Z797 self-check passed")
        return 0

    if os.name == "nt" and not is_admin():
        if relaunch_as_admin():
            return 0
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                None,
                "TCTC Guardian Z797 requires Administrator privileges. The application will close because continuing without elevation would produce incomplete results.",
                "Administrator access required",
                0x10 | 0x1000,
            )
        except Exception:
            print("Administrator access is required. Relaunch the application and approve the UAC prompt.")
        return 1

    try:
        # Apply the narrow ICC warning filter before importing/initializing Qt.
        from guardian.qt_runtime import configure_qt_logging_environment
        configure_qt_logging_environment()
        from PySide6.QtWidgets import QApplication, QMessageBox, QProgressDialog
        from guardian.ui import GuardianWindow
    except ImportError as exc:
        message = f"PySide6 is required. Run Install-Dependencies.bat first. Details: {exc}"
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, message, "Missing application dependency", 0x10)
        except Exception:
            print(message, file=sys.stderr)
        return 2

    app = QApplication(sys.argv[:1])
    app.setApplicationName("TCTC Guardian Z797")
    app.setOrganizationName("TCTC Guardian Project")
    app.setQuitOnLastWindowClosed(False)

    # Sysmon is an application-managed prerequisite: users do not run a separate installer.
    # If setup is declined or fails, the UI still opens for manual investigation;
    # continuous monitoring remains unavailable until Sysmon passes readiness checks.
    try:
        from guardian.sysmon_setup import ensure_sysmon_ready
        ensure_sysmon_ready(None, QMessageBox, QProgressDialog, QApplication)
    except Exception:
        logging.exception("Unexpected failure during application-managed Sysmon setup")

    window = GuardianWindow(start_monitoring_requested=args.start_monitoring, start_hidden=args.start_hidden)
    # Do not strand a hidden process when Windows has no usable tray shell.
    if not args.start_hidden or getattr(window, "tray", None) is None:
        window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
