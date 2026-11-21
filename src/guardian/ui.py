from __future__ import annotations

import copy
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QThread, Signal, QUrl, QTimer
from PySide6.QtGui import (
    QAction,
    QCloseEvent,
    QDesktopServices,
    QIcon,
    QColor,
    QPainter,
    QPixmap,
    QPen,
    QBrush,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSystemTrayIcon,
    QTabWidget,
    QTableWidget,
    QHeaderView,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
    QGroupBox,
    QScrollArea,
    QSizePolicy,
    QSplitter,
)

from guardian import __version__, windows
from guardian.scanner import ScanEngine
from guardian.reports import save_report, report_directory
from guardian.network_diagnostics import collect_network_diagnostics
from guardian.threat_profile import DEFAULT_THREAT_PROFILE
from guardian.tray_status import tray_status_details
from guardian.settings import (
    DEFAULT_SETTINGS,
    read_settings as _read_settings,
    write_settings as _write_settings,
    enabled_stages as _enabled_stages,
    engine_args as _engine_args,
)
from guardian.containment_policy import is_exact_sample_auto_containment_candidate
from guardian.resource_paths import resolve_resource
from guardian.remediation import (
    read_quarantine_index,
    remediate_finding,
    restore_quarantined_file,
    permanently_delete_quarantined_file,
    restore_registry_backup,
    restore_action_backup,
    backup_directory,
)

APP_NAME = "TCTC Guardian Z797"

DARK_QSS = """
QWidget {
    background: #0a1220;
    color: #e8eef7;
    font-family: 'Segoe UI';
    font-size: 9pt;
}
QMainWindow { background: #0a1220; }
QFrame#Header, QFrame#Panel, QFrame#StatusPanel {
    background: #111e30;
    border: 1px solid #263a52;
    border-radius: 13px;
}
QFrame#Header { background: #101c2d; border-color: #2b425d; }
QFrame#StatusPanel { background: #0f1b2b; border-color: #22364d; }
QLabel#Brand { font-size: 15.5pt; font-weight: 750; color: #f5f8ff; }
QLabel#Subtle { color: #91a6bf; }
QLabel#Metric, QLabel#MetricCritical, QLabel#MetricHigh,
QLabel#MetricMedium, QLabel#MetricTotal {
    font-size: 23pt;
    font-weight: 750;
    color: #f5f8ff;
}
QLabel#MetricCritical { color: #ff727a; }
QLabel#MetricHigh { color: #ffad66; }
QLabel#MetricMedium { color: #e9c66b; }
QLabel#MetricTotal { color: #e8f3ff; }
QLabel#HeaderStatus {
    border: 1px solid #665331;
    border-radius: 10px;
    padding: 6px 10px;
    background: #2a241b;
    color: #f3c36d;
    font-weight: 700;
}
QLabel#HeaderStatus[state="active"] {
    border-color: #246a5a;
    background: #142d2b;
    color: #5de0ae;
}
QLabel#HeaderStatus[state="warning"] {
    border-color: #765b2d;
    background: #30291e;
    color: #f4c66d;
}
QLabel#CurrentTask { color: #62d5e1; font-weight: 650; }
QTabWidget::pane {
    border: 1px solid #263a52;
    border-radius: 11px;
    top: -1px;
    background: #0e1928;
}
QTabBar::tab {
    background: #111d2e;
    color: #9db0c6;
    padding: 8px 13px;
    margin-right: 3px;
    min-height: 16px;
    border: 1px solid #1b2d43;
    border-bottom: 2px solid transparent;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
}
QTabBar::tab:hover { background: #182a40; color: #dce9f7; }
QTabBar::tab:selected {
    background: #1a3048;
    color: #5bd3df;
    border-color: #2c4a65;
    border-bottom: 2px solid #27b7c7;
}
QPushButton {
    background: #1a2e45;
    color: #edf5ff;
    border: 1px solid #304b68;
    border-radius: 8px;
    padding: 7px 12px;
    min-height: 16px;
    font-weight: 650;
}
QPushButton:hover { background: #25435f; border-color: #3c9baa; }
QPushButton:pressed { background: #14273b; }
QPushButton:disabled { color: #647990; background: #142235; border-color: #223249; }
QPushButton#Primary { background: #087f91; border-color: #1098aa; color: white; }
QPushButton#Primary:hover { background: #0999ad; border-color: #36c4d0; }
QPushButton#Danger { background: #512638; border-color: #79384f; color: #ffeaf0; }
QPushButton#Danger:hover { background: #713047; border-color: #a44b65; }
QLineEdit, QPlainTextEdit, QTextBrowser, QComboBox, QSpinBox {
    background: #0b1726;
    border: 1px solid #2a405a;
    border-radius: 8px;
    padding: 6px;
    selection-background-color: #087f91;
}
QLineEdit:focus, QPlainTextEdit:focus, QTextBrowser:focus,
QComboBox:focus, QSpinBox:focus { border-color: #168fa0; }
QComboBox QAbstractItemView {
    background: #132238;
    color: #e8eef7;
    border: 1px solid #344e69;
    selection-background-color: #1d4560;
    padding: 4px;
}
QFrame#SettingCard {
    background: #0d1a2a;
    border: 1px solid #253a52;
    border-radius: 9px;
}
QFrame#SettingCard:hover { border-color: #31536c; }
QGroupBox {
    background: #101d2d;
    border: 1px solid #283d56;
    border-radius: 10px;
    margin-top: 10px;
    padding: 9px 9px 8px 9px;
    font-weight: 700;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: #b8cadd;
}
QCheckBox { spacing: 7px; padding: 1px; }
QCheckBox::indicator { width: 17px; height: 17px; }
QCheckBox::indicator:unchecked { background: #0b1726; border: 1px solid #536a82; border-radius: 5px; }
QCheckBox::indicator:checked { background: #13a0ad; border: 1px solid #13a0ad; border-radius: 5px; }
QTableWidget {
    background: #0b1726;
    alternate-background-color: #101e30;
    gridline-color: #20344b;
    border: 1px solid #293f59;
    border-radius: 9px;
    selection-background-color: #19485a;
    selection-color: #f2fbff;
}
QHeaderView::section {
    background: #182a40;
    color: #b6c8da;
    padding: 8px 7px;
    border: none;
    border-bottom: 1px solid #2a405a;
    font-weight: 700;
}
QTableWidget::item { padding: 4px; }
QProgressBar {
    background: #1a2a3e;
    border: 0;
    border-radius: 6px;
    height: 11px;
    text-align: center;
}
QProgressBar::chunk { background: #20b8c9; border-radius: 6px; }
QScrollBar:vertical { background: #0c1726; width: 9px; margin: 2px; border-radius: 5px; }
QScrollBar::handle:vertical { background: #344c66; min-height: 28px; border-radius: 5px; }
QScrollBar::handle:vertical:hover { background: #4b6a87; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: #0c1726; height: 9px; margin: 2px; border-radius: 5px; }
QScrollBar::handle:horizontal { background: #344c66; min-width: 28px; border-radius: 5px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QTextBrowser a { color: #54cbd8; }
QToolTip { background: #18283b; color: #fff; border: 1px solid #405a76; padding: 5px; }
"""


def _named(widget, name: str):
    widget.setObjectName(name)
    return widget


class ScanWorker(QThread):
    event = Signal(dict)
    completed = Signal(dict, dict)
    failed = Signal(str)

    def __init__(
        self,
        args: dict[str, Any],
        scan_lock: threading.Lock,
        cancel_event: threading.Event,
    ):
        super().__init__()
        self.args = args
        self.scan_lock = scan_lock
        self.cancel_event = cancel_event

    def run(self) -> None:
        try:
            with self.scan_lock:
                engine = ScanEngine(
                    event_callback=self.event.emit,
                    cancel_event=self.cancel_event,
                    **self.args,
                )
                report = engine.run()
            paths = save_report(report)
            self.completed.emit(report.to_dict(), paths)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class MonitorWorker(QThread):
    event = Signal(dict)
    cycle_completed = Signal(dict, dict)
    failed = Signal(str)
    state = Signal(str)

    def __init__(self, settings: dict[str, Any], scan_lock: threading.Lock):
        super().__init__()
        self.settings = copy.deepcopy(settings)
        self.scan_lock = scan_lock
        self.stop_event = threading.Event()
        self.realtime_sensor = None
        # Shared only by this monitor thread; manual investigations always perform full hashes.
        self.staging_cache: dict[str, dict[str, Any]] = {}

    def stop(self) -> None:
        # Non-blocking: native Event Log and filesystem observers are closed in
        # this QThread's finally block, never on the Qt GUI thread.
        self.stop_event.set()

    def run(self) -> None:
        interval = max(1, int(self.settings.get("monitoring_interval_minutes", 3))) * 60
        self.state.emit("Checking required Sysmon sensor")
        sysmon_mode_label = "offline"
        if os.name == "nt":
            from guardian.realtime import sysmon_readiness

            ready, detail = sysmon_readiness()
            if not ready:
                self.event.emit(
                    {
                        "type": "log",
                        "level": "ERROR",
                        "message": "Required Sysmon sensor is not ready",
                        "detail": detail
                        + " Restart TCTC Guardian to run the automatic Sysmon setup. Monitoring will not start in degraded mode.",
                    }
                )
                self.state.emit("Monitoring stopped · Sysmon prerequisite missing")
                return
            self.event.emit(
                {
                    "type": "log",
                    "level": "SUCCESS",
                    "message": "Required Sysmon sensor verified",
                    "detail": detail,
                }
            )
            sysmon_mode_label = (
                "PE block ON"
                if "PE creation block ENABLED" in detail
                else "PE detect-only"
            )
        self.state.emit("Monitoring active · " + sysmon_mode_label)
        if os.name == "nt":
            try:
                from guardian.realtime import RealtimeMonitor

                self.realtime_sensor = RealtimeMonitor(
                    callback=self.event.emit,
                    monitor_processes=bool(
                        self.settings.get("monitor_processes", True)
                    ),
                    monitor_files=bool(self.settings.get("monitor_files", True)),
                    monitor_network=bool(self.settings.get("monitor_network", True)),
                    monitor_persistence=bool(
                        self.settings.get("monitor_persistence", True)
                    ),
                    monitor_powershell=bool(
                        self.settings.get("monitor_eventlogs", True)
                    ),
                )
                status = self.realtime_sensor.start()
                event_channels = [
                    name
                    for name in (
                        "Sysmon",
                        "Security",
                        "PowerShell",
                        "Task Scheduler",
                        "WMI Activity",
                    )
                    if status.get(name) == "active"
                ]
                sources = list(event_channels)
                if status.get("filesystem") == "active":
                    sources.append("targeted file watcher")
                unavailable = [
                    name
                    for name, value in status.items()
                    if value in {"unavailable", "error"}
                ]
                self.event.emit(
                    {
                        "type": "log",
                        "level": "SUCCESS" if sources else "WARNING",
                        "message": "Real-time sources initialized: "
                        + (", ".join(sources) if sources else "none"),
                        "detail": (
                            "Event Log subscriptions opened: "
                            + (", ".join(event_channels) if event_channels else "none")
                            + ". "
                            + (
                                "Unavailable: " + ", ".join(unavailable) + ". "
                                if unavailable
                                else ""
                            )
                            + "An open subscription does not prove that audit policies or provider filters are enabled. Future events only; historical events are not replayed."
                        ),
                        "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    }
                )
            except Exception as exc:
                self.event.emit(
                    {
                        "type": "log",
                        "level": "ERROR",
                        "message": "Required event-driven sensor initialization failed",
                        "detail": f"{type(exc).__name__}: {exc}. Monitoring is stopped rather than presented as fully active.",
                        "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    }
                )
                self.state.emit(
                    "Monitoring stopped · required Sysmon subscription failed"
                )
                return
        else:
            self.event.emit(
                {
                    "type": "log",
                    "level": "INFO",
                    "message": "Event-driven sensors are Windows-only; only offline development checks are available on this platform.",
                }
            )
        try:
            while not self.stop_event.is_set():
                acquired = self.scan_lock.acquire(blocking=False)
                if not acquired:
                    self.state.emit("Monitoring · waiting for active investigation")
                    if self.stop_event.wait(2):
                        break
                    continue
                try:
                    engine = ScanEngine(
                        event_callback=self.event.emit,
                        cancel_event=self.stop_event,
                        **_engine_args(
                            self.settings,
                            monitoring=True,
                            staging_cache=self.staging_cache,
                        ),
                    )
                    report = engine.run()
                    paths = (
                        save_report(report) if report.findings or report.errors else {}
                    )
                    self.cycle_completed.emit(report.to_dict(), paths)
                except Exception as exc:
                    self.failed.emit(f"{type(exc).__name__}: {exc}")
                finally:
                    self.scan_lock.release()
                self.state.emit(
                    f"Monitoring · {sysmon_mode_label} · next check in {interval // 60} min"
                )
                remaining = interval
                while remaining > 0 and not self.stop_event.is_set():
                    step = min(10, remaining)
                    if self.stop_event.wait(step):
                        break
                    remaining -= step
                    if os.name == "nt":
                        from guardian.realtime import sysmon_readiness

                        ready, detail = sysmon_readiness()
                        if not ready:
                            self.event.emit(
                                {
                                    "type": "log",
                                    "level": "ERROR",
                                    "message": "Required Sysmon sensor was lost",
                                    "detail": detail,
                                }
                            )
                            self.state.emit("Monitoring stopped · Sysmon sensor lost")
                            self.stop_event.set()
                            break
        finally:
            if self.realtime_sensor is not None:
                self.realtime_sensor.stop()
                self.realtime_sensor = None
        self.state.emit("Monitoring stopped")


class ActionWorker(QThread):
    completed = Signal(dict)
    failed = Signal(str)

    def __init__(self, finding: dict[str, Any], *, confirmed: bool = False):
        super().__init__()
        self.finding = finding
        self.confirmed = bool(confirmed)

    def run(self) -> None:
        try:
            result = remediate_finding(self.finding, user_confirmed=self.confirmed)
            self.completed.emit(result)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class UtilityWorker(QThread):
    completed = Signal(str)
    failed = Signal(str)

    def __init__(self, fn, *args):
        super().__init__()
        self.fn, self.args = fn, args

    def run(self) -> None:
        try:
            self.completed.emit(str(self.fn(*self.args)))
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class GuardianWindow(QMainWindow):
    def __init__(
        self, *, start_monitoring_requested: bool = False, start_hidden: bool = False
    ):
        super().__init__()
        self.settings = _read_settings()
        self.scan_lock = threading.Lock()
        self.scan_worker: ScanWorker | None = None
        self.monitor_worker: MonitorWorker | None = None
        self.action_worker: ActionWorker | None = None
        self.utility_worker: UtilityWorker | None = None
        self._auto_action_queue: list[dict[str, Any]] = []
        self._auto_action_ids: set[str] = set()
        self._active_action_finding_id = ""
        self.scan_cancel = threading.Event()
        self.findings: dict[str, dict[str, Any]] = {}
        self.activity: list[str] = []
        self.last_report_paths: dict[str, str] = {}
        self._active_stage_index = 0
        self._active_stage_total = 1
        self.tray_exit_requested = False
        self._tray_monitoring_active = False
        self.tray_status_action: QAction | None = None
        self.tray_monitor_action: QAction | None = None
        self.shutdown_started = False
        self.setWindowTitle(f"{APP_NAME} · {__version__}")
        # Deliberately fixed-size dashboard: the compact layout is tuned for this canvas.
        # Settings/Legal pages retain their own scroll areas for longer content.
        self.setFixedSize(1000, 700)
        self.setStyleSheet(DARK_QSS)
        # Source mode and Nuitka standalone place assets in different roots.
        icon_path = resolve_resource("assets", "app-icon.ico") or resolve_resource(
            "assets", "app-icon.png"
        )
        self.app_icon = QIcon(str(icon_path)) if icon_path is not None else QIcon()
        if not self.app_icon.isNull():
            self.setWindowIcon(self.app_icon)
        self._build_ui()
        self._setup_tray()
        self._refresh_quarantine()
        self._refresh_counts()
        if self.settings.get("monitoring_enabled") or start_monitoring_requested:
            self.start_monitoring()
        if start_hidden and self.tray is not None and self.tray.isVisible():
            self.hide()

    def _set_header_status(self, text: str, state: str = "idle") -> None:
        self.header_status.setText(text)
        self.header_status.setProperty("state", state)
        self.header_status.style().unpolish(self.header_status)
        self.header_status.style().polish(self.header_status)
        self.header_status.update()

    def _build_ui(self) -> None:
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 10, 12, 10)
        root.setSpacing(8)

        header = _named(QFrame(), "Header")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(14, 9, 14, 9)
        brand_col = QVBoxLayout()
        brand = _named(QLabel(APP_NAME), "Brand")
        subtitle = _named(
            QLabel("SAMPLE-SPECIFIC WINDOWS RESPONSE  ·  Z797 / TCTC"), "Subtle"
        )
        brand_col.addWidget(brand)
        brand_col.addWidget(subtitle)
        hl.addLayout(brand_col)
        hl.addStretch(1)
        self.header_status = _named(QLabel("Protection idle"), "HeaderStatus")
        self.header_status.setProperty("state", "idle")
        hl.addWidget(self.header_status)
        root.addWidget(header)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setMovable(False)
        self.tabs.tabBar().setUsesScrollButtons(True)
        self.tabs.addTab(self._overview_page(), "Overview")
        self.tabs.addTab(self._findings_page(), "Findings")
        self.tabs.addTab(self._quarantine_page(), "Quarantine")
        self.tabs.addTab(self._activity_page(), "Activity")
        self.tabs.addTab(self._settings_page(), "Settings")
        self.tabs.addTab(self._legal_page(), "Legal & credits")
        root.addWidget(self.tabs, 1)

        status = _named(QFrame(), "StatusPanel")
        sl = QHBoxLayout(status)
        sl.setContentsMargins(10, 5, 10, 5)
        self.monitor_label = QLabel("Tray ready · monitoring off")
        self.monitor_label.setObjectName("Subtle")
        self.coverage_label = QLabel("Z797 campaign scope")
        self.coverage_label.setObjectName("Subtle")
        self.coverage_label.setMaximumWidth(520)
        self.coverage_label.setToolTip("Coverage summary for the latest investigation")
        sl.addWidget(self.monitor_label)
        sl.addStretch(1)
        sl.addWidget(self.coverage_label)
        root.addWidget(status)
        self.setCentralWidget(central)

    def _overview_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(10, 9, 10, 9)
        layout.setSpacing(8)

        metric_row = QGridLayout()
        metric_row.setHorizontalSpacing(8)
        metric_row.setVerticalSpacing(8)
        self.metric_labels: dict[str, QLabel] = {}
        for index, (key, title) in enumerate(
            (
                ("Critical", "CRITICAL"),
                ("High", "HIGH"),
                ("Medium", "MEDIUM"),
                ("total", "TOTAL FINDINGS"),
            )
        ):
            card = _named(QFrame(), "Panel")
            box = QVBoxLayout(card)
            box.setContentsMargins(11, 8, 11, 8)
            card.setMinimumHeight(72)
            metric_name = {
                "Critical": "MetricCritical",
                "High": "MetricHigh",
                "Medium": "MetricMedium",
                "total": "MetricTotal",
            }[key]
            value = _named(QLabel("0"), metric_name)
            label = _named(QLabel(title), "Subtle")
            box.addWidget(value)
            box.addWidget(label)
            metric_row.addWidget(card, 0, index)
            self.metric_labels[key] = value
        layout.addLayout(metric_row)

        action_row = QHBoxLayout()
        self.scan_button = QPushButton("Investigate now")
        self.scan_button.setObjectName("Primary")
        self.scan_button.clicked.connect(self.start_scan)
        self.cancel_button = QPushButton("Cancel scan")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.monitor_button = QPushButton("Start monitoring")
        self.monitor_button.clicked.connect(self.toggle_monitoring)
        action_row.addWidget(self.scan_button)
        action_row.addWidget(self.cancel_button)
        action_row.addWidget(self.monitor_button)
        action_row.addStretch(1)
        layout.addLayout(action_row)

        progress_panel = _named(QFrame(), "Panel")
        progress_panel.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        pl = QVBoxLayout(progress_panel)
        pl.setContentsMargins(10, 8, 10, 8)
        pl.setSpacing(6)
        top = QHBoxLayout()
        self.progress_title = QLabel("Ready to inspect this device")
        self.progress_title.setStyleSheet("font-weight:700;")
        self.progress_percent = _named(QLabel("0%"), "Subtle")
        top.addWidget(self.progress_title)
        top.addStretch(1)
        top.addWidget(self.progress_percent)
        pl.addLayout(top)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        pl.addWidget(self.progress_bar)
        self.stage_label = _named(
            QLabel(
                "The investigation checks only TCTC-related paths, indicators and supported process targets."
            ),
            "Subtle",
        )
        self.stage_label.setWordWrap(True)
        pl.addWidget(self.stage_label)
        self.current_task_label = _named(
            QLabel("Current activity · Waiting for an investigation"), "CurrentTask"
        )
        self.current_task_label.setWordWrap(True)
        pl.addWidget(self.current_task_label)
        log_header = QHBoxLayout()
        log_title = _named(QLabel("LIVE ACTIVITY"), "Subtle")
        log_title.setStyleSheet("font-weight:700; letter-spacing:0.5px;")
        log_hint = _named(QLabel("Latest events · full history in Activity"), "Subtle")
        log_header.addWidget(log_title)
        log_header.addStretch(1)
        log_header.addWidget(log_hint)
        pl.addLayout(log_header)

        self.live_log_view = QPlainTextEdit()
        self.live_log_view.setObjectName("LiveLog")
        self.live_log_view.setReadOnly(True)
        self.live_log_view.setMinimumHeight(138)
        self.live_log_view.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.live_log_view.setMaximumBlockCount(14)
        self.live_log_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.live_log_view.setPlaceholderText(
            "Investigation and monitoring events will appear here…"
        )
        self.live_log_view.setStyleSheet(
            "font-family:Consolas;font-size:8.5pt;background:#081321;border:1px solid #24364d;border-radius:7px;padding:6px;"
        )
        pl.addWidget(self.live_log_view, 1)
        layout.addWidget(progress_panel, 1)
        return page

    def _findings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.findings_table = QTableWidget(0, 6)
        self.findings_table.setHorizontalHeaderLabels(
            [
                "Severity",
                "Finding",
                "Type",
                "Confidence",
                "Evidence source",
                "Available response",
            ]
        )
        self.findings_table.setAlternatingRowColors(True)
        self.findings_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.findings_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.findings_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.findings_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.findings_table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.ResizeToContents
        )
        self.findings_table.itemSelectionChanged.connect(self._show_selected_finding)
        splitter.addWidget(self.findings_table)

        details_box = QWidget()
        details_layout = QVBoxLayout(details_box)
        details_layout.setContentsMargins(0, 6, 0, 0)
        heading = QLabel("Finding details · select a row above")
        heading.setObjectName("Subtle")
        heading.setStyleSheet("font-weight:700;")
        details_layout.addWidget(heading)
        self.finding_details = QPlainTextEdit()
        self.finding_details.setReadOnly(True)
        self.finding_details.setMinimumHeight(190)
        self.finding_details.setPlaceholderText(
            "Select a finding to see the exact evidence, what it means for this Z797 infection, what it does not prove, and the available cleanup action."
        )
        self.finding_details.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        details_layout.addWidget(self.finding_details, 1)
        row = QHBoxLayout()
        self.respond_button = QPushButton("Clean / contain…")
        self.respond_button.setObjectName("Primary")
        self.respond_button.setEnabled(False)
        self.respond_button.clicked.connect(self.respond_to_selected)
        self.recheck_button = QPushButton("Re-check current device")
        self.recheck_button.setEnabled(False)
        self.recheck_button.clicked.connect(self.start_scan)
        self.copy_finding_button = QPushButton("Copy details")
        self.copy_finding_button.clicked.connect(
            lambda: QApplication.clipboard().setText(self.finding_details.toPlainText())
        )
        row.addWidget(self.respond_button)
        row.addWidget(self.recheck_button)
        row.addWidget(self.copy_finding_button)
        row.addStretch(1)
        details_layout.addLayout(row)
        splitter.addWidget(details_box)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([300, 270])
        layout.addWidget(splitter, 1)
        return page

    def _quarantine_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        self.quarantine_table = QTableWidget(0, 4)
        self.quarantine_table.setHorizontalHeaderLabels(
            ["Item", "Original location", "SHA-256", "State"]
        )
        self.quarantine_table.setAlternatingRowColors(True)
        self.quarantine_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.quarantine_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.quarantine_table.horizontalHeader().setStretchLastSection(True)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        layout.addWidget(self.quarantine_table, 1)
        row = QHBoxLayout()
        restore = QPushButton("Restore selected")
        restore.clicked.connect(self.restore_selected)
        delete = QPushButton("Permanently delete")
        delete.setObjectName("Danger")
        delete.clicked.connect(self.delete_selected)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh_quarantine)
        row.addWidget(restore)
        row.addWidget(delete)
        row.addStretch(1)
        row.addWidget(refresh)
        layout.addLayout(row)
        layout.addWidget(
            _named(
                QLabel(
                    "Quarantine verifies the recorded SHA-256 before recovery or permanent deletion."
                ),
                "Subtle",
            )
        )
        return page

    def _activity_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        self.activity_view = QPlainTextEdit()
        self.activity_view.setReadOnly(True)
        layout.addWidget(self.activity_view, 1)
        row = QHBoxLayout()
        open_reports = QPushButton("Open reports folder")
        open_reports.clicked.connect(
            lambda: QDesktopServices.openUrl(
                QUrl.fromLocalFile(str(report_directory()))
            )
        )
        copy = QPushButton("Copy activity")
        copy.clicked.connect(
            lambda: QApplication.clipboard().setText(self.activity_view.toPlainText())
        )
        row.addWidget(open_reports)
        row.addWidget(copy)
        row.addStretch(1)
        layout.addLayout(row)
        return page

    def _settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(8)
        intro = QLabel(
            "Choose what Guardian checks for this exact infection, when it watches the PC, and what it may clean. "
            "Every option below is connected to a real scan or monitoring action."
        )
        intro.setWordWrap(True)
        intro.setObjectName("Subtle")
        layout.addWidget(intro)
        self.settings_tabs = QTabWidget()
        layout.addWidget(self.settings_tabs, 1)

        # GENERAL — how long Guardian stays active and what cleanup it may perform.
        general_scroll = QScrollArea()
        general_scroll.setWidgetResizable(True)
        general = QWidget()
        gl = QVBoxLayout(general)
        gl.setContentsMargins(10, 10, 10, 10)
        gl.setSpacing(10)
        monitor = QGroupBox("Keep watching this PC")
        mf = QFormLayout(monitor)
        mf.setVerticalSpacing(8)
        self.monitor_enabled = QCheckBox("Watch for new signs of this infection")
        self.monitor_enabled.setChecked(
            bool(self.settings.get("monitoring_enabled", True))
        )
        self.monitor_enabled.setToolTip(
            "Repeats the selected infection checks while Guardian is open or minimized to the tray. Closing Guardian stops monitoring."
        )
        mf.addRow(self.monitor_enabled)
        self.monitor_interval = QSpinBox()
        self.monitor_interval.setRange(1, 60)
        self.monitor_interval.setSuffix(" minutes")
        self.monitor_interval.setValue(
            max(1, min(60, int(self.settings.get("monitoring_interval_minutes", 5))))
        )
        mf.addRow("Repeat full checks every", self.monitor_interval)
        self.monitor_notifications = QCheckBox(
            "Notify me when a new high-confidence Z797 effect is found"
        )
        self.monitor_notifications.setChecked(
            bool(self.settings.get("monitoring_notifications", True))
        )
        mf.addRow(self.monitor_notifications)
        self.monitor_startup = QCheckBox(
            "Start Guardian automatically when I sign in to Windows"
        )
        self.monitor_startup.setChecked(
            bool(self.settings.get("monitoring_start_with_windows", False))
        )
        mf.addRow(self.monitor_startup)
        gl.addWidget(monitor)

        cleanup = QGroupBox("Automatic cleanup")
        cl = QVBoxLayout(cleanup)
        self.auto_contain_exact = QCheckBox(
            "Automatically stop and quarantine an exact recovered Z797 payload"
        )
        self.auto_contain_exact.setChecked(
            bool(self.settings.get("auto_contain_exact_sample", True))
        )
        cl.addWidget(self.auto_contain_exact)
        note = QLabel(
            "This applies only when both SHA-256 and byte size match one of the recovered sample files, "
            "the file is inside the two analysed Temp\\Local staging folders, and the live PID still maps "
            "to that exact image. Everything else requires your confirmation."
        )
        note.setWordWrap(True)
        note.setObjectName("Subtle")
        cl.addWidget(note)
        self.firewall_policy = QComboBox()
        self.firewall_policy.addItems(
            [
                "Ask before blocking a confirmed Z797 server",
                "Never change Windows Firewall",
            ]
        )
        current_firewall = str(
            self.settings.get("firewall_policy", "Ask before blocking")
        )
        self.firewall_policy.setCurrentIndex(
            1 if current_firewall == "Never change Firewall rules" else 0
        )
        cl.addWidget(QLabel("Block a confirmed Z797 server"))
        cl.addWidget(self.firewall_policy)
        network_note = QLabel(
            "Guardian only offers this for a built-in Z797 IP when the connected process is proven to be an exact recovered payload. It will never block an address based only on a DNS or IP sighting."
        )
        network_note.setWordWrap(True)
        network_note.setObjectName("Subtle")
        cl.addWidget(network_note)
        gl.addWidget(cleanup)
        gl.addStretch(1)
        general_scroll.setWidget(general)
        self.settings_tabs.addTab(general_scroll, "Basics")

        # DETECTION — the same switches are consumed by Scan Now and monitoring.
        detection_scroll = QScrollArea()
        detection_scroll.setWidgetResizable(True)
        detection = QWidget()
        dl = QVBoxLayout(detection)
        dl.setContentsMargins(10, 10, 10, 10)
        dl.setSpacing(8)
        sensor_group = QGroupBox("Choose the infection effects to check")
        sensor_layout = QVBoxLayout(sensor_group)
        sensor_layout.setSpacing(8)
        self.monitor_checks: dict[str, QCheckBox] = {}
        options = (
            (
                "monitor_processes",
                "Payloads running now",
                "Looks for the exact recovered Z797 payload fingerprints executing from the analysed staging locations.",
            ),
            (
                "monitor_memory",
                "Injection effects in known target processes",
                "Read-only checks for the manual-map, redirected-thread, image-tampering and AMSI-stub effects observed in this sample.",
            ),
            (
                "monitor_files",
                "Downloaded Z797 delivery files",
                "Checks only the two analysed Temp\\Local staging roots for exact hashes, delivery filenames and embedded Z797 URLs.",
            ),
            (
                "monitor_persistence",
                "Automatic restart points",
                "Checks Run / RunOnce, scheduled tasks, services and Startup entries only when their command points to this Z797 chain.",
            ),
            (
                "monitor_network",
                "Connections to Z797 infrastructure",
                "Checks the recovered controller / delivery domains, exact hosts-file mappings and current connections owned by an exact recovered payload.",
            ),
            (
                "monitor_eventlogs",
                "Past execution evidence",
                "Reviews Sysmon, PowerShell, process-creation / persistence audit, Task Scheduler and WMI records only when they contain Z797-specific indicators.",
            ),
        )
        for key, title, help_text in options:
            wrapper = QFrame()
            wrapper.setObjectName("SettingCard")
            row = QVBoxLayout(wrapper)
            row.setContentsMargins(10, 7, 10, 7)
            row.setSpacing(3)
            check = QCheckBox(title)
            check.setChecked(bool(self.settings.get(key, True)))
            self.monitor_checks[key] = check
            row.addWidget(check)
            help_label = QLabel(help_text)
            help_label.setWordWrap(True)
            help_label.setObjectName("Subtle")
            help_label.setContentsMargins(24, 0, 0, 0)
            row.addWidget(help_label)
            sensor_layout.addWidget(wrapper)
        dl.addWidget(sensor_group)
        core = QLabel(
            "These switches control the same checks in Investigate now and continuous monitoring. "
            "Guardian keeps the minimum Sysmon process-create feed needed to link actors to the analysed payload; "
            "turning off a category skips its deeper check. Missing or never-recorded Windows events cannot be recreated."
        )
        core.setWordWrap(True)
        core.setObjectName("Subtle")
        dl.addWidget(core)
        dl.addStretch(1)
        detection_scroll.setWidget(detection)
        self.settings_tabs.addTab(detection_scroll, "Z797 checks")

        # ADVANCED — evidence depth and optional memory indicators only.
        advanced_scroll = QScrollArea()
        advanced_scroll.setWidgetResizable(True)
        advanced = QWidget()
        al = QVBoxLayout(advanced)
        al.setContentsMargins(10, 10, 10, 10)
        al.setSpacing(10)
        history = QGroupBox("How much Windows history to review")
        hf = QFormLayout(history)
        self.event_log_limit = QSpinBox()
        self.event_log_limit.setRange(100, 5000)
        self.event_log_limit.setSingleStep(100)
        self.event_log_limit.setSuffix(" event records per channel")
        self.event_log_limit.setValue(
            max(100, min(5000, int(self.settings.get("event_log_record_limit", 5000))))
        )
        hf.addRow("Records per source", self.event_log_limit)
        history_note = QLabel(
            "Higher values review more of the selected event types before Z797-specific matching, but take longer. The limit applies separately to each channel; Windows may already have overwritten older records."
        )
        history_note.setWordWrap(True)
        history_note.setObjectName("Subtle")
        hf.addRow(history_note)
        al.addWidget(history)
        mem = QGroupBox("Memory inspection (read-only)")
        ml = QVBoxLayout(mem)
        self.memory_evidence = QCheckBox(
            "Save suspicious memory regions for later review"
        )
        self.memory_evidence.setChecked(
            bool(self.settings.get("memory_capture_regions", True))
        )
        ml.addWidget(self.memory_evidence)
        self.memory_switches: dict[str, QCheckBox] = {}
        for key, label in (
            (
                "memory_private_exec",
                "Look for private executable code created inside the target process",
            ),
            ("memory_manual_map", "Look for a manually mapped PE image"),
            (
                "memory_thread_start",
                "Check whether a thread starts inside that private code",
            ),
            (
                "memory_integrity",
                "Check mapped image identity and the AMSI bypass pattern found in this sample",
            ),
            ("memory_image_identity", "Record loaded-image paths for evidence"),
        ):
            check = QCheckBox(label)
            check.setChecked(bool(self.settings.get(key, True)))
            self.memory_switches[key] = check
            ml.addWidget(check)
        mem_note = QLabel(
            "These options affect only the selected target-process memory checks. Memory is read-only; memory anomalies alone never terminate a process."
        )
        mem_note.setWordWrap(True)
        mem_note.setObjectName("Subtle")
        ml.addWidget(mem_note)
        al.addWidget(mem)
        al.addStretch(1)
        advanced_scroll.setWidget(advanced)
        self.settings_tabs.addTab(advanced_scroll, "Advanced")

        bottom = QHBoxLayout()
        save = QPushButton("Save and apply")
        save.setObjectName("Primary")
        save.clicked.connect(self.save_settings)
        bottom.addWidget(save)
        bottom.addStretch(1)
        layout.addLayout(bottom)
        return page

    def _legal_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)
        browser.setHtml("""
        <h3>TCTC Guardian Z797</h3>
        <p>A defensive Windows utility for the specific ClickFix → crandle.txt → Z797.ps1 → tctc.bba chain analysed in this project. It is not a general-purpose antivirus and does not import third-party security-product alerts.</p>
        <h4>Research basis</h4>
        <ul>
          <li><a href="https://www.plume.com/newsroom/before-gta-vi">Plume Security Lab — Before GTA VI</a>: public reporting closest to the analysed delivery chain.</li>
          <li><a href="https://learn.microsoft.com/sysinternals/downloads/sysmon">Microsoft Sysinternals — Sysmon</a>: process, file, network and PE-creation telemetry documentation.</li>
        </ul>
        <h4>What Guardian checks</h4>
        <p>Only the recovered Z797 fingerprints, delivery names and controller endpoints; the two analysed Temp\\Local staging roots; the sample-targeted process and memory effects; Z797-linked Run / RunOnce values, services, scheduled tasks and Startup items; exact Hosts mappings; and historical Windows telemetry containing the same indicators.</p>
        <p>Guardian does not inspect browser profile databases or browser history. Chrome is included only as a sample-observed process target for read-only memory checks. Historical RunMRU entries are evidence only and are not deleted because removing command history does not stop the infection.</p>
        <h4>Third-party software</h4>
        <ul>
          <li>Python — <a href="https://www.python.org/psf/license/">PSF license</a>.</li>
          <li>PySide6 / Qt for Python — review the <a href="https://doc.qt.io/qtforpython-6/licenses.html">official licensing notes</a> before redistributing a binary.</li>
          <li>Nuitka — <a href="https://nuitka.net/">build tool</a>.</li>
          <li>Microsoft Sysmon is downloaded from the official Microsoft endpoint at runtime; it is not bundled in this source package.</li>
        </ul>
        <h4>Limitations</h4>
        <p>Monitoring runs only while Guardian is open or minimized to the tray; it is not a Windows service. Memory inspection is read-only. Events that were not logged or were overwritten cannot be reconstructed. A clean targeted scan is not proof of complete eradication.</p>
        <p>Quarantine, persistence cleanup and firewall actions require a current revalidated Z797 target and explicit confirmation, except exact recovered payloads that meet the separately documented automatic-containment gate. Reports and memory evidence may contain sensitive local data; review and redact them before sharing.</p>
        <h4>Copyright & project ownership</h4>
        <p><b>Copyright © 2026 Jo0X01. All rights reserved.</b></p>
        <p>Official project repository:
        <a href="https://github.com/Jo0X01/TCTC-Guardian-Z797">github.com/Jo0X01/TCTC-Guardian-Z797</a></p>
        <p>The original project code is not offered under an open-source license. Third-party components remain subject to their respective licenses.</p>
        """)
        layout.addWidget(browser, 1)
        return page

    @staticmethod
    def _dot_icon(color: str, size: int = 16) -> QIcon:
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(QPen(QColor("#07111f"), max(1, size // 9)))
        painter.setBrush(QBrush(QColor(color)))
        margin = max(2, size // 7)
        painter.drawEllipse(margin, margin, size - 2 * margin, size - 2 * margin)
        painter.end()
        return QIcon(pixmap)

    def _compose_tray_icon(self, color: str) -> QIcon:
        pixmap = self.app_icon.pixmap(64, 64)
        if pixmap.isNull():
            return self._dot_icon(color, 32)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        # The lower-right status dot remains legible on both light and dark taskbars.
        painter.setPen(QPen(QColor("#07111f"), 3))
        painter.setBrush(QBrush(QColor(color)))
        painter.drawEllipse(45, 45, 17, 17)
        painter.end()
        return QIcon(pixmap)

    def _update_tray_status(self, active: bool) -> None:
        self._tray_monitoring_active = bool(active)
        details = tray_status_details(self._tray_monitoring_active)
        color = details["color"]
        if self.tray is not None:
            self.tray.setIcon(self._compose_tray_icon(color))
            self.tray.setToolTip(details["tooltip"])
        if self.tray_status_action is not None:
            self.tray_status_action.setText(details["menu_text"])
            self.tray_status_action.setIcon(self._dot_icon(color, 16))
        if self.tray_monitor_action is not None:
            self.tray_monitor_action.setText(
                "Stop monitoring" if active else "Start monitoring"
            )

    def _setup_tray(self) -> None:
        self.tray: QSystemTrayIcon | None = None
        if not QSystemTrayIcon.isSystemTrayAvailable() or self.app_icon.isNull():
            self._append_activity(
                "WARN",
                "System tray unavailable; close will exit the app instead of hiding it.",
            )
            return
        self.tray = QSystemTrayIcon(self.app_icon, self)
        menu = QMenu()
        self.tray_status_action = QAction(
            self._dot_icon("#ef4444"), "Monitoring: OFF · app running", self
        )
        self.tray_status_action.setEnabled(False)
        show_action = QAction("Open TCTC Guardian Z797", self)
        show_action.triggered.connect(self.show_window)
        scan_action = QAction("Investigate now", self)
        scan_action.triggered.connect(self.start_scan)
        self.tray_monitor_action = QAction("Start monitoring", self)
        self.tray_monitor_action.triggered.connect(self.toggle_monitoring)
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.exit_application)
        menu.addAction(self.tray_status_action)
        menu.addSeparator()
        menu.addAction(show_action)
        menu.addAction(scan_action)
        menu.addAction(self.tray_monitor_action)
        menu.addSeparator()
        menu.addAction(exit_action)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._tray_activated)
        self._update_tray_status(False)
        self.tray.show()

    def _tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self.show_window()

    def show_window(self) -> None:
        self.show()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, event: QCloseEvent) -> None:
        if (
            not self.tray_exit_requested
            and self.tray is not None
            and self.tray.isVisible()
        ):
            event.ignore()
            self.hide()
            if self.settings.get("monitoring_notifications", True):
                self.tray.showMessage(
                    APP_NAME,
                    "Still running in the system tray.",
                    QSystemTrayIcon.MessageIcon.Information,
                    2500,
                )
            return
        event.ignore()
        self._begin_shutdown()

    def exit_application(self) -> None:
        self.tray_exit_requested = True
        self._begin_shutdown()

    def _begin_shutdown(self) -> None:
        if self.shutdown_started:
            return
        self.shutdown_started = True
        self.hide()
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_cancel.set()
        if self.monitor_worker and self.monitor_worker.isRunning():
            self.monitor_worker.stop()
        self._set_header_status("Stopping safely…", "warning")
        QTimer.singleShot(100, self._finish_shutdown_when_idle)

    def _finish_shutdown_when_idle(self) -> None:
        workers = (
            self.scan_worker,
            self.monitor_worker,
            self.action_worker,
            self.utility_worker,
        )
        if any(worker is not None and worker.isRunning() for worker in workers):
            QTimer.singleShot(150, self._finish_shutdown_when_idle)
            return
        if self.tray:
            self.tray.hide()
        QApplication.quit()

    def _append_activity(self, level: str, message: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        line = f"{stamp}  [{level}]  {message}"
        log_method = getattr(logging, str(level).lower(), logging.info)
        log_method(line)
        self.activity.append(line)
        if len(self.activity) > 2000:
            self.activity = self.activity[-1500:]
        if hasattr(self, "activity_view"):
            self.activity_view.appendPlainText(line)
        if hasattr(self, "live_log_view"):
            self.live_log_view.setPlainText("\n".join(self.activity[-14:]))
            cursor = self.live_log_view.textCursor()
            cursor.movePosition(cursor.MoveOperation.End)
            self.live_log_view.setTextCursor(cursor)
        if hasattr(self, "current_task_label") and level.upper() not in {
            "DONE",
            "SUCCESS",
        }:
            self.current_task_label.setText(f"Current activity · {message[:230]}")

    def _handle_event(self, event: dict[str, Any]) -> None:
        etype = event.get("type")
        if etype == "log":
            self._append_activity(
                str(event.get("level", "INFO")),
                str(event.get("message", ""))
                + (" · " + str(event.get("detail")) if event.get("detail") else ""),
            )
        elif etype == "sensor_failure":
            self._append_activity(
                "ERROR", str(event.get("message", "Required sensor failed"))
            )
            if self.monitor_worker and self.monitor_worker.isRunning():
                self.monitor_worker.stop()
            self._monitor_state("Monitoring stopped · Sysmon sensor lost")
        elif etype == "stage":
            stage = event.get("stage", {})
            index, total = int(event.get("index", 0)), max(
                1, int(event.get("total", 1))
            )
            self._active_stage_index, self._active_stage_total = index, total
            pct = int((index - 1) / total * 100)
            self.progress_bar.setValue(pct)
            self.progress_percent.setText(f"{pct}%")
            self.progress_title.setText(str(stage.get("name", "Investigating")))
            self.stage_label.setText(
                str(stage.get("description", "Checking the selected source…"))
            )
            self.current_task_label.setText(
                f"Current activity · Stage {index}/{total}: {stage.get('name', 'Investigating')}"
            )
        elif etype == "stage_done":
            stage = event.get("stage", {})
            index, total = int(event.get("index", 0)), max(
                1, int(event.get("total", 1))
            )
            pct = int(index / total * 100)
            self.progress_bar.setValue(pct)
            self.progress_percent.setText(f"{pct}%")
            self.stage_label.setText(
                f"{stage.get('name', '')}: {stage.get('message', '')}"
            )
        elif etype == "current_task":
            stage = str(event.get("stage", "Investigation"))
            current = str(event.get("current", ""))
            detail = str(event.get("detail", ""))
            self.current_task_label.setText(f"Current activity · {stage}: {current}")
            if detail:
                self.stage_label.setText(detail)
            self._update_subtask_progress(event)
        elif etype == "memory_process_start":
            process_index = int(event.get("process_index", 0) or 0)
            process_total = int(event.get("process_total", 0) or 0)
            self.current_task_label.setText(
                f"Current activity · Reading memory map {process_index}/{process_total}: "
                f"{event.get('process')} (PID {event.get('pid')})"
                if process_total
                else f"Current activity · Reading memory map: {event.get('process')} (PID {event.get('pid')})"
            )
            self.stage_label.setText(str(event.get("path", "")))
            if process_total:
                self._update_subtask_progress(
                    {"completed": process_index - 1, "total": process_total}
                )
        elif etype == "memory_progress":
            self.current_task_label.setText(
                f"Current activity · {event.get('process')} (PID {event.get('pid')}) · {event.get('regions', 0)} memory regions reviewed"
            )
        elif etype == "memory_process_done":
            process_index = int(event.get("process_index", 0) or 0)
            process_total = int(event.get("process_total", 0) or 0)
            self.current_task_label.setText(
                f"Current activity · Finished memory review: {event.get('process')} (PID {event.get('pid')})"
            )
            stats = event.get("stats", {}) or {}
            if stats:
                self._append_activity(
                    "MEMORY",
                    f"{event.get('process')} PID {event.get('pid')}: "
                    f"{stats.get('regions_examined', 0)} regions walked · "
                    f"{stats.get('manual_map_probe_calls', 0)} PE header probe(s) · "
                    f"{stats.get('remote_read_attempts', 0)} ReadProcessMemory call(s) / "
                    f"{stats.get('remote_bytes_read', 0):,} bytes · "
                    f"{stats.get('threads_enumerated', 0)} thread(s) · "
                    f"{stats.get('findings', 0)} finding(s).",
                )
            elif event.get("skipped"):
                self._append_activity(
                    "MEMORY",
                    f"{event.get('process')} PID {event.get('pid')} skipped: {event.get('skip_reason', 'process safety exclusion or access unavailable')}.",
                )
            if process_total:
                self._update_subtask_progress(
                    {"completed": process_index, "total": process_total}
                )
        elif etype == "memory_scan_summary":
            stats = event.get("stats", {}) or {}
            self._append_activity(
                "MEMORY",
                f"Memory scan API summary: {stats.get('processes_opened', 0)}/{stats.get('processes_selected', 0)} handles · "
                f"{stats.get('regions_examined', 0)} regions · {stats.get('remote_read_attempts', 0)} ReadProcessMemory calls / "
                f"{stats.get('remote_bytes_read', 0):,} bytes · {stats.get('thread_start_query_attempts', 0)} thread-start queries · "
                f"depth={stats.get('inspection_depth', 'unknown')}.",
            )
        elif etype == "finding":
            finding = event.get("finding", {})
            fid = str(
                finding.get("finding_id")
                or f"{finding.get('title')}|{finding.get('path')}"
            )
            is_new = fid not in self.findings
            self.findings[fid] = finding
            self._refresh_findings()
            self._refresh_counts()
            severity = str(finding.get("severity", "Info"))
            self._append_activity(
                severity.upper(), str(finding.get("title", "New finding"))
            )
            if (
                is_new
                and severity in {"Critical", "High"}
                and self.tray
                and self.settings.get("monitoring_notifications", True)
            ):
                self.tray.showMessage(
                    APP_NAME,
                    f"{severity}: {finding.get('title', 'Threat indicator detected')}",
                    QSystemTrayIcon.MessageIcon.Warning,
                    6000,
                )
            exact_live_artifact = is_exact_sample_auto_containment_candidate(finding)
            if (
                is_new
                and exact_live_artifact
                and self.settings.get("auto_contain_exact_sample", True)
            ):
                self._append_activity(
                    "ACTION",
                    "Exact Z797 artifact verified by SHA-256 + size; immediate containment queued.",
                )
                self._queue_auto_containment(finding)

    def _update_subtask_progress(self, event: dict[str, Any]) -> None:
        completed = int(event.get("completed", 0) or 0)
        total = int(event.get("total", 0) or 0)
        if total <= 0 or self._active_stage_total <= 0:
            return
        fraction = min(1.0, max(0.0, completed / total))
        overall = (
            (max(1, self._active_stage_index) - 1) + fraction
        ) / self._active_stage_total
        percent = min(99, max(0, int(overall * 100)))
        self.progress_bar.setValue(percent)
        self.progress_percent.setText(f"{percent}%")

    def _scan_completed(self, report: dict[str, Any], paths: dict[str, Any]) -> None:
        self.last_report_paths = paths
        self.progress_bar.setValue(100)
        self.progress_percent.setText("100%")
        self.progress_title.setText(
            "Investigation complete"
            if not report.get("cancelled")
            else "Investigation cancelled"
        )
        summary = report.get("summary", {})
        self.stage_label.setText(
            f"{len(report.get('findings', []))} finding(s) · {summary.get('errors', 0)} check error(s). "
            "Review coverage notes; a clean result is not proof of eradication."
        )
        self.current_task_label.setText(
            "Current activity · Investigation complete. Review findings and coverage warnings."
        )
        coverage_text = (
            f"Coverage: {summary.get('completed_stages', 0)} completed · "
            f"{summary.get('warning_stages', 0)} warnings · "
            f"{summary.get('skipped_stages', 0)} disabled / skipped"
        )
        event_log_coverage = (report.get("coverage", {}) or {}).get(
            "event_logs", {}
        ) or {}
        if event_log_coverage:
            parts = []
            for label, item in event_log_coverage.items():
                status = str(item.get("status", "unknown"))
                if status == "read":
                    inspected = int(item.get("records_inspected", 0) or 0)
                    returned = int(item.get("records_returned", inspected) or 0)
                    cap = int(item.get("limit_per_channel", 0) or 0)
                    note = (
                        f"{label} {inspected}/{cap}" if cap else f"{label} {inspected}"
                    )
                    if item.get("truncated"):
                        note += f" (>{cap}; {returned} returned)"
                    parts.append(note)
                else:
                    parts.append(f"{label}: {status}")
            coverage_text += " · Event logs: " + " | ".join(parts[:4])
            if len(parts) > 4:
                coverage_text += f" | +{len(parts) - 4} sources"
        self.coverage_label.setText(coverage_text)
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.scan_worker = None
        self._append_activity("DONE", f"Report saved: {paths.get('html', '')}")
        self._refresh_counts()

    def _scan_failed(self, message: str) -> None:
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.scan_worker = None
        self._append_activity("ERROR", message)
        QMessageBox.critical(self, APP_NAME, message)

    def start_scan(self) -> None:
        if self.scan_worker and self.scan_worker.isRunning():
            return
        self.save_settings(silent=True)
        self.scan_cancel = threading.Event()
        self.scan_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.progress_percent.setText("0%")
        self.progress_title.setText("Starting targeted investigation…")
        self.stage_label.setText(
            "Scanning in background; the window remains responsive."
        )
        self._append_activity("INFO", "Started targeted TCTC / Z797 investigation")
        self.scan_worker = ScanWorker(
            _engine_args(self.settings, monitoring=False),
            self.scan_lock,
            self.scan_cancel,
        )
        self.scan_worker.event.connect(self._handle_event)
        self.scan_worker.completed.connect(self._scan_completed)
        self.scan_worker.failed.connect(self._scan_failed)
        self.scan_worker.start()

    def cancel_scan(self) -> None:
        self.scan_cancel.set()
        self.cancel_button.setEnabled(False)
        self._append_activity(
            "INFO",
            "Cancellation requested; current operation will stop at its next safe checkpoint.",
        )

    def start_monitoring(self) -> None:
        if self.monitor_worker and self.monitor_worker.isRunning():
            return
        self.save_settings(silent=True)
        if not _enabled_stages(self.settings, monitoring=True) - {"verification"}:
            QMessageBox.warning(
                self, APP_NAME, "Enable at least one monitoring source in Settings."
            )
            return
        self.settings["monitoring_enabled"] = True
        _write_settings(self.settings)
        selected_stages = _enabled_stages(self.settings, monitoring=True) - {
            "verification"
        }
        stage_labels = {
            "processes": "processes",
            "memory": "target-process memory",
            "persistence": "persistence",
            "staging": "staging files",
            "network": "network / DNS",
            "eventlogs": "Windows event logs",
        }
        selected_names = [
            label for key, label in stage_labels.items() if key in selected_stages
        ]
        self.monitor_worker = MonitorWorker(self.settings, self.scan_lock)
        self.monitor_worker.event.connect(self._handle_event)
        self.monitor_worker.cycle_completed.connect(self._monitor_cycle_completed)
        self.monitor_worker.failed.connect(
            lambda msg: self._append_activity("ERROR", msg)
        )
        self.monitor_worker.state.connect(self._monitor_state)
        self.monitor_worker.start()
        self.monitor_button.setText("Stop monitoring")
        self._update_tray_status(True)
        self._set_header_status("Monitoring active", "active")
        self._append_activity(
            "INFO",
            "Continuous TCTC monitoring started; it remains active while the app is running in the tray.",
        )
        self._append_activity(
            "INFO", "Active monitoring sources: " + ", ".join(selected_names)
        )
        if "memory" not in selected_stages:
            self._append_activity(
                "WARNING",
                "Target-process memory monitoring is OFF. Enable it in Settings → Advanced to include RuntimeBroker / Explorer / Chrome memory checks in tray cycles.",
            )
        if "eventlogs" not in selected_stages:
            self._append_activity(
                "INFO",
                "Windows event-log monitoring is OFF; on-demand investigations can still query selected logs.",
            )

    def stop_monitoring(self) -> None:
        if self.monitor_worker and self.monitor_worker.isRunning():
            self.monitor_worker.stop()
        self.settings["monitoring_enabled"] = False
        _write_settings(self.settings)
        self.monitor_button.setText("Start monitoring")
        self._update_tray_status(False)
        self._set_header_status("Protection idle", "idle")
        self.monitor_label.setText("Tray ready · monitoring off")
        self._append_activity("INFO", "Continuous monitoring stopped")

    def toggle_monitoring(self) -> None:
        if self.monitor_worker and self.monitor_worker.isRunning():
            self.stop_monitoring()
        else:
            self.start_monitoring()

    def _monitor_state(self, state: str) -> None:
        self.monitor_label.setText(state)
        normalized = state.strip().lower()
        if normalized.startswith("monitoring stopped"):
            self._update_tray_status(False)
            self.monitor_button.setText("Start monitoring")
            self._set_header_status("Protection idle", "idle")
        elif normalized.startswith("monitoring active") or normalized.startswith(
            "monitoring ·"
        ):
            self._update_tray_status(True)
            self.monitor_button.setText("Stop monitoring")
            self._set_header_status("Monitoring active", "active")

    def _monitor_cycle_completed(
        self, report: dict[str, Any], paths: dict[str, Any]
    ) -> None:
        if paths:
            self.last_report_paths = paths
        summary = report.get("summary", {})
        self._append_activity(
            "MONITOR",
            f"Monitor cycle finished · {len(report.get('findings', []))} finding(s), {summary.get('errors', 0)} error(s)",
        )
        self._refresh_counts()
        for finding in report.get("findings", []):
            # The dedicated switch may contain a periodic-scan exact artifact,
            # but only after the same hash + byte-size + path gate as live events.
            if self.settings.get(
                "auto_contain_exact_sample", True
            ) and is_exact_sample_auto_containment_candidate(
                finding, require_event_driven=False
            ):
                self._queue_auto_containment(finding)

    def _selected_finding(self) -> dict[str, Any] | None:
        rows = self.findings_table.selectionModel().selectedRows()
        if not rows:
            return None
        fid = self.findings_table.item(rows[0].row(), 0).data(Qt.ItemDataRole.UserRole)
        return self.findings.get(str(fid))

    @staticmethod
    def _finding_action_info(finding: dict[str, Any]) -> tuple[str, str]:
        action = str(finding.get("remediation", "none"))
        mapping = {
            "quarantine_file": (
                "Quarantine this verified file",
                "Guardian re-hashes the current file and checks its recorded size before moving it into its private quarantine. You can restore it later from Quarantine.",
            ),
            "contain_exact_sample_process": (
                "Stop and quarantine exact Z797 payload",
                "Guardian verifies the recovered SHA-256, exact byte size, analysed Temp\\Local path and live PID image identity. Only that exact sample process can be stopped.",
            ),
            "remove_registry_value": (
                "Remove this Z797 Run / RunOnce entry",
                "Guardian checks that the value still matches the recorded Z797 command, saves a backup, then removes only that value.",
            ),
            "disable_task": (
                "Disable this Z797 scheduled task",
                "Guardian re-reads the task XML, verifies its current action still matches the recorded Z797 command, saves its state and disables only that task.",
            ),
            "disable_service": (
                "Disable this Z797 service",
                "Guardian rechecks the exact service ImagePath and startup mode, saves a backup, disables that service and requests it to stop.",
            ),
            "remove_hosts_entry": (
                "Remove this Z797 Hosts mapping",
                "Guardian removes only the exact recorded line for a built-in Z797 domain and saves a full Hosts-file backup.",
            ),
            "block_network_ip": (
                "Block confirmed Z797 server address",
                "Guardian adds a Guardian-owned outbound rule only for a built-in Z797 IP after confirmation. It does not block domains, shared CDNs or DNS-learned addresses.",
            ),
        }
        meta = finding.get("metadata") or {}
        # Historical/context-only records always remain review-only, even if the
        # underlying event contains a path/hash that could map to a cleanup type.
        if meta.get("historical_only") or meta.get("historical"):
            return (
                "Historical evidence · re-check before cleanup",
                "This record describes past activity. The event itself cannot be removed and does not prove the same file, process or persistence item is still present. Use Re-check current device; a cleanup action appears only if Guardian finds a current, revalidatable Z797 target.",
            )
        if meta.get("context_only"):
            return (
                "Context only · no cleanup",
                "This is contextual telemetry, not a sufficiently attributed Z797 action. Guardian will not modify the device based on this record alone.",
            )
        if meta.get("evidence_only"):
            return (
                "Historical trace · no active persistence",
                "This item records a past command or trace. Removing the history would not stop malware, so Guardian keeps it as evidence and does not treat it as a cleanup target.",
            )
        if action in mapping:
            return mapping[action]
        return (
            "No safe cleanup target",
            "Guardian has not established a current, sample-specific target that can be changed safely. Re-check the current device and review the evidence before taking action.",
        )

    def _refresh_findings(self) -> None:
        if not hasattr(self, "findings_table"):
            return
        values = sorted(
            self.findings.values(),
            key=lambda f: (
                {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(
                    f.get("severity", "Info"), 5
                ),
                f.get("title", ""),
            ),
        )
        self.findings_table.setRowCount(len(values))
        for row, finding in enumerate(values):
            severity = str(finding.get("severity", "Info"))
            action_label, _ = self._finding_action_info(finding)
            source = str(
                (finding.get("metadata") or {}).get("channel")
                or (finding.get("metadata") or {}).get("source")
                or finding.get("stage_id", "")
            ).replace("_", " ")
            items = [
                QTableWidgetItem(severity),
                QTableWidgetItem(str(finding.get("title", ""))),
                QTableWidgetItem(str(finding.get("category", "Z797 evidence"))),
                QTableWidgetItem(str(finding.get("confidence", ""))),
                QTableWidgetItem(source),
                QTableWidgetItem(action_label),
            ]
            items[0].setData(Qt.ItemDataRole.UserRole, finding.get("finding_id"))
            color = {
                "Critical": "#f16d83",
                "High": "#f3b75e",
                "Medium": "#b5a0ff",
                "Low": "#42c5d5",
                "Info": "#91a4ba",
            }.get(severity, "#91a4ba")
            items[0].setForeground(Qt.GlobalColor.white)
            items[0].setBackground(QColor(color))
            for col, item in enumerate(items):
                self.findings_table.setItem(row, col, item)
        self.findings_table.resizeColumnToContents(0)
        self.findings_table.resizeColumnToContents(2)
        self.findings_table.resizeColumnToContents(3)
        self.findings_table.resizeColumnToContents(4)
        self.findings_table.resizeColumnToContents(5)
        self.findings_table.horizontalHeader().setStretchLastSection(False)
        self.respond_button.setEnabled(False)

    def _show_selected_finding(self) -> None:
        finding = self._selected_finding()
        if not finding:
            self.finding_details.clear()
            self.respond_button.setEnabled(False)
            self.recheck_button.setEnabled(False)
            return
        meta = finding.get("metadata") or {}
        action, action_why = self._finding_action_info(finding)
        event_id = meta.get("event_id", "Not supplied")
        channel = (
            meta.get("channel")
            or meta.get("source")
            or finding.get("stage_id", "Current device check")
        )
        timestamp = (
            meta.get("timestamp")
            or meta.get("time_created")
            or finding.get("timestamp")
            or "Not recorded by this source"
        )
        source_image = (
            meta.get("source_image")
            or meta.get("process_path")
            or meta.get("process_image")
            or meta.get("image")
            or "Not recorded"
        )
        target_image = (
            meta.get("target_image") or meta.get("target_path") or "Not recorded"
        )
        pid = (
            meta.get("source_pid")
            or meta.get("pid")
            or meta.get("process_id")
            or "Not recorded"
        )
        target_pid = meta.get("target_pid") or "Not recorded"
        guid = (
            meta.get("source_process_guid")
            or meta.get("source_guid")
            or meta.get("process_guid")
            or "Not recorded"
        )
        target_guid = (
            meta.get("target_process_guid") or meta.get("target_guid") or "Not recorded"
        )
        size = meta.get("file_size") or meta.get("expected_size") or "Not recorded"
        record_id = meta.get("record_id") or "Not recorded"
        status = meta.get("response_status") or "No cleanup action has been run"
        digest = (
            finding.get("sha256")
            or "Not supplied by this event type (this does not mean hashing failed)"
        )
        confidence = str(finding.get("confidence", "Unknown"))
        severity = str(finding.get("severity", "Info"))
        historical = bool(meta.get("historical") or meta.get("historical_only"))
        lines = [
            f"{finding.get('title', 'Z797 finding')}  |  {severity} severity  |  {confidence} confidence",
            "=" * 76,
            f"Finding ID: {finding.get('finding_id', 'Not recorded')}  |  Category: {finding.get('category', 'Not classified')}  |  Scan stage: {finding.get('stage_id', 'Not recorded')}",
            "",
            "1. WHAT GUARDIAN OBSERVED",
            str(finding.get("description", "No description was supplied.")),
            "",
            "2. WHY THIS MATCHES THE ANALYSED TCTC / Z797 CHAIN",
            *(
                f"• {item}"
                for item in (
                    finding.get("evidence") or ["No explanatory evidence was attached."]
                )
            ),
            "",
            "3. EVENT AND PROCESS ATTRIBUTION",
            f"Evidence type: {'Historical Windows event' if historical else 'Current device / live sensor result'}",
            f"Event source / channel: {channel}",
            f"Provider: {meta.get('provider') or 'Not recorded'}",
            f"Event ID: {event_id}",
            f"Record ID: {record_id}",
            f"Timestamp: {timestamp}",
            f"Actor / source image: {source_image}",
            f"Actor PID: {pid}",
            f"Actor Process GUID: {guid}",
            f"Target image: {target_image}",
            f"Target PID: {target_pid}",
            f"Target Process GUID: {target_guid}",
            f"Parent image: {meta.get('parent_image') or meta.get('parent_process_image') or 'Not recorded'}",
            f"Parent PID: {meta.get('parent_pid') or 'Not recorded'}",
            f"Parent Process GUID: {meta.get('parent_process_guid') or 'Not recorded'}",
            "",
            "4. FILE, NETWORK OR PERSISTENCE DETAILS",
            f"Path / object: {finding.get('path') or meta.get('ip') or meta.get('task_name') or meta.get('service_name') or 'Not recorded'}",
            f"SHA-256: {digest}",
            f"File size: {size}",
            f"Campaign domain(s): {', '.join(meta.get('matched_domains', [])) if isinstance(meta.get('matched_domains'), list) else meta.get('domain', 'Not recorded')}",
            f"Remote IP: {meta.get('ip') or ', '.join(meta.get('resolved_ips', [])) if meta.get('resolved_ips') else meta.get('ip', 'Not recorded')}",
            (
                f"Registry value: {meta.get('root', '')}\\{meta.get('subkey', '')}\\{meta.get('value_name', '')}"
                if meta.get("value_name")
                else "Registry value: Not applicable"
            ),
            f"Scheduled task: {meta.get('task_name', 'Not applicable')}",
            f"Service: {meta.get('service_name', 'Not applicable')}",
            f"Task / WMI object: {meta.get('task_name') or meta.get('wmi_consumer') or meta.get('wmi_filter') or 'Not recorded'}",
            f"Memory indicator: {meta.get('memory_indicator') or meta.get('indicator') or 'Not applicable'}",
            f"Memory region: {('0x%X' % int(meta.get('base_address'))) if isinstance(meta.get('base_address'), int) else meta.get('base_address', 'Not recorded')}",
            f"Region size: {meta.get('region_size', 'Not recorded')}",
            f"Matched Z797 markers: {', '.join(meta.get('matched_markers', [])) if isinstance(meta.get('matched_markers'), list) else meta.get('matched_markers', 'Not recorded')}",
            "",
            "5. WHAT THIS DOES — AND DOES NOT — PROVE",
            (
                "This is a record of past activity; it does not prove that the same process or persistence target is still active."
                if historical
                else "This is current inventory or sensor evidence, but confidence depends on the exact identifiers shown above."
            ),
            (
                "Context-only evidence: Guardian deliberately does not classify this alone as a confirmed infection or offer a cleanup action."
                if meta.get("context_only")
                else ""
            ),
            "An IP, process name, Temp\\Local path, private executable memory region or historical event alone is not proof of infection.",
            "Attribution rule: a process name, target-process name, generic Temp\\Local path or old event by itself is not proof of this infection.",
            "",
            "6. RECOMMENDED RESPONSE",
            action,
            action_why,
            f"Response status: {status}",
        ]
        for key, label in (
            ("command_line", "Command line"),
            ("process_command", "Recorded command / script"),
            ("command_excerpt", "Recorded event command excerpt"),
            ("event_excerpt", "Raw event field excerpt"),
            ("ip", "Remote IP"),
            ("hostname", "Remote host"),
            ("access_mask", "Granted access mask"),
            ("start_address", "Thread start address"),
            ("evidence_file", "Memory evidence file"),
            ("expected_value_data", "Expected current registry data"),
            ("task_action", "Recorded scheduled-task action"),
        ):
            value = meta.get(key)
            if value:
                lines.extend(["", label.upper(), str(value)])
        can_action = (
            str(finding.get("remediation", "none"))
            in {
                "quarantine_file",
                "contain_exact_sample_process",
                "remove_registry_value",
                "disable_task",
                "disable_service",
                "remove_hosts_entry",
                "block_network_ip",
            }
            and not meta.get("historical")
            and not meta.get("historical_only")
            and not meta.get("context_only")
            and not meta.get("evidence_only")
            and not meta.get("response_status")
        )
        self.finding_details.setPlainText("\n".join(lines))
        self.respond_button.setEnabled(bool(can_action))
        action_button_labels = {
            "quarantine_file": "Quarantine verified file…",
            "contain_exact_sample_process": "Stop + quarantine exact payload…",
            "remove_registry_value": "Remove Z797 auto-start…",
            "disable_task": "Disable Z797 task…",
            "disable_service": "Disable Z797 service…",
            "remove_hosts_entry": "Remove Z797 Hosts entry…",
            "block_network_ip": "Block confirmed Z797 IP…",
        }
        self.respond_button.setText(
            action_button_labels.get(
                str(finding.get("remediation", "none")), "No safe cleanup action"
            )
            if can_action
            else "No safe cleanup action"
        )
        self.recheck_button.setEnabled(True)

    def respond_to_selected(self) -> None:
        finding = self._selected_finding()
        if not finding:
            return
        action = str(finding.get("remediation", "none"))
        label, explanation = self._finding_action_info(finding)
        meta = finding.get("metadata") or {}
        target = (
            finding.get("path")
            or meta.get("ip")
            or meta.get("task_name")
            or meta.get("service_name")
            or "Not specified"
        )
        digest = finding.get("sha256") or "Not available"
        size = meta.get("expected_size") or meta.get("file_size") or "Not recorded"
        details = (
            f"Finding: {finding.get('title')}\n\n"
            f"Action: {label}\n{explanation}\n\n"
            f"Target: {target}\nSHA-256: {digest}\nSize: {size}\n\n"
            "Guardian will revalidate the target where supported. Backups are created for reversible system changes. Continue?"
        )
        answer = QMessageBox.warning(
            self,
            "Confirm cleanup action",
            details,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self._active_action_finding_id = str(finding.get("finding_id", ""))
            self._run_action(finding, confirmed=True)

    def _queue_auto_containment(self, finding: dict[str, Any]) -> None:
        meta = finding.get("metadata") or {}
        fid = str(
            finding.get("finding_id")
            or (
                finding.get("sha256", "")
                + "|"
                + finding.get("path", "")
                + "|"
                + str(meta.get("pid", ""))
            )
        )
        if fid in self._auto_action_ids:
            return
        self._auto_action_ids.add(fid)
        self._auto_action_queue.append(finding)
        self._start_next_auto_containment()

    def _start_next_auto_containment(self) -> None:
        if self.action_worker and self.action_worker.isRunning():
            return
        if not self._auto_action_queue:
            return
        finding = self._auto_action_queue.pop(0)
        self._run_action(finding, confirmed=True, automatic=True)

    def _run_action(
        self, finding: dict[str, Any], *, confirmed: bool, automatic: bool = False
    ) -> None:
        if self.action_worker and self.action_worker.isRunning():
            if automatic:
                self._auto_action_queue.append(finding)
            return
        self._active_action_finding_id = str(finding.get("finding_id", ""))
        self.action_worker = ActionWorker(finding, confirmed=confirmed)
        self.action_worker.completed.connect(
            lambda result: self._action_done(result, automatic)
        )
        self.action_worker.failed.connect(self._action_failed)
        self.action_worker.start()
        self._append_activity(
            "ACTION",
            f"{'Automatic ' if automatic else ''}response started: {finding.get('title')}",
        )

    def _action_done(self, result: dict[str, Any], automatic: bool) -> None:
        self._append_activity("ACTION DONE", str(result.get("message", result)))
        if (
            self._active_action_finding_id
            and self._active_action_finding_id in self.findings
        ):
            meta = dict(
                self.findings[self._active_action_finding_id].get("metadata") or {}
            )
            meta["response_status"] = (
                str(result.get("status", "success"))
                + " · "
                + str(result.get("message", "Completed"))
            )
            self.findings[self._active_action_finding_id]["metadata"] = meta
            self._show_selected_finding()
        self._refresh_quarantine()
        if self.tray and self.settings.get("monitoring_notifications", True):
            self.tray.showMessage(
                APP_NAME,
                str(result.get("message", "Response completed")),
                QSystemTrayIcon.MessageIcon.Information,
                5000,
            )
        self.action_worker = None
        QTimer.singleShot(100, self._start_next_auto_containment)

    def _action_failed(self, message: str) -> None:
        self._append_activity("ACTION ERROR", message)
        self.action_worker = None
        QTimer.singleShot(100, self._start_next_auto_containment)

    def _refresh_counts(self) -> None:
        counts = {
            key: sum(1 for f in self.findings.values() if f.get("severity") == key)
            for key in ("Critical", "High", "Medium")
        }
        for key, label in counts.items():
            if key in getattr(self, "metric_labels", {}):
                self.metric_labels[key].setText(str(label))
        if hasattr(self, "metric_labels"):
            self.metric_labels["total"].setText(str(len(self.findings)))

    def _refresh_quarantine(self) -> None:
        if not hasattr(self, "quarantine_table"):
            return
        try:
            records = read_quarantine_index()
        except Exception as exc:
            self._append_activity("WARN", f"Could not read quarantine index: {exc}")
            records = []
        visible = [r for r in records if not r.get("permanently_deleted")]
        self.quarantine_table.setRowCount(len(visible))
        for row, record in enumerate(visible):
            name = Path(str(record.get("original_path", ""))).name
            state = "Restored" if record.get("restored") else "Quarantined"
            values = [
                name,
                str(record.get("original_path", "")),
                str(record.get("sha256", ""))[:18] + "…",
                state,
            ]
            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, record.get("id"))
                self.quarantine_table.setItem(row, col, item)
        self.quarantine_table.resizeColumnsToContents()
        self.quarantine_table.horizontalHeader().setStretchLastSection(True)

    def _selected_quarantine_id(self) -> str | None:
        rows = self.quarantine_table.selectionModel().selectedRows()
        if not rows:
            return None
        return self.quarantine_table.item(rows[0].row(), 0).data(
            Qt.ItemDataRole.UserRole
        )

    def restore_selected(self) -> None:
        qid = self._selected_quarantine_id()
        if not qid:
            QMessageBox.information(self, APP_NAME, "Select a quarantined item first.")
            return
        if (
            QMessageBox.question(
                self,
                "Restore item",
                "Restore the selected file to its original location? Existing files will not be overwritten.",
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        self._run_utility(restore_quarantined_file, str(qid))

    def delete_selected(self) -> None:
        qid = self._selected_quarantine_id()
        if not qid:
            QMessageBox.information(self, APP_NAME, "Select a quarantined item first.")
            return
        answer = QMessageBox.warning(
            self,
            "Permanent deletion",
            "This cannot be undone. The file will be permanently deleted only after its quarantine path and SHA-256 are revalidated. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self._run_utility(permanently_delete_quarantined_file, str(qid))

    def _run_utility(self, fn, *args) -> None:
        if self.utility_worker and self.utility_worker.isRunning():
            return
        self.utility_worker = UtilityWorker(fn, *args)
        self.utility_worker.completed.connect(self._utility_done)
        self.utility_worker.failed.connect(
            lambda msg: QMessageBox.critical(self, APP_NAME, msg)
        )
        self.utility_worker.start()

    def _utility_done(self, result: str) -> None:
        self._append_activity("RECOVERY", result)
        self._refresh_quarantine()
        self.utility_worker = None

    def save_settings(self, *, silent: bool = False) -> None:
        if not hasattr(self, "monitor_enabled"):
            return
        was_running = bool(self.monitor_worker and self.monitor_worker.isRunning())
        desired_running = self.monitor_enabled.isChecked()
        old_startup = bool(self.settings.get("monitoring_start_with_windows", False))
        self.settings["monitoring_enabled"] = desired_running
        self.settings["monitoring_interval_minutes"] = self.monitor_interval.value()
        self.settings["monitoring_notifications"] = (
            self.monitor_notifications.isChecked()
        )
        for key, control in self.monitor_checks.items():
            self.settings[key] = control.isChecked()
        self.settings["monitoring_start_with_windows"] = (
            self.monitor_startup.isChecked()
        )
        self.settings["auto_contain_exact_sample"] = self.auto_contain_exact.isChecked()
        self.settings["firewall_policy"] = (
            "Never change Firewall rules"
            if self.firewall_policy.currentIndex() == 1
            else "Ask before blocking"
        )
        self.settings["event_log_record_limit"] = self.event_log_limit.value()
        self.settings["settings_schema_version"] = 4
        self.settings["memory_capture_regions"] = self.memory_evidence.isChecked()
        for key, control in self.memory_switches.items():
            self.settings[key] = control.isChecked()
        # The IOC profile and staging roots are built in and immutable.
        self.settings["c2_domains"] = list(DEFAULT_THREAT_PROFILE["c2_domains"])
        self.settings["c2_ips"] = list(DEFAULT_THREAT_PROFILE["c2_ips"])
        self.settings["c2_urls"] = list(DEFAULT_THREAT_PROFILE["c2_urls"])
        _write_settings(self.settings)

        if (
            windows.IS_WINDOWS
            and not silent
            and old_startup != self.monitor_startup.isChecked()
        ):
            try:
                result = windows.configure_startup_task(
                    self.monitor_startup.isChecked(), start_monitoring=True
                )
                QMessageBox.information(self, APP_NAME, result)
            except Exception as exc:
                QMessageBox.warning(
                    self, APP_NAME, f"Could not update Windows startup: {exc}"
                )

        if not silent:
            self._append_activity(
                "SETTINGS",
                "Saved Z797-only settings; applying selected monitoring sources",
            )
            if was_running:
                # The current monitor owns a snapshot of its settings. Stop it and
                # restart with the new snapshot once its worker has exited.
                self.monitor_button.setEnabled(False)
                self.monitor_button.setText("Applying settings…")
                self.monitor_worker.stop()
                self._finish_settings_apply(desired_running)
            elif desired_running:
                self.start_monitoring()
            else:
                self._update_tray_status(False)
                self._set_header_status("Protection idle", "idle")
                self.monitor_button.setText("Start monitoring")
            self._append_activity(
                "SETTINGS",
                "Detection switches affect Scan Now immediately and continuous monitoring after its restart.",
            )

    def _finish_settings_apply(self, desired_running: bool) -> None:
        worker = self.monitor_worker
        if worker is not None and worker.isRunning():
            QTimer.singleShot(150, lambda: self._finish_settings_apply(desired_running))
            return
        self.monitor_worker = None
        self.monitor_button.setEnabled(True)
        if desired_running:
            self.start_monitoring()
        else:
            self.monitor_button.setText("Start monitoring")
            self._update_tray_status(False)
            self._set_header_status("Protection idle", "idle")
            self.monitor_label.setText("Tray ready · monitoring off")

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key.Key_Escape:
            self.hide()
            event.accept()
            return
        super().keyPressEvent(event)
