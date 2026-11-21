from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class UiPolishTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "src" / "guardian" / "ui.py").read_text(encoding="utf-8")

    def test_dashboard_uses_a_fixed_compact_window_size(self):
        self.assertIn("self.setFixedSize(1000, 700)", self.source)
        self.assertNotIn("self.setMinimumSize(", self.source)
        self.assertNotIn("self.resize(", self.source)
        self.assertIn("class GuardianWindow(QMainWindow):", self.source)

    def test_overview_log_expands_and_is_bounded_to_recent_events(self):
        self.assertIn("self.live_log_view.setMinimumHeight(138)", self.source)
        self.assertRegex(self.source, r"self\.live_log_view\.setSizePolicy\(\s*QSizePolicy\.Policy\.Expanding,\s*QSizePolicy\.Policy\.Expanding\s*\)")
        self.assertIn("self.live_log_view.setMaximumBlockCount(14)", self.source)
        self.assertIn('self.activity[-14:]', self.source)
        self.assertIn("pl.addWidget(self.live_log_view, 1)", self.source)
        self.assertIn("layout.addWidget(progress_panel, 1)", self.source)

    def test_overview_removes_redundant_memory_scope_paragraph(self):
        overview = self.source.split("    def _overview_page(self)", 1)[1].split("    def _findings_page(self)", 1)[0]
        self.assertNotIn("Memory inspection is read-only and limited to", overview)
        self.assertIn('"LIVE ACTIVITY"', overview)

    def test_qmainwindow_does_not_call_dialog_only_size_grip_api(self):
        self.assertNotIn("self.setSizeGripEnabled(", self.source)

    def test_severity_cards_have_distinct_visual_hierarchy(self):
        for name in ("MetricCritical", "MetricHigh", "MetricMedium", "MetricTotal"):
            self.assertIn(name, self.source)
        self.assertIn("card.setMinimumHeight(72)", self.source)

    def test_live_event_ids_are_not_mislabeled_as_historical_findings(self):
        self.assertIn('historical = bool(meta.get("historical") or meta.get("historical_only"))', self.source)
        self.assertNotIn('historical = bool(meta.get("historical") or meta.get("historical_only") or meta.get("event_id")', self.source)

    def test_finding_details_explain_missing_event_hash_instead_of_blank_value(self):
        self.assertIn("Not supplied by this event type", self.source)
        self.assertIn("event itself cannot be removed", self.source)
        self.assertIn("Re-check current device", self.source)

    def test_live_event_records_are_not_described_as_historical_evidence(self):
        self.assertIn('if meta.get("historical_only") or meta.get("historical"):', self.source)
        self.assertNotIn('if meta.get("historical_only") or meta.get("historical") or meta.get("event_id")', self.source)
        self.assertIn('self.event_log_limit.setSuffix(" event records per channel")', self.source)

    def test_findings_detail_has_campaign_specific_evidence_and_recheck_action(self):
        self.assertIn("WHY THIS MATCHES THE ANALYSED TCTC / Z797 CHAIN", self.source)
        self.assertIn("Actor Process GUID", self.source)
        self.assertIn("Target Process GUID", self.source)
        self.assertIn("WHAT THIS DOES — AND DOES NOT — PROVE", self.source)
        self.assertIn("self.recheck_button.clicked.connect(self.start_scan)", self.source)

    def test_settings_are_sample_specific_and_user_facing(self):
        settings = (ROOT / "src" / "guardian" / "settings.py").read_text(encoding="utf-8")
        self.assertIn("read_settings", settings)
        self.assertIn("write_settings", settings)
        self.assertIn("DEFAULT_SETTINGS", settings)
        self.assertIn("Save and apply", self.source)
        self.assertIn("Choose what Guardian checks for this exact infection", self.source)
        self.assertIn('self.settings_tabs.addTab(general_scroll, "Basics")', self.source)
        self.assertIn('self.settings_tabs.addTab(detection_scroll, "Z797 checks")', self.source)
        self.assertIn('QFrame#SettingCard', self.source)
        self.assertNotIn("monitor_realtime_enabled", self.source)

    def test_historical_and_context_only_findings_override_any_cleanup_label(self):
        method = self.source.split("    def _finding_action_info", 1)[1].split("    def _refresh_findings", 1)[0]
        self.assertLess(method.index('if meta.get("historical_only") or meta.get("historical"):') , method.index('if action in mapping:'))
        self.assertLess(method.index('if meta.get("context_only"):') , method.index('if action in mapping:'))
        self.assertLess(method.index('if meta.get("evidence_only"):') , method.index('if action in mapping:'))

    def test_findings_offer_action_specific_cleanup_labels(self):
        for label in (
            "Quarantine verified file…", "Stop + quarantine exact payload…",
            "Remove Z797 auto-start…", "Disable Z797 task…",
            "Disable Z797 service…", "Remove Z797 Hosts entry…",
        ):
            self.assertIn(label, self.source)
        self.assertIn("No safe cleanup action", self.source)

    def test_no_defender_events_are_subscribed_or_scanned(self):
        scanner = (ROOT / "src" / "guardian" / "scanner.py").read_text(encoding="utf-8")
        realtime = (ROOT / "src" / "guardian" / "realtime.py").read_text(encoding="utf-8")
        self.assertNotIn("Defender Operational", scanner)
        self.assertNotIn("Defender Operational", realtime)
        self.assertNotIn("Windows Defender Operational", scanner)

    def test_protection_status_uses_stateful_stylesheet_properties(self):
        self.assertIn('QLabel#HeaderStatus[state="active"]', self.source)
        self.assertIn('QLabel#HeaderStatus[state="warning"]', self.source)
        self.assertIn("def _set_header_status", self.source)


if __name__ == "__main__":
    unittest.main()
