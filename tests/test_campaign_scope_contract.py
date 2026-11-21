import unittest
from pathlib import Path

from guardian.settings import DEFAULT_SETTINGS, enabled_stages, engine_args
from guardian.realtime import build_subscription_plan

ROOT = Path(__file__).resolve().parents[1]


class CampaignScopeContractTests(unittest.TestCase):
    def test_only_sample_specific_options_are_exposed(self):
        self.assertNotIn("auto_network_snapshot", DEFAULT_SETTINGS)
        self.assertNotIn("memory_on_demand", DEFAULT_SETTINGS)
        self.assertFalse(any(str(key).startswith("scope_") for key in DEFAULT_SETTINGS))
        self.assertNotIn("custom_staging_roots", DEFAULT_SETTINGS)
        self.assertNotIn("related_campaign_ips", DEFAULT_SETTINGS)
        self.assertNotIn("c2_ports", DEFAULT_SETTINGS)

    def test_each_detection_switch_maps_to_a_scan_stage(self):
        mapping = {
            "monitor_processes": "processes",
            "monitor_memory": "memory",
            "monitor_persistence": "persistence",
            "monitor_files": "staging",
            "monitor_network": "network",
            "monitor_eventlogs": "eventlogs",
        }
        for key, stage in mapping.items():
            values = dict(DEFAULT_SETTINGS)
            for candidate in mapping:
                values[candidate] = candidate == key
            self.assertIn(stage, enabled_stages(values))
            self.assertIn(stage, engine_args(values)["enabled_stages"])

    def test_only_sample_relevant_event_channels_are_subscribed(self):
        plan = build_subscription_plan()
        labels = {label for _channel, _query, label in plan}
        self.assertEqual(labels, {"Sysmon", "Security", "PowerShell", "Task Scheduler", "WMI Activity"})
        combined = "\n".join(query for _channel, query, _label in plan).lower()
        self.assertNotIn("4663", combined)
        self.assertNotIn("4719", combined)
        self.assertNotIn("defender", combined)

    def test_no_defender_or_mde_import_in_detection_pipeline(self):
        scanner = (ROOT / "src" / "guardian" / "scanner.py").read_text(encoding="utf-8").lower()
        realtime = (ROOT / "src" / "guardian" / "realtime.py").read_text(encoding="utf-8").lower()
        windows = (ROOT / "src" / "guardian" / "windows.py").read_text(encoding="utf-8").lower()
        self.assertNotIn("windows defender operational", scanner)
        self.assertNotIn("defender operational", realtime)
        self.assertNotIn("defender operational", windows)
        self.assertNotIn("mde", scanner)
        self.assertNotIn("mde", realtime)


if __name__ == "__main__":
    unittest.main()
