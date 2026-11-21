import unittest
from guardian.settings import DEFAULT_SETTINGS, enabled_stages as _enabled_stages, engine_args as _engine_args

class SampleScopeSettingsTests(unittest.TestCase):
    def test_same_sensor_switches_apply_to_manual_and_monitoring(self):
        settings = dict(DEFAULT_SETTINGS)
        settings.update({"monitor_processes": False, "monitor_memory": False, "monitor_persistence": True, "monitor_files": True, "monitor_network": False, "monitor_eventlogs": False})
        self.assertEqual(_enabled_stages(settings), _enabled_stages(settings, monitoring=True))
        self.assertEqual(_enabled_stages(settings), {"persistence", "staging", "verification"})

    def test_engine_uses_only_built_in_z797_indicators_and_roots(self):
        settings = dict(DEFAULT_SETTINGS)
        settings.update({"related_campaign_ips": ["203.0.113.7"], "c2_ports": ["4444"], "custom_staging_roots": ["C:/"]})
        args = _engine_args(settings)
        self.assertNotIn("related_campaign_ips", args)
        self.assertNotIn("c2_ports", args)
        self.assertNotIn("custom_staging_roots", args)
        self.assertNotIn("defender", args["enabled_stages"])

if __name__ == "__main__":
    unittest.main()
