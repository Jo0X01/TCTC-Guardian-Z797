import unittest

from guardian.scanner import ScanEngine
from guardian.threat_profile import (
    CONFIRMED_CAMPAIGN_IPS, DEFAULT_THREAT_PROFILE, merge_default_indicators,
)


class ThreatProfileDefaultTests(unittest.TestCase):
    def test_defaults_contain_only_locally_recovered_z797_indicators(self):
        merged = merge_default_indicators({"c2_ips": [], "c2_domains": [], "c2_urls": []})
        self.assertEqual(merged["c2_ips"], list(CONFIRMED_CAMPAIGN_IPS))
        self.assertIn("benderoflight.com", merged["c2_domains"])
        self.assertIn("survivomatic.com", merged["c2_domains"])
        self.assertIn("ruthaiv.com", merged["c2_domains"])
        self.assertEqual(set(DEFAULT_THREAT_PROFILE), {"c2_domains", "c2_ips", "c2_urls"})

    def test_unverified_user_and_sibling_indicators_are_not_merged(self):
        merged = merge_default_indicators({"c2_ips": ["203.0.113.8", "93.94.52.4"]})
        self.assertNotIn("203.0.113.8", merged["c2_ips"])
        self.assertNotIn("93.94.52.4", merged["c2_ips"])
        self.assertIn("109.238.86.137", merged["c2_ips"])

    def test_scan_engine_uses_only_built_in_z797_profile(self):
        engine = ScanEngine()
        self.assertIn("93.94.52.29", engine.c2_ips)
        self.assertIn("109.238.86.137", engine.c2_ips)
        self.assertIn("benderoflight.com", engine.c2_domains)
        self.assertIn("https://benderoflight.com/nfront.php", engine.c2_urls)
        self.assertEqual(engine.related_campaign_ips, ())


if __name__ == "__main__":
    unittest.main()
