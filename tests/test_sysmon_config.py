import unittest
from pathlib import Path
import xml.etree.ElementTree as ET


class SysmonConfigurationTests(unittest.TestCase):
    def test_config_is_well_formed_and_hashes_sha256(self):
        root = ET.parse(Path(__file__).resolve().parents[1] / "src" / "Sysmon-TCTC-Z797.xml").getroot()
        self.assertEqual(root.tag, "Sysmon")
        self.assertEqual(root.findtext("HashAlgorithms"), "SHA256")

    def test_file_create_filter_is_limited_to_temp_local(self):
        root = ET.parse(Path(__file__).resolve().parents[1] / "src" / "Sysmon-TCTC-Z797.xml").getroot()
        file_create = root.find("./EventFiltering/FileCreate")
        self.assertIsNotNone(file_create)
        values = [x.text or "" for x in file_create]
        self.assertEqual(values, ["\\Temp\\Local\\"])

    def test_network_config_only_contains_confirmed_campaign_infrastructure(self):
        root = ET.parse(Path(__file__).resolve().parents[1] / "src" / "Sysmon-TCTC-Z797.xml").getroot()
        network = root.findall(".//NetworkConnect")
        ips = [x.text for item in network for x in item.findall("DestinationIp")]
        hosts = [x.text for item in network for x in item.findall("DestinationHostname")]
        self.assertEqual(set(ips), {"93.94.52.29", "109.238.86.137"})
        self.assertEqual(set(hosts), {"benderoflight.com", "survivomatic.com", "ruthaiv.com"})

    def test_process_descendant_and_cleanup_telemetry_are_configured(self):
        root = ET.parse(Path(__file__).resolve().parents[1] / "src" / "Sysmon-TCTC-Z797.xml").getroot()
        parent_images = [node.text.lower() for node in root.findall(".//ProcessCreate/ParentImage")]
        self.assertIn(r"\powershell.exe", parent_images)
        self.assertIn(r"\mshta.exe", parent_images)
        self.assertIsNotNone(root.find("./EventFiltering/FileCreateTime"))
        self.assertIsNotNone(root.find("./EventFiltering/FileDeleteDetected"))

    def test_detect_only_policy_monitors_pe_creation_without_blocking(self):
        root = ET.parse(Path(__file__).resolve().parents[1] / "src" / "Sysmon-TCTC-Z797.xml").getroot()
        self.assertIsNotNone(root.find("./EventFiltering/FileExecutableDetected"))
        self.assertIsNone(root.find("./EventFiltering/FileBlockExecutable"))


    def test_live_subscription_plan_uses_only_sysmon_events_enabled_by_shipped_xml(self):
        from guardian.realtime import build_subscription_plan
        plan = build_subscription_plan()
        sysmon_query = next(query for _channel, query, label in plan if label == "Sysmon")
        for configured in (1, 2, 3, 4, 7, 8, 10, 11, 12, 13, 14, 16, 22, 25, 26, 29):
            self.assertIn(f"EventID={configured}", sysmon_query)
        for not_configured in (17, 18, 23, 27):
            self.assertNotIn(f"EventID={not_configured}", sysmon_query)

    def test_only_detect_only_sysmon_policy_is_shipped(self):
        project = Path(__file__).resolve().parents[1]
        self.assertFalse((project / "Sysmon-TCTC-Z797-BlockPE.xml").exists())
        self.assertFalse((project / "Configure-Sysmon-PE-Block.bat").exists())
        self.assertFalse((project / "Test-Sysmon-PE-Block.ps1").exists())


if __name__ == "__main__":
    unittest.main()
