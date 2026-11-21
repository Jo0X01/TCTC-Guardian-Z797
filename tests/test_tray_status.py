import unittest

from guardian.tray_status import tray_status_details


class TrayStatusTests(unittest.TestCase):
    def test_active_monitoring_uses_green_and_active_text(self):
        status = tray_status_details(True)
        self.assertEqual(status["color"], "#22c55e")
        self.assertIn("ON", status["menu_text"])
        self.assertIn("ACTIVE", status["tooltip"])

    def test_stopped_monitoring_uses_red_and_explains_app_is_still_running(self):
        status = tray_status_details(False)
        self.assertEqual(status["color"], "#ef4444")
        self.assertIn("OFF", status["menu_text"])
        self.assertIn("app is still running", status["menu_text"])
        self.assertIn("STOPPED", status["tooltip"])


if __name__ == "__main__":
    unittest.main()
