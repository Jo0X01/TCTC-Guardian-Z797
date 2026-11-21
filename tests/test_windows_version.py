import unittest
from unittest.mock import patch

from guardian import windows


class WindowsVersionTests(unittest.TestCase):
    def test_windows_11_build_is_not_mislabeled_windows_10(self):
        with patch("guardian.windows.IS_WINDOWS", True), \
             patch("guardian.windows._windows_version_tuple", return_value=(10, 0, 26300)), \
             patch("guardian.windows.platform.machine", return_value="AMD64"):
            self.assertEqual(windows.format_os(), "Windows 11 · Build 26300 / AMD64")

    def test_windows_10_build_keeps_windows_10_label(self):
        with patch("guardian.windows.IS_WINDOWS", True), \
             patch("guardian.windows._windows_version_tuple", return_value=(10, 0, 19045)), \
             patch("guardian.windows.platform.machine", return_value="AMD64"):
            self.assertEqual(windows.format_os(), "Windows 10 · Build 19045 / AMD64")

    def test_non_windows_fallback_does_not_claim_windows_marketing_version(self):
        with patch("guardian.windows._windows_version_tuple", return_value=None), \
             patch("guardian.windows.platform.system", return_value="Linux"), \
             patch("guardian.windows.platform.release", return_value="6.8"), \
             patch("guardian.windows.platform.machine", return_value="x86_64"):
            self.assertEqual(windows.format_os(), "Linux 6.8 / x86_64")


if __name__ == "__main__":
    unittest.main()
