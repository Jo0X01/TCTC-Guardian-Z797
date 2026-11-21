from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from guardian.qt_runtime import configure_qt_logging_environment


class QtRuntimeTests(unittest.TestCase):
    def test_filters_only_qt_icc_warning_and_preserves_other_rules(self):
        with patch.dict(os.environ, {
            "QT_LOGGING_RULES": "qt.network.ssl.warning=true;qt.gui.icc.warning=true\nqt.qpa.*=false"
        }, clear=False):
            configure_qt_logging_environment()
            rules = os.environ["QT_LOGGING_RULES"].splitlines()
        self.assertIn("qt.network.ssl.warning=true", rules)
        self.assertIn("qt.qpa.*=false", rules)
        self.assertIn("qt.gui.icc.warning=false", rules)
        self.assertNotIn("qt.gui.icc.warning=true", rules)

    def test_filter_does_not_disable_other_qt_warning_categories(self):
        with patch.dict(os.environ, {"QT_LOGGING_RULES": ""}, clear=False):
            configure_qt_logging_environment()
            rules = os.environ["QT_LOGGING_RULES"].splitlines()
        self.assertEqual(rules, ["qt.gui.icc.warning=false"])


if __name__ == "__main__":
    unittest.main()
