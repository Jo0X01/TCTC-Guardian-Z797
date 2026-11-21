import unittest
from unittest.mock import patch

from guardian import windows


class StartupTaskTests(unittest.TestCase):
    def test_startup_task_uses_highest_privileges_and_monitor_switch(self):
        with patch("guardian.windows.IS_WINDOWS", True), patch("guardian.windows.run_command", return_value=(0, "SUCCESS", "")) as run:
            message = windows.configure_startup_task(True, start_monitoring=True)
        args = run.call_args.args[0]
        self.assertIn("/Create", args)
        self.assertIn("HIGHEST", args)
        self.assertTrue(any("--start-monitoring" in value for value in args))
        self.assertTrue(any("--start-hidden" in value for value in args))
        self.assertIn("highest available privileges", message)

    def test_disabling_absent_startup_task_is_idempotent(self):
        with patch("guardian.windows.IS_WINDOWS", True), patch("guardian.windows.run_command", return_value=(1, "", "not found")) as run:
            message = windows.configure_startup_task(False)
        self.assertEqual(run.call_count, 1)
        self.assertIn("No Windows logon task", message)

    def test_startup_task_creation_failure_is_reported(self):
        with patch("guardian.windows.IS_WINDOWS", True), patch("guardian.windows.run_command", return_value=(1, "", "Access denied")):
            with self.assertRaisesRegex(RuntimeError, "Access denied"):
                windows.configure_startup_task(True)


if __name__ == "__main__":
    unittest.main()
