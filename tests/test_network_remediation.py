import unittest
import hashlib
from pathlib import Path
from unittest.mock import patch

from guardian import remediation


class FirewallRemediationTests(unittest.TestCase):
    def test_blocks_only_exact_outbound_ip_and_saves_rollback_record(self):
        rule_name = "TCTC Guardian - Block - " + hashlib.sha256(b"109.238.86.137").hexdigest()[:16]
        with patch.object(remediation.windows, "IS_WINDOWS", True), \
             patch.object(remediation.windows, "run_command", side_effect=[
                 (1, "No rules match the specified criteria.", ""),
                 (0, "Ok.", ""),
                 (0, f"Rule Name: {rule_name}", ""),
             ]) as run, \
             patch.object(remediation, "_save_action_backup", return_value=Path("backup.json")) as save:
            result = remediation.block_remote_ip_with_backup("109.238.86.137")
        self.assertIn("Blocked outbound traffic to 109.238.86.137", result)
        add_args = run.call_args_list[1].args[0]
        self.assertIn("dir=out", add_args)
        self.assertIn("action=block", add_args)
        self.assertIn("remoteip=109.238.86.137", add_args)
        save.assert_called_once()
        self.assertEqual(save.call_args.args[0]["remote_ip"], "109.238.86.137")

    def test_refuses_an_unrelated_ip_without_touching_firewall(self):
        with patch.object(remediation.windows, "IS_WINDOWS", True), patch.object(remediation.windows, "run_command") as run:
            with self.assertRaisesRegex(RuntimeError, "built-in, confirmed"):
                remediation.block_remote_ip_with_backup("203.0.113.8")
        run.assert_not_called()

    def test_rolls_back_rule_if_verification_fails(self):
        with patch.object(remediation.windows, "IS_WINDOWS", True), \
             patch.object(remediation.windows, "run_command", side_effect=[
                 (1, "No rules match.", ""),
                 (0, "Ok.", ""),
                 (1, "No rule found.", ""),
                 (0, "Deleted.", ""),
             ]) as run, \
             patch.object(remediation, "_save_action_backup") as save:
            with self.assertRaisesRegex(RuntimeError, "rolled back"):
                remediation.block_remote_ip_with_backup("109.238.86.137")
        self.assertEqual(run.call_count, 4)
        self.assertIn("delete", run.call_args_list[3].args[0])
        save.assert_not_called()

    def test_refuses_loopback_or_special_ip_without_touching_firewall(self):
        with patch.object(remediation.windows, "IS_WINDOWS", True), \
             patch.object(remediation.windows, "run_command") as run:
            with self.assertRaisesRegex(RuntimeError, "built-in, confirmed TCTC/Z797 campaign IP|non-routable special-purpose"):
                remediation.block_remote_ip_with_backup("127.0.0.1")
        run.assert_not_called()

    def test_refuses_to_remove_rule_not_owned_by_guardian(self):
        with patch.object(remediation.windows, "IS_WINDOWS", True), \
             patch.object(remediation.windows, "run_command") as run:
            with self.assertRaisesRegex(RuntimeError, "not created by TCTC Guardian"):
                remediation.remove_guardian_firewall_rule("Allow all traffic")
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
