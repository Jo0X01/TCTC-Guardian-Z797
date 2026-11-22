from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SourceLayoutContractTests(unittest.TestCase):
    def test_runtime_entrypoint_and_sysmon_policy_share_src_root(self):
        self.assertTrue((ROOT / "src" / "main.py").is_file())
        self.assertTrue((ROOT / "src" / "Sysmon-TCTC-Z797.xml").is_file())
        main = (ROOT / "src" / "main.py").read_text(encoding="utf-8")
        self.assertIn("from guardian.windows", main)

    def test_source_launcher_resolves_project_root_and_new_entrypoint(self):
        launcher = (ROOT / "scripts" / "Run-TCTC-Guardian.bat").read_text(encoding="utf-8")
        self.assertIn('for %%I in ("%~dp0..")', launcher)
        self.assertIn(r"%PROJECT_ROOT%\src\main.py", launcher)

    def test_dependency_installer_uses_root_requirements_file(self):
        installer = (ROOT / "scripts" / "Install-Dependencies.bat").read_text(encoding="utf-8")
        self.assertIn(r"%PROJECT_ROOT%\requirements.txt", installer)

    def test_nuitka_build_uses_src_entrypoint_and_bundles_current_resource_paths(self):
        build = (ROOT / "scripts" / "Build-Windows.bat").read_text(encoding="utf-8")
        self.assertIn("--include-package=guardian", build)
        self.assertIn(r"src\main.py", build)
        self.assertIn(r"src\Sysmon-TCTC-Z797.xml=Sysmon-TCTC-Z797.xml", build)
        self.assertIn("--output-folder-name=TCTC-Guardian-Z797", build)
        self.assertIn(r"scripts\Run-Standalone.bat", build)
        self.assertTrue((ROOT / "scripts" / "Run-Standalone.bat").is_file())
        self.assertIn("--include-data-dir=assets=assets", build)

    def test_safe_lab_batch_files_call_script_in_their_own_folder(self):
        run = (ROOT / "labs" / "Run-Safe-Z797-Lab.bat").read_text(encoding="utf-8")
        cleanup = (ROOT / "labs" / "Cleanup-Safe-Z797-Lab.bat").read_text(encoding="utf-8")
        self.assertIn("safe_z797_lab.py prepare", run)
        self.assertIn("safe_z797_lab.py cleanup", cleanup)
        self.assertNotIn("tools\\safe_z797_lab.py", run + cleanup)

    def test_ci_uses_src_and_package_discovery_layout(self):
        workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
        self.assertIn("compileall -q src tests", workflow)
        self.assertIn("src/main.py --self-check", workflow)
        self.assertIn("discover -s tests -t .", workflow)


if __name__ == "__main__":
    unittest.main()
