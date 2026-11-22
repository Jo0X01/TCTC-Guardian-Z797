import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import guardian.resource_paths as resource_paths
from guardian.resource_paths import resolve_resource


class ResourcePathTests(unittest.TestCase):
    def test_source_tree_resource_resolves_from_project_root(self):
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            package = project / "src" / "guardian"
            package.mkdir(parents=True)

            resource = project / "assets" / "app-icon.ico"
            resource.parent.mkdir()
            resource.write_bytes(b"icon")

            result = resolve_resource(
                "assets", "app-icon.ico",
                executable_path=project / "src" / "main.py",
                package_file=package / "resource_paths.py",
            )

            self.assertEqual(result, resource)

    def test_nuitka_standalone_prefers_resources_beside_executable(self):
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td) / "TCTC-Guardian.dist"
            resource = bundle / "assets" / "app-icon.ico"
            resource.parent.mkdir(parents=True)
            resource.write_bytes(b"bundle icon")

            unrelated_source = (
                Path(td) / "project" / "src" / "guardian" /
                "resource_paths.py"
            )
            unrelated_source.parent.mkdir(parents=True)

            result = resolve_resource(
                "assets", "app-icon.ico",
                executable_path=bundle / "TCTC-Guardian-Z797.exe",
                package_file=unrelated_source,
            )

            self.assertEqual(result, resource)

    def test_nuitka_onefile_finds_resource_in_runtime_directory(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runtime = root / "onefile-unpacked"
            executable_dir = root / "bin"
            source_package = root / "source" / "src" / "guardian"

            resource = runtime / "assets" / "app-icon.ico"
            resource.parent.mkdir(parents=True)
            resource.write_bytes(b"onefile icon")

            executable_dir.mkdir()
            source_package.mkdir(parents=True)

            with patch.object(
                resource_paths,
                "__compiled__",
                SimpleNamespace(python_runtime_dir=str(runtime)),
                create=True,
            ):
                result = resolve_resource(
                    "assets", "app-icon.ico",
                    executable_path=(
                        executable_dir / "TCTC-Guardian-Z797.exe"
                    ),
                    package_file=source_package / "resource_paths.py",
                )

            self.assertEqual(result, resource)

    def test_nuitka_onefile_runtime_resource_has_priority_over_sidecar(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runtime = root / "runtime"
            executable_dir = root / "bin"

            runtime_resource = runtime / "assets" / "app-icon.ico"
            sidecar_resource = executable_dir / "assets" / "app-icon.ico"

            runtime_resource.parent.mkdir(parents=True)
            sidecar_resource.parent.mkdir(parents=True)

            runtime_resource.write_bytes(b"bundled icon")
            sidecar_resource.write_bytes(b"external icon")

            with patch.object(
                resource_paths,
                "__compiled__",
                SimpleNamespace(python_runtime_dir=str(runtime)),
                create=True,
            ):
                result = resolve_resource(
                    "assets", "app-icon.ico",
                    executable_path=(
                        executable_dir / "TCTC-Guardian-Z797.exe"
                    ),
                )

            self.assertEqual(result, runtime_resource)

    def test_missing_nuitka_runtime_attribute_falls_back_to_executable(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            executable_dir = root / "bin"
            resource = executable_dir / "assets" / "app-icon.ico"
            resource.parent.mkdir(parents=True)
            resource.write_bytes(b"sidecar icon")

            with patch.object(
                resource_paths,
                "__compiled__",
                SimpleNamespace(),
                create=True,
            ):
                result = resolve_resource(
                    "assets", "app-icon.ico",
                    executable_path=(
                        executable_dir / "TCTC-Guardian-Z797.exe"
                    ),
                )

            self.assertEqual(result, resource)

    def test_parent_traversal_resource_is_rejected(self):
        self.assertIsNone(resolve_resource("..", "private.txt"))


if __name__ == "__main__":
    unittest.main()