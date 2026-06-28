"""Coverage for appliance profile and module registry CLI commands."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tools.appliance.engine import cli


class ApplianceRegistryCliTest(unittest.TestCase):
    def test_lists_profiles_and_modules_in_sorted_order(self) -> None:
        with self._registry_roots() as (profile_root, module_root):
            self._write_profile(profile_root / "z-wan.json", "wan-raw")
            self._write_profile(profile_root / "a-lan.json", "lan-raw")
            self._write_module(module_root / "z-wifi" / "module.json", "wifi-monitor")
            self._write_module(module_root / "a-base" / "module.json", "base-tools")

            profiles_exit, profiles_payload = self._run_json(["profiles", "list", "--json"])
            modules_exit, modules_payload = self._run_json(["modules", "list", "--json"])

        self.assertEqual(profiles_exit, 0)
        self.assertEqual(
            [profile["name"] for profile in profiles_payload["profiles"]],
            ["lan-raw", "wan-raw"],
        )
        self.assertEqual(modules_exit, 0)
        self.assertEqual(
            [module["name"] for module in modules_payload["modules"]],
            ["base-tools", "wifi-monitor"],
        )

    def test_shows_profile_and_module_json(self) -> None:
        with self._registry_roots() as (profile_root, module_root):
            self._write_profile(profile_root / "wan.json", "wan-raw")
            self._write_module(
                module_root / "base" / "module.json",
                "base-tools",
                profiles=["wan-raw", "lan-raw"],
            )

            profile_exit, profile_payload = self._run_json(
                ["profiles", "show", "wan-raw", "--json"]
            )
            module_exit, module_payload = self._run_json(
                ["modules", "show", "base-tools", "--json"]
            )

        self.assertEqual(profile_exit, 0)
        self.assertEqual(profile_payload["profile"]["name"], "wan-raw")
        self.assertEqual(profile_payload["profile"]["description"], "test profile")
        self.assertEqual(module_exit, 0)
        self.assertEqual(module_payload["module"]["name"], "base-tools")
        self.assertEqual(module_payload["module"]["profiles"], ["wan-raw", "lan-raw"])

    def test_unknown_profile_json_error_exits_2(self) -> None:
        with self._registry_roots() as (profile_root, _module_root):
            self._write_profile(profile_root / "wan.json", "wan-raw")

            exit_code, payload = self._run_json(["profiles", "show", "lan-raw", "--json"])

        self.assertEqual(exit_code, 2)
        self.assertEqual(payload["ok"], False)
        self.assertEqual(payload["error"], "unknown_profile")
        self.assertEqual(payload["name"], "lan-raw")
        self.assertEqual(payload["known"], ["wan-raw"])

    def test_unknown_module_json_error_exits_2(self) -> None:
        with self._registry_roots() as (_profile_root, module_root):
            self._write_module(module_root / "base" / "module.json", "base-tools")

            exit_code, payload = self._run_json(
                ["modules", "show", "wifi-monitor", "--json"]
            )

        self.assertEqual(exit_code, 2)
        self.assertEqual(payload["ok"], False)
        self.assertEqual(payload["error"], "unknown_module")
        self.assertEqual(payload["name"], "wifi-monitor")
        self.assertEqual(payload["known"], ["base-tools"])

    def test_text_output_smoke(self) -> None:
        with self._registry_roots() as (profile_root, module_root):
            self._write_profile(profile_root / "wan.json", "wan-raw")
            self._write_module(module_root / "base" / "module.json", "base-tools")

            profile_list_exit, profile_list_text = self._run_text(["profiles", "list"])
            profile_show_exit, profile_show_text = self._run_text(
                ["profiles", "show", "wan-raw"]
            )
            module_list_exit, module_list_text = self._run_text(["modules", "list"])
            module_show_exit, module_show_text = self._run_text(
                ["modules", "show", "base-tools"]
            )

        self.assertEqual(profile_list_exit, 0)
        self.assertIn("wan-raw", profile_list_text)
        self.assertEqual(profile_show_exit, 0)
        self.assertIn("network_mode:", profile_show_text)
        self.assertEqual(module_list_exit, 0)
        self.assertIn("base-tools", module_list_text)
        self.assertEqual(module_show_exit, 0)
        self.assertIn("profiles:", module_show_text)

    def _run_json(self, argv: list[str]) -> tuple[int, dict[str, object]]:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = cli.main(argv)
        payload = json.loads(stdout.getvalue())
        self.assertIsInstance(payload, dict)
        return exit_code, payload

    def _run_text(self, argv: list[str]) -> tuple[int, str]:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = cli.main(argv)
        return exit_code, stdout.getvalue()

    def _registry_roots(self) -> "_PatchedRegistryRoots":
        return _PatchedRegistryRoots()

    def _write_profile(self, path: Path, name: str) -> None:
        path.write_text(
            (
                "{\n"
                f'  "name": "{name}",\n'
                '  "description": "test profile"\n'
                "}\n"
            ),
            encoding="utf-8",
        )

    def _write_module(
        self,
        path: Path,
        name: str,
        *,
        profiles: list[str] | None = None,
    ) -> None:
        selected_profiles = profiles or ["wan-raw"]
        path.parent.mkdir(parents=True, exist_ok=True)
        profiles_json = ", ".join(f'"{profile}"' for profile in selected_profiles)
        path.write_text(
            (
                "{\n"
                f'  "name": "{name}",\n'
                '  "description": "test module",\n'
                f'  "profiles": [{profiles_json}]\n'
                "}\n"
            ),
            encoding="utf-8",
        )


class _PatchedRegistryRoots:
    def __enter__(self) -> tuple[Path, Path]:
        self._temp = tempfile.TemporaryDirectory()
        root = Path(self._temp.name)
        self.profile_root = root / "profiles"
        self.module_root = root / "modules"
        self.profile_root.mkdir()
        self.module_root.mkdir()
        self._profile_patch = patch.object(
            cli.profile_registry,
            "profiles_dir",
            return_value=self.profile_root,
        )
        self._module_patch = patch.object(
            cli.module_registry,
            "modules_dir",
            return_value=self.module_root,
        )
        self._profile_patch.start()
        self._module_patch.start()
        return self.profile_root, self.module_root

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self._module_patch.stop()
        self._profile_patch.stop()
        self._temp.cleanup()


if __name__ == "__main__":
    unittest.main()
