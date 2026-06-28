"""Coverage for appliance module manifest registry loading."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.appliance.engine.modules import (
    UnknownApplianceModuleError,
    filter_modules_by_profile,
    list_module_names,
    load_modules,
    resolve_module,
)


class ApplianceModuleRegistryTest(unittest.TestCase):
    def test_lists_module_names_in_sorted_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_module(root / "z-wifi" / "module.json", "wifi-monitor")
            self._write_module(root / "a-base" / "module.json", "base-tools")

            self.assertEqual(list_module_names(root), ("base-tools", "wifi-monitor"))

    def test_resolve_module_rejects_unknown_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_module(root / "base" / "module.json", "base-tools")

            with self.assertRaises(UnknownApplianceModuleError) as captured:
                resolve_module("nrf-whad", root)

            self.assertEqual(captured.exception.name, "nrf-whad")
            self.assertEqual(captured.exception.known, ("base-tools",))
            self.assertIn("known modules: base-tools", str(captured.exception))

    def test_rejects_duplicate_module_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_module(root / "first" / "module.json", "base-tools")
            self._write_module(root / "second" / "module.json", "base-tools")

            with self.assertRaisesRegex(ValueError, "duplicate appliance module 'base-tools'"):
                load_modules(root)

    def test_filters_modules_by_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_module(
                root / "base" / "module.json",
                "base-tools",
                profiles=["wan-raw", "lan-raw"],
            )
            self._write_module(
                root / "nrf" / "module.json",
                "nrf-whad",
                profiles=["whad-serial"],
            )
            self._write_module(
                root / "wifi" / "module.json",
                "wifi-monitor",
                profiles=["dot11-monitor", "lan-raw"],
            )

            modules = filter_modules_by_profile("lan-raw", root)

            self.assertEqual([module.name for module in modules], ["base-tools", "wifi-monitor"])

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


if __name__ == "__main__":
    unittest.main()
