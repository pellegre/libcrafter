"""Coverage for tracked built-in appliance module manifests."""

from __future__ import annotations

import unittest

from tools.appliance.engine.modules import list_module_names, resolve_module


class BuiltinModulesTest(unittest.TestCase):
    def test_base_module_is_registered_for_raw_profiles(self) -> None:
        self.assertIn("base", list_module_names())

        module = resolve_module("base")

        self.assertEqual(module.name, "base")
        self.assertEqual(module.profiles, ["wan-raw", "lan-raw"])
        self.assertEqual(module.metadata["dockerfile"], "tools/appliance/Dockerfile")

    def test_base_module_has_no_host_device_requirements(self) -> None:
        module = resolve_module("base")

        self.assertEqual(module.host_prepare, [])
        self.assertEqual(module.devices, [])
        self.assertEqual(module.interfaces, [])

    def test_base_module_sorts_before_hardware_modules(self) -> None:
        names = list_module_names()

        self.assertEqual(names, tuple(sorted(names)))
        self.assertLess(names.index("base"), len(names))
        for hardware_module in ("nrf-whad", "wifi-monitor"):
            if hardware_module in names:
                self.assertLess(names.index("base"), names.index(hardware_module))


if __name__ == "__main__":
    unittest.main()
