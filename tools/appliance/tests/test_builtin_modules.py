"""Coverage for tracked built-in appliance module manifests."""

from __future__ import annotations

import json
import unittest

from tools.appliance.engine.checks import (
    CHECK_KIND_SERIAL_DEVICE_EXISTS,
    CHECK_KIND_WHAD_DISCOVERY,
    render_profile_check_plans,
)
from tools.appliance.engine.modules import list_module_names, resolve_module
from tools.appliance.engine.profiles import resolve_profile


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
        for hardware_module in ("nrf52840-whad", "wifi-monitor"):
            if hardware_module in names:
                self.assertLess(names.index("base"), names.index(hardware_module))

    def test_nrf52840_whad_module_references_whad_serial_profile(self) -> None:
        self.assertIn("nrf52840-whad", list_module_names())

        module = resolve_module("nrf52840-whad")

        self.assertEqual(module.name, "nrf52840-whad")
        self.assertEqual(module.profiles, ["whad-serial"])
        self.assertEqual(module.metadata["whad_domains"], ["ble", "dot15d4"])
        self.assertEqual(module.metadata["hardware_family"], "nrf52840")
        self.assertEqual(module.metadata["firmware_family"], "butterfly")

    def test_nrf52840_whad_module_uses_generic_device_placeholders(self) -> None:
        module = resolve_module("nrf52840-whad")

        self.assertEqual(module.devices, ["/dev/ttyACM*"])
        self.assertEqual(module.metadata["device_env"], "LIBCRAFTER_WHAD_DEVICE")
        self.assertEqual(module.metadata["host_device_glob"], "/dev/ttyACM*")
        self.assertEqual(module.metadata["placeholder_device"], "/dev/ttyACM0")
        self.assertIn("qemu", module.metadata["substrates"])
        self.assertIn("virtualbox", module.metadata["substrates"])

        manifest_json = json.dumps(module.to_dict(), sort_keys=True).lower()
        for forbidden_key in ("serial_number", "usb_id", "vid_pid", "mac_address"):
            self.assertNotIn(forbidden_key, manifest_json)

    def test_nrf52840_whad_module_checks_render_through_shared_planner(self) -> None:
        module = resolve_module("nrf52840-whad")
        profile = resolve_profile("whad-serial")

        plans = render_profile_check_plans(
            profile,
            checks=[check.to_dict() for check in module.checks],
        )

        self.assertEqual(
            [plan.kind for plan in plans],
            [
                CHECK_KIND_SERIAL_DEVICE_EXISTS,
                CHECK_KIND_WHAD_DISCOVERY,
            ],
        )
        self.assertEqual(
            plans[0].command_argv[:3],
            ["python3", "-m", "tools.appliance.checks.serial_device_exists"],
        )
        self.assertEqual(plans[0].command_argv[-2:], ["--device", "/dev/ttyACM0"])
        self.assertTrue(plans[0].required)
        self.assertEqual(
            plans[1].command_argv[:3],
            ["python3", "-m", "tools.appliance.checks.whad_discovery"],
        )
        self.assertEqual(plans[1].command_argv[-2:], ["--device", "/dev/ttyACM0"])
        self.assertFalse(plans[1].required)
        self.assertFalse(plans[1].metadata["live_transmit"])


if __name__ == "__main__":
    unittest.main()
