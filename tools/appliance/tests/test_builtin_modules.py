"""Coverage for tracked built-in appliance module manifests."""

from __future__ import annotations

import json
import re
import unittest

from tools.appliance.engine.checks import (
    CHECK_KIND_DOT11_INJECTION_SMOKE,
    CHECK_KIND_DOT11_MONITOR_INTERFACE,
    CHECK_KIND_INTERFACE_EXISTS,
    CHECK_KIND_PCAP_OPEN,
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

    def test_wifi_monitor_module_references_dot11_monitor_profile(self) -> None:
        self.assertIn("wifi-monitor", list_module_names())

        module = resolve_module("wifi-monitor")

        self.assertEqual(module.name, "wifi-monitor")
        self.assertEqual(module.profiles, ["dot11-monitor"])
        self.assertEqual(module.devices, ["monitor-capable-wifi-dongle"])
        self.assertEqual(module.interfaces, ["monitor-mode-interface"])
        self.assertEqual(module.metadata["interface_env"], "LIBCRAFTER_DOT11_IFACE")
        self.assertEqual(module.metadata["channel_env"], "LIBCRAFTER_DOT11_CHANNEL")

    def test_wifi_monitor_module_declares_generic_host_or_vm_requirements(self) -> None:
        module = resolve_module("wifi-monitor")
        requirements = {requirement.name: requirement for requirement in module.host_prepare}

        self.assertEqual(
            set(requirements),
            {
                "monitor-capable-wifi-dongle",
                "driver-available",
                "monitor-interface-prepared",
                "channel-pinned",
                "pcap-permissions",
            },
        )
        for requirement in requirements.values():
            self.assertEqual(requirement.scope, "host-or-vm")
            self.assertTrue(requirement.required)

        requirement_text = " ".join(
            requirement.description for requirement in requirements.values()
        ).lower()
        self.assertIn("monitor-capable wi-fi adapter", requirement_text)
        self.assertIn("wi-fi driver", requirement_text)
        self.assertIn("monitor mode", requirement_text)
        self.assertIn("rf channel", requirement_text)
        self.assertIn("pcap", requirement_text)

    def test_wifi_monitor_module_checks_render_through_shared_planner(self) -> None:
        module = resolve_module("wifi-monitor")
        profile = resolve_profile("dot11-monitor")

        plans = render_profile_check_plans(
            profile,
            checks=[check.to_dict() for check in module.checks],
        )

        self.assertEqual(
            [plan.kind for plan in plans],
            [
                CHECK_KIND_INTERFACE_EXISTS,
                CHECK_KIND_DOT11_MONITOR_INTERFACE,
                CHECK_KIND_PCAP_OPEN,
                CHECK_KIND_DOT11_INJECTION_SMOKE,
            ],
        )
        for plan in plans:
            self.assertEqual(plan.command_argv[-2:], ["--iface-env", "LIBCRAFTER_DOT11_IFACE"])
        self.assertFalse(plans[3].required)
        self.assertIn("--dry-run", plans[3].command_argv)
        self.assertFalse(plans[3].metadata["live_transmit"])
        self.assertTrue(plans[3].metadata["requires_live_gate"])

    def test_wifi_monitor_module_has_copyable_extension_guidance(self) -> None:
        module = resolve_module("wifi-monitor")
        guidance = module.metadata["extension_guidance"]

        self.assertIn("Copy this module", guidance["copy_module"])
        self.assertIn("module-local Dockerfile", guidance["dockerfile_overlay"])
        self.assertIn("host or VM preparation script", guidance["host_prep_script"])
        self.assertIn("ignored operator configuration", guidance["local_overrides"])

    def test_wifi_monitor_module_has_no_real_hardware_ids_or_local_rf_details(self) -> None:
        module = resolve_module("wifi-monitor")

        self.assertEqual(_hardware_identifier_findings(module.to_dict()), [])

        manifest_json = json.dumps(module.to_dict(), sort_keys=True).lower()
        for forbidden_text in (
            "wlan0",
            "mon0",
            "wlx",
            "ssid",
            "bssid",
            "148f:",
            "0bda:",
        ):
            with self.subTest(forbidden_text=forbidden_text):
                self.assertNotIn(forbidden_text, manifest_json)

    def test_wifi_monitor_module_stays_provider_neutral(self) -> None:
        module = resolve_module("wifi-monitor")

        self.assertIs(module.metadata["provider_neutral"], True)
        self.assertEqual(
            module.metadata["substrates"],
            ["local", "qemu", "virtualbox", "generic-ssh"],
        )

        manifest_json = json.dumps(module.to_dict(), sort_keys=True).lower()
        for provider in ("hetzner", "aws", "gcp", "azure", "digitalocean", "linode", "vultr"):
            with self.subTest(provider=provider):
                self.assertNotIn(provider, manifest_json)


def _hardware_identifier_findings(value: object, path: str = "$") -> list[str]:
    sensitive_keys = {
        "bssid",
        "hardware_id",
        "hardware_ids",
        "mac",
        "mac_address",
        "pid",
        "serial",
        "serial_number",
        "serial_numbers",
        "ssid",
        "usb_id",
        "usb_ids",
        "vid",
        "vid_pid",
    }
    usb_id = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$")
    mac_address = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")

    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = key.lower().replace("-", "_")
            if normalized in sensitive_keys and _has_non_empty_value(item):
                findings.append(f"{path}.{key}")
            findings.extend(_hardware_identifier_findings(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_hardware_identifier_findings(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        if usb_id.fullmatch(value) or mac_address.fullmatch(value):
            findings.append(path)
    return findings


def _has_non_empty_value(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value != ""
    if isinstance(value, dict):
        return any(_has_non_empty_value(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_non_empty_value(item) for item in value)
    return True


if __name__ == "__main__":
    unittest.main()
