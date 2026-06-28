"""Coverage for appliance module manifest models."""

from __future__ import annotations

import unittest

from tools.appliance.engine.module import ApplianceModule


class ApplianceModuleTest(unittest.TestCase):
    def test_parses_generic_module(self) -> None:
        module = ApplianceModule.from_dict(
            {
                "name": "generic-tools",
                "description": "Generic appliance userland extension",
                "profiles": ["wan-raw", "lan-raw"],
                "devices": ["raw-socket-access"],
                "interfaces": ["routed-network"],
                "metadata": {
                    "owner": "appliance",
                    "hardware_family": "generic",
                },
            }
        )

        self.assertEqual(
            module.to_dict(),
            {
                "name": "generic-tools",
                "description": "Generic appliance userland extension",
                "profiles": ["wan-raw", "lan-raw"],
                "image_extensions": [],
                "host_prepare": [],
                "checks": [],
                "devices": ["raw-socket-access"],
                "interfaces": ["routed-network"],
                "metadata": {
                    "owner": "appliance",
                    "hardware_family": "generic",
                },
            },
        )

    def test_parses_optional_dockerfile_metadata(self) -> None:
        module = ApplianceModule.from_dict(
            {
                "name": "whad-userland",
                "profiles": ["whad-serial"],
                "image_extensions": [
                    {
                        "dockerfile": "Dockerfile",
                        "context": ".",
                        "target": "whad-userland",
                        "build_args": {
                            "WHAD_FEATURES": "serial",
                        },
                        "metadata": {
                            "stage": "userland",
                        },
                    }
                ],
            }
        )

        self.assertEqual(
            module.image_extensions[0].to_dict(),
            {
                "path": "Dockerfile",
                "context": ".",
                "target": "whad-userland",
                "build_args": {
                    "WHAD_FEATURES": "serial",
                },
                "metadata": {
                    "stage": "userland",
                },
            },
        )

    def test_parses_host_prepare_and_check_metadata(self) -> None:
        module = ApplianceModule.from_dict(
            {
                "name": "nrf-whad",
                "profiles": ["whad-serial"],
                "host_prepare": [
                    {
                        "name": "usb-passthrough",
                        "description": "WHAD serial dongle is passed through to the VM",
                        "kind": "usb",
                        "scope": "vm",
                        "command": ["test", "-e", "/dev/whad0"],
                        "required": True,
                        "metadata": {
                            "device_family": "nrf-whad",
                        },
                    }
                ],
                "checks": [
                    {
                        "name": "whad-tools",
                        "description": "WHAD command-line tools are available",
                        "scope": "container",
                        "command": ["python3", "-m", "whad", "--help"],
                        "required": True,
                        "metadata": {
                            "dry_run_safe": True,
                        },
                    }
                ],
            }
        )

        self.assertEqual(module.host_prepare[0].kind, "usb")
        self.assertEqual(module.host_prepare[0].scope, "vm")
        self.assertEqual(module.checks[0].scope, "container")
        self.assertEqual(module.checks[0].metadata, {"dry_run_safe": True})

    def test_rejects_empty_or_invalid_names(self) -> None:
        for name in ("", "wifi_monitor", "../wifi", "WiFi", "wifi.monitor"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    ApplianceModule.from_dict(
                        {
                            "name": name,
                            "profiles": ["dot11-monitor"],
                        }
                    )

    def test_rejects_empty_profile_references(self) -> None:
        with self.assertRaisesRegex(ValueError, "profiles entries"):
            ApplianceModule.from_dict(
                {
                    "name": "bad-profile-reference",
                    "profiles": [""],
                }
            )

    def test_rejects_tracked_hardware_identifiers(self) -> None:
        with self.assertRaisesRegex(ValueError, "real serial numbers or hardware IDs"):
            ApplianceModule.from_dict(
                {
                    "name": "local-dongle",
                    "profiles": ["whad-serial"],
                    "metadata": {
                        "serial_number": "ABC123",
                    },
                }
            )


if __name__ == "__main__":
    unittest.main()
