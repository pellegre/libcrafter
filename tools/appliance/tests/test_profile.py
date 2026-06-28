"""Coverage for appliance runtime profile models."""

from __future__ import annotations

import unittest

from tools.appliance.engine import model
from tools.appliance.engine.profile import ApplianceProfile, DEFAULT_IMAGE


class ApplianceProfileTest(unittest.TestCase):
    def test_parses_minimal_profile(self) -> None:
        profile = ApplianceProfile.from_dict({"name": "wan-raw"})

        self.assertEqual(
            profile.to_dict(),
            {
                "name": "wan-raw",
                "description": "",
                "image": DEFAULT_IMAGE,
                "network_mode": "bridge",
                "cap_add": [],
                "devices": [],
                "env": {},
                "mounts": [],
                "checks": [],
                "host_requirements": [],
                "metadata": {},
            },
        )
        self.assertEqual(
            profile.docker_run_policy().to_dict(),
            {
                "image": DEFAULT_IMAGE,
                "network_mode": "bridge",
                "cap_add": [],
                "devices": [],
                "env": {},
                "mounts": [],
            },
        )

    def test_rejects_protocol_specific_profile_names(self) -> None:
        with self.assertRaisesRegex(ValueError, "coarse placements"):
            ApplianceProfile.from_dict(
                {
                    "name": "tcp-only",
                    "cap_add": ["NET_RAW"],
                }
            )

    def test_rejects_non_explicit_environment(self) -> None:
        with self.assertRaisesRegex(ValueError, "env must be an object"):
            ApplianceProfile.from_dict(
                {
                    "name": "lan-raw",
                    "env": ["RUST_LOG=debug"],
                }
            )

        with self.assertRaisesRegex(ValueError, "env keys must not contain '='"):
            ApplianceProfile.from_dict(
                {
                    "name": "lan-raw",
                    "env": {"RUST_LOG=debug": "1"},
                }
            )

    def test_serializes_deterministically(self) -> None:
        profile = ApplianceProfile.from_dict(
            {
                "name": "whad-serial",
                "description": "WHAD serial appliance",
                "cap_add": ["NET_RAW", "NET_ADMIN"],
                "devices": [
                    {
                        "host_path": "/dev/ttyACM0",
                        "container_path": "/dev/whad0",
                        "permissions": "rw",
                    }
                ],
                "env": {
                    "WHAD_ADAPTER": "nrf52840",
                    "RUST_LOG": "info",
                },
                "mounts": [
                    {
                        "source": "/tmp/work",
                        "target": "/work",
                        "read_only": True,
                    }
                ],
                "checks": [
                    {
                        "name": "whad-present",
                        "description": "Probe serial",
                        "command": ["test", "-e", "/dev/ttyACM0"],
                    }
                ],
                "host_requirements": ["serial device available"],
                "metadata": {
                    "zeta": 2,
                    "alpha": {"enabled": True},
                },
            }
        )

        self.assertEqual(
            model.dumps_json(profile),
            (
                "{\n"
                '  "cap_add": [\n'
                '    "NET_RAW",\n'
                '    "NET_ADMIN"\n'
                "  ],\n"
                '  "checks": [\n'
                "    {\n"
                '      "command": [\n'
                '        "test",\n'
                '        "-e",\n'
                '        "/dev/ttyACM0"\n'
                "      ],\n"
                '      "description": "Probe serial",\n'
                '      "name": "whad-present"\n'
                "    }\n"
                "  ],\n"
                '  "description": "WHAD serial appliance",\n'
                '  "devices": [\n'
                "    {\n"
                '      "container_path": "/dev/whad0",\n'
                '      "host_path": "/dev/ttyACM0",\n'
                '      "permissions": "rw"\n'
                "    }\n"
                "  ],\n"
                '  "env": {\n'
                '    "RUST_LOG": "info",\n'
                '    "WHAD_ADAPTER": "nrf52840"\n'
                "  },\n"
                '  "host_requirements": [\n'
                '    "serial device available"\n'
                "  ],\n"
                f'  "image": "{DEFAULT_IMAGE}",\n'
                '  "metadata": {\n'
                '    "alpha": {\n'
                '      "enabled": true\n'
                "    },\n"
                '    "zeta": 2\n'
                "  },\n"
                '  "mounts": [\n'
                "    {\n"
                '      "read_only": true,\n'
                '      "source": "/tmp/work",\n'
                '      "target": "/work"\n'
                "    }\n"
                "  ],\n"
                '  "name": "whad-serial",\n'
                '  "network_mode": "bridge"\n'
                "}\n"
            ),
        )


if __name__ == "__main__":
    unittest.main()
