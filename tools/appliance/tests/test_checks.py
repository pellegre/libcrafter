"""Coverage for appliance profile readiness check planning."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.appliance.engine.checks import (
    CHECK_KIND_DOCKER_DAEMON,
    CHECK_KIND_DOT11_INJECTION_SMOKE,
    CHECK_KIND_DOT11_MONITOR_INTERFACE,
    CHECK_KIND_IMAGE_AVAILABLE,
    CHECK_KIND_INTERFACE_EXISTS,
    CHECK_KIND_PCAP_OPEN,
    CHECK_KIND_RAW_SOCKET_PERMISSION,
    CHECK_KIND_SERIAL_DEVICE_EXISTS,
    CHECK_KIND_WHAD_DISCOVERY,
    UnknownCheckKindError,
    render_profile_check_plans,
)
from tools.appliance.engine.profile import ApplianceProfile, ProfileCheck, ProfileDevice


class ProfileCheckPlanTest(unittest.TestCase):
    def test_renders_known_check_kinds(self) -> None:
        plans = render_profile_check_plans(
            {
                "name": "dot11-monitor",
                "image": "registry.example/libcrafter/appliance:test",
                "env": {
                    "LIBCRAFTER_DOT11_IFACE": "",
                },
                "devices": [
                    {
                        "host_path": "/dev/ttyACM-test",
                        "container_path": "/dev/whad0",
                        "permissions": "rw",
                    }
                ],
                "checks": [
                    {"kind": CHECK_KIND_DOCKER_DAEMON},
                    {"kind": CHECK_KIND_IMAGE_AVAILABLE},
                    {
                        "kind": CHECK_KIND_INTERFACE_EXISTS,
                        "parameters": {"interface": "mon-test0"},
                    },
                    {"kind": CHECK_KIND_RAW_SOCKET_PERMISSION},
                    {"kind": CHECK_KIND_PCAP_OPEN},
                    {"kind": CHECK_KIND_SERIAL_DEVICE_EXISTS},
                    {"kind": CHECK_KIND_WHAD_DISCOVERY},
                    {"kind": CHECK_KIND_DOT11_MONITOR_INTERFACE},
                    {"kind": CHECK_KIND_DOT11_INJECTION_SMOKE},
                ],
            },
            docker_command="docker-test",
        )

        by_kind = {plan.kind: plan for plan in plans}
        self.assertEqual(
            by_kind[CHECK_KIND_DOCKER_DAEMON].command_argv,
            [
                "python3",
                "-m",
                "tools.appliance.checks.docker_daemon",
                "--docker",
                "docker-test",
            ],
        )
        self.assertEqual(
            by_kind[CHECK_KIND_IMAGE_AVAILABLE].command_argv,
            [
                "python3",
                "-m",
                "tools.appliance.checks.image_available",
                "--docker",
                "docker-test",
                "--image",
                "registry.example/libcrafter/appliance:test",
            ],
        )
        self.assertEqual(
            by_kind[CHECK_KIND_INTERFACE_EXISTS].command_argv[-2:],
            ["--iface", "mon-test0"],
        )
        self.assertEqual(
            by_kind[CHECK_KIND_PCAP_OPEN].command_argv[-2:],
            ["--iface-env", "LIBCRAFTER_DOT11_IFACE"],
        )
        self.assertEqual(
            by_kind[CHECK_KIND_SERIAL_DEVICE_EXISTS].command_argv[-2:],
            ["--device", "/dev/ttyACM-test"],
        )
        self.assertIn("--dry-run", by_kind[CHECK_KIND_DOT11_INJECTION_SMOKE].command_argv)
        self.assertEqual(
            by_kind[CHECK_KIND_DOT11_INJECTION_SMOKE].metadata,
            {
                "live_transmit": False,
                "placeholder": True,
            },
        )
        json.loads(json.dumps([plan.to_dict() for plan in plans], sort_keys=True))

    def test_planning_has_no_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing_device = Path(directory) / "ttyFAKE0"

            plans = render_profile_check_plans(
                ApplianceProfile(
                    name="whad-serial",
                    devices=[
                        ProfileDevice(
                            host_path=str(missing_device),
                            container_path="/dev/whad0",
                            permissions="rw",
                        )
                    ],
                    checks=[ProfileCheck(name=CHECK_KIND_SERIAL_DEVICE_EXISTS)],
                )
            )

            self.assertEqual(plans[0].command_argv[-2:], ["--device", str(missing_device)])
            self.assertFalse(missing_device.exists())

    def test_stable_check_names(self) -> None:
        profile = {
            "name": "wan-raw",
            "checks": [
                {"kind": CHECK_KIND_DOCKER_DAEMON},
                {"kind": CHECK_KIND_IMAGE_AVAILABLE},
                {"kind": CHECK_KIND_INTERFACE_EXISTS},
                {"kind": CHECK_KIND_RAW_SOCKET_PERMISSION},
            ],
        }

        first = [plan.name for plan in render_profile_check_plans(profile)]
        second = [plan.name for plan in render_profile_check_plans(profile)]

        self.assertEqual(first, second)
        self.assertEqual(
            first,
            [
                CHECK_KIND_DOCKER_DAEMON,
                CHECK_KIND_IMAGE_AVAILABLE,
                CHECK_KIND_INTERFACE_EXISTS,
                CHECK_KIND_RAW_SOCKET_PERMISSION,
            ],
        )

    def test_clear_error_for_unknown_check_kind(self) -> None:
        with self.assertRaisesRegex(
            UnknownCheckKindError,
            "unknown appliance check kind 'packet-scan'",
        ) as captured:
            render_profile_check_plans(
                {
                    "name": "lan-raw",
                    "checks": [{"kind": "packet-scan"}],
                }
            )

        self.assertEqual(captured.exception.kind, "packet-scan")
        self.assertIn(CHECK_KIND_DOCKER_DAEMON, captured.exception.known)

    def test_explicit_legacy_commands_are_preserved(self) -> None:
        plans = render_profile_check_plans(
            ApplianceProfile(
                name="lan-raw",
                checks=[
                    ProfileCheck(
                        name="legacy-check",
                        description="Existing command declaration",
                        command=["test", "-r", "/etc/os-release"],
                    )
                ],
            )
        )

        self.assertEqual(plans[0].name, "legacy-check")
        self.assertEqual(plans[0].kind, "command")
        self.assertEqual(plans[0].command_argv, ["test", "-r", "/etc/os-release"])


if __name__ == "__main__":
    unittest.main()
