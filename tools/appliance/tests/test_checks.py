"""Coverage for appliance profile readiness check planning."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.appliance.checks import (
    dot11_injection_smoke,
    dot11_monitor_interface,
    serial_device_exists,
    whad_discovery,
)
from tools.appliance.checks.common import CommandResult
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


class RFCheckScriptTest(unittest.TestCase):
    def test_whad_serial_check_accepts_fake_device_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_device = Path(directory) / "dev" / "ttyACM-check0"
            fake_device.parent.mkdir()
            fake_device.write_text("", encoding="utf-8")

            exit_code, payload = _run_check_script(
                serial_device_exists.main,
                ["--device", str(fake_device)],
            )

        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["check"], CHECK_KIND_SERIAL_DEVICE_EXISTS)
        self.assertEqual(payload["device"], str(fake_device))
        self.assertTrue(payload["exists"])
        self.assertTrue(payload["readable"])
        self.assertFalse(payload["character_device"])

    def test_whad_serial_check_reports_missing_fake_device(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing_device = Path(directory) / "dev" / "ttyACM-missing"

            exit_code, payload = _run_check_script(
                serial_device_exists.main,
                ["--device", str(missing_device)],
            )

        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["check"], CHECK_KIND_SERIAL_DEVICE_EXISTS)
        self.assertEqual(payload["error"], "missing_serial_device")
        self.assertEqual(payload["device"], str(missing_device))
        self.assertFalse(payload["exists"])
        self.assertFalse(payload["readable"])

    def test_whad_discovery_uses_fake_runner_and_fake_device(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str]) -> CommandResult:
            calls.append(list(argv))
            return CommandResult(returncode=0, stdout="adapter: fake-whad")

        with tempfile.TemporaryDirectory() as directory:
            fake_device = str(Path(directory) / "dev" / "ttyACM-check1")
            exit_code, payload = _run_check_script(
                whad_discovery.main,
                ["--tool", "whad-test", "--device", fake_device],
                runner=runner,
            )

        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["check"], CHECK_KIND_WHAD_DISCOVERY)
        self.assertFalse(payload["live_transmit"])
        self.assertEqual(payload["device"], fake_device)
        self.assertEqual(
            payload["command_argv"],
            ["whad-test", "discover", "--device", fake_device],
        )
        self.assertEqual(calls, [["whad-test", "discover", "--device", fake_device]])

    def test_dot11_monitor_interface_reports_missing_fake_interface(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sysfs_root = Path(directory)
            exit_code, payload = _run_check_script(
                dot11_monitor_interface.main,
                ["--iface", "mon-check0", "--sysfs-root", str(sysfs_root)],
            )

        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["check"], CHECK_KIND_DOT11_MONITOR_INTERFACE)
        self.assertEqual(payload["error"], "missing_interface")
        self.assertEqual(payload["iface"], "mon-check0")
        self.assertEqual(payload["sysfs_root"], str(sysfs_root))
        self.assertFalse(payload["exists"])
        self.assertFalse(payload["monitor_mode"])

    def test_dot11_monitor_interface_reports_monitor_mode_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            interface_path = Path(directory) / "mon-check1"
            interface_path.mkdir()
            (interface_path / "type").write_text("803\n", encoding="utf-8")

            exit_code, payload = _run_check_script(
                dot11_monitor_interface.main,
                ["--iface", "mon-check1", "--sysfs-root", str(directory)],
            )

        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["check"], CHECK_KIND_DOT11_MONITOR_INTERFACE)
        self.assertEqual(payload["iface"], "mon-check1")
        self.assertTrue(payload["exists"])
        self.assertTrue(payload["monitor_mode"])
        self.assertEqual(payload["interface_type"], "803")
        self.assertEqual(payload["source"], "sysfs-type")
        self.assertEqual(payload["interface_path"], str(interface_path))

    def test_dot11_injection_smoke_is_gated_to_dry_run_planning(self) -> None:
        exit_code, payload = _run_check_script(
            dot11_injection_smoke.main,
            ["--dry-run", "--iface", "mon-check2", "--channel", "6"],
        )

        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["check"], CHECK_KIND_DOT11_INJECTION_SMOKE)
        self.assertTrue(payload["dry_run"])
        self.assertFalse(payload["live_transmit"])
        self.assertTrue(payload["requires_live_gate"])
        self.assertTrue(payload["plan"]["interface_must_be_monitor_mode"])

        rejected_exit_code, rejected_payload = _run_check_script(
            dot11_injection_smoke.main,
            ["--iface", "mon-check2"],
        )

        self.assertEqual(rejected_exit_code, 1)
        self.assertFalse(rejected_payload["ok"])
        self.assertEqual(rejected_payload["error"], "live_check_rejected")
        self.assertFalse(rejected_payload["live_transmit"])


def _run_check_script(
    main: object,
    argv: list[str],
    **kwargs: object,
) -> tuple[int, dict[str, object]]:
    output = io.StringIO()
    exit_code = main(argv, stdout=output, **kwargs)  # type: ignore[operator]
    payload = json.loads(output.getvalue())
    return exit_code, payload


if __name__ == "__main__":
    unittest.main()
