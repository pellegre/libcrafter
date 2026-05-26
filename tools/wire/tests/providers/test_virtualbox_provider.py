"""Fake-run coverage for VirtualBox endpoint planning."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from unittest import mock

from tools.wire.engine import cli as wire_cli
from tools.wire.engine.process import CommandResult
from tools.wire.engine.providers import resolve_provider, virtualbox
from tools.wire.engine.providers.virtualbox.constants import VBOX_BRIDGE_IFACE_ENV
from tools.wire.engine.registry import ProviderExposureError


class VirtualBoxRegistryTest(unittest.TestCase):
    def test_virtualbox_rejects_non_lan_exposures_before_provider_work(self) -> None:
        for exposure in ("wan", "private", "wifi"):
            with self.subTest(exposure=exposure):
                with self.assertRaisesRegex(ProviderExposureError, "supported exposures"):
                    resolve_provider("virtualbox", exposure)


class VirtualBoxDoctorTest(unittest.TestCase):
    def test_doctor_reports_required_commands_and_selected_bridge(self) -> None:
        calls: list[tuple[str, ...]] = []

        def fake_runner(argv: Sequence[object], **_: object) -> CommandResult:
            parts = tuple(str(part) for part in argv)
            calls.append(parts)
            return _result(parts, stdout=_bridgedifs())

        with mock.patch(
            "tools.wire.engine.providers.virtualbox.doctor.shutil.which",
            side_effect=lambda command: f"/usr/bin/{command}",
        ):
            report = virtualbox.doctor(
                provider="virtualbox",
                exposure="lan",
                dry_run=True,
                env={VBOX_BRIDGE_IFACE_ENV: "wlan0"},
                command_runner=fake_runner,
            )

        self.assertTrue(report["ok"])
        self.assertEqual(calls, [("VBoxManage", "list", "bridgedifs")])
        self.assertTrue(report["commands"]["VBoxManage"]["installed"])  # type: ignore[index]
        self.assertEqual(report["bridge"]["selected_name"], "wlan0")  # type: ignore[index]
        self.assertEqual(report["bridge"]["requested_name"], "wlan0")  # type: ignore[index]
        self.assertTrue(report["bridge"]["discovered"])  # type: ignore[index]

    def test_doctor_reports_missing_requested_bridge(self) -> None:
        def fake_runner(argv: Sequence[object], **_: object) -> CommandResult:
            return _result(tuple(str(part) for part in argv), stdout=_bridgedifs())

        with mock.patch(
            "tools.wire.engine.providers.virtualbox.doctor.shutil.which",
            side_effect=lambda command: f"/usr/bin/{command}",
        ):
            report = virtualbox.doctor(
                provider="virtualbox",
                exposure="lan",
                dry_run=True,
                env={VBOX_BRIDGE_IFACE_ENV: "eth9"},
                command_runner=fake_runner,
            )

        self.assertFalse(report["ok"])
        bridge_check = [
            check for check in report["checks"] if check["name"] == "bridge_discovery"  # type: ignore[index]
        ][0]
        self.assertIn("was not found", bridge_check["message"])
        self.assertIsNone(report["bridge"]["selected_name"])  # type: ignore[index]


class VirtualBoxCreateEndpointTest(unittest.TestCase):
    def test_dry_run_manifest_has_absolute_paths_and_planned_lan_interfaces(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            with mock.patch(
                "tools.wire.engine.providers.virtualbox.create.free_localhost_tcp_port",
                return_value=25222,
            ):
                output = virtualbox.create_endpoint(
                    provider="virtualbox",
                    exposure="lan",
                    role="probe",
                    dry_run=True,
                    env={VBOX_BRIDGE_IFACE_ENV: "wlan0"},
                )

        self.assertFalse(output["created"])
        self.assertTrue(output["dry_run"])
        self.assertEqual(output["status"], "planned")
        self.assertEqual(output["endpoint_id"], "planned-virtualbox-lan-probe")
        self.assertEqual(output["ssh"]["host"], "127.0.0.1")  # type: ignore[index]
        self.assertEqual(output["ssh"]["port"], 25222)  # type: ignore[index]
        self.assertTrue(Path(str(output["ssh"]["identity_file"])).is_absolute())  # type: ignore[index]
        self.assertTrue(Path(str(output["artifact_dir"])).is_absolute())
        self.assertTrue(Path(str(output["manifest_path"])).is_absolute())

        interfaces = {interface["name"]: interface for interface in output["interfaces"]}  # type: ignore[index]
        self.assertEqual(interfaces["nat-control"]["metadata"]["type"], "nat-control")
        self.assertEqual(interfaces["nat-control"]["metadata"]["host_port"], 25222)
        self.assertEqual(interfaces["lan"]["exposure"], "lan")
        self.assertEqual(interfaces["lan"]["metadata"]["type"], "bridged-lan")
        self.assertEqual(interfaces["lan"]["metadata"]["bridge_interface"], "wlan0")
        self.assertEqual(output["metadata"]["virtualbox"]["bridge_interface"], "wlan0")  # type: ignore[index]
        self.assertEqual(output["metadata"]["virtualbox"]["ssh_port"], 25222)  # type: ignore[index]
        self.assertIn("vm_guest_artifacts", output["metadata"])  # type: ignore[operator]
        self.assertIn("artifact_paths", output["metadata"])  # type: ignore[operator]

    def test_dry_run_rejects_private_group_and_ip(self) -> None:
        with self.assertRaisesRegex(ValueError, "--private-group"):
            virtualbox.create_endpoint(
                provider="virtualbox",
                exposure="lan",
                role="probe",
                private_group="pair-a",
                dry_run=True,
            )
        with self.assertRaisesRegex(ValueError, "--private-ip"):
            virtualbox.create_endpoint(
                provider="virtualbox",
                exposure="lan",
                role="probe",
                private_ip="10.0.0.9",
                dry_run=True,
            )

    def test_cli_virtualbox_lan_dry_run_json(self) -> None:
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            with (
                mock.patch(
                    "tools.wire.engine.providers.virtualbox.create.free_localhost_tcp_port",
                    return_value=25222,
                ),
                redirect_stdout(stdout),
            ):
                exit_code = wire_cli.main(
                    [
                        "create-endpoint",
                        "--provider",
                        "virtualbox",
                        "--exposure",
                        "lan",
                        "--dry-run",
                        "--json",
                    ]
                )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["provider"], "virtualbox")
        self.assertEqual(payload["exposure"], "lan")
        self.assertFalse(payload["created"])
        self.assertTrue(payload["dry_run"])
        self.assertIsInstance(payload["provider_resources"], list)


@contextmanager
def _wire_env(root: Path, extra: Mapping[str, str] | None = None) -> Iterator[None]:
    env = {
        "LIBCRAFTER_WIRE_STATE_ROOT": str(root / "wire-state"),
        "LIBCRAFTER_WIRE_ARTIFACT_ROOT": str(root / "wire-artifacts"),
    }
    if extra is not None:
        env.update(extra)
    old_values = {key: os.environ.get(key) for key in env}
    os.environ.update(env)
    try:
        yield
    finally:
        for key, value in old_values.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _bridgedifs() -> str:
    return """Name:            enp0s31f6
GUID:            00000000-0000-4000-8000-001122334455
Dhcp:            Enabled
IPAddress:       192.0.2.10
NetworkMask:     255.255.255.0
HardwareAddress: 00:11:22:33:44:55
MediumType:      Ethernet
Wireless:        No
Status:          Down
VBoxNetworkName: HostInterfaceNetworking-enp0s31f6

Name:            wlan0
GUID:            00000000-0000-4000-8000-001122334466
Dhcp:            Enabled
IPAddress:       192.0.2.11
NetworkMask:     255.255.255.0
HardwareAddress: 00:11:22:33:44:66
MediumType:      Ethernet
Wireless:        Yes
Status:          Up
VBoxNetworkName: HostInterfaceNetworking-wlan0
"""


def _result(
    argv: Sequence[str],
    *,
    exit_code: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> CommandResult:
    return CommandResult(
        argv=tuple(argv),
        redacted_argv=tuple(argv),
        cwd=None,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
    )


if __name__ == "__main__":
    unittest.main()

