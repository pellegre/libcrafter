"""Fake-run coverage for QEMU endpoint planning."""

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
from tools.wire.engine.model import EndpointManifest
from tools.wire.engine.process import CommandResult
from tools.wire.engine.providers import qemu, resolve_provider
from tools.wire.engine.providers.qemu.constants import QEMU_ACCEL_ENV, QEMU_SYSTEM_COMMAND
from tools.wire.engine.providers.vm import CLOUD_LOCALDS_COMMAND, QEMU_IMG_COMMAND
from tools.wire.engine.registry import ProviderExposureError


class QemuRegistryTest(unittest.TestCase):
    def test_qemu_rejects_lan_and_wifi_before_provider_work(self) -> None:
        self.assertIs(resolve_provider("qemu", "wan"), qemu)
        self.assertIs(resolve_provider("qemu", "private"), qemu)
        for exposure in ("lan", "wifi"):
            with self.subTest(exposure=exposure):
                with self.assertRaisesRegex(ProviderExposureError, "supported exposures"):
                    resolve_provider("qemu", exposure)


class QemuDoctorTest(unittest.TestCase):
    def test_doctor_reports_required_commands_and_default_tcg(self) -> None:
        with mock.patch(
            "tools.wire.engine.providers.qemu.doctor.shutil.which",
            side_effect=lambda command: f"/usr/bin/{command}",
        ):
            report = qemu.doctor(
                provider="qemu",
                exposure="wan",
                dry_run=True,
                env={},
                command_runner=_fail_runner,
            )

        self.assertTrue(report["ok"])
        self.assertEqual(report["acceleration"]["effective"], "tcg")  # type: ignore[index]
        self.assertFalse(report["acceleration"]["kvm"]["checked"])  # type: ignore[index]
        self.assertTrue(report["commands"][QEMU_SYSTEM_COMMAND]["installed"])  # type: ignore[index]
        self.assertTrue(report["commands"][QEMU_IMG_COMMAND]["installed"])  # type: ignore[index]
        self.assertTrue(report["commands"][CLOUD_LOCALDS_COMMAND]["installed"])  # type: ignore[index]

    def test_doctor_reports_kvm_access_and_running_virtualbox_vms(self) -> None:
        calls: list[tuple[str, ...]] = []

        def fake_runner(argv: Sequence[object], **_: object) -> CommandResult:
            parts = tuple(str(part) for part in argv)
            calls.append(parts)
            return _result(parts, stdout='"farm" {00000000-0000-0000-0000-000000000001}\n')

        with (
            mock.patch(
                "tools.wire.engine.providers.qemu.doctor.shutil.which",
                side_effect=lambda command: f"/usr/bin/{command}",
            ),
            mock.patch(
                "tools.wire.engine.providers.qemu.doctor._kvm_device_report",
                return_value={
                    "check": {
                        "name": "kvm_device_access",
                        "ok": True,
                        "message": "/dev/kvm is accessible",
                    },
                    "metadata": {
                        "required": True,
                        "checked": True,
                        "path": "/dev/kvm",
                        "exists": True,
                        "readable_writable": True,
                    },
                },
            ),
        ):
            report = qemu.doctor(
                provider="qemu",
                exposure="wan",
                dry_run=True,
                env={QEMU_ACCEL_ENV: "kvm"},
                command_runner=fake_runner,
            )

        self.assertFalse(report["ok"])
        self.assertEqual(calls, [("VBoxManage", "list", "runningvms")])
        self.assertEqual(report["acceleration"]["effective"], "kvm")  # type: ignore[index]
        self.assertEqual(
            report["acceleration"]["virtualbox"]["running_vms"],  # type: ignore[index]
            ['"farm" {00000000-0000-0000-0000-000000000001}'],
        )

    def test_doctor_reports_invalid_acceleration(self) -> None:
        with mock.patch(
            "tools.wire.engine.providers.qemu.doctor.shutil.which",
            side_effect=lambda command: f"/usr/bin/{command}",
        ):
            report = qemu.doctor(
                provider="qemu",
                exposure="wan",
                dry_run=True,
                env={QEMU_ACCEL_ENV: "hvf"},
            )

        self.assertFalse(report["ok"])
        self.assertIsNone(report["acceleration"]["effective"])  # type: ignore[index]


class QemuCreateEndpointTest(unittest.TestCase):
    def test_wan_dry_run_manifest_has_absolute_paths_and_user_networking(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            with mock.patch(
                "tools.wire.engine.providers.qemu.create.free_localhost_tcp_port",
                return_value=26222,
            ):
                output = qemu.create_endpoint(
                    provider="qemu",
                    exposure="wan",
                    role="probe",
                    dry_run=True,
                    env={},
                )

        self.assertFalse(output["created"])
        self.assertTrue(output["dry_run"])
        self.assertEqual(output["status"], "planned")
        self.assertEqual(output["endpoint_id"], "planned-qemu-wan-probe")
        self.assertEqual(output["ssh"]["host"], "127.0.0.1")  # type: ignore[index]
        self.assertEqual(output["ssh"]["port"], 26222)  # type: ignore[index]
        self.assertTrue(Path(str(output["ssh"]["identity_file"])).is_absolute())  # type: ignore[index]
        self.assertTrue(Path(str(output["artifact_dir"])).is_absolute())
        self.assertTrue(Path(str(output["manifest_path"])).is_absolute())

        interfaces = {interface["name"]: interface for interface in output["interfaces"]}  # type: ignore[index]
        self.assertEqual(interfaces["user-control"]["metadata"]["type"], "qemu-user-net-control")
        self.assertEqual(interfaces["user-control"]["metadata"]["host_port"], 26222)
        self.assertEqual(interfaces["wan"]["exposure"], "wan")
        self.assertEqual(interfaces["wan"]["metadata"]["type"], "qemu-user-net")
        self.assertTrue(interfaces["wan"]["metadata"]["outbound_nat"])
        self.assertEqual(output["metadata"]["qemu"]["acceleration"], "tcg")  # type: ignore[index]
        self.assertEqual(output["metadata"]["vm_guest_artifacts"]["disk_format"], "qcow2")  # type: ignore[index]
        self.assertIn("artifact_paths", output["metadata"])  # type: ignore[operator]

        manifest = EndpointManifest.from_dict(output)
        self.assertEqual(manifest.provider, "qemu")

    def test_private_dry_run_manifest_records_group_and_requested_ip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            with mock.patch(
                "tools.wire.engine.providers.qemu.create.free_localhost_tcp_port",
                return_value=26223,
            ):
                output = qemu.create_endpoint(
                    provider="qemu",
                    exposure="private",
                    role="oracle",
                    private_group="pair-a",
                    private_ip="10.55.0.9",
                    dry_run=True,
                    env={QEMU_ACCEL_ENV: "kvm"},
                )

        self.assertEqual(output["endpoint_id"], "planned-qemu-private-oracle-pair-a")
        self.assertEqual(output["metadata"]["private_group"], "pair-a")  # type: ignore[index]
        self.assertEqual(output["metadata"]["private_ip"], "10.55.0.9")  # type: ignore[index]
        self.assertEqual(
            output["metadata"]["private_group_record"]["network_resource"]["network_id"],  # type: ignore[index]
            "qemu-private-group-pair-a",
        )
        interfaces = {interface["name"]: interface for interface in output["interfaces"]}  # type: ignore[index]
        self.assertEqual(interfaces["private"]["ipv4"], "10.55.0.9")
        self.assertEqual(interfaces["private"]["provider_network_id"], "qemu-private-group-pair-a")
        self.assertEqual(interfaces["private"]["metadata"]["private_group"], "pair-a")
        self.assertEqual(output["metadata"]["qemu"]["acceleration"], "kvm")  # type: ignore[index]
        self.assertIsNotNone(
            output["metadata"]["vm_guest_artifacts"]["network_config_path"]  # type: ignore[index]
        )

    def test_wan_rejects_private_group_and_ip(self) -> None:
        with self.assertRaisesRegex(ValueError, "--private-group"):
            qemu.create_endpoint(
                provider="qemu",
                exposure="wan",
                role="probe",
                private_group="pair-a",
                dry_run=True,
            )
        with self.assertRaisesRegex(ValueError, "--private-ip"):
            qemu.create_endpoint(
                provider="qemu",
                exposure="wan",
                role="probe",
                private_ip="10.55.0.9",
                dry_run=True,
            )

    def test_live_create_requires_confirmation_before_provider_work(self) -> None:
        with self.assertRaisesRegex(PermissionError, "confirm-live-run"):
            qemu.create_endpoint(
                provider="qemu",
                exposure="wan",
                role="probe",
                dry_run=False,
                confirm_live_run=False,
            )

    def test_cli_qemu_wan_dry_run_json(self) -> None:
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            with (
                mock.patch(
                    "tools.wire.engine.providers.qemu.create.free_localhost_tcp_port",
                    return_value=26222,
                ),
                redirect_stdout(stdout),
            ):
                exit_code = wire_cli.main(
                    [
                        "create-endpoint",
                        "--provider",
                        "qemu",
                        "--exposure",
                        "wan",
                        "--dry-run",
                        "--json",
                    ]
                )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["provider"], "qemu")
        self.assertEqual(payload["exposure"], "wan")
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


def _fail_runner(argv: Sequence[object], **_: object) -> CommandResult:
    raise AssertionError(f"unexpected command: {argv}")


def _result(
    argv: Sequence[str],
    *,
    stdout: str = "",
    stderr: str = "",
    exit_code: int = 0,
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

