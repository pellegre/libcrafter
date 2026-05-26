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
from tools.wire.engine.providers.qemu.constants import (
    QEMU_ACCEL_ENV,
    QEMU_DEFAULT_PRIVATE_CIDR,
    QEMU_PRIVATE_CIDR_ENV,
    QEMU_SYSTEM_COMMAND,
)
from tools.wire.engine.providers.vm import (
    CLOUD_LOCALDS_COMMAND,
    LINUX_INTERFACE_DISCOVERY_COMMAND,
    QEMU_IMG_COMMAND,
)
from tools.wire.engine.registry import ProviderExposureError
from tools.wire.engine.state import read_private_group_record, update_private_group_allocation


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
        self.assertEqual(
            output["metadata"]["private_group_record"]["private_cidr"],  # type: ignore[index]
            QEMU_DEFAULT_PRIVATE_CIDR,
        )
        self.assertEqual(
            output["metadata"]["private_network"]["backend"],  # type: ignore[index]
            "socket-mcast",
        )
        self.assertEqual(
            output["metadata"]["private_network"]["ip_range"],  # type: ignore[index]
            QEMU_DEFAULT_PRIVATE_CIDR,
        )
        self.assertIn("mcast", output["metadata"]["private_network"])  # type: ignore[operator]
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

    def test_live_wan_create_runs_qemu_sequence_and_writes_active_manifest(self) -> None:
        endpoint_id = "qemu-wan-probe-20260526230500-abcdef"
        fake = _QemuLiveFakeRunner()
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            root = Path(temp_dir)
            with (
                mock.patch(
                    "tools.wire.engine.providers.qemu.create.vm_endpoint_id",
                    return_value=endpoint_id,
                ),
                mock.patch(
                    "tools.wire.engine.providers.qemu.create.utc_now",
                    return_value="2026-05-26T23:05:00Z",
                ),
                mock.patch(
                    "tools.wire.engine.providers.qemu.create.free_localhost_tcp_port",
                    return_value=26224,
                ),
            ):
                output = qemu.create_endpoint(
                    provider="qemu",
                    exposure="wan",
                    role="probe",
                    confirm_live_run=True,
                    env={
                        QEMU_ACCEL_ENV: "tcg",
                        "LIBCRAFTER_QEMU_MEMORY_MB": "1536",
                        "LIBCRAFTER_QEMU_CPUS": "1",
                    },
                    command_runner=fake,
                    download_runner=_fake_download,
                    ssh_wait_timeout=1,
                    ssh_wait_interval=0.01,
                )
                manifest_path = Path(str(output["manifest_path"]))
                manifest_exists = manifest_path.exists()
                stored = json.loads(manifest_path.read_text(encoding="utf-8"))
                command_log_exists = Path(
                    str(output["metadata"]["qemu"]["command_log_path"])  # type: ignore[index]
                ).exists()

        self.assertTrue(output["created"])
        self.assertFalse(output["dry_run"])
        self.assertEqual(output["status"], "active")
        self.assertEqual(output["endpoint_id"], endpoint_id)
        self.assertTrue(Path(str(output["manifest_path"])).is_absolute())
        self.assertTrue(manifest_exists)
        self.assertTrue(command_log_exists)

        metadata = output["metadata"]["qemu"]  # type: ignore[index]
        self.assertEqual(metadata["pid"], 4242)
        self.assertEqual(metadata["acceleration"], "tcg")
        self.assertEqual(metadata["memory_mb"], 1536)
        self.assertEqual(metadata["cpus"], 1)
        self.assertEqual(metadata["ssh_port"], 26224)
        self.assertTrue(Path(str(metadata["pidfile_path"])).is_absolute())
        self.assertTrue(Path(str(metadata["serial_log_path"])).is_absolute())
        self.assertTrue(Path(str(metadata["qemu_log_path"])).is_absolute())
        self.assertIn(root / "wire-state", Path(str(metadata["pidfile_path"])).parents)

        self.assertEqual(len(fake.qemu_calls), 1)
        qemu_call = fake.qemu_calls[0]
        self.assertEqual(qemu_call[qemu_call.index("-accel") + 1], "tcg")
        self.assertEqual(qemu_call[qemu_call.index("-m") + 1], "1536")
        self.assertEqual(qemu_call[qemu_call.index("-smp") + 1], "1")
        self.assertIn("-daemonize", qemu_call)
        self.assertIn("-pidfile", qemu_call)
        self.assertIn("user,id=control0,hostfwd=tcp:127.0.0.1:26224-:22", qemu_call)
        self.assertIn("virtio-net-pci,netdev=control0", qemu_call)

        interfaces = {interface["name"]: interface for interface in output["interfaces"]}  # type: ignore[index]
        self.assertEqual(interfaces["enp0s1"]["exposure"], "wan")
        self.assertEqual(interfaces["enp0s1"]["ipv4"], "10.0.2.15")
        self.assertEqual(interfaces["enp0s1"]["metadata"]["type"], "qemu-user-net")
        self.assertTrue(interfaces["enp0s1"]["metadata"]["outbound_nat"])
        self.assertEqual(output["ssh"]["host"], "127.0.0.1")  # type: ignore[index]
        self.assertEqual(output["ssh"]["port"], 26224)  # type: ignore[index]

        self.assertEqual(stored["status"], "active")
        self.assertEqual(stored["metadata"]["qemu"]["pid"], 4242)
        resource_kinds = [resource["kind"] for resource in stored["provider_resources"]["resources"]]
        self.assertIn("process", resource_kinds)

    def test_live_private_create_allocates_group_and_starts_socket_network(self) -> None:
        endpoint_id = "qemu-private-oracle-20260526231000-abcdef"
        fake = _QemuLiveFakeRunner(private_ipv4="10.77.0.2")
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            with (
                mock.patch(
                    "tools.wire.engine.providers.qemu.create.vm_endpoint_id",
                    return_value=endpoint_id,
                ),
                mock.patch(
                    "tools.wire.engine.providers.qemu.create.utc_now",
                    return_value="2026-05-26T23:10:00Z",
                ),
                mock.patch(
                    "tools.wire.engine.providers.qemu.create.free_localhost_tcp_port",
                    return_value=26226,
                ),
            ):
                output = qemu.create_endpoint(
                    provider="qemu",
                    exposure="private",
                    role="oracle",
                    private_group="pair-a",
                    confirm_live_run=True,
                    env={},
                    command_runner=fake,
                    download_runner=_fake_download,
                    ssh_wait_timeout=1,
                    ssh_wait_interval=0.01,
                )
                stored = json.loads(Path(str(output["manifest_path"])).read_text(encoding="utf-8"))
                record = read_private_group_record("qemu", "pair-a")
                network_config = Path(
                    str(output["metadata"]["vm_guest_artifacts"]["network_config_path"])  # type: ignore[index]
                ).read_text(encoding="utf-8")

        self.assertTrue(output["created"])
        self.assertFalse(output["dry_run"])
        self.assertEqual(output["status"], "active")
        self.assertEqual(record.allocated_endpoint_ids, [endpoint_id])
        self.assertEqual(record.allocated_private_ipv4s, ["10.77.0.2"])
        self.assertEqual(record.private_cidr, QEMU_DEFAULT_PRIVATE_CIDR)
        self.assertEqual(record.network_resource["network_id"], "qemu-private-group-pair-a")
        self.assertEqual(output["metadata"]["private_group"], "pair-a")  # type: ignore[index]
        self.assertEqual(output["metadata"]["private_ip"], "10.77.0.2")  # type: ignore[index]
        self.assertEqual(
            output["metadata"]["private_group_record"]["allocated_private_ipv4s"],  # type: ignore[index]
            ["10.77.0.2"],
        )

        qemu_call = fake.qemu_calls[0]
        private_network = output["metadata"]["qemu"]["network"]["private"]  # type: ignore[index]
        self.assertEqual(private_network["backend"], "socket-mcast")
        self.assertEqual(private_network["network_id"], "qemu-private-group-pair-a")
        self.assertIn(f"socket,id=private0,mcast={private_network['mcast']}", qemu_call)
        self.assertTrue(
            any(part.startswith("virtio-net-pci,netdev=control0,mac=") for part in qemu_call)
        )
        self.assertTrue(
            any(part.startswith("virtio-net-pci,netdev=private0,mac=") for part in qemu_call)
        )

        interfaces = {interface["exposure"]: interface for interface in output["interfaces"]}  # type: ignore[index]
        self.assertEqual(interfaces["control"]["metadata"]["host_port"], 26226)
        self.assertEqual(interfaces["private"]["name"], "wirepriv0")
        self.assertEqual(interfaces["private"]["ipv4"], "10.77.0.2")
        self.assertEqual(interfaces["private"]["provider_network_id"], "qemu-private-group-pair-a")
        self.assertEqual(interfaces["private"]["metadata"]["private_group"], "pair-a")
        self.assertEqual(interfaces["private"]["metadata"]["backend"], "socket-mcast")
        self.assertIn("10.77.0.2/24", network_config)
        self.assertIn(str(interfaces["private"]["mac"]), network_config)
        self.assertEqual(stored["metadata"]["private_group_record"]["provider"], "qemu")

    def test_live_private_create_honors_requested_static_ip(self) -> None:
        endpoint_id = "qemu-private-probe-20260526231100-abcdef"
        fake = _QemuLiveFakeRunner(private_ipv4="10.88.0.42")
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            with (
                mock.patch(
                    "tools.wire.engine.providers.qemu.create.vm_endpoint_id",
                    return_value=endpoint_id,
                ),
                mock.patch(
                    "tools.wire.engine.providers.qemu.create.utc_now",
                    return_value="2026-05-26T23:11:00Z",
                ),
                mock.patch(
                    "tools.wire.engine.providers.qemu.create.free_localhost_tcp_port",
                    return_value=26227,
                ),
            ):
                output = qemu.create_endpoint(
                    provider="qemu",
                    exposure="private",
                    role="probe",
                    private_group="pair-static",
                    private_ip="10.88.0.42",
                    confirm_live_run=True,
                    env={QEMU_PRIVATE_CIDR_ENV: "10.88.0.0/24"},
                    command_runner=fake,
                    download_runner=_fake_download,
                    ssh_wait_timeout=1,
                    ssh_wait_interval=0.01,
                )
                record = read_private_group_record("qemu", "pair-static")

        private_interface = next(
            interface
            for interface in output["interfaces"]  # type: ignore[index]
            if interface["exposure"] == "private"
        )
        self.assertEqual(private_interface["ipv4"], "10.88.0.42")
        self.assertEqual(record.private_cidr, "10.88.0.0/24")
        self.assertEqual(record.allocated_private_ipv4s, ["10.88.0.42"])

    def test_live_private_create_rejects_allocated_static_ip_before_provider_work(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            update_private_group_allocation(
                provider="qemu",
                group="pair-a",
                endpoint_id="existing",
                private_ipv4="10.77.0.9",
                private_cidr=QEMU_DEFAULT_PRIVATE_CIDR,
                network_resource={"network_id": "qemu-private-group-pair-a"},
            )

            with self.assertRaisesRegex(ValueError, "already allocated"):
                qemu.create_endpoint(
                    provider="qemu",
                    exposure="private",
                    role="probe",
                    private_group="pair-a",
                    private_ip="10.77.0.9",
                    confirm_live_run=True,
                    env={},
                    command_runner=_fail_runner,
                    download_runner=_fake_download,
                )

    def test_live_wan_create_writes_failed_manifest_after_ssh_timeout(self) -> None:
        endpoint_id = "qemu-wan-probe-20260526230600-abcdef"
        fake = _QemuLiveFakeRunner(fail_ssh=True)
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            root = Path(temp_dir)
            with (
                mock.patch(
                    "tools.wire.engine.providers.qemu.create.vm_endpoint_id",
                    return_value=endpoint_id,
                ),
                mock.patch(
                    "tools.wire.engine.providers.qemu.create.utc_now",
                    return_value="2026-05-26T23:06:00Z",
                ),
                mock.patch(
                    "tools.wire.engine.providers.qemu.create.free_localhost_tcp_port",
                    return_value=26225,
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "wait for ssh timed out"):
                    qemu.create_endpoint(
                        provider="qemu",
                        exposure="wan",
                        role="probe",
                        confirm_live_run=True,
                        env={},
                        command_runner=fake,
                        download_runner=_fake_download,
                        ssh_wait_timeout=0.01,
                        ssh_wait_interval=0.001,
                    )

            manifest_path = root / "wire-state" / "endpoints" / endpoint_id / "endpoint.json"
            self.assertTrue(manifest_path.exists())
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(manifest["status"], "failed")
        self.assertTrue(manifest["metadata"]["created"])
        self.assertEqual(manifest["metadata"]["qemu"]["pid"], 4242)
        self.assertIn("wait for ssh timed out", manifest["metadata"]["error"])
        resources = manifest["provider_resources"]["resources"]
        self.assertEqual(resources[0]["kind"], "qemu-vm")
        self.assertEqual(resources[1]["kind"], "process")

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


class _QemuLiveFakeRunner:
    def __init__(self, *, fail_ssh: bool = False, private_ipv4: str | None = None) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.fail_ssh = fail_ssh
        self.private_ipv4 = private_ipv4
        self.control_mac: str | None = None
        self.private_mac: str | None = None

    @property
    def qemu_calls(self) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[0] == QEMU_SYSTEM_COMMAND]

    def __call__(self, argv: Sequence[object], **_: object) -> CommandResult:
        parts = tuple(str(part) for part in argv)
        self.calls.append(parts)
        if parts[0] == "ssh-keygen":
            key_path = Path(parts[parts.index("-f") + 1])
            key_path.write_text("private\n", encoding="utf-8")
            key_path.with_name(f"{key_path.name}.pub").write_text(
                "ssh-ed25519 AAAAlive\n",
                encoding="utf-8",
            )
            return _result(parts)
        if parts[0] == CLOUD_LOCALDS_COMMAND:
            Path(parts[-3]).write_text("seed\n", encoding="utf-8")
            return _result(parts)
        if parts[:2] == (QEMU_IMG_COMMAND, "create"):
            Path(parts[-1]).write_text("qcow2 overlay\n", encoding="utf-8")
            return _result(parts)
        if parts[0] == QEMU_SYSTEM_COMMAND:
            self.control_mac = _device_mac(parts, "control0")
            self.private_mac = _device_mac(parts, "private0")
            pidfile_path = Path(parts[parts.index("-pidfile") + 1])
            pidfile_path.write_text("4242\n", encoding="utf-8")
            serial_index = parts.index("-serial") + 1
            serial_path = Path(parts[serial_index].removeprefix("file:"))
            serial_path.write_text("serial\n", encoding="utf-8")
            qemu_log_path = Path(parts[parts.index("-D") + 1])
            qemu_log_path.write_text("qemu log\n", encoding="utf-8")
            return _result(parts)
        if parts[0] == "ssh":
            if parts[-1] == "true":
                if self.fail_ssh:
                    return _result(parts, exit_code=255, stderr="connection refused")
                return _result(parts)
            if parts[-1] == LINUX_INTERFACE_DISCOVERY_COMMAND:
                if self.private_ipv4 is not None and self.private_mac is not None:
                    return _result(
                        parts,
                        stdout=_qemu_private_discovery_output(
                            private_ipv4=self.private_ipv4,
                            control_mac=self.control_mac or "52:54:00:aa:bb:cc",
                            private_mac=self.private_mac,
                        ),
                    )
                return _result(parts, stdout=_qemu_discovery_output())
        raise AssertionError(f"unexpected command: {parts}")


def _fake_download(_: str, output_path: Path) -> None:
    output_path.write_text("base-image\n", encoding="utf-8")


def _qemu_discovery_output() -> str:
    addresses = [
        {
            "ifindex": 2,
            "ifname": "enp0s1",
            "address": "52:54:00:aa:bb:cc",
            "operstate": "UP",
            "mtu": 1500,
            "addr_info": [
                {"family": "inet", "local": "10.0.2.15", "prefixlen": 24},
                {"family": "inet6", "local": "fec0::5054:ff:feaa:bbcc", "prefixlen": 64},
            ],
        }
    ]
    links = [
        {
            "ifindex": 2,
            "ifname": "enp0s1",
            "address": "52:54:00:aa:bb:cc",
            "operstate": "UP",
            "mtu": 1500,
        }
    ]
    routes = [{"dst": "1.1.1.1", "dev": "enp0s1", "prefsrc": "10.0.2.15"}]
    return "\n".join(
        [
            "__WIRE_IP_ADDR__",
            json.dumps(addresses),
            "__WIRE_IP_LINK__",
            json.dumps(links),
            "__WIRE_IP_ROUTE__",
            json.dumps(routes),
        ]
    )


def _qemu_private_discovery_output(
    *,
    private_ipv4: str,
    control_mac: str,
    private_mac: str,
) -> str:
    addresses = [
        {
            "ifindex": 2,
            "ifname": "enp0s1",
            "address": control_mac,
            "operstate": "UP",
            "mtu": 1500,
            "addr_info": [
                {"family": "inet", "local": "10.0.2.15", "prefixlen": 24},
            ],
        },
        {
            "ifindex": 3,
            "ifname": "wirepriv0",
            "address": private_mac,
            "operstate": "UP",
            "mtu": 1500,
            "addr_info": [
                {"family": "inet", "local": private_ipv4, "prefixlen": 24},
            ],
        },
    ]
    links = [
        {
            "ifindex": 2,
            "ifname": "enp0s1",
            "address": control_mac,
            "operstate": "UP",
            "mtu": 1500,
        },
        {
            "ifindex": 3,
            "ifname": "wirepriv0",
            "address": private_mac,
            "operstate": "UP",
            "mtu": 1500,
        },
    ]
    routes = [{"dst": "1.1.1.1", "dev": "enp0s1", "prefsrc": "10.0.2.15"}]
    return "\n".join(
        [
            "__WIRE_IP_ADDR__",
            json.dumps(addresses),
            "__WIRE_IP_LINK__",
            json.dumps(links),
            "__WIRE_IP_ROUTE__",
            json.dumps(routes),
        ]
    )


def _device_mac(argv: Sequence[str], netdev: str) -> str | None:
    prefix = f"virtio-net-pci,netdev={netdev},mac="
    for part in argv:
        if part.startswith(prefix):
            return part.removeprefix(prefix)
    return None


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
