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

import tools.endpoint.engine.providers.virtualbox.create as virtualbox_create
from tools.endpoint.engine import cli as wire_cli
from tools.endpoint.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResource,
    ProviderResources,
)
from tools.endpoint.engine.process import CommandResult
from tools.endpoint.engine.providers import resolve_provider, virtualbox
from tools.endpoint.engine.providers.virtualbox.constants import VBOX_BRIDGE_IFACE_ENV
from tools.endpoint.engine.providers.vm import (
    CLOUD_LOCALDS_COMMAND,
    LINUX_INTERFACE_DISCOVERY_COMMAND,
    QEMU_IMG_COMMAND,
)
from tools.endpoint.engine.registry import ProviderExposureError
from tools.endpoint.engine.state import (
    read_endpoint_manifest,
    read_private_group_record,
    update_private_group_allocation,
    write_endpoint_manifest,
)


class VirtualBoxRegistryTest(unittest.TestCase):
    def test_virtualbox_supports_lan_and_private_exposures(self) -> None:
        self.assertIs(resolve_provider("virtualbox", "lan"), virtualbox)
        self.assertIs(resolve_provider("virtualbox", "private"), virtualbox)
        for exposure in ("wan", "wifi"):
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
            "tools.endpoint.engine.providers.virtualbox.doctor.shutil.which",
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
            "tools.endpoint.engine.providers.virtualbox.doctor.shutil.which",
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

    def test_doctor_private_skips_bridge_discovery(self) -> None:
        calls: list[tuple[str, ...]] = []

        def fake_runner(argv: Sequence[object], **_: object) -> CommandResult:
            parts = tuple(str(part) for part in argv)
            calls.append(parts)
            return _result(parts, stdout=_bridgedifs())

        with mock.patch(
            "tools.endpoint.engine.providers.virtualbox.doctor.shutil.which",
            side_effect=lambda command: f"/usr/bin/{command}",
        ):
            report = virtualbox.doctor(
                provider="virtualbox",
                exposure="private",
                dry_run=True,
                command_runner=fake_runner,
            )

        self.assertTrue(report["ok"])
        self.assertEqual(calls, [])
        self.assertTrue(report["bridge"]["skipped"])  # type: ignore[index]
        self.assertTrue(report["private_network"]["isolated"])  # type: ignore[index]


class VirtualBoxCreateEndpointTest(unittest.TestCase):
    def test_dry_run_manifest_has_absolute_paths_and_planned_lan_interfaces(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            with mock.patch(
                "tools.endpoint.engine.providers.virtualbox.create.free_localhost_tcp_port",
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

    def test_dry_run_manifest_has_private_internal_network(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            with mock.patch(
                "tools.endpoint.engine.providers.virtualbox.create.free_localhost_tcp_port",
                return_value=25223,
            ):
                output = virtualbox.create_endpoint(
                    provider="virtualbox",
                    exposure="private",
                    role="probe",
                    private_group="pair-a",
                    private_ip="10.78.0.10",
                    dry_run=True,
                    env={},
                )

        self.assertFalse(output["created"])
        self.assertEqual(output["endpoint_id"], "planned-virtualbox-private-probe-pair-a")
        interfaces = {interface["name"]: interface for interface in output["interfaces"]}  # type: ignore[index]
        self.assertEqual(interfaces["wirepriv0"]["exposure"], "private")
        self.assertEqual(interfaces["wirepriv0"]["ipv4"], "10.78.0.10")
        self.assertEqual(
            interfaces["wirepriv0"]["metadata"]["type"],
            "virtualbox-internal-network",
        )
        self.assertEqual(interfaces["wirepriv0"]["metadata"]["promiscuous_mode"], "allow-all")
        self.assertEqual(
            output["metadata"]["virtualbox"]["private_promiscuous_mode"],  # type: ignore[index]
            "allow-all",
        )
        self.assertTrue(output["metadata"]["virtualbox"]["private_network"]["isolated"])  # type: ignore[index]
        self.assertIsNone(output["metadata"]["virtualbox"]["bridge_interface"])  # type: ignore[index]

    def test_private_boot_commands_allow_promiscuous_internal_network(self) -> None:
        commands = virtualbox_create._virtualbox_boot_commands(
            exposure="private",
            vm_name="wire-virtualbox-private-test",
            bridge_name=None,
            ssh_port=25222,
            disk_path=Path("/tmp/disk.vdi"),
            seed_iso_path=Path("/tmp/seed.iso"),
            private_network={"network_name": "libcrafter-private-test"},
            private_mac="08:00:27:12:34:56",
        )

        private_nic = next(command for command in commands if "--nic2" in command)
        self.assertIn("--nic-promisc2", private_nic)
        promisc_index = private_nic.index("--nic-promisc2")
        self.assertEqual(private_nic[promisc_index + 1], "allow-all")

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
                    "tools.endpoint.engine.providers.virtualbox.create.free_localhost_tcp_port",
                    return_value=25222,
                ),
                redirect_stdout(stdout),
            ):
                exit_code = wire_cli.main(
                    [
                        "create",
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

    def test_live_create_runs_vboxmanage_sequence_and_writes_active_manifest(self) -> None:
        endpoint_id = "virtualbox-lan-probe-20260526223300-abcdef"
        fake = _VirtualBoxLiveFakeRunner()
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            root = Path(temp_dir)
            with (
                mock.patch(
                    "tools.endpoint.engine.providers.virtualbox.create.vm_endpoint_id",
                    return_value=endpoint_id,
                ),
                mock.patch(
                    "tools.endpoint.engine.providers.virtualbox.create.utc_now",
                    return_value="2026-05-26T22:33:00Z",
                ),
                mock.patch(
                    "tools.endpoint.engine.providers.virtualbox.create.free_localhost_tcp_port",
                    return_value=25222,
                ),
            ):
                output = virtualbox.create_endpoint(
                    provider="virtualbox",
                    exposure="lan",
                    role="probe",
                    confirm_live_run=True,
                    env={VBOX_BRIDGE_IFACE_ENV: "wlan0"},
                    command_runner=fake,
                    download_runner=_fake_download,
                    ssh_wait_timeout=1,
                    ssh_wait_interval=0.01,
                )
                manifest_path = Path(str(output["manifest_path"]))
                manifest_exists = manifest_path.exists()
                stored = json.loads(manifest_path.read_text(encoding="utf-8"))
                command_log_exists = Path(
                    str(output["metadata"]["virtualbox"]["command_log_path"])  # type: ignore[index]
                ).exists()

        self.assertTrue(output["created"])
        self.assertFalse(output["dry_run"])
        self.assertEqual(output["status"], "active")
        self.assertEqual(output["endpoint_id"], endpoint_id)
        self.assertTrue(Path(str(output["manifest_path"])).is_absolute())
        self.assertTrue(manifest_exists)

        metadata = output["metadata"]["virtualbox"]  # type: ignore[index]
        vm_name = str(metadata["vm_name"])
        disk_path = str(output["metadata"]["vm_guest_artifacts"]["disk_path"])  # type: ignore[index]
        seed_iso_path = str(output["metadata"]["vm_guest_artifacts"]["seed_iso_path"])  # type: ignore[index]
        self.assertEqual(
            fake.vbox_calls,
            [
                ("VBoxManage", "list", "bridgedifs"),
                (
                    "VBoxManage",
                    "modifymedium",
                    disk_path,
                    "--resize",
                    "16384",
                ),
                (
                    "VBoxManage",
                    "createvm",
                    "--name",
                    vm_name,
                    "--basefolder",
                    str(metadata["basefolder"]),
                    "--ostype",
                    "Ubuntu_64",
                    "--register",
                ),
                (
                    "VBoxManage",
                    "modifyvm",
                    vm_name,
                    "--memory",
                    "2048",
                    "--cpus",
                    "2",
                    "--boot1",
                    "disk",
                    "--boot2",
                    "dvd",
                    "--boot3",
                    "none",
                    "--boot4",
                    "none",
                ),
                (
                    "VBoxManage",
                    "modifyvm",
                    vm_name,
                    "--nic1",
                    "nat",
                    "--natpf1",
                    "wire-ssh,tcp,127.0.0.1,25222,,22",
                ),
                (
                    "VBoxManage",
                    "modifyvm",
                    vm_name,
                    "--nic2",
                    "bridged",
                    "--bridgeadapter2",
                    "wlan0",
                ),
                (
                    "VBoxManage",
                    "storagectl",
                    vm_name,
                    "--name",
                    "SATA",
                    "--add",
                    "sata",
                    "--controller",
                    "IntelAhci",
                    "--portcount",
                    "2",
                    "--bootable",
                    "on",
                ),
                (
                    "VBoxManage",
                    "storageattach",
                    vm_name,
                    "--storagectl",
                    "SATA",
                    "--port",
                    "0",
                    "--device",
                    "0",
                    "--type",
                    "hdd",
                    "--medium",
                    disk_path,
                ),
                (
                    "VBoxManage",
                    "storageattach",
                    vm_name,
                    "--storagectl",
                    "SATA",
                    "--port",
                    "1",
                    "--device",
                    "0",
                    "--type",
                    "dvddrive",
                    "--medium",
                    seed_iso_path,
                ),
                ("VBoxManage", "startvm", vm_name, "--type", "headless"),
            ],
        )

        interfaces = {interface["name"]: interface for interface in output["interfaces"]}  # type: ignore[index]
        self.assertEqual(interfaces["enp0s3"]["exposure"], "control")
        self.assertEqual(interfaces["enp0s3"]["metadata"]["type"], "nat-control")
        self.assertEqual(interfaces["enp0s3"]["metadata"]["host_port"], 25222)
        self.assertEqual(interfaces["enp0s8"]["exposure"], "lan")
        self.assertEqual(interfaces["enp0s8"]["ipv4"], "192.168.1.44")
        self.assertEqual(interfaces["enp0s8"]["metadata"]["bridge_interface"], "wlan0")
        self.assertEqual(output["ssh"]["host"], "127.0.0.1")  # type: ignore[index]
        self.assertEqual(output["ssh"]["port"], 25222)  # type: ignore[index]
        self.assertTrue(command_log_exists)

        self.assertEqual(stored["status"], "active")
        self.assertEqual(stored["metadata"]["virtualbox"]["bridge_interface"], "wlan0")
        self.assertIn(root / "wire-state", Path(stored["metadata"]["virtualbox"]["basefolder"]).parents)

    def test_live_create_writes_failed_manifest_after_partial_vbox_failure(self) -> None:
        endpoint_id = "virtualbox-lan-probe-20260526223400-abcdef"
        fake = _VirtualBoxLiveFakeRunner(fail_memory_modify=True)
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            root = Path(temp_dir)
            with (
                mock.patch(
                    "tools.endpoint.engine.providers.virtualbox.create.vm_endpoint_id",
                    return_value=endpoint_id,
                ),
                mock.patch(
                    "tools.endpoint.engine.providers.virtualbox.create.utc_now",
                    return_value="2026-05-26T22:34:00Z",
                ),
                mock.patch(
                    "tools.endpoint.engine.providers.virtualbox.create.free_localhost_tcp_port",
                    return_value=25223,
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "VirtualBox command failed"):
                    virtualbox.create_endpoint(
                        provider="virtualbox",
                        exposure="lan",
                        role="probe",
                        confirm_live_run=True,
                        env={VBOX_BRIDGE_IFACE_ENV: "wlan0"},
                        command_runner=fake,
                        download_runner=_fake_download,
                        ssh_wait_timeout=1,
                        ssh_wait_interval=0.01,
                    )

            manifest_path = (
                root / "wire-state" / "endpoints" / endpoint_id / "endpoint.json"
            )
            self.assertTrue(manifest_path.exists())
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(manifest["status"], "failed")
        self.assertTrue(manifest["metadata"]["created"])
        self.assertTrue(manifest["metadata"]["virtualbox"]["vm_registered"])
        self.assertIn("VirtualBox command failed", manifest["metadata"]["error"])
        resources = manifest["provider_resources"]["resources"]
        self.assertEqual(resources[0]["kind"], "virtualbox-vm")
        self.assertEqual(resources[0]["metadata"]["registered"], True)


class VirtualBoxDestroyEndpointTest(unittest.TestCase):
    def test_destroy_running_vm_uses_acpi_then_poweroff_and_unregisters(self) -> None:
        fake = _VirtualBoxDestroyFakeRunner(state="running")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _virtualbox_manifest(root)
            artifact_file = Path(manifest.artifact_dir) / "probe.txt"
            artifact_file.parent.mkdir(parents=True, exist_ok=True)
            artifact_file.write_text("preserve me\n", encoding="utf-8")

            with _wire_env(root):
                write_endpoint_manifest(manifest)
                output = virtualbox.destroy_endpoint(
                    read_endpoint_manifest(manifest.endpoint_id),
                    command_runner=fake,
                    shutdown_timeout=0,
                    poll_interval=0,
                )
                stored = read_endpoint_manifest(manifest.endpoint_id)
                artifact_preserved = artifact_file.exists()

        self.assertTrue(output["ok"])
        self.assertTrue(output["destroyed"])
        self.assertEqual(stored.status, "destroyed")
        self.assertTrue(artifact_preserved)
        self.assertEqual(
            fake.vbox_calls,
            [
                ("VBoxManage", "showvminfo", "wire-virtualbox-lan-test", "--machinereadable"),
                ("VBoxManage", "controlvm", "wire-virtualbox-lan-test", "acpipowerbutton"),
                ("VBoxManage", "controlvm", "wire-virtualbox-lan-test", "poweroff"),
                ("VBoxManage", "unregistervm", "wire-virtualbox-lan-test", "--delete"),
            ],
        )
        self.assertEqual(
            [action["action"] for action in output["actions"]],
            ["inspect", "acpi-shutdown", "poweroff", "unregister"],
        )
        self.assertEqual(stored.metadata["virtualbox"]["vm_registered"], False)
        self.assertEqual(stored.metadata["destroy"]["provider"], "virtualbox")

    def test_destroy_powered_off_vm_only_unregisters(self) -> None:
        fake = _VirtualBoxDestroyFakeRunner(state="poweroff")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _virtualbox_manifest(root)

            with _wire_env(root):
                write_endpoint_manifest(manifest)
                output = virtualbox.destroy_endpoint(
                    read_endpoint_manifest(manifest.endpoint_id),
                    command_runner=fake,
                )
                stored = read_endpoint_manifest(manifest.endpoint_id)

        self.assertEqual(stored.status, "destroyed")
        self.assertEqual(
            fake.vbox_calls,
            [
                ("VBoxManage", "showvminfo", "wire-virtualbox-lan-test", "--machinereadable"),
                ("VBoxManage", "unregistervm", "wire-virtualbox-lan-test", "--delete"),
            ],
        )
        self.assertEqual(
            [action["action"] for action in output["actions"]],
            ["inspect", "unregister"],
        )
        self.assertEqual(
            [skip["action"] for skip in output["skipped"]],
            ["skip"],
        )

    def test_destroy_missing_vm_marks_manifest_destroyed(self) -> None:
        fake = _VirtualBoxDestroyFakeRunner(missing=True)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _virtualbox_manifest(root)

            with _wire_env(root):
                write_endpoint_manifest(manifest)
                output = virtualbox.destroy_endpoint(
                    read_endpoint_manifest(manifest.endpoint_id),
                    command_runner=fake,
                )
                stored = read_endpoint_manifest(manifest.endpoint_id)

        self.assertEqual(stored.status, "destroyed")
        self.assertEqual(
            fake.vbox_calls,
            [("VBoxManage", "showvminfo", "wire-virtualbox-lan-test", "--machinereadable")],
        )
        self.assertEqual(
            [action["action"] for action in output["actions"]],
            ["already-missing"],
        )

    def test_destroy_already_destroyed_manifest_does_not_contact_virtualbox(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _virtualbox_manifest(root, status="destroyed")

            def fail_runner(argv: Sequence[object], **_: object) -> CommandResult:
                self.fail(f"destroyed endpoint should not contact provider: {argv}")

            with _wire_env(root):
                write_endpoint_manifest(manifest)
                output = virtualbox.destroy_endpoint(
                    read_endpoint_manifest(manifest.endpoint_id),
                    command_runner=fail_runner,
                )

        self.assertTrue(output["ok"])
        self.assertTrue(output["already_destroyed"])
        self.assertFalse(output["destroyed"])

    def test_destroy_private_endpoint_removes_group_allocation(self) -> None:
        fake = _VirtualBoxDestroyFakeRunner(
            state="poweroff",
            vm_name="wire-virtualbox-private-test",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _virtualbox_private_manifest(root)

            with _wire_env(root):
                write_endpoint_manifest(manifest)
                update_private_group_allocation(
                    provider="virtualbox",
                    group="pair-a",
                    endpoint_id=manifest.endpoint_id,
                    private_ipv4="10.78.0.10",
                    private_cidr="10.78.0.0/24",
                    network_resource={
                        "network_id": "virtualbox-private-group-pair-a",
                    },
                )
                update_private_group_allocation(
                    provider="virtualbox",
                    group="pair-a",
                    endpoint_id="virtualbox-private-peer",
                    private_ipv4="10.78.0.20",
                    private_cidr="10.78.0.0/24",
                    network_resource={
                        "network_id": "virtualbox-private-group-pair-a",
                    },
                )

                output = virtualbox.destroy_endpoint(
                    read_endpoint_manifest(manifest.endpoint_id),
                    command_runner=fake,
                )
                stored = read_endpoint_manifest(manifest.endpoint_id)
                record = read_private_group_record("virtualbox", "pair-a")

        self.assertEqual(stored.status, "destroyed")
        self.assertEqual(record.allocated_endpoint_ids, ["virtualbox-private-peer"])
        self.assertEqual(record.allocated_private_ipv4s, ["10.78.0.20"])
        self.assertEqual(
            [action["action"] for action in output["actions"]],
            ["inspect", "unregister", "remove-private-allocation"],
        )
        self.assertEqual(stored.metadata["private_group_destroy"]["record_found"], True)
        self.assertEqual(
            stored.metadata["private_group_destroy"]["remaining_endpoints"],
            ["virtualbox-private-peer"],
        )


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


def _virtualbox_manifest(root: Path, *, status: str = "active") -> EndpointManifest:
    endpoint_id = "virtualbox-lan-test"
    state_dir = root / "wire-state" / "endpoints" / endpoint_id
    artifact_dir = root / "wire-artifacts" / endpoint_id
    vm_name = "wire-virtualbox-lan-test"
    return EndpointManifest(
        endpoint_id=endpoint_id,
        provider="virtualbox",
        exposure="lan",
        status=status,
        role="test",
        created_at="2026-05-26T22:45:00Z",
        ssh=EndpointSSHInfo(
            host="127.0.0.1",
            user="root",
            port=25222,
            identity_file=str(state_dir / "id_ed25519"),
            known_hosts_file=str(state_dir / "known_hosts"),
            metadata={
                "transport": "virtualbox-nat-port-forward",
                "vm_name": vm_name,
                "control_interface": "enp0s3",
            },
        ),
        interfaces=[
            NetworkInterface(
                name="enp0s3",
                exposure="control",
                ipv4="10.0.2.15",
                metadata={"type": "nat-control", "host_port": 25222},
            ),
            NetworkInterface(
                name="enp0s8",
                exposure="lan",
                ipv4="192.168.1.44",
                metadata={"type": "bridged-lan", "bridge_interface": "wlan0"},
            ),
        ],
        provider_resources=ProviderResources(
            resources=[
                ProviderResource(
                    kind="virtualbox-vm",
                    provider_id=vm_name,
                    name=vm_name,
                    metadata={
                        "type": "virtualbox-vm",
                        "vm_name": vm_name,
                        "registered": True,
                    },
                ),
                ProviderResource(
                    kind="local-file",
                    provider_id=str(state_dir),
                    name="endpoint-state",
                    metadata={"type": "local-file", "path": str(state_dir)},
                ),
            ],
            cleanup_order=["virtualbox-vm", "local-file"],
            metadata={
                "provider": "virtualbox",
                "exposure": "lan",
                "vm_registered": True,
            },
        ),
        artifact_dir=str(artifact_dir),
        metadata={
            "created": True,
            "dry_run": False,
            "state_dir": str(state_dir),
            "manifest_path": str(state_dir / "endpoint.json"),
            "virtualbox": {
                "command": "VBoxManage",
                "vm_name": vm_name,
                "vm_registered": True,
                "basefolder": str(state_dir / "virtualbox"),
            },
        },
    )


def _virtualbox_private_manifest(
    root: Path,
    *,
    status: str = "active",
) -> EndpointManifest:
    endpoint_id = "virtualbox-private-test"
    state_dir = root / "wire-state" / "endpoints" / endpoint_id
    artifact_dir = root / "wire-artifacts" / endpoint_id
    vm_name = "wire-virtualbox-private-test"
    private_network = {
        "type": "network",
        "provider": "virtualbox",
        "network_id": "virtualbox-private-group-pair-a",
        "network_name": "wire-vbox-pair-a",
        "private_group": "pair-a",
        "ip_range": "10.78.0.0/24",
        "backend": "internal-network",
    }
    return EndpointManifest(
        endpoint_id=endpoint_id,
        provider="virtualbox",
        exposure="private",
        status=status,
        role="test",
        created_at="2026-05-26T22:46:00Z",
        ssh=EndpointSSHInfo(
            host="127.0.0.1",
            user="root",
            port=25223,
            identity_file=str(state_dir / "id_ed25519"),
            known_hosts_file=str(state_dir / "known_hosts"),
            metadata={
                "transport": "virtualbox-nat-port-forward",
                "vm_name": vm_name,
                "control_interface": "enp0s3",
            },
        ),
        interfaces=[
            NetworkInterface(
                name="enp0s3",
                exposure="control",
                ipv4="10.0.2.15",
                metadata={"type": "nat-control", "host_port": 25223},
            ),
            NetworkInterface(
                name="wirepriv0",
                exposure="private",
                ipv4="10.78.0.10",
                provider_network_id="virtualbox-private-group-pair-a",
                metadata={
                    "type": "virtualbox-internal-network",
                    "private_group": "pair-a",
                    "private_ip": "10.78.0.10",
                    "network_resource": private_network,
                },
            ),
        ],
        provider_resources=ProviderResources(
            resources=[
                ProviderResource(
                    kind="virtualbox-vm",
                    provider_id=vm_name,
                    name=vm_name,
                    metadata={
                        "type": "virtualbox-vm",
                        "vm_name": vm_name,
                        "registered": True,
                    },
                ),
                ProviderResource(
                    kind="local-file",
                    provider_id=str(state_dir),
                    name="endpoint-state",
                    metadata={"type": "local-file", "path": str(state_dir)},
                ),
            ],
            cleanup_order=["virtualbox-vm", "local-file"],
            metadata={
                "provider": "virtualbox",
                "exposure": "private",
                "vm_registered": True,
            },
        ),
        artifact_dir=str(artifact_dir),
        metadata={
            "created": True,
            "dry_run": False,
            "state_dir": str(state_dir),
            "manifest_path": str(state_dir / "endpoint.json"),
            "private_group": "pair-a",
            "private_ip": "10.78.0.10",
            "private_network": private_network,
            "virtualbox": {
                "command": "VBoxManage",
                "vm_name": vm_name,
                "vm_registered": True,
                "basefolder": str(state_dir / "virtualbox"),
                "private_network": private_network,
                "private_ip": "10.78.0.10",
            },
        },
    )


class _VirtualBoxLiveFakeRunner:
    def __init__(self, *, fail_memory_modify: bool = False) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.fail_memory_modify = fail_memory_modify

    @property
    def vbox_calls(self) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[0] == "VBoxManage"]

    def __call__(self, argv: Sequence[object], **_: object) -> CommandResult:
        parts = tuple(str(part) for part in argv)
        self.calls.append(parts)
        if parts == ("VBoxManage", "list", "bridgedifs"):
            return _result(parts, stdout=_bridgedifs())
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
        if parts[:2] == (QEMU_IMG_COMMAND, "convert"):
            Path(parts[-1]).write_text("vdi\n", encoding="utf-8")
            return _result(parts)
        if parts[:3] == ("VBoxManage", "modifyvm", "wire-virtualbox-lan-probe-20260526223400-abcdef"):
            if self.fail_memory_modify and "--memory" in parts:
                return _result(parts, exit_code=1, stderr="modify failed")
        if parts[0] == "VBoxManage":
            return _result(parts)
        if parts[0] == "ssh":
            if parts[-1] == "true":
                return _result(parts)
            if parts[-1] == LINUX_INTERFACE_DISCOVERY_COMMAND:
                return _result(parts, stdout=_virtualbox_discovery_output())
        raise AssertionError(f"unexpected command: {parts}")


class _VirtualBoxDestroyFakeRunner:
    def __init__(
        self,
        *,
        state: str = "poweroff",
        missing: bool = False,
        vm_name: str = "wire-virtualbox-lan-test",
    ) -> None:
        self.state = state
        self.missing = missing
        self.vm_name = vm_name
        self.calls: list[tuple[str, ...]] = []

    @property
    def vbox_calls(self) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[0] == "VBoxManage"]

    def __call__(self, argv: Sequence[object], **_: object) -> CommandResult:
        parts = tuple(str(part) for part in argv)
        self.calls.append(parts)
        if parts == ("VBoxManage", "showvminfo", self.vm_name, "--machinereadable"):
            if self.missing:
                return _result(
                    parts,
                    exit_code=1,
                    stderr=f"Could not find a registered machine named '{self.vm_name}'",
                )
            return _result(
                parts,
                stdout=f'name="{self.vm_name}"\nVMState="{self.state}"\n',
            )
        if parts == ("VBoxManage", "controlvm", self.vm_name, "acpipowerbutton"):
            return _result(parts)
        if parts == ("VBoxManage", "controlvm", self.vm_name, "poweroff"):
            self.state = "poweroff"
            return _result(parts)
        if parts == ("VBoxManage", "unregistervm", self.vm_name, "--delete"):
            self.missing = True
            return _result(parts)
        raise AssertionError(f"unexpected command: {parts}")


def _fake_download(_: str, output_path: Path) -> None:
    output_path.write_text("base-image\n", encoding="utf-8")


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


def _virtualbox_discovery_output() -> str:
    addresses = [
        {
            "ifindex": 2,
            "ifname": "enp0s3",
            "address": "08:00:27:aa:bb:cc",
            "operstate": "UP",
            "mtu": 1500,
            "addr_info": [
                {"family": "inet", "local": "10.0.2.15", "prefixlen": 24},
                {"family": "inet6", "local": "fe80::a00:27ff:feaa:bbcc", "prefixlen": 64},
            ],
        },
        {
            "ifindex": 3,
            "ifname": "enp0s8",
            "address": "08:00:27:dd:ee:ff",
            "operstate": "UP",
            "mtu": 1500,
            "addr_info": [
                {"family": "inet", "local": "192.168.1.44", "prefixlen": 24},
                {"family": "inet6", "local": "fe80::a00:27ff:fedd:eeff", "prefixlen": 64},
            ],
        },
    ]
    links = [
        {
            "ifindex": 2,
            "ifname": "enp0s3",
            "address": "08:00:27:aa:bb:cc",
            "operstate": "UP",
            "mtu": 1500,
        },
        {
            "ifindex": 3,
            "ifname": "enp0s8",
            "address": "08:00:27:dd:ee:ff",
            "operstate": "UP",
            "mtu": 1500,
        },
    ]
    routes = [{"dst": "1.1.1.1", "dev": "enp0s3", "prefsrc": "10.0.2.15"}]
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
