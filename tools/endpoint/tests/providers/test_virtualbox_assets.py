"""Persistent VirtualBox endpoint asset lifecycle coverage."""

from __future__ import annotations

import os
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from unittest import mock

from tools.endpoint.engine.assets import (
    AssetHardware,
    AssetSSHInfo,
    EndpointAsset,
    read_endpoint_asset,
    write_endpoint_asset,
)
from tools.endpoint.engine.process import CommandResult
from tools.endpoint.engine.providers.virtualbox.assets import (
    inspect_virtualbox_asset,
    start_virtualbox_asset,
    virtualbox_asset_vm_name,
)


class VirtualBoxAssetLifecycleTest(unittest.TestCase):
    def test_stopped_asset_start_runs_headless_start_and_persists_power_state(self) -> None:
        fake = _FakeVBoxManageRunner(
            [
                _showvminfo("poweroff"),
                _result(
                    ("VBoxManage", "startvm", "libcrafter-asset-a", "--type", "headless"),
                    stdout="VM started",
                ),
            ]
        )
        with tempfile.TemporaryDirectory() as temp_dir, _endpoint_env(Path(temp_dir)):
            asset = _asset(Path(temp_dir))
            write_endpoint_asset(asset)

            output = start_virtualbox_asset(asset, command_runner=fake)

            stored = read_endpoint_asset(asset.asset_id)

        self.assertTrue(output["ok"])
        self.assertTrue(output["executed"])
        self.assertEqual(
            fake.calls,
            [
                ("VBoxManage", "showvminfo", "libcrafter-asset-a", "--machinereadable"),
                ("VBoxManage", "startvm", "libcrafter-asset-a", "--type", "headless"),
            ],
        )
        virtualbox_metadata = stored.metadata["virtualbox"]  # type: ignore[index]
        self.assertEqual(virtualbox_metadata["last_power_state"], "running")  # type: ignore[index]
        self.assertIn("last_checked_at", virtualbox_metadata)  # type: ignore[operator]
        self.assertEqual(
            virtualbox_metadata["expected_profiles"],  # type: ignore[index]
            ["linux-root", "packet-capture"],
        )
        self.assertEqual(
            virtualbox_metadata["usb_filters"],  # type: ignore[index]
            [{"name": "dut-uart", "vendor_id": "1209", "product_id": "0001"}],
        )

    def test_running_asset_inspect_does_not_start_vm(self) -> None:
        fake = _FakeVBoxManageRunner([_showvminfo("running")])
        with tempfile.TemporaryDirectory() as temp_dir, _endpoint_env(Path(temp_dir)):
            asset = _asset(Path(temp_dir))
            write_endpoint_asset(asset)

            output = start_virtualbox_asset(asset, command_runner=fake)

        self.assertTrue(output["ok"])
        self.assertFalse(output["executed"])
        self.assertEqual(output["vm_state"], "running")
        self.assertEqual(
            fake.calls,
            [("VBoxManage", "showvminfo", "libcrafter-asset-a", "--machinereadable")],
        )
        last_action = output["actions"][-1]  # type: ignore[index]
        self.assertEqual(last_action["reason"], "VM is already running")

    def test_missing_asset_vm_is_structured_failure_without_unregister(self) -> None:
        fake = _FakeVBoxManageRunner(
            [
                _result(
                    ("VBoxManage", "showvminfo", "libcrafter-asset-a", "--machinereadable"),
                    exit_code=1,
                    stderr=(
                        "VBoxManage: error: Could not find a registered machine named "
                        "'libcrafter-asset-a'"
                    ),
                )
            ]
        )
        with tempfile.TemporaryDirectory() as temp_dir, _endpoint_env(Path(temp_dir)):
            asset = _asset(Path(temp_dir))
            write_endpoint_asset(asset)

            output = start_virtualbox_asset(asset, command_runner=fake)
            stored = read_endpoint_asset(asset.asset_id)

        self.assertFalse(output["ok"])
        self.assertFalse(output["executed"])
        self.assertEqual(output["last_power_state"], "missing")
        virtualbox_metadata = stored.metadata["virtualbox"]  # type: ignore[index]
        self.assertEqual(virtualbox_metadata["last_power_state"], "missing")  # type: ignore[index]
        self.assertEqual(
            fake.calls,
            [("VBoxManage", "showvminfo", "libcrafter-asset-a", "--machinereadable")],
        )
        flattened = [part for call in fake.calls for part in call]
        self.assertNotIn("unregistervm", flattened)

    def test_start_failure_reports_command_result_and_keeps_inspected_state(self) -> None:
        fake = _FakeVBoxManageRunner(
            [
                _showvminfo("poweroff"),
                _result(
                    ("VBoxManage", "startvm", "libcrafter-asset-a", "--type", "headless"),
                    exit_code=1,
                    stderr="VBoxManage: error: The virtual machine failed to start",
                ),
            ]
        )
        with tempfile.TemporaryDirectory() as temp_dir, _endpoint_env(Path(temp_dir)):
            asset = _asset(Path(temp_dir))
            write_endpoint_asset(asset)

            output = start_virtualbox_asset(asset, command_runner=fake)
            stored = read_endpoint_asset(asset.asset_id)

        self.assertFalse(output["ok"])
        self.assertTrue(output["executed"])
        self.assertEqual(output["actions"][-1]["exit_code"], 1)  # type: ignore[index]
        self.assertIn("failed to start", output["actions"][-1]["stderr"])  # type: ignore[index]
        self.assertEqual(output["last_power_state"], "poweroff")
        virtualbox_metadata = stored.metadata["virtualbox"]  # type: ignore[index]
        self.assertEqual(
            virtualbox_metadata["last_power_state"],  # type: ignore[index]
            "poweroff",
        )

    def test_check_only_start_plans_without_starting(self) -> None:
        fake = _FakeVBoxManageRunner([_showvminfo("saved")])
        with tempfile.TemporaryDirectory() as temp_dir, _endpoint_env(Path(temp_dir)):
            asset = _asset(Path(temp_dir))
            write_endpoint_asset(asset)

            output = start_virtualbox_asset(asset, command_runner=fake, check_only=True)

        self.assertTrue(output["ok"])
        self.assertFalse(output["executed"])
        self.assertTrue(output["planned"])
        self.assertTrue(output["check_only"])
        self.assertEqual(output["last_power_state"], "saved")
        self.assertEqual(
            fake.calls,
            [("VBoxManage", "showvminfo", "libcrafter-asset-a", "--machinereadable")],
        )
        self.assertEqual(
            output["actions"][-1]["command"],  # type: ignore[index]
            "VBoxManage startvm libcrafter-asset-a --type headless",
        )

    def test_inspect_returns_vm_info_and_asset_vm_name(self) -> None:
        fake = _FakeVBoxManageRunner([_showvminfo("running", cpus="4")])
        with tempfile.TemporaryDirectory() as temp_dir, _endpoint_env(Path(temp_dir)):
            asset = _asset(Path(temp_dir))
            write_endpoint_asset(asset)

            output = inspect_virtualbox_asset(asset, command_runner=fake)

        self.assertEqual(virtualbox_asset_vm_name(asset), "libcrafter-asset-a")
        self.assertTrue(output["ok"])
        self.assertEqual(output["vm_info"]["VMState"], "running")  # type: ignore[index]
        self.assertEqual(output["vm_info"]["cpus"], "4")  # type: ignore[index]


class _FakeVBoxManageRunner:
    def __init__(self, results: Sequence[CommandResult]) -> None:
        self._results = list(results)
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Sequence[object], **_: object) -> CommandResult:
        call = tuple(str(part) for part in argv)
        self.calls.append(call)
        if not self._results:
            return _result(call, exit_code=127, stderr=f"unexpected command: {call!r}")
        expected = self._results.pop(0)
        self.assert_command(expected.argv, call)
        return expected

    @staticmethod
    def assert_command(expected: tuple[str, ...], actual: tuple[str, ...]) -> None:
        if expected != actual:
            raise AssertionError(f"expected command {expected!r}, got {actual!r}")


def _asset(root: Path) -> EndpointAsset:
    return EndpointAsset(
        asset_id="virtualbox-asset-a",
        substrate="virtualbox",
        status="available",
        supported_profiles=["linux-root", "packet-capture"],
        ssh=AssetSSHInfo(
            host="127.0.0.1",
            user="root",
            port=25222,
            identity_file=str(
                root / "wire-state" / "assets" / "virtualbox-asset-a" / "id_ed25519"
            ),
            known_hosts_file=str(
                root / "wire-state" / "assets" / "virtualbox-asset-a" / "known_hosts"
            ),
            metadata={"control_endpoint": "nat-ssh"},
        ),
        hardware=AssetHardware(
            architecture="x86_64",
            cpu_count=4,
            memory_mb=4096,
            disk_gb=32,
            provider_instance_type="virtualbox-vm",
        ),
        metadata={
            "virtualbox": {
                "vm_name": "libcrafter-asset-a",
                "expected_profiles": ["linux-root", "packet-capture"],
                "usb_filters": [
                    {"name": "dut-uart", "vendor_id": "1209", "product_id": "0001"}
                ],
            }
        },
    )


def _showvminfo(vm_state: str, **values: str) -> CommandResult:
    lines = [
        'name="libcrafter-asset-a"',
        'UUID="00000000-0000-0000-0000-000000000001"',
        f'VMState="{vm_state}"',
    ]
    lines.extend(f'{key}="{value}"' for key, value in values.items())
    return _result(
        ("VBoxManage", "showvminfo", "libcrafter-asset-a", "--machinereadable"),
        stdout="\n".join(lines),
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


def _endpoint_env(
    root: Path,
    extra: Mapping[str, str] | None = None,
) -> mock._patch_dict[str, str]:
    env = {
        "LIBCRAFTER_ENDPOINT_STATE_ROOT": str(root / "wire-state"),
        "LIBCRAFTER_ENDPOINT_ARTIFACT_ROOT": str(root / "wire-artifacts"),
    }
    if extra is not None:
        env.update(extra)
    return mock.patch.dict(os.environ, env)


if __name__ == "__main__":
    unittest.main()
