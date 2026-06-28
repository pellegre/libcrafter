"""Persistent QEMU endpoint asset lifecycle coverage."""

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
from tools.endpoint.engine.model import read_json
from tools.endpoint.engine.process import CommandResult
from tools.endpoint.engine.providers.qemu.assets import (
    inspect_qemu_asset,
    plan_start_qemu_asset,
    qemu_asset_metadata,
    start_qemu_asset,
)
from tools.endpoint.engine.providers.qemu.constants import QEMU_SYSTEM_COMMAND


class QemuAssetLifecycleTest(unittest.TestCase):
    def test_planned_start_returns_command_without_runner_calls(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _endpoint_env(Path(temp_dir)):
            asset = _asset(Path(temp_dir))
            write_endpoint_asset(asset)

            output = plan_start_qemu_asset(asset)

        self.assertTrue(output["ok"])
        self.assertFalse(output["executed"])
        self.assertTrue(output["planned"])
        self.assertEqual(output["pidfile_path"], _pidfile(Path(temp_dir)))
        action = output["actions"][0]  # type: ignore[index]
        self.assertEqual(action["argv"][:3], [QEMU_SYSTEM_COMMAND, "-name", "asset-a"])
        self.assertEqual(action["argv"][-2:], ["-pidfile", _pidfile(Path(temp_dir))])
        self.assertIn(_pidfile(Path(temp_dir)), action["command"])

    def test_already_running_asset_does_not_call_qemu_start(self) -> None:
        fake_runner = _FakeQemuRunner()
        process_signal = _ProcessSignalFake(running=True)
        with tempfile.TemporaryDirectory() as temp_dir, _endpoint_env(Path(temp_dir)):
            root = Path(temp_dir)
            asset = _asset(root)
            write_endpoint_asset(asset)
            _pidfile_path(root).parent.mkdir(parents=True, exist_ok=True)
            _pidfile_path(root).write_text("31337\n", encoding="utf-8")

            output = start_qemu_asset(
                asset,
                command_runner=fake_runner,
                process_signal=process_signal,
            )
            stored = read_endpoint_asset(asset.asset_id)

        self.assertTrue(output["ok"])
        self.assertFalse(output["executed"])
        self.assertEqual(fake_runner.calls, [])
        self.assertEqual(process_signal.calls, [(31337, 0)])
        self.assertEqual(output["pid"], 31337)
        qemu_metadata = stored.metadata["qemu"]  # type: ignore[index]
        self.assertEqual(qemu_metadata["last_power_state"], "running")  # type: ignore[index]
        self.assertEqual(qemu_metadata["pid"], 31337)  # type: ignore[index]

    def test_missing_pidfile_inspect_is_structured_stopped_state(self) -> None:
        process_signal = _ProcessSignalFake(running=True)
        with tempfile.TemporaryDirectory() as temp_dir, _endpoint_env(Path(temp_dir)):
            root = Path(temp_dir)
            asset = _asset(root)
            write_endpoint_asset(asset)

            output = inspect_qemu_asset(asset, process_signal=process_signal)
            stored = read_endpoint_asset(asset.asset_id)

        self.assertTrue(output["ok"])
        self.assertEqual(output["vm_state"], "stopped")
        self.assertEqual(output["pidfile_status"], "missing")
        self.assertIsNone(output["pid"])
        self.assertEqual(process_signal.calls, [])
        qemu_metadata = stored.metadata["qemu"]  # type: ignore[index]
        self.assertEqual(qemu_metadata["last_power_state"], "stopped")  # type: ignore[index]
        self.assertNotIn("pid", qemu_metadata)

    def test_stopped_vm_start_runs_prepared_command_and_persists_pid_metadata(self) -> None:
        process_signal = _ProcessSignalFake(running=False)
        with tempfile.TemporaryDirectory() as temp_dir, _endpoint_env(Path(temp_dir)):
            root = Path(temp_dir)
            asset = _asset(root)
            write_endpoint_asset(asset)
            _pidfile_path(root).parent.mkdir(parents=True, exist_ok=True)
            _pidfile_path(root).write_text("1111\n", encoding="utf-8")
            fake_runner = _FakeQemuRunner(pidfile_path=_pidfile_path(root), pid=4242)

            output = start_qemu_asset(
                asset,
                command_runner=fake_runner,
                process_signal=process_signal,
            )
            stored = read_endpoint_asset(asset.asset_id)
            command_log = read_json(_command_log_path(root))

        self.assertTrue(output["ok"])
        self.assertTrue(output["executed"])
        self.assertEqual(process_signal.calls, [(1111, 0)])
        self.assertEqual(len(fake_runner.calls), 1)
        self.assertEqual(fake_runner.calls[0][-2:], ("-pidfile", _pidfile(root)))
        self.assertEqual(output["pid"], 4242)
        self.assertEqual(output["command_log_path"], str(_command_log_path(root)))
        qemu_metadata = stored.metadata["qemu"]  # type: ignore[index]
        self.assertEqual(qemu_metadata["last_power_state"], "running")  # type: ignore[index]
        self.assertEqual(qemu_metadata["pid"], 4242)  # type: ignore[index]
        self.assertEqual(qemu_metadata["pidfile_path"], _pidfile(root))  # type: ignore[index]
        self.assertEqual(qemu_metadata["command_log_path"], str(_command_log_path(root)))  # type: ignore[index]
        self.assertIsInstance(command_log, dict)
        self.assertEqual(len(command_log["commands"]), 1)  # type: ignore[index]
        self.assertTrue(command_log["commands"][0]["ok"])  # type: ignore[index]

    def test_invalid_command_metadata_fails_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _endpoint_env(Path(temp_dir)):
            root = Path(temp_dir)
            cases: list[tuple[str, object, str]] = [
                ("missing command", {}, "command must be a list of strings"),
                (
                    "non-list command",
                    {"command": QEMU_SYSTEM_COMMAND},
                    "command must be a list of strings",
                ),
                (
                    "empty command entry",
                    {"command": [QEMU_SYSTEM_COMMAND, ""]},
                    r"command\[1\] must be a non-empty string",
                ),
                (
                    "relative pidfile",
                    {"command": [QEMU_SYSTEM_COMMAND], "pidfile_path": "qemu.pid"},
                    "pidfile_path must be an absolute path",
                ),
            ]
            for name, qemu_metadata, message in cases:
                with self.subTest(name=name):
                    asset = _asset(root, qemu_metadata=qemu_metadata)
                    with self.assertRaisesRegex(ValueError, message):
                        qemu_asset_metadata(asset)


class _FakeQemuRunner:
    def __init__(self, *, pidfile_path: Path | None = None, pid: int = 4242) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.pidfile_path = pidfile_path
        self.pid = pid

    def __call__(self, argv: Sequence[object], **_: object) -> CommandResult:
        call = tuple(str(part) for part in argv)
        self.calls.append(call)
        if self.pidfile_path is not None:
            self.pidfile_path.write_text(f"{self.pid}\n", encoding="utf-8")
        return _result(call)


class _ProcessSignalFake:
    def __init__(self, *, running: bool) -> None:
        self.running = running
        self.calls: list[tuple[int, int]] = []

    def __call__(self, pid: int, sig: int) -> None:
        self.calls.append((pid, sig))
        if sig == 0 and not self.running:
            raise ProcessLookupError(pid)


def _asset(
    root: Path,
    *,
    qemu_metadata: object | None = None,
) -> EndpointAsset:
    return EndpointAsset(
        asset_id="qemu-asset-a",
        substrate="qemu",
        status="available",
        supported_profiles=["linux-root", "packet-capture"],
        ssh=AssetSSHInfo(
            host="127.0.0.1",
            user="root",
            port=25222,
            identity_file=str(root / "wire-state" / "assets" / "qemu-asset-a" / "id_ed25519"),
            known_hosts_file=str(
                root / "wire-state" / "assets" / "qemu-asset-a" / "known_hosts"
            ),
            metadata={"control_endpoint": "qemu-user-net"},
        ),
        hardware=AssetHardware(
            architecture="x86_64",
            cpu_count=2,
            memory_mb=2048,
            disk_gb=16,
            provider_instance_type="qemu-vm",
        ),
        metadata={
            "qemu": qemu_metadata
            if qemu_metadata is not None
            else {
                "command": [
                    QEMU_SYSTEM_COMMAND,
                    "-name",
                    "asset-a",
                    "-display",
                    "none",
                    "-daemonize",
                ],
                "vm_name": "asset-a",
                "expected_profiles": ["linux-root", "packet-capture"],
                "usb_passthrough": [{"bus": "1", "device": "2", "description": "DUT"}],
            }
        },
    )


def _pidfile_path(root: Path) -> Path:
    return root / "wire-state" / "assets" / "qemu-asset-a" / "qemu" / "qemu.pid"


def _pidfile(root: Path) -> str:
    return str(_pidfile_path(root))


def _command_log_path(root: Path) -> Path:
    return root / "wire-state" / "assets" / "qemu-asset-a" / "qemu" / "qemu-commands.json"


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
