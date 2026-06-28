"""Generic SSH Docker endpoint asset substrate coverage."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.endpoint.engine import cli as wire_cli
from tools.endpoint.engine.assets import (
    AssetSSHInfo,
    EndpointAsset,
    EndpointLease,
    acquire_endpoint_asset_lease_by_profile,
    asset_has_provider_lifecycle,
    read_endpoint_asset,
    release_endpoint_asset_lease,
    write_endpoint_asset,
)
from tools.endpoint.engine.process import CommandResult


class GenericSSHAssetTest(unittest.TestCase):
    def test_register_accepts_ssh_docker_without_provider_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            exit_code, output = _run_json(
                root,
                [
                    "asset",
                    "register",
                    "generic-ssh-a",
                    "--substrate",
                    "ssh-docker",
                    "--profile",
                    "wan-raw",
                    "--profile",
                    "lan-raw",
                    "--ssh-host",
                    "192.0.2.20",
                    "--ssh-user",
                    "root",
                    "--ssh-port",
                    "2222",
                    "--identity-file",
                    str(_asset_state_dir(root, "generic-ssh-a") / "id_ed25519"),
                    "--known-hosts-file",
                    str(_asset_state_dir(root, "generic-ssh-a") / "known_hosts"),
                    "--docker-command",
                    "docker",
                    "--metadata-json",
                    '{"owner":"fixture"}',
                    "--json",
                ],
            )

            with _endpoint_env(root):
                loaded = read_endpoint_asset("generic-ssh-a")

        self.assertEqual(exit_code, 0)
        self.assertTrue(output["registered"])
        self.assertEqual(output["asset"]["substrate"], "ssh-docker")
        self.assertEqual(output["asset"]["supported_profiles"], ["wan-raw", "lan-raw"])
        self.assertEqual(output["asset"]["ssh"]["host"], "192.0.2.20")
        self.assertNotIn("provider", output["asset"]["metadata"])
        self.assertFalse(asset_has_provider_lifecycle(loaded))
        self.assertEqual(loaded.to_dict(), output["asset"])

    def test_check_generic_ssh_asset_verifies_docker_and_plans_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                write_endpoint_asset(_generic_asset(root))
            runner = _FakeRunner()

            exit_code, output = _run_check(root, runner, profile="wan-raw")

        self.assertEqual(exit_code, 0)
        self.assertTrue(output["ok"])
        self.assertTrue(output["docker_check"]["ok"])
        self.assertEqual(runner.calls, [output["docker_check"]["plan"]["command_argv"]])
        self.assertTrue(output["hardware_check"]["ok"])
        self.assertFalse(output["hardware_check"]["required"])
        self.assertTrue(output["profile_checks"])
        self.assertTrue(all(not check["executed"] for check in output["checks"][1:]))
        self.assertFalse(output["live_transmit"])
        self.assertTrue(output["dry_run"])

    def test_missing_docker_fails_docker_check_without_profile_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                write_endpoint_asset(_generic_asset(root))
            runner = _FakeRunner(exit_code=127, stderr="docker: command not found\n")

            exit_code, output = _run_check(root, runner, profile="lan-raw")

        self.assertEqual(exit_code, 127)
        self.assertFalse(output["ok"])
        self.assertFalse(output["docker_check"]["ok"])
        self.assertEqual(output["docker_check"]["result"]["exit_code"], 127)
        self.assertIn("command not found", output["docker_check"]["result"]["stderr"])
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(runner.calls[0], output["docker_check"]["plan"]["command_argv"])
        self.assertTrue(output["profile_checks"])
        self.assertTrue(all(check["executed"] is False for check in output["checks"][1:]))
        self.assertFalse(output["live_transmit"])
        self.assertTrue(output["dry_run"])

    def test_acquire_and_release_by_profile_returns_target_and_artifact_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                write_endpoint_asset(
                    _generic_asset(
                        root,
                        metadata={
                            "appliance": {
                                "remote_work_root": "/srv/libcrafter/work",
                                "remote_artifact_root": "/srv/libcrafter/artifacts",
                            }
                        },
                    )
                )
                acquired = acquire_endpoint_asset_lease_by_profile(
                    "lan-raw",
                    600,
                    owner="generic-ssh-test",
                    now="2026-06-28T12:00:00Z",
                    lease_id_factory=lambda: "lease-generic-ssh",
                )
                stored = read_endpoint_asset("generic-ssh-a")
                released = release_endpoint_asset_lease(
                    "lease-generic-ssh",
                    now="2026-06-28T12:05:00Z",
                )
                after_release = read_endpoint_asset("generic-ssh-a")

        self.assertTrue(acquired["ok"])
        self.assertEqual(acquired["asset_id"], "generic-ssh-a")
        self.assertEqual(acquired["profile"], "lan-raw")
        self.assertEqual(acquired["target"], acquired["ssh_target"])
        self.assertEqual(acquired["target"]["metadata"]["substrate"], "ssh-docker")
        self.assertEqual(acquired["target"]["remote_work_root"], "/srv/libcrafter/work")
        self.assertEqual(acquired["remote_artifact_root"], "/srv/libcrafter/artifacts")
        self.assertEqual(
            acquired["artifact_root"],
            str(root / "wire-artifacts" / "assets" / "generic-ssh-a" / "lease-generic-ssh"),
        )
        self.assertEqual(stored.lease.holder, "lease-generic-ssh")  # type: ignore[union-attr]
        self.assertTrue(released["released"])
        self.assertIsNone(after_release.lease)

    def test_release_does_not_invoke_provider_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            leased = _generic_asset(
                root,
                lease=EndpointLease(
                    holder="lease-generic-ssh",
                    leased_at="2026-06-28T12:00:00Z",
                    leased_until="2999-01-01T00:00:00Z",
                    ttl_seconds=3600,
                    metadata={"lease_id": "lease-generic-ssh", "profile": "wan-raw"},
                ),
            )
            with _endpoint_env(root):
                write_endpoint_asset(leased)

            with (
                _endpoint_env(root),
                mock.patch.object(
                    wire_cli,
                    "resolve_provider",
                    side_effect=AssertionError("asset release must not resolve providers"),
                ) as resolve_provider,
                mock.patch(
                    "tools.endpoint.engine.providers.qemu.assets.stop_qemu_asset"
                ) as stop_qemu,
                mock.patch(
                    "tools.endpoint.engine.providers.virtualbox.assets.stop_virtualbox_asset"
                ) as stop_virtualbox,
            ):
                exit_code, output = _run_json(
                    root,
                    ["asset", "release", "lease-generic-ssh", "--json"],
                    patch_env=False,
                )
                stored = read_endpoint_asset("generic-ssh-a")

            state_root = root / "wire-state"
            asset_record_exists = (
                state_root / "assets" / "generic-ssh-a" / "asset.json"
            ).exists()
            qemu_state_exists = (state_root / "qemu").exists()
            virtualbox_state_exists = (state_root / "virtualbox").exists()
            hetzner_state_exists = (state_root / "hetzner").exists()

        self.assertEqual(exit_code, 0)
        self.assertTrue(output["released"])
        resolve_provider.assert_not_called()
        stop_qemu.assert_not_called()
        stop_virtualbox.assert_not_called()
        self.assertIsNone(stored.lease)
        self.assertNotIn("provider", stored.metadata)
        self.assertNotIn("qemu", stored.metadata)
        self.assertNotIn("virtualbox", stored.metadata)
        self.assertNotIn("hetzner", stored.metadata)
        self.assertTrue(asset_record_exists)
        self.assertFalse(qemu_state_exists)
        self.assertFalse(virtualbox_state_exists)
        self.assertFalse(hetzner_state_exists)


class _FakeRunner:
    def __init__(
        self,
        *,
        exit_code: int = 0,
        stdout: str = '"24.0.0"\n',
        stderr: str = "",
    ) -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> CommandResult:
        self.calls.append(list(argv))
        return CommandResult(
            argv=tuple(argv),
            redacted_argv=tuple(argv),
            cwd=None,
            exit_code=self.exit_code,
            stdout=self.stdout,
            stderr=self.stderr,
        )


def _run_check(
    root: Path,
    runner: _FakeRunner,
    *,
    profile: str,
) -> tuple[int, dict[str, object]]:
    with mock.patch.object(wire_cli, "run_command", runner):
        return _run_json(
            root,
            [
                "asset",
                "check",
                "generic-ssh-a",
                "--profile",
                profile,
                "--json",
            ],
        )


def _run_json(
    root: Path,
    argv: list[str],
    *,
    patch_env: bool = True,
) -> tuple[int, dict[str, object]]:
    stdout = io.StringIO()
    with contextlib.ExitStack() as stack:
        if patch_env:
            stack.enter_context(_endpoint_env(root))
        stack.enter_context(contextlib.redirect_stdout(stdout))
        exit_code = wire_cli.main(argv)
    return exit_code, json.loads(stdout.getvalue())


def _generic_asset(
    root: Path,
    *,
    lease: EndpointLease | None = None,
    metadata: dict[str, object] | None = None,
) -> EndpointAsset:
    return EndpointAsset(
        asset_id="generic-ssh-a",
        substrate="ssh-docker",
        status="available",
        supported_profiles=["wan-raw", "lan-raw"],
        ssh=AssetSSHInfo(
            host="192.0.2.20",
            user="root",
            port=2222,
            identity_file=str(_asset_state_dir(root, "generic-ssh-a") / "id_ed25519"),
            known_hosts_file=str(_asset_state_dir(root, "generic-ssh-a") / "known_hosts"),
        ),
        docker={"command": "docker"},
        lease=lease,
        metadata={} if metadata is None else metadata,
    )


def _asset_state_dir(root: Path, asset_id: str) -> Path:
    return root / "wire-state" / "assets" / asset_id


def _endpoint_env(root: Path) -> mock._patch_dict[str, str]:
    return mock.patch.dict(
        os.environ,
        {
            "LIBCRAFTER_ENDPOINT_STATE_ROOT": str(root / "wire-state"),
            "LIBCRAFTER_ENDPOINT_ARTIFACT_ROOT": str(root / "wire-artifacts"),
        },
    )


if __name__ == "__main__":
    unittest.main()
