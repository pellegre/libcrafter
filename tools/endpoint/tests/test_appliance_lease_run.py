"""CLI coverage for running endpoint appliances from asset leases."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from unittest import mock

from tools.endpoint.engine import cli as wire_cli
from tools.endpoint.engine.appliance import (
    DEFAULT_APPLIANCE_RUN_ARTIFACT_DIRNAME,
    DEFAULT_APPLIANCE_RUN_ID,
)
from tools.endpoint.engine.assets import (
    AssetSSHInfo,
    EndpointAsset,
    EndpointLease,
    write_endpoint_asset,
)
from tools.endpoint.engine.process import CommandResult


class EndpointApplianceLeaseRunTest(unittest.TestCase):
    def test_active_lease_run_uses_asset_ssh_docker_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                write_endpoint_asset(_leased_asset(root, profile="wan-raw"))
            runner = _ApplianceRunner()

            exit_code, output = _run_json(
                root,
                [
                    "appliance",
                    "run",
                    "--lease",
                    "lease-a",
                    "wan-raw",
                    "--json",
                    "--",
                    "true",
                ],
                runner=runner,
            )

        self.assertEqual(exit_code, 0)
        self.assertTrue(output["ok"])
        self.assertEqual(output["kind"], "endpoint-appliance-run")
        self.assertEqual(output["endpoint_id"], "asset-a")
        self.assertEqual(output["lease_id"], "lease-a")
        self.assertEqual(output["asset_id"], "asset-a")
        self.assertEqual(output["plan"]["target"]["target"]["host"], "192.0.2.44")
        self.assertEqual(output["plan"]["target"]["target"]["port"], 2244)
        self.assertEqual(output["command_argv"], ["true"])
        self.assertEqual(len(runner.calls), 2)
        self.assertIn("mkdir -p", runner.calls[0][-1])
        self.assertIn("docker-test run", runner.calls[1][-1])

    def test_expired_lease_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                write_endpoint_asset(
                    _leased_asset(
                        root,
                        profile="wan-raw",
                        leased_until="2000-01-01T00:00:00Z",
                    )
                )
            runner = _ApplianceRunner()

            exit_code, output = _run_json(
                root,
                [
                    "appliance",
                    "run",
                    "--lease",
                    "lease-a",
                    "wan-raw",
                    "--dry-run",
                    "--json",
                    "--",
                    "true",
                ],
                runner=runner,
            )

        self.assertNotEqual(exit_code, 0)
        self.assertFalse(output["ok"])
        self.assertEqual(output["lease_id"], "lease-a")
        self.assertIn("expired at 2000-01-01T00:00:00Z", output["error"])
        self.assertEqual(runner.calls, [])

    def test_lease_profile_metadata_must_match_requested_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                write_endpoint_asset(_leased_asset(root, profile="lan-raw"))

            exit_code, output = _run_json(
                root,
                [
                    "appliance",
                    "run",
                    "--lease",
                    "lease-a",
                    "wan-raw",
                    "--dry-run",
                    "--json",
                    "--",
                    "true",
                ],
            )

        self.assertNotEqual(exit_code, 0)
        self.assertFalse(output["ok"])
        self.assertEqual(output["lease_id"], "lease-a")
        self.assertIn("was acquired for profile 'lan-raw'", output["error"])
        self.assertIn("not requested profile 'wan-raw'", output["error"])

    def test_text_output_guides_release_after_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                write_endpoint_asset(_leased_asset(root, profile="wan-raw"))

            stdout = io.StringIO()
            with _endpoint_env(root), contextlib.redirect_stdout(stdout):
                exit_code = wire_cli.main(
                    [
                        "appliance",
                        "run",
                        "--lease",
                        "lease-a",
                        "wan-raw",
                        "--dry-run",
                        "--",
                        "true",
                    ]
                )

            text = stdout.getvalue()

        self.assertEqual(exit_code, 0)
        self.assertIn("lease_id=lease-a", text)
        self.assertIn("asset_id=asset-a", text)
        self.assertIn("release: endpoint asset release lease-a", text)

    def test_lease_artifact_root_shapes_run_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                write_endpoint_asset(_leased_asset(root, profile="wan-raw"))

            exit_code, output = _run_json(
                root,
                [
                    "appliance",
                    "run",
                    "--lease",
                    "lease-a",
                    "wan-raw",
                    "--dry-run",
                    "--json",
                    "--",
                    "true",
                ],
            )

        lease_root = root / "wire-artifacts" / "assets" / "asset-a" / "lease-a"
        run_root = lease_root / DEFAULT_APPLIANCE_RUN_ARTIFACT_DIRNAME / DEFAULT_APPLIANCE_RUN_ID

        self.assertEqual(exit_code, 0)
        self.assertEqual(output["lease_artifact_root"], str(lease_root))
        self.assertEqual(output["artifact_dir"], str(run_root))
        self.assertEqual(output["run"]["local_artifact_dir"], str(run_root))
        self.assertEqual(output["run"]["local_stdout_path"], str(run_root / "run.stdout.txt"))
        self.assertEqual(output["run"]["local_stderr_path"], str(run_root / "run.stderr.txt"))

    def test_lease_run_plan_uses_asset_profile_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                write_endpoint_asset(
                    _leased_asset(
                        root,
                        profile="lan-raw",
                        profile_environment={"LIBCRAFTER_IFACE": "lan-test0"},
                    )
                )

            exit_code, output = _run_json(
                root,
                [
                    "appliance",
                    "run",
                    "--lease",
                    "lease-a",
                    "lan-raw",
                    "--dry-run",
                    "--json",
                    "--",
                    "true",
                ],
            )

        docker_run = output["run"]["docker_run"]  # type: ignore[index]
        docker_argv = docker_run["docker_argv"]  # type: ignore[index]
        self.assertEqual(exit_code, 0)
        self.assertEqual(docker_run["env"]["LIBCRAFTER_IFACE"], "lan-test0")  # type: ignore[index]
        self.assertIn("LIBCRAFTER_IFACE=lan-test0", docker_argv)


class _ApplianceRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Sequence[object], **kwargs: object) -> CommandResult:
        normalized = tuple(str(part) for part in argv)
        self.calls.append(normalized)
        remote_command = normalized[-1]
        stdout = "container stdout\n" if "docker-test run" in remote_command else "mkdir\n"
        timeout = kwargs.get("timeout")
        return CommandResult(
            argv=normalized,
            redacted_argv=normalized,
            cwd=None,
            exit_code=0,
            stdout=stdout,
            stderr="",
            timeout=timeout if isinstance(timeout, float) else None,
        )


def _run_json(
    root: Path,
    argv: list[str],
    *,
    runner: _ApplianceRunner | None = None,
) -> tuple[int, dict[str, object]]:
    stdout = io.StringIO()
    with contextlib.ExitStack() as stack:
        stack.enter_context(_endpoint_env(root))
        stack.enter_context(contextlib.redirect_stdout(stdout))
        if runner is not None:
            stack.enter_context(mock.patch.object(wire_cli, "run_command", runner))
        exit_code = wire_cli.main(argv)
    return exit_code, json.loads(stdout.getvalue())


def _leased_asset(
    root: Path,
    *,
    profile: str,
    leased_until: str = "2999-01-01T00:00:00Z",
    profile_environment: dict[str, str] | None = None,
) -> EndpointAsset:
    asset_id = "asset-a"
    appliance_metadata: dict[str, object] = {
        "remote_work_root": "/srv/libcrafter/work",
        "remote_artifact_root": "/srv/libcrafter/artifacts",
    }
    if profile_environment is not None:
        appliance_metadata["profile_environments"] = {profile: profile_environment}
    return EndpointAsset(
        asset_id=asset_id,
        substrate="ssh-docker",
        status="available",
        supported_profiles=["wan-raw", "lan-raw"],
        ssh=AssetSSHInfo(
            host="192.0.2.44",
            user="root",
            port=2244,
            identity_file=str(_asset_state_dir(root, asset_id) / "id_ed25519"),
            known_hosts_file=str(_asset_state_dir(root, asset_id) / "known_hosts"),
        ),
        docker={"command": "docker-test"},
        lease=EndpointLease(
            holder="lease-a",
            leased_at="2026-06-28T12:00:00Z",
            leased_until=leased_until,
            ttl_seconds=3600,
            metadata={"lease_id": "lease-a", "profile": profile},
        ),
        metadata={"appliance": appliance_metadata},
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
