"""CLI coverage for persistent endpoint asset readiness checks."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from tools.endpoint.engine import cli as wire_cli
from tools.endpoint.engine.assets import (
    AssetHardware,
    AssetSSHInfo,
    EndpointAsset,
    read_endpoint_asset,
    write_endpoint_asset,
)
from tools.endpoint.engine.process import CommandResult


class EndpointAssetCheckCliTest(unittest.TestCase):
    def test_successful_fake_check_returns_structured_results(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_asset(root)
            runner = _FakeRunner()

            exit_code, output = _run_asset_check(
                root,
                runner,
                now=datetime(2026, 6, 28, 12, 0, 0, tzinfo=UTC),
            )

        self.assertEqual(exit_code, 0)
        self.assertTrue(output["ok"])
        self.assertEqual(output["kind"], "endpoint-asset-check")
        self.assertEqual(output["asset_id"], "asset-a")
        self.assertEqual(output["profile"], "lan-raw")
        self.assertEqual(output["checked_at"], "2026-06-28T12:00:00Z")
        self.assertEqual(output["last_check"], "2026-06-28T12:00:00Z")
        self.assertTrue(output["docker_check"]["ok"])
        self.assertEqual(output["docker_check"]["result"]["exit_code"], 0)
        self.assertEqual(runner.calls, [output["docker_check"]["plan"]["command_argv"]])
        self.assertTrue(output["hardware_check"]["ok"])
        self.assertEqual(output["hardware_check"]["hardware"]["cpu_count"], 4)
        self.assertTrue(output["host_requirements"])
        self.assertTrue(output["profile_checks"])

    def test_missing_profile_support_returns_json_error_without_last_check_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_asset(root, last_check="2026-06-28T10:00:00Z")
            runner = _FakeRunner()

            exit_code, output = _run_asset_check(root, runner, profile="dot11-monitor")

            with _endpoint_env(root):
                stored = read_endpoint_asset("asset-a")

        self.assertNotEqual(exit_code, 0)
        self.assertFalse(output["ok"])
        self.assertEqual(output["kind"], "endpoint-asset-error")
        self.assertIn("does not support profile", output["error"])
        self.assertEqual(stored.last_check, "2026-06-28T10:00:00Z")
        self.assertEqual(runner.calls, [])

    def test_failed_ssh_or_docker_check_is_reflected_and_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_asset(root)
            runner = _FakeRunner(exit_code=255, stderr="ssh failed\n")

            exit_code, output = _run_asset_check(
                root,
                runner,
                now=datetime(2026, 6, 28, 12, 5, 0, tzinfo=UTC),
            )

            with _endpoint_env(root):
                stored = read_endpoint_asset("asset-a")

        self.assertEqual(exit_code, 255)
        self.assertFalse(output["ok"])
        self.assertFalse(output["docker_check"]["ok"])
        self.assertEqual(output["docker_check"]["result"]["exit_code"], 255)
        self.assertIn("ssh failed", output["docker_check"]["result"]["stderr"])
        self.assertEqual(output["last_check"], "2026-06-28T12:05:00Z")
        self.assertEqual(stored.last_check, "2026-06-28T12:05:00Z")

    def test_last_check_persistence_replaces_previous_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_asset(root, last_check="2026-06-28T10:00:00Z")
            runner = _FakeRunner()

            exit_code, output = _run_asset_check(
                root,
                runner,
                now=datetime(2026, 6, 28, 13, 30, 0, tzinfo=UTC),
            )

            with _endpoint_env(root):
                stored = read_endpoint_asset("asset-a")

        self.assertEqual(exit_code, 0)
        self.assertEqual(output["last_check"], "2026-06-28T13:30:00Z")
        self.assertEqual(stored.last_check, "2026-06-28T13:30:00Z")

    def test_dot11_rf_checks_remain_dry_run_readiness_plans(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_asset(root, profiles=("dot11-monitor",))
            runner = _FakeRunner()

            exit_code, output = _run_asset_check(
                root,
                runner,
                profile="dot11-monitor",
                now=datetime(2026, 6, 28, 14, 0, 0, tzinfo=UTC),
            )

        injection = _profile_check(output, "dot11-injection-smoke")
        monitor = _profile_check(output, "dot11-monitor-interface")
        self.assertEqual(exit_code, 0)
        self.assertEqual(len(runner.calls), 1)
        self.assertIn("--dry-run", injection["command_argv"])
        self.assertFalse(injection["metadata"]["live_transmit"])
        self.assertTrue(injection["metadata"]["requires_live_gate"])
        self.assertFalse(injection["required"])
        self.assertNotIn("--dry-run", monitor["command_argv"])
        self.assertFalse(output["live_transmit"])
        self.assertTrue(output["dry_run"])


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


def _run_asset_check(
    root: Path,
    runner: _FakeRunner,
    *,
    profile: str = "lan-raw",
    now: datetime | None = None,
) -> tuple[int, dict[str, object]]:
    stdout = io.StringIO()
    patches = [mock.patch.object(wire_cli, "run_command", runner)]
    if now is not None:
        patches.append(mock.patch("tools.endpoint.engine.assets._utc_now", return_value=now))
    with contextlib.ExitStack() as stack:
        stack.enter_context(_endpoint_env(root))
        stack.enter_context(contextlib.redirect_stdout(stdout))
        for patch in patches:
            stack.enter_context(patch)
        exit_code = wire_cli.main(
            [
                "asset",
                "check",
                "asset-a",
                "--profile",
                profile,
                "--json",
            ]
        )
    return exit_code, json.loads(stdout.getvalue())


def _write_asset(
    root: Path,
    *,
    profiles: tuple[str, ...] = ("lan-raw",),
    last_check: str | None = None,
) -> EndpointAsset:
    state_dir = root / "wire-state" / "assets" / "asset-a"
    asset = EndpointAsset(
        asset_id="asset-a",
        substrate="qemu",
        status="available",
        supported_profiles=list(profiles),
        ssh=AssetSSHInfo(
            host="192.0.2.10",
            user="root",
            port=2222,
            identity_file=str(state_dir / "id_ed25519"),
            known_hosts_file=str(state_dir / "known_hosts"),
        ),
        docker={"command": "docker-test"},
        hardware=AssetHardware(
            architecture="x86_64",
            cpu_count=4,
            memory_mb=8192,
        ),
        last_check=last_check,
        metadata={
            "appliance": {
                "remote_work_root": "/srv/libcrafter/work",
                "remote_artifact_root": "/srv/libcrafter/artifacts",
            }
        },
    )
    with _endpoint_env(root):
        write_endpoint_asset(asset)
    return asset


def _profile_check(output: dict[str, object], name: str) -> dict[str, object]:
    checks = output["profile_checks"]
    if not isinstance(checks, list):
        raise AssertionError("profile_checks must be a list")
    for check in checks:
        if isinstance(check, dict) and check.get("name") == name:
            return check
    raise AssertionError(f"profile check not found: {name}")


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
