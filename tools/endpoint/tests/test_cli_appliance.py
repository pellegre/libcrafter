"""CLI coverage for endpoint appliance operations."""

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
from tools.endpoint.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResources,
)
from tools.endpoint.engine.state import write_endpoint_manifest


class EndpointApplianceCliTest(unittest.TestCase):
    def test_appliance_help_lists_nested_commands(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as raised:
                wire_cli.main(["appliance", "--help"])

        self.assertEqual(raised.exception.code, 0)
        output = stdout.getvalue()
        self.assertIn("plan", output)
        self.assertIn("check", output)
        self.assertIn("deploy", output)
        self.assertIn("run", output)
        self.assertIn("collect", output)

    def test_json_dry_run_plan_uses_endpoint_profile_and_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = _workspace(root)
            manifest = _write_manifest(root)
            stdout = io.StringIO()

            with _endpoint_env(root), contextlib.redirect_stdout(stdout):
                exit_code = wire_cli.main(
                    [
                        "appliance",
                        "plan",
                        manifest.endpoint_id,
                        "lan-raw",
                        "--work-dir",
                        str(workspace),
                        "--artifact-dir",
                        str(root / "custom-artifacts"),
                        "--dry-run",
                        "--json",
                        "--",
                        "cargo",
                        "test",
                        "-p",
                        "crafter",
                    ]
                )

            output = json.loads(stdout.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertEqual(output["kind"], "endpoint-appliance-plan")
        self.assertFalse(output["executes"])
        self.assertEqual(output["endpoint_id"], "endpoint-a")
        self.assertEqual(output["profile"], "lan-raw")
        self.assertEqual(output["deploy"]["kind"], "endpoint-appliance-deploy-plan")
        self.assertEqual(output["sync"]["kind"], "endpoint-appliance-sync-plan")
        self.assertEqual(output["run"]["kind"], "endpoint-appliance-run-plan")
        self.assertEqual(output["run"]["command_argv"], ["cargo", "test", "-p", "crafter"])
        self.assertEqual(output["run"]["docker_run"]["network_mode"], "host")

    def test_json_missing_endpoint_returns_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            stdout = io.StringIO()

            with _endpoint_env(root), contextlib.redirect_stdout(stdout):
                exit_code = wire_cli.main(
                    [
                        "appliance",
                        "plan",
                        "missing-endpoint",
                        "lan-raw",
                        "--dry-run",
                        "--json",
                        "--",
                        "true",
                    ]
                )

            output = json.loads(stdout.getvalue())

        self.assertNotEqual(exit_code, 0)
        self.assertFalse(output["ok"])
        self.assertEqual(output["endpoint_id"], "missing-endpoint")
        self.assertIn("endpoint manifest not found", output["error"])

    def test_json_unknown_profile_returns_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _write_manifest(root)
            stdout = io.StringIO()

            with _endpoint_env(root), contextlib.redirect_stdout(stdout):
                exit_code = wire_cli.main(
                    [
                        "appliance",
                        "plan",
                        manifest.endpoint_id,
                        "missing-profile",
                        "--dry-run",
                        "--json",
                        "--",
                        "true",
                    ]
                )

            output = json.loads(stdout.getvalue())

        self.assertNotEqual(exit_code, 0)
        self.assertFalse(output["ok"])
        self.assertEqual(output["profile"], "missing-profile")
        self.assertIn("unknown appliance profile", output["error"])

    def test_run_command_argv_after_double_dash_is_preserved_in_json_plan(self) -> None:
        command = [
            "python3",
            "-m",
            "synthetic.tool",
            "--",
            "--literal-flag",
            "two words",
            "semi;colon",
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _write_manifest(root)
            stdout = io.StringIO()

            with _endpoint_env(root), contextlib.redirect_stdout(stdout):
                exit_code = wire_cli.main(
                    [
                        "appliance",
                        "run",
                        manifest.endpoint_id,
                        "lan-raw",
                        "--dry-run",
                        "--json",
                        "--",
                        *command,
                    ]
                )

            output = json.loads(stdout.getvalue())

        run_plan = output["run"]
        remote_command = run_plan["commands"][1]["command_argv"][-1]
        self.assertEqual(exit_code, 0)
        self.assertEqual(run_plan["command_argv"], command)
        self.assertEqual(run_plan["docker_run"]["command_argv"], command)
        self.assertEqual(run_plan["docker_run"]["docker_argv"][-len(command) :], command)
        self.assertIn("'two words'", remote_command)
        self.assertIn("'semi;colon'", remote_command)


def _endpoint_env(root: Path) -> mock._patch_dict[str, str]:
    return mock.patch.dict(
        os.environ,
        {
            "LIBCRAFTER_ENDPOINT_STATE_ROOT": str(root / "wire-state"),
            "LIBCRAFTER_ENDPOINT_ARTIFACT_ROOT": str(root / "wire-artifacts"),
        },
    )


def _write_manifest(root: Path) -> EndpointManifest:
    manifest = _manifest(root)
    with _endpoint_env(root):
        write_endpoint_manifest(manifest)
    return manifest


def _workspace(root: Path) -> Path:
    workspace = root / "workspace"
    (workspace / "src").mkdir(parents=True)
    (workspace / "src" / "lib.rs").write_text("// synthetic\n", encoding="utf-8")
    return workspace


def _manifest(root: Path) -> EndpointManifest:
    endpoint_id = "endpoint-a"
    state_dir = root / "wire-state" / "endpoints" / endpoint_id
    return EndpointManifest(
        endpoint_id=endpoint_id,
        provider="qemu",
        exposure="private",
        status="active",
        role="probe",
        created_at="2026-06-28T00:00:00Z",
        ssh=EndpointSSHInfo(
            host="192.0.2.10",
            user="root",
            port=2201,
            identity_file=str(state_dir / "id_ed25519"),
            known_hosts_file=str(state_dir / "known_hosts"),
        ),
        interfaces=[NetworkInterface(name="eth0", exposure="private", ipv4="192.0.2.10")],
        provider_resources=ProviderResources(),
        artifact_dir=str(root / "wire-artifacts" / endpoint_id),
        metadata={"appliance": {"docker_command": "docker-test"}},
    )


if __name__ == "__main__":
    unittest.main()
