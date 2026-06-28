"""CLI coverage for persistent endpoint asset commands."""

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
    EndpointAsset,
    EndpointLease,
    asset_record_path,
    read_endpoint_asset,
    write_endpoint_asset,
)


class EndpointAssetCliTest(unittest.TestCase):
    def test_register_list_and_info_json_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            stdout = io.StringIO()

            with _endpoint_env(root), contextlib.redirect_stdout(stdout):
                exit_code = wire_cli.main(
                    [
                        "asset",
                        "register",
                        "qemu-reusable-a",
                        "--substrate",
                        "qemu",
                        "--profile",
                        "lan-raw",
                        "--profile",
                        "dot11-monitor",
                        "--ssh-host",
                        "192.0.2.10",
                        "--ssh-user",
                        "root",
                        "--ssh-port",
                        "2222",
                        "--identity-file",
                        str(
                            root
                            / "wire-state"
                            / "assets"
                            / "qemu-reusable-a"
                            / "id_ed25519"
                        ),
                        "--known-hosts-file",
                        str(
                            root
                            / "wire-state"
                            / "assets"
                            / "qemu-reusable-a"
                            / "known_hosts"
                        ),
                        "--docker-command",
                        "docker",
                        "--metadata-json",
                        '{"owner":"endpoint-test"}',
                        "--provider-metadata-json",
                        '{"name":"qemu","vm":"asset-a"}',
                        "--hardware-json",
                        '{"architecture":"x86_64","cpu_count":4,"memory_mb":8192}',
                        "--json",
                    ]
                )
            registered = json.loads(stdout.getvalue())

            with _endpoint_env(root):
                loaded = read_endpoint_asset("qemu-reusable-a")

            self.assertEqual(exit_code, 0)
            self.assertTrue(registered["registered"])
            self.assertEqual(registered["asset"]["asset_id"], "qemu-reusable-a")
            self.assertEqual(
                registered["asset"]["supported_profiles"],
                ["lan-raw", "dot11-monitor"],
            )
            self.assertEqual(registered["asset"]["docker"], {"command": "docker"})
            self.assertEqual(registered["asset"]["metadata"]["owner"], "endpoint-test")
            self.assertEqual(registered["asset"]["metadata"]["provider"]["vm"], "asset-a")
            self.assertEqual(registered["asset"]["hardware"]["cpu_count"], 4)
            self.assertEqual(loaded.to_dict(), registered["asset"])

            with _endpoint_env(root):
                leased = EndpointAsset(
                    asset_id=loaded.asset_id,
                    substrate=loaded.substrate,
                    status=loaded.status,
                    supported_profiles=loaded.supported_profiles,
                    ssh=loaded.ssh,
                    docker=loaded.docker,
                    hardware=loaded.hardware,
                    last_check="2026-06-28T12:00:00Z",
                    lease=EndpointLease(
                        holder="agent-31",
                        leased_at="2026-06-28T12:00:00Z",
                        leased_until="2026-06-28T12:30:00Z",
                        ttl_seconds=1800,
                    ),
                    metadata=loaded.metadata,
                )
                write_endpoint_asset(leased)

            list_stdout = io.StringIO()
            with _endpoint_env(root), contextlib.redirect_stdout(list_stdout):
                list_exit = wire_cli.main(["asset", "list", "--json"])
            listed = json.loads(list_stdout.getvalue())

            self.assertEqual(list_exit, 0)
            self.assertEqual(listed["kind"], "endpoint-asset-list")
            self.assertEqual(len(listed["assets"]), 1)
            self.assertEqual(listed["assets"][0]["asset_id"], "qemu-reusable-a")
            self.assertEqual(listed["assets"][0]["lease_state"], "leased")
            self.assertEqual(listed["assets"][0]["lease"]["holder"], "agent-31")
            self.assertEqual(listed["assets"][0]["last_check_state"], "checked")
            self.assertEqual(listed["assets"][0]["last_check"], "2026-06-28T12:00:00Z")

            info_stdout = io.StringIO()
            with _endpoint_env(root), contextlib.redirect_stdout(info_stdout):
                info_exit = wire_cli.main(["asset", "info", "qemu-reusable-a", "--json"])
            info = json.loads(info_stdout.getvalue())

            self.assertEqual(info_exit, 0)
            self.assertEqual(info["kind"], "endpoint-asset-info")
            self.assertEqual(info["asset"]["asset_id"], "qemu-reusable-a")
            self.assertEqual(info["asset"]["lease"]["holder"], "agent-31")

    def test_register_rejects_duplicate_asset_id_without_overwriting(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first = _register_argv(root, "--ssh-host", "192.0.2.10")
            second = _register_argv(root, "--ssh-host", "192.0.2.11")

            with _endpoint_env(root), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(wire_cli.main(first), 0)

            stdout = io.StringIO()
            with _endpoint_env(root), contextlib.redirect_stdout(stdout):
                exit_code = wire_cli.main(second)
            output = json.loads(stdout.getvalue())

            with _endpoint_env(root):
                loaded = read_endpoint_asset("qemu-reusable-a")

            self.assertNotEqual(exit_code, 0)
            self.assertFalse(output["ok"])
            self.assertIn("already registered", output["error"])
            self.assertEqual(loaded.ssh.host, "192.0.2.10")

    def test_register_rejects_invalid_profile_as_json_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            stdout = io.StringIO()

            argv = _register_argv(root, "--profile", "missing-profile")
            with _endpoint_env(root), contextlib.redirect_stdout(stdout):
                exit_code = wire_cli.main(argv)
            output = json.loads(stdout.getvalue())

            self.assertNotEqual(exit_code, 0)
            self.assertFalse(output["ok"])
            self.assertEqual(output["asset_id"], "qemu-reusable-a")
            self.assertIn("unknown appliance profile", output["error"])

    def test_state_root_environment_override_controls_asset_storage(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            state_root = root / "custom-state"
            artifact_root = root / "custom-artifacts"

            with _endpoint_env_paths(state_root, artifact_root), contextlib.redirect_stdout(
                io.StringIO()
            ):
                exit_code = wire_cli.main(_register_argv(root))
                path = asset_record_path("qemu-reusable-a")

            self.assertEqual(exit_code, 0)
            self.assertEqual(path, state_root / "assets" / "qemu-reusable-a" / "asset.json")
            self.assertTrue(path.exists())
            self.assertFalse((artifact_root / "assets").exists())

    def test_asset_help_lists_nested_commands(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as raised:
                wire_cli.main(["asset", "--help"])

        self.assertEqual(raised.exception.code, 0)
        output = stdout.getvalue()
        self.assertIn("register", output)
        self.assertIn("list", output)
        self.assertIn("info", output)


def _register_argv(root: Path, *overrides: str) -> list[str]:
    values = {
        "--ssh-host": "192.0.2.10",
        "--profile": "lan-raw",
    }
    if overrides:
        if len(overrides) % 2 != 0:
            raise ValueError("overrides must be option/value pairs")
        for index in range(0, len(overrides), 2):
            values[overrides[index]] = overrides[index + 1]
    return [
        "asset",
        "register",
        "qemu-reusable-a",
        "--substrate",
        "qemu",
        "--profile",
        values["--profile"],
        "--ssh-host",
        values["--ssh-host"],
        "--ssh-user",
        "root",
        "--ssh-port",
        "2222",
        "--identity-file",
        str(root / "wire-state" / "assets" / "qemu-reusable-a" / "id_ed25519"),
        "--known-hosts-file",
        str(root / "wire-state" / "assets" / "qemu-reusable-a" / "known_hosts"),
        "--hardware-json",
        '{"cpu_count":2,"memory_mb":4096}',
        "--json",
    ]


def _endpoint_env(root: Path) -> mock._patch_dict[str, str]:
    return _endpoint_env_paths(root / "wire-state", root / "wire-artifacts")


def _endpoint_env_paths(
    state_root: Path,
    artifact_root: Path,
) -> mock._patch_dict[str, str]:
    return mock.patch.dict(
        os.environ,
        {
            "LIBCRAFTER_ENDPOINT_STATE_ROOT": str(state_root),
            "LIBCRAFTER_ENDPOINT_ARTIFACT_ROOT": str(artifact_root),
        },
    )


if __name__ == "__main__":
    unittest.main()
