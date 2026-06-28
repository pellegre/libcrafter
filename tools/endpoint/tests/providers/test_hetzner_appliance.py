"""Hetzner endpoint appliance substrate coverage."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from collections.abc import Sequence
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from tools.endpoint.engine.appliance import resolve_endpoint_appliance_target
from tools.endpoint.engine.assets import asset_ssh_docker_target
from tools.endpoint.engine.model import NetworkInterface
from tools.endpoint.engine.process import CommandResult
from tools.endpoint.engine.providers import hetzner
from tools.endpoint.engine.providers.hetzner import create as hetzner_create
from tools.endpoint.engine.providers.hetzner.appliance import (
    hetzner_endpoint_asset,
    render_hetzner_appliance_deploy_plan,
)
from tools.endpoint.engine.state import read_endpoint_manifest


class HetznerApplianceTest(unittest.TestCase):
    def test_dry_run_metadata_advertises_appliance_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            wan = hetzner.create_endpoint(
                provider="hetzner",
                exposure="wan",
                role="probe",
                dry_run=True,
            )
            private = hetzner.create_endpoint(
                provider="hetzner",
                exposure="private",
                role="oracle",
                private_group="pair-a",
                private_ip="10.42.19.9",
                dry_run=True,
            )

        wan_appliance = wan["metadata"]["appliance"]  # type: ignore[index]
        private_appliance = private["metadata"]["appliance"]  # type: ignore[index]
        self.assertEqual(wan_appliance["substrate"], "ssh-docker")  # type: ignore[index]
        self.assertEqual(wan_appliance["supported_profiles"], ["wan-raw"])  # type: ignore[index]
        self.assertTrue(wan_appliance["appliance_capable"])  # type: ignore[index]
        self.assertTrue(wan_appliance["nested_docker"])  # type: ignore[index]
        self.assertTrue(wan_appliance["docker_execution_supported"])  # type: ignore[index]
        self.assertEqual(wan_appliance["docker_setup"], "install-or-verify")  # type: ignore[index]
        self.assertEqual(private_appliance["substrate"], "ssh-docker")  # type: ignore[index]
        self.assertEqual(private_appliance["supported_profiles"], ["lan-raw"])  # type: ignore[index]
        self.assertTrue(private_appliance["private_lab"])  # type: ignore[index]
        self.assertEqual(private_appliance["raw_profile"], "lan-raw")  # type: ignore[index]

    def test_live_create_does_not_serialize_token_values(self) -> None:
        secret = "hetzner-secret-token-should-not-leak"
        fallback_secret = "hcloud-fallback-token-should-not-leak"

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            def fake_runner(argv: Sequence[str], **_: object) -> CommandResult:
                return _hcloud_result(argv, _wan_hcloud_payload(argv))

            with _patched_endpoint_helpers(), _wire_env(root):
                output = hetzner.create_endpoint(
                    provider="hetzner",
                    exposure="wan",
                    role="probe",
                    dry_run=False,
                    confirm_live_run=True,
                    env={
                        "HETZNER_API_TOKEN": secret,
                        "HCLOUD_TOKEN": fallback_secret,
                    },
                    command_runner=fake_runner,
                )
                stored = read_endpoint_manifest(str(output["endpoint_id"]))

        serialized = json.dumps(
            {
                "output": output,
                "stored": stored.to_dict(),
            },
            sort_keys=True,
        )
        self.assertNotIn(secret, serialized)
        self.assertNotIn(fallback_secret, serialized)
        self.assertEqual(stored.metadata["appliance"]["supported_profiles"], ["wan-raw"])  # type: ignore[index]

    def test_docker_deploy_plan_installs_or_verifies_docker(self) -> None:
        token = "deploy-plan-token-should-not-leak"

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _create_live_wan_endpoint(root, env={"HCLOUD_TOKEN": token})
            plan = render_hetzner_appliance_deploy_plan(
                manifest,
                image_tag="registry.example.invalid/libcrafter/appliance:test",
            )

        self.assertTrue(plan.install_docker)
        self.assertFalse(plan.executes)
        self.assertEqual(
            [command.kind for command in plan.commands[:2]],
            ["ssh-docker-check", "ssh-docker-install"],
        )
        docker_check, docker_install = plan.commands[:2]
        self.assertEqual(
            docker_check.remote_command_argv,
            ["docker", "info", "--format", "{{json .ServerVersion}}"],
        )
        self.assertEqual(docker_install.remote_command_argv[:2], ["sh", "-lc"])
        self.assertIn("apt-get install -y docker.io", docker_install.remote_command_argv[2])
        self.assertEqual(plan.target.metadata["appliance"]["docker_execution_supported"], True)
        self.assertEqual(plan.target.target.host, "198.51.100.44")
        self.assertNotIn(token, plan.to_json())

    def test_hetzner_manifest_converts_to_generic_ssh_docker_asset(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            manifest = hetzner.create_endpoint(
                provider="hetzner",
                exposure="wan",
                role="probe",
                dry_run=True,
            )
            resolved = resolve_endpoint_appliance_target(manifest)
            asset = hetzner_endpoint_asset(manifest)
            target = asset_ssh_docker_target(asset)

        self.assertEqual(asset.substrate, "ssh-docker")
        self.assertEqual(asset.supported_profiles, ["wan-raw"])
        self.assertEqual(asset.docker["command"], "docker")
        self.assertEqual(asset.metadata["provider"], "hetzner")
        self.assertEqual(asset.metadata["endpoint_id"], manifest["endpoint_id"])
        self.assertEqual(target.host, resolved.target.host)
        self.assertEqual(target.user, resolved.target.user)
        self.assertEqual(target.remote_work_root, resolved.target.remote_work_root)
        self.assertEqual(target.remote_artifact_root, resolved.target.remote_artifact_root)


@contextmanager
def _patched_endpoint_helpers():
    with (
        mock.patch.object(hetzner_create, "_ensure_endpoint_key", return_value=None),
        mock.patch.object(hetzner_create, "wait_for_ssh", return_value=None),
        mock.patch.object(
            hetzner_create,
            "discover_endpoint_interfaces",
            return_value=_discovered_interfaces(),
        ),
    ):
        yield


def _create_live_wan_endpoint(
    root: Path,
    *,
    env: dict[str, str],
) -> dict[str, object]:
    def fake_runner(argv: Sequence[str], **_: object) -> CommandResult:
        return _hcloud_result(argv, _wan_hcloud_payload(argv))

    with _patched_endpoint_helpers(), _wire_env(root):
        return hetzner.create_endpoint(
            provider="hetzner",
            exposure="wan",
            role="probe",
            dry_run=False,
            confirm_live_run=True,
            env=env,
            command_runner=fake_runner,
        )


def _hcloud_result(argv: Sequence[str], payload: dict[str, object]) -> CommandResult:
    return CommandResult(
        argv=tuple(argv),
        redacted_argv=tuple(argv),
        cwd=None,
        exit_code=0,
        stdout=json.dumps(payload),
        stderr="",
    )


def _wan_hcloud_payload(argv: Sequence[str]) -> dict[str, object]:
    parts = tuple(argv)
    if parts[:3] == ("hcloud", "ssh-key", "create"):
        return {"ssh_key": {"id": "ssh-key-101", "name": parts[parts.index("--name") + 1]}}
    if parts[:3] == ("hcloud", "server", "create"):
        return {
            "server": {
                "id": "server-202",
                "name": parts[parts.index("--name") + 1],
                "status": "initializing",
                "public_net": {
                    "ipv4": {"ip": "198.51.100.44"},
                    "ipv6": {"ip": "2001:db8::44"},
                },
            }
        }
    if parts[:3] == ("hcloud", "server", "describe"):
        return {"server": {"id": "server-202", "status": "running"}}
    raise AssertionError(f"unexpected hcloud argv: {parts}")


def _discovered_interfaces() -> list[NetworkInterface]:
    return [
        NetworkInterface(
            name="eth0",
            exposure="wan",
            ipv4="198.51.100.44",
            ipv6="2001:db8::44",
            metadata={"source": "test"},
        )
    ]


def _wire_env(root: Path):
    return mock.patch.dict(
        os.environ,
        {
            "LIBCRAFTER_ENDPOINT_STATE_ROOT": str(root / "wire-state"),
            "LIBCRAFTER_ENDPOINT_ARTIFACT_ROOT": str(root / "wire-artifacts"),
        },
    )


if __name__ == "__main__":
    unittest.main()
