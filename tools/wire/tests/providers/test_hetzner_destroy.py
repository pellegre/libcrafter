"""Fake-run coverage for Hetzner endpoint destroy."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.wire.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResource,
    ProviderResources,
)
from tools.wire.engine.process import CommandResult
from tools.wire.engine.providers import hetzner
from tools.wire.engine.state import (
    read_endpoint_manifest,
    read_private_group_record,
    update_private_group_allocation,
    write_endpoint_manifest,
)


class HetznerDestroyEndpointTest(unittest.TestCase):
    def test_destroy_endpoint_deletes_resources_and_marks_manifest_destroyed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(root)
            calls: list[tuple[str, ...]] = []

            def fake_runner(argv: list[str], **_: object) -> CommandResult:
                calls.append(tuple(argv))
                return CommandResult(
                    argv=tuple(argv),
                    redacted_argv=tuple(argv),
                    cwd=None,
                    exit_code=0,
                    stdout="",
                    stderr="",
                )

            with _wire_env(root):
                write_endpoint_manifest(manifest)
                output = hetzner.destroy_endpoint(
                    read_endpoint_manifest(manifest.endpoint_id),
                    env={},
                    command_runner=fake_runner,
                )
                stored = read_endpoint_manifest(manifest.endpoint_id)

            self.assertEqual(
                calls,
                [
                    ("hcloud", "server", "delete", "server-123"),
                    ("hcloud", "ssh-key", "delete", "ssh-key-123"),
                ],
            )
            self.assertTrue(output["ok"])
            self.assertEqual(output["status"], "destroyed")
            self.assertEqual(stored.status, "destroyed")
            self.assertEqual(stored.artifact_dir, manifest.artifact_dir)

    def test_destroy_endpoint_tolerates_provider_resources_already_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(root)

            def fake_runner(argv: list[str], **_: object) -> CommandResult:
                return CommandResult(
                    argv=tuple(argv),
                    redacted_argv=tuple(argv),
                    cwd=None,
                    exit_code=1,
                    stdout="",
                    stderr="not found",
                )

            with _wire_env(root):
                write_endpoint_manifest(manifest)
                output = hetzner.destroy_endpoint(
                    read_endpoint_manifest(manifest.endpoint_id),
                    env={},
                    command_runner=fake_runner,
                )
                stored = read_endpoint_manifest(manifest.endpoint_id)

            self.assertEqual(stored.status, "destroyed")
            self.assertEqual(
                [action["action"] for action in output["actions"]],
                ["already-missing", "already-missing"],
            )

    def test_destroy_endpoint_is_idempotent_after_local_destroy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(root, status="destroyed")

            def fake_runner(argv: list[str], **_: object) -> CommandResult:
                self.fail(f"destroyed endpoint should not contact provider: {argv}")

            with _wire_env(root):
                write_endpoint_manifest(manifest)
                output = hetzner.destroy_endpoint(
                    read_endpoint_manifest(manifest.endpoint_id),
                    env={},
                    command_runner=fake_runner,
                )

            self.assertTrue(output["ok"])
            self.assertTrue(output["already_destroyed"])
            self.assertFalse(output["destroyed"])

    def test_destroy_private_endpoint_preserves_shared_network(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _private_manifest(root)
            calls: list[tuple[str, ...]] = []

            def fake_runner(argv: list[str], **_: object) -> CommandResult:
                calls.append(tuple(argv))
                return CommandResult(
                    argv=tuple(argv),
                    redacted_argv=tuple(argv),
                    cwd=None,
                    exit_code=0,
                    stdout="",
                    stderr="",
                )

            with _wire_env(root):
                write_endpoint_manifest(manifest)
                update_private_group_allocation(
                    provider="hetzner",
                    group="group-a",
                    endpoint_id=manifest.endpoint_id,
                    private_ipv4="10.0.0.2",
                    network_resource=_network_resource(),
                )
                update_private_group_allocation(
                    provider="hetzner",
                    group="group-a",
                    endpoint_id="hetzner-private-peer",
                    private_ipv4="10.0.0.3",
                    network_resource=_network_resource(),
                )

                output = hetzner.destroy_endpoint(
                    read_endpoint_manifest(manifest.endpoint_id),
                    env={},
                    command_runner=fake_runner,
                )
                record = read_private_group_record("hetzner", "group-a")

            self.assertEqual(
                calls,
                [
                    (
                        "hcloud",
                        "server",
                        "detach-from-network",
                        "server-123",
                        "--network",
                        "network-123",
                    ),
                    ("hcloud", "server", "delete", "server-123"),
                    ("hcloud", "ssh-key", "delete", "ssh-key-123"),
                ],
            )
            self.assertTrue(output["ok"])
            self.assertEqual(record.allocated_endpoint_ids, ["hetzner-private-peer"])
            self.assertEqual(record.allocated_private_ipv4s, ["10.0.0.3"])

    def test_destroy_last_private_endpoint_deletes_private_network(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _private_manifest(root)
            calls: list[tuple[str, ...]] = []

            def fake_runner(argv: list[str], **_: object) -> CommandResult:
                calls.append(tuple(argv))
                return CommandResult(
                    argv=tuple(argv),
                    redacted_argv=tuple(argv),
                    cwd=None,
                    exit_code=0,
                    stdout="",
                    stderr="",
                )

            with _wire_env(root):
                write_endpoint_manifest(manifest)
                update_private_group_allocation(
                    provider="hetzner",
                    group="group-a",
                    endpoint_id=manifest.endpoint_id,
                    private_ipv4="10.0.0.2",
                    network_resource=_network_resource(),
                )

                output = hetzner.destroy_endpoint(
                    read_endpoint_manifest(manifest.endpoint_id),
                    env={},
                    command_runner=fake_runner,
                )
                record = read_private_group_record("hetzner", "group-a")

            self.assertEqual(
                calls,
                [
                    (
                        "hcloud",
                        "server",
                        "detach-from-network",
                        "server-123",
                        "--network",
                        "network-123",
                    ),
                    ("hcloud", "server", "delete", "server-123"),
                    ("hcloud", "ssh-key", "delete", "ssh-key-123"),
                    ("hcloud", "network", "delete", "network-123"),
                ],
            )
            self.assertTrue(output["ok"])
            self.assertEqual(record.allocated_endpoint_ids, [])
            self.assertEqual(record.allocated_private_ipv4s, [])
            self.assertEqual(
                [action["action"] for action in output["actions"]],
                ["detach", "delete", "delete", "delete"],
            )


def _manifest(root: Path, *, status: str = "active") -> EndpointManifest:
    return EndpointManifest(
        endpoint_id="hetzner-wan-test",
        provider="hetzner",
        exposure="wan",
        status=status,
        role="test",
        created_at="2026-05-25T00:00:00Z",
        ssh=EndpointSSHInfo(
            host="203.0.113.10",
            user="root",
            identity_file=str(root / "state" / "id_ed25519"),
            known_hosts_file=str(root / "state" / "known_hosts"),
        ),
        interfaces=[NetworkInterface(name="public", exposure="wan", ipv4="203.0.113.10")],
        provider_resources=ProviderResources(
            resources=[
                ProviderResource(kind="server", provider_id="server-123", name="server"),
                ProviderResource(kind="ssh-key", provider_id="ssh-key-123", name="key"),
            ],
            cleanup_order=["server", "ssh-key"],
        ),
        artifact_dir=str(root / "artifacts" / "hetzner-wan-test"),
    )


def _private_manifest(root: Path, *, status: str = "active") -> EndpointManifest:
    return EndpointManifest(
        endpoint_id="hetzner-private-test",
        provider="hetzner",
        exposure="private",
        status=status,
        role="test",
        created_at="2026-05-25T00:00:00Z",
        ssh=EndpointSSHInfo(
            host="203.0.113.10",
            user="root",
            identity_file=str(root / "state" / "id_ed25519"),
            known_hosts_file=str(root / "state" / "known_hosts"),
        ),
        interfaces=[
            NetworkInterface(
                name="private",
                exposure="private",
                ipv4="10.0.0.2",
                provider_network_id="network-123",
                metadata={
                    "private_group": "group-a",
                    "private_ip": "10.0.0.2",
                    "network": _network_resource(),
                },
            )
        ],
        provider_resources=ProviderResources(
            resources=[
                ProviderResource(kind="server", provider_id="server-123", name="server"),
                ProviderResource(kind="ssh-key", provider_id="ssh-key-123", name="key"),
            ],
            cleanup_order=["server", "ssh-key"],
            metadata={
                "exposure": "private",
                "private_network_cleanup": "private-group-owned",
            },
        ),
        artifact_dir=str(root / "artifacts" / "hetzner-private-test"),
        metadata={
            "private_group": "group-a",
            "private_ip": "10.0.0.2",
            "private": {
                "private_group": "group-a",
                "private_ip": "10.0.0.2",
                "network": _network_resource(),
            },
        },
    )


def _network_resource() -> dict[str, object]:
    return {
        "type": "network",
        "provider": "hetzner",
        "network_id": "network-123",
        "network_name": "wire-group-a",
        "private_group": "group-a",
        "ip_range": "10.0.0.0/16",
    }


def _wire_env(root: Path):
    return mock.patch.dict(
        os.environ,
        {
            "LIBCRAFTER_WIRE_STATE_ROOT": str(root / "wire-state"),
            "LIBCRAFTER_WIRE_ARTIFACT_ROOT": str(root / "wire-artifacts"),
        },
    )


if __name__ == "__main__":
    unittest.main()
