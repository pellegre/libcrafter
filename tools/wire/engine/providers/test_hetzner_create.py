"""Fake-run coverage for Hetzner endpoint creation."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from collections.abc import Sequence
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from tools.wire.engine.model import NetworkInterface
from tools.wire.engine.process import CommandResult
from tools.wire.engine.providers import hetzner
from tools.wire.engine.state import read_endpoint_manifest, read_private_group_record


class HetznerCreateEndpointTest(unittest.TestCase):
    def test_dry_run_manifest_has_absolute_paths_and_no_runner_calls(self) -> None:
        def fake_runner(argv: Sequence[str], **_: object) -> CommandResult:
            self.fail(f"dry-run create should not run hcloud: {argv}")

        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            output = hetzner.create_endpoint(
                provider="hetzner",
                exposure="private",
                role="oracle",
                private_group="pair-a",
                private_ip="10.0.0.9",
                dry_run=True,
                command_runner=fake_runner,
            )

        self.assertFalse(output["created"])
        self.assertTrue(output["dry_run"])
        self.assertEqual(output["status"], "planned")
        self.assertEqual(output["metadata"]["private_group"], "pair-a")  # type: ignore[index]
        self.assertTrue(Path(str(output["artifact_dir"])).is_absolute())
        self.assertTrue(Path(str(output["manifest_path"])).is_absolute())
        self.assertTrue(Path(str(output["ssh"]["identity_file"])).is_absolute())  # type: ignore[index]
        self.assertEqual(output["interfaces"][0]["provider_network_id"], "planned-private-network-pair-a")  # type: ignore[index]

    def test_live_create_requires_confirmation_before_credentials_or_runner(self) -> None:
        def fake_runner(argv: Sequence[str], **_: object) -> CommandResult:
            self.fail(f"unconfirmed live create should not run hcloud: {argv}")

        with self.assertRaisesRegex(PermissionError, "confirm-live-run"):
            hetzner.create_endpoint(
                provider="hetzner",
                exposure="wan",
                role="probe",
                dry_run=False,
                confirm_live_run=False,
                env={},
                command_runner=fake_runner,
            )

    def test_wan_live_create_builds_expected_hcloud_commands_with_fake_runner(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            calls: list[tuple[str, ...]] = []

            def fake_runner(argv: Sequence[str], **_: object) -> CommandResult:
                calls.append(tuple(argv))
                return _hcloud_result(argv, _wan_hcloud_payload(argv))

            with _patched_endpoint_helpers(), _wire_env(root):
                output = hetzner.create_endpoint(
                    provider="hetzner",
                    exposure="wan",
                    role="probe",
                    dry_run=False,
                    confirm_live_run=True,
                    env={"HETZNER_API_TOKEN": "token"},
                    command_runner=fake_runner,
                )
                stored = read_endpoint_manifest(str(output["endpoint_id"]))

            endpoint_id = str(output["endpoint_id"])
            self.assertTrue(output["created"])
            self.assertFalse(output["dry_run"])
            self.assertEqual(stored.status, "active")
            self.assertEqual(stored.ssh.host, "198.51.100.44")
            self.assertEqual(
                calls,
                [
                    (
                        "hcloud",
                        "ssh-key",
                        "create",
                        "--name",
                        f"wire-{endpoint_id}-key",
                        "--public-key-from-file",
                        str(root / "wire-state" / "endpoints" / endpoint_id / "id_ed25519.pub"),
                        "-o",
                        "json",
                    ),
                    (
                        "hcloud",
                        "server",
                        "create",
                        "--name",
                        f"wire-{endpoint_id}",
                        "--type",
                        "cx22",
                        "--image",
                        "ubuntu-24.04",
                        "--location",
                        "hel1",
                        "--ssh-key",
                        f"wire-{endpoint_id}-key",
                        "--label",
                        "libcrafter-wire=true",
                        "--label",
                        f"libcrafter-wire-endpoint-id={endpoint_id}",
                        "--label",
                        "libcrafter-wire-role=probe",
                        "--label",
                        "libcrafter-wire-exposure=wan",
                        "-o",
                        "json",
                    ),
                    ("hcloud", "server", "describe", "server-202", "-o", "json"),
                ],
            )

    def test_private_live_create_builds_network_commands_and_records_group(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            calls: list[tuple[str, ...]] = []

            def fake_runner(argv: Sequence[str], **_: object) -> CommandResult:
                calls.append(tuple(argv))
                return _hcloud_result(argv, _private_hcloud_payload(argv))

            with _patched_endpoint_helpers(), _wire_env(root):
                output = hetzner.create_endpoint(
                    provider="hetzner",
                    exposure="private",
                    role="oracle",
                    private_group="pair-a",
                    private_ip="10.0.0.9",
                    dry_run=False,
                    confirm_live_run=True,
                    env={"HCLOUD_TOKEN": "token"},
                    command_runner=fake_runner,
                )
                stored = read_endpoint_manifest(str(output["endpoint_id"]))
                record = read_private_group_record("hetzner", "pair-a")

            endpoint_id = str(output["endpoint_id"])
            self.assertTrue(output["created"])
            self.assertEqual(stored.exposure, "private")
            self.assertEqual(stored.interfaces[0].ipv4, "10.0.0.9")
            self.assertEqual(record.allocated_endpoint_ids, [endpoint_id])
            self.assertEqual(record.allocated_private_ipv4s, ["10.0.0.9"])
            self.assertEqual(record.network_resource["network_id"], "network-303")
            self.assertEqual(
                calls,
                [
                    ("hcloud", "network", "describe", "wire-pair-a", "-o", "json"),
                    (
                        "hcloud",
                        "network",
                        "create",
                        "--name",
                        "wire-pair-a",
                        "--ip-range",
                        "10.0.0.0/16",
                        "--label",
                        "libcrafter-wire=true",
                        "--label",
                        "libcrafter-wire-private-group=pair-a",
                        "-o",
                        "json",
                    ),
                    (
                        "hcloud",
                        "ssh-key",
                        "create",
                        "--name",
                        f"wire-{endpoint_id}-key",
                        "--public-key-from-file",
                        str(root / "wire-state" / "endpoints" / endpoint_id / "id_ed25519.pub"),
                        "-o",
                        "json",
                    ),
                    (
                        "hcloud",
                        "server",
                        "create",
                        "--name",
                        f"wire-{endpoint_id}",
                        "--type",
                        "cx22",
                        "--image",
                        "ubuntu-24.04",
                        "--location",
                        "hel1",
                        "--ssh-key",
                        f"wire-{endpoint_id}-key",
                        "--label",
                        "libcrafter-wire=true",
                        "--label",
                        f"libcrafter-wire-endpoint-id={endpoint_id}",
                        "--label",
                        "libcrafter-wire-role=oracle",
                        "--label",
                        "libcrafter-wire-exposure=private",
                        "--label",
                        "libcrafter-wire-private-group=pair-a",
                        "-o",
                        "json",
                    ),
                    (
                        "hcloud",
                        "server",
                        "attach-to-network",
                        "server-202",
                        "--network",
                        "network-303",
                        "--ip",
                        "10.0.0.9",
                        "-o",
                        "json",
                    ),
                    ("hcloud", "server", "describe", "server-202", "-o", "json"),
                ],
            )


@contextmanager
def _patched_endpoint_helpers():
    with (
        mock.patch.object(hetzner, "_ensure_endpoint_key", return_value=None),
        mock.patch.object(hetzner, "wait_for_ssh", return_value=None),
        mock.patch.object(
            hetzner,
            "discover_endpoint_interfaces",
            return_value=_discovered_interfaces(),
        ),
    ):
        yield


def _hcloud_result(argv: Sequence[str], payload: dict[str, object] | None) -> CommandResult:
    if payload is None:
        return CommandResult(
            argv=tuple(argv),
            redacted_argv=tuple(argv),
            cwd=None,
            exit_code=1,
            stdout="",
            stderr="not found",
        )
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


def _private_hcloud_payload(argv: Sequence[str]) -> dict[str, object] | None:
    parts = tuple(argv)
    if parts == ("hcloud", "network", "describe", "wire-pair-a", "-o", "json"):
        return None
    if parts[:3] == ("hcloud", "network", "create"):
        return {
            "network": {
                "id": "network-303",
                "name": "wire-pair-a",
                "ip_range": "10.0.0.0/16",
                "subnets": [
                    {
                        "type": "server",
                        "network_zone": "eu-central",
                        "ip_range": "10.0.0.0/16",
                    }
                ],
            }
        }
    if parts[:3] == ("hcloud", "server", "attach-to-network"):
        return {}
    return _wan_hcloud_payload(argv)


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
            "LIBCRAFTER_WIRE_STATE_ROOT": str(root / "wire-state"),
            "LIBCRAFTER_WIRE_ARTIFACT_ROOT": str(root / "wire-artifacts"),
        },
    )


if __name__ == "__main__":
    unittest.main()
