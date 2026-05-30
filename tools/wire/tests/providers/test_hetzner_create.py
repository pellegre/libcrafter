"""Fake-run coverage for Hetzner endpoint creation."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from collections.abc import Sequence
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from unittest import mock

from tools.wire.engine import cli as wire_cli
from tools.wire.engine.model import NetworkInterface
from tools.wire.engine.process import CommandResult
from tools.wire.engine.providers import hetzner
from tools.wire.engine.providers.hetzner import create as hetzner_create
from tools.wire.engine.providers.hetzner import network as hetzner_network
from tools.wire.engine.state import read_endpoint_manifest, read_private_group_record


class HetznerCreateEndpointTest(unittest.TestCase):
    def test_cli_create_endpoint_routes_dry_run_through_resolved_provider(self) -> None:
        fake_provider = mock.Mock()
        fake_provider.create_endpoint.return_value = {
            "endpoint_id": "hetzner-wan-planned",
            "provider": "hetzner",
            "exposure": "wan",
            "created": False,
            "dry_run": True,
        }
        fake_provider.cli_output_manifest.side_effect = lambda manifest: {
            **manifest,
            "formatted_by": "fake-provider",
        }

        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            with (
                mock.patch.object(
                    wire_cli,
                    "resolve_provider",
                    return_value=fake_provider,
                ) as resolver,
                redirect_stdout(stdout),
            ):
                exit_code = wire_cli.main(
                    [
                        "create-endpoint",
                        "--provider",
                        "hetzner",
                        "--exposure",
                        "wan",
                        "--dry-run",
                        "--json",
                    ]
                )

        self.assertEqual(exit_code, 0)
        resolver.assert_called_once_with("hetzner", "wan")
        fake_provider.create_endpoint.assert_called_once()
        self.assertEqual(
            fake_provider.create_endpoint.call_args.kwargs,
            {
                "provider": "hetzner",
                "exposure": "wan",
                "role": "libcrafter",
                "private_group": None,
                "private_ip": None,
                "dry_run": True,
                "confirm_live_run": False,
            },
        )
        self.assertEqual(json.loads(stdout.getvalue())["formatted_by"], "fake-provider")

    def test_cli_create_endpoint_reports_resolved_provider_errors(self) -> None:
        fake_provider = mock.Mock()
        fake_provider.create_endpoint.side_effect = RuntimeError("provider exploded")

        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            with (
                mock.patch.object(wire_cli, "resolve_provider", return_value=fake_provider),
                redirect_stdout(stdout),
            ):
                exit_code = wire_cli.main(
                    [
                        "create-endpoint",
                        "--provider",
                        "hetzner",
                        "--exposure",
                        "wan",
                        "--dry-run",
                        "--json",
                    ]
                )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertFalse(payload["ok"])
        self.assertFalse(payload["created"])
        self.assertEqual(payload["error"], "provider exploded")

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
                        "cx23",
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

            with _patched_endpoint_helpers(_private_discovered_interfaces()), _wire_env(root):
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
            self.assertEqual(stored.interfaces[0].name, "ens10")
            self.assertEqual(stored.interfaces[0].ipv4, "10.0.0.9")
            self.assertEqual(stored.interfaces[0].mac, "86:00:00:00:00:09")
            self.assertEqual(stored.metadata["discovery"]["private_interface"], "ens10")
            self.assertTrue(stored.metadata["discovery"]["private_interface_matched"])
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
                        "cx23",
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
                    ),
                    ("hcloud", "server", "describe", "server-202", "-o", "json"),
                ],
            )

    def test_private_live_create_retries_until_private_interface_has_requested_ip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            def fake_runner(argv: Sequence[str], **_: object) -> CommandResult:
                return _hcloud_result(argv, _private_hcloud_payload(argv))

            with (
                mock.patch.object(hetzner_create, "_ensure_endpoint_key", return_value=None),
                mock.patch.object(hetzner_create, "wait_for_ssh", return_value=None),
                mock.patch.object(
                    hetzner_create,
                    "_configure_private_network_interface",
                    return_value=None,
                ),
                mock.patch.object(
                    hetzner_create,
                    "discover_endpoint_interfaces",
                    side_effect=[_discovered_interfaces(), _private_discovered_interfaces()],
                ) as discovery,
                mock.patch.object(hetzner_create.time, "sleep", return_value=None) as sleep,
                _wire_env(root),
            ):
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

            self.assertEqual(stored.interfaces[0].name, "ens10")
            self.assertEqual(discovery.call_count, 2)
            sleep.assert_called_once()
            self.assertEqual(stored.metadata["discovery"]["private_interface"], "ens10")

    def test_private_interface_configuration_uses_onlink_gateway_route(self) -> None:
        script = hetzner_create._configure_private_network_interface_script(
            public_ipv4="198.51.100.44",
            private_ipv4="10.42.19.20",
            private_cidr="10.42.19.0/24",
        )

        self.assertIn('ip addr replace "$private_ipv4/32" dev "$private_iface"', script)
        self.assertIn('ip route replace "$private_gateway/32"', script)
        self.assertIn('src "$private_ipv4" onlink', script)

    def test_private_network_add_subnet_uses_non_json_hcloud_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            calls: list[tuple[str, ...]] = []

            def fake_runner(argv: Sequence[str], **_: object) -> CommandResult:
                parts = tuple(argv)
                calls.append(parts)
                if parts == ("hcloud", "network", "describe", "wire-pair-a", "-o", "json"):
                    return _hcloud_result(
                        argv,
                        {
                            "network": {
                                "id": "network-303",
                                "name": "wire-pair-a",
                                "ip_range": "10.0.0.0/16",
                                "subnets": [],
                            }
                        },
                    )
                if parts[:3] == ("hcloud", "network", "add-subnet"):
                    return _hcloud_result(argv, {})
                if parts == ("hcloud", "network", "describe", "network-303", "-o", "json"):
                    return _hcloud_result(
                        argv,
                        {
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
                        },
                    )
                raise AssertionError(f"unexpected hcloud argv: {parts}")

            with _wire_env(Path(temp_dir)):
                output = hetzner_network._ensure_private_network(
                    provider="hetzner",
                    private_group="pair-a",
                    private_cidr="10.0.0.0/16",
                    network_zone="eu-central",
                    env={"HCLOUD_TOKEN": "token"},
                    command_runner=fake_runner,
                )

            self.assertFalse(output["created"])
            self.assertIn(
                (
                    "hcloud",
                    "network",
                    "add-subnet",
                    "network-303",
                    "--type",
                    "server",
                    "--network-zone",
                    "eu-central",
                    "--ip-range",
                    "10.0.0.0/16",
                ),
                calls,
            )


@contextmanager
def _patched_endpoint_helpers(
    discovered_interfaces: list[NetworkInterface] | None = None,
):
    with (
        mock.patch.object(hetzner_create, "_ensure_endpoint_key", return_value=None),
        mock.patch.object(hetzner_create, "wait_for_ssh", return_value=None),
        mock.patch.object(
            hetzner_create,
            "_configure_private_network_interface",
            return_value=None,
        ),
        mock.patch.object(
            hetzner_create,
            "discover_endpoint_interfaces",
            return_value=discovered_interfaces or _discovered_interfaces(),
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


def _private_discovered_interfaces() -> list[NetworkInterface]:
    return [
        NetworkInterface(
            name="eth0",
            exposure="private",
            ipv4="198.51.100.44",
            ipv6="2001:db8::44",
            mac="86:00:00:00:00:01",
            metadata={"source": "test", "default_route": True},
        ),
        NetworkInterface(
            name="ens10",
            exposure="private",
            ipv4="10.0.0.9",
            mac="86:00:00:00:00:09",
            metadata={"source": "test", "default_route": False},
        ),
    ]


def _wire_env(root: Path):
    return mock.patch.dict(
        os.environ,
        {
            "LIBCRAFTER_WIRE_STATE_ROOT": str(root / "wire-state"),
            "LIBCRAFTER_WIRE_ARTIFACT_ROOT": str(root / "wire-artifacts"),
        },
    )


class HetznerPrivateNetworkSubnetTest(unittest.TestCase):
    """Regression: real `hcloud network create` returns a subnet-less network,
    so `_ensure_private_network` must call `network add-subnet` and that action
    command must not carry `-o/--output` (the CLI rejects it)."""

    def test_add_subnet_called_without_output_flag(self) -> None:
        from tools.wire.engine.providers.hetzner.network import _ensure_private_network

        calls: list[tuple[str, ...]] = []

        def fake_runner(argv: Sequence[str], **_: object) -> CommandResult:
            parts = tuple(argv)
            calls.append(parts)

            def result(
                payload: dict[str, object] | None,
                *,
                exit_code: int = 0,
                stderr: str = "",
            ) -> CommandResult:
                return CommandResult(
                    argv=parts,
                    redacted_argv=parts,
                    cwd=None,
                    exit_code=exit_code,
                    stdout=json.dumps(payload) if payload is not None else "",
                    stderr=stderr,
                )

            if parts[:3] == ("hcloud", "network", "describe") and "wire-pair-a" in parts:
                return result(None, exit_code=1, stderr="network not found")
            if parts[:3] == ("hcloud", "network", "create"):
                return result(
                    {
                        "network": {
                            "id": "network-303",
                            "name": "wire-pair-a",
                            "ip_range": "10.0.0.0/16",
                            "subnets": [],
                        }
                    }
                )
            if parts[:3] == ("hcloud", "network", "add-subnet"):
                # action command: emits human-readable text, not JSON
                return result(None)
            if parts[:3] == ("hcloud", "network", "describe") and "network-303" in parts:
                return result(
                    {
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
                )
            raise AssertionError(f"unexpected hcloud argv: {parts}")

        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            outcome = _ensure_private_network(
                provider="hetzner",
                private_group="pair-a",
                private_cidr="10.0.0.0/16",
                network_zone="eu-central",
                env={},
                command_runner=fake_runner,
            )

        add_subnet_calls = [c for c in calls if c[:3] == ("hcloud", "network", "add-subnet")]
        self.assertEqual(len(add_subnet_calls), 1)
        add_subnet = add_subnet_calls[0]
        self.assertNotIn("-o", add_subnet)
        self.assertNotIn("--output", add_subnet)
        self.assertNotIn("json", add_subnet)
        self.assertEqual(
            add_subnet,
            (
                "hcloud",
                "network",
                "add-subnet",
                "network-303",
                "--type",
                "server",
                "--network-zone",
                "eu-central",
                "--ip-range",
                "10.0.0.0/16",
            ),
        )
        self.assertTrue(outcome["created"])


if __name__ == "__main__":
    unittest.main()
