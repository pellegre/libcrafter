"""Fake-run coverage for endpoint exec."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.endpoint.engine.cli import exec_endpoint
from tools.endpoint.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResources,
)
from tools.endpoint.engine.process import CommandResult


class WireExecEndpointTest(unittest.TestCase):
    def test_exec_endpoint_builds_ssh_argv_and_writes_artifacts(self) -> None:
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
                    exit_code=7,
                    stdout="remote stdout\n",
                    stderr="remote stderr\n",
                )

            result = exec_endpoint(
                manifest,
                ["--", "printf", "hello"],
                runner=fake_runner,
            )

            self.assertEqual(result.exit_code, 7)
            self.assertEqual(
                calls,
                [
                    (
                        "ssh",
                        "-i",
                        str(root / "state" / "id_ed25519"),
                        "-p",
                        "2222",
                        "-o",
                        "StrictHostKeyChecking=accept-new",
                        "-o",
                        f"UserKnownHostsFile={root / 'state' / 'known_hosts'}",
                        "-o",
                        "ConnectTimeout=10",
                        "-o",
                        "ServerAliveInterval=5",
                        "-o",
                        "ServerAliveCountMax=2",
                        "ubuntu@198.51.100.20",
                        "printf hello",
                    )
                ],
            )
            self.assertEqual(
                (root / "artifacts" / "hetzner-wan-test" / "stdout").read_text(
                    encoding="utf-8"
                ),
                "remote stdout\n",
            )
            self.assertEqual(
                (root / "artifacts" / "hetzner-wan-test" / "stderr").read_text(
                    encoding="utf-8"
                ),
                "remote stderr\n",
            )

    def test_exec_endpoint_uses_virtualbox_manifest_ssh_details(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _virtualbox_manifest(root)
            calls: list[tuple[str, ...]] = []

            def fake_runner(argv: list[str], **_: object) -> CommandResult:
                calls.append(tuple(argv))
                return CommandResult(
                    argv=tuple(argv),
                    redacted_argv=tuple(argv),
                    cwd=None,
                    exit_code=0,
                    stdout="virtualbox stdout\n",
                    stderr="",
                )

            result = exec_endpoint(
                manifest,
                ["--", "ip", "-brief", "addr"],
                runner=fake_runner,
            )

            self.assertEqual(result.exit_code, 0)
            self.assertEqual(
                calls,
                [
                    (
                        "ssh",
                        "-i",
                        str(root / "wire-state" / "endpoints" / "vbox-lan-test" / "id_ed25519"),
                        "-p",
                        "25222",
                        "-o",
                        "StrictHostKeyChecking=accept-new",
                        "-o",
                        "UserKnownHostsFile="
                        f"{root / 'wire-state' / 'endpoints' / 'vbox-lan-test' / 'known_hosts'}",
                        "-o",
                        "ConnectTimeout=10",
                        "-o",
                        "ServerAliveInterval=5",
                        "-o",
                        "ServerAliveCountMax=2",
                        "ubuntu@127.0.0.1",
                        "ip -brief addr",
                    )
                ],
            )
            self.assertEqual(
                (root / "wire-artifacts" / "vbox-lan-test" / "stdout").read_text(
                    encoding="utf-8"
                ),
                "virtualbox stdout\n",
            )

    def test_exec_endpoint_preserves_bash_script_argument_grouping(self) -> None:
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

            exec_endpoint(
                manifest,
                ["--", "bash", "-lc", "mkdir -p /root"],
                runner=fake_runner,
            )

            self.assertEqual(calls[0][-1], "bash -lc 'mkdir -p /root'")

def _manifest(root: Path) -> EndpointManifest:
    return EndpointManifest(
        endpoint_id="hetzner-wan-test",
        provider="hetzner",
        exposure="wan",
        status="active",
        role="test",
        created_at="2026-05-25T00:00:00Z",
        ssh=EndpointSSHInfo(
            host="198.51.100.20",
            user="ubuntu",
            port=2222,
            identity_file=str(root / "state" / "id_ed25519"),
            known_hosts_file=str(root / "state" / "known_hosts"),
        ),
        interfaces=[NetworkInterface(name="public", exposure="wan", ipv4="198.51.100.20")],
        provider_resources=ProviderResources(),
        artifact_dir=str(root / "artifacts" / "hetzner-wan-test"),
    )


def _virtualbox_manifest(root: Path) -> EndpointManifest:
    endpoint_id = "vbox-lan-test"
    endpoint_state_dir = root / "wire-state" / "endpoints" / endpoint_id
    artifact_dir = root / "wire-artifacts" / endpoint_id
    return EndpointManifest(
        endpoint_id=endpoint_id,
        provider="virtualbox",
        exposure="lan",
        status="active",
        role="test",
        created_at="2026-05-26T00:00:00Z",
        ssh=EndpointSSHInfo(
            host="127.0.0.1",
            user="ubuntu",
            port=25222,
            identity_file=str(endpoint_state_dir / "id_ed25519"),
            known_hosts_file=str(endpoint_state_dir / "known_hosts"),
        ),
        interfaces=[
            NetworkInterface(
                name="control",
                exposure="nat",
                ipv4="10.0.2.15",
                metadata={"purpose": "ssh"},
            ),
            NetworkInterface(
                name="enp0s8",
                exposure="lan",
                ipv4="192.168.1.77",
                mac="08:00:27:aa:bb:cc",
                metadata={"purpose": "packet"},
            ),
        ],
        provider_resources=ProviderResources(
            metadata={"created_by": "tools/endpoint-test", "provider": "virtualbox"},
        ),
        artifact_dir=str(artifact_dir),
        metadata={
            "state_dir": str(endpoint_state_dir),
            "manifest_path": str(endpoint_state_dir / "endpoint.json"),
        },
    )


if __name__ == "__main__":
    unittest.main()
