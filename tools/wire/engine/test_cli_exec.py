"""Fake-run coverage for wire exec."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.wire.engine.cli import exec_endpoint
from tools.wire.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResources,
)
from tools.wire.engine.process import CommandResult


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
                        "ubuntu@198.51.100.20",
                        "printf",
                        "hello",
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


if __name__ == "__main__":
    unittest.main()
