"""Fake-run coverage for wire endpoint transfers."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.wire.engine import cli as wire_cli
from tools.wire.engine.cli import (
    _ssh_info_output,
    collect_artifacts,
    download_endpoint,
    upload_endpoint,
)
from tools.wire.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResources,
)
from tools.wire.engine.process import CommandResult
from tools.wire.engine.state import write_endpoint_manifest


class WireTransferEndpointTest(unittest.TestCase):
    def test_upload_endpoint_builds_scp_argv_and_writes_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(root)
            local_path = root / "input.txt"
            local_path.write_text("request\n", encoding="utf-8")
            calls: list[tuple[str, ...]] = []

            def fake_runner(argv: list[str], **_: object) -> CommandResult:
                calls.append(tuple(argv))
                return CommandResult(
                    argv=tuple(argv),
                    redacted_argv=tuple(argv),
                    cwd=None,
                    exit_code=0,
                    stdout="upload stdout\n",
                    stderr="upload stderr\n",
                )

            result = upload_endpoint(
                manifest,
                local_path,
                "/tmp/request.json",
                runner=fake_runner,
            )

            self.assertEqual(result.exit_code, 0)
            self.assertEqual(
                calls,
                [
                    (
                        "scp",
                        "-i",
                        str(root / "state" / "id_ed25519"),
                        "-P",
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
                        str(local_path),
                        "ubuntu@198.51.100.20:/tmp/request.json",
                    )
                ],
            )
            self.assertEqual(
                (root / "artifacts" / "hetzner-wan-test" / "upload.stdout").read_text(
                    encoding="utf-8"
                ),
                "upload stdout\n",
            )
            self.assertEqual(
                (root / "artifacts" / "hetzner-wan-test" / "upload.stderr").read_text(
                    encoding="utf-8"
                ),
                "upload stderr\n",
            )
            report = json.loads(
                (root / "artifacts" / "hetzner-wan-test" / "upload.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(report["operation"], "upload")
            self.assertEqual(report["local_path"], str(local_path))
            self.assertEqual(report["remote_path"], "/tmp/request.json")

    def test_upload_endpoint_uses_virtualbox_manifest_ssh_details(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _virtualbox_manifest(root)
            local_path = root / "input.txt"
            local_path.write_text("request\n", encoding="utf-8")
            calls: list[tuple[str, ...]] = []

            def fake_runner(argv: list[str], **_: object) -> CommandResult:
                calls.append(tuple(argv))
                return CommandResult(
                    argv=tuple(argv),
                    redacted_argv=tuple(argv),
                    cwd=None,
                    exit_code=0,
                    stdout="upload stdout\n",
                    stderr="",
                )

            result = upload_endpoint(
                manifest,
                local_path,
                "/tmp/request.json",
                runner=fake_runner,
            )

            self.assertEqual(result.exit_code, 0)
            self.assertEqual(
                calls,
                [
                    (
                        "scp",
                        "-i",
                        str(root / "wire-state" / "endpoints" / "vbox-lan-test" / "id_ed25519"),
                        "-P",
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
                        str(local_path),
                        "ubuntu@127.0.0.1:/tmp/request.json",
                    )
                ],
            )

    def test_download_endpoint_builds_scp_argv_and_writes_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(root)
            local_path = root / "output" / "response.json"
            calls: list[tuple[str, ...]] = []

            def fake_runner(argv: list[str], **_: object) -> CommandResult:
                calls.append(tuple(argv))
                return CommandResult(
                    argv=tuple(argv),
                    redacted_argv=tuple(argv),
                    cwd=None,
                    exit_code=5,
                    stdout="download stdout\n",
                    stderr="download stderr\n",
                )

            result = download_endpoint(
                manifest,
                "/tmp/response.json",
                local_path,
                runner=fake_runner,
            )

            self.assertEqual(result.exit_code, 5)
            self.assertEqual(
                calls,
                [
                    (
                        "scp",
                        "-r",
                        "-i",
                        str(root / "state" / "id_ed25519"),
                        "-P",
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
                        "ubuntu@198.51.100.20:/tmp/response.json",
                        str(local_path),
                    )
                ],
            )
            self.assertEqual(
                (root / "artifacts" / "hetzner-wan-test" / "download.stdout").read_text(
                    encoding="utf-8"
                ),
                "download stdout\n",
            )
            report = json.loads(
                (root / "artifacts" / "hetzner-wan-test" / "download.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(report["operation"], "download")
            self.assertEqual(report["ok"], False)
            self.assertEqual(report["local_path"], str(local_path))
            self.assertEqual(report["remote_path"], "/tmp/response.json")

    def test_download_endpoint_uses_virtualbox_manifest_ssh_details(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _virtualbox_manifest(root)
            local_path = root / "output" / "response.json"
            calls: list[tuple[str, ...]] = []

            def fake_runner(argv: list[str], **_: object) -> CommandResult:
                calls.append(tuple(argv))
                return CommandResult(
                    argv=tuple(argv),
                    redacted_argv=tuple(argv),
                    cwd=None,
                    exit_code=0,
                    stdout="download stdout\n",
                    stderr="",
                )

            result = download_endpoint(
                manifest,
                "/tmp/response.json",
                local_path,
                runner=fake_runner,
            )

            self.assertEqual(result.exit_code, 0)
            self.assertEqual(
                calls,
                [
                    (
                        "scp",
                        "-r",
                        "-i",
                        str(root / "wire-state" / "endpoints" / "vbox-lan-test" / "id_ed25519"),
                        "-P",
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
                        "ubuntu@127.0.0.1:/tmp/response.json",
                        str(local_path),
                    )
                ],
            )

    def test_upload_endpoint_rejects_relative_local_path_before_running_scp(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = _manifest(Path(temp_dir))

            def fake_runner(argv: list[str], **_: object) -> CommandResult:
                self.fail(f"relative local path should not run scp: {argv}")

            with self.assertRaisesRegex(ValueError, "absolute local path"):
                upload_endpoint(
                    manifest,
                    "relative/path",
                    "/tmp/request.json",
                    runner=fake_runner,
                )

    def test_collect_artifacts_print_target_downloads_remote_into_artifact_dir(self) -> None:
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
                    stdout="artifact stdout\n",
                    stderr="artifact stderr\n",
                )

            output = collect_artifacts(
                manifest,
                "/var/tmp/wire/report.tar.gz",
                runner=fake_runner,
            )

            artifact_dir = root / "artifacts" / "hetzner-wan-test"
            self.assertEqual(output["artifact_dir"], str(artifact_dir))
            self.assertEqual(output["local_path"], str(artifact_dir / "report.tar.gz"))
            self.assertEqual(output["remote_path"], "/var/tmp/wire/report.tar.gz")
            self.assertEqual(output["collected"], True)
            self.assertEqual(
                calls[-1],
                (
                    "scp",
                    "-r",
                    "-i",
                    str(root / "state" / "id_ed25519"),
                    "-P",
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
                    "ubuntu@198.51.100.20:/var/tmp/wire/report.tar.gz",
                    str(artifact_dir / "report.tar.gz"),
                ),
            )

    def test_collect_artifacts_without_remote_creates_and_returns_artifact_dir(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(root)

            output = collect_artifacts(manifest)

            artifact_dir = root / "artifacts" / "hetzner-wan-test"
            self.assertEqual(output["artifact_dir"], str(artifact_dir))
            self.assertEqual(output["collected"], False)
            self.assertTrue(artifact_dir.is_dir())

    def test_ssh_info_output_includes_printable_command_and_connection_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(root)

            output = _ssh_info_output(manifest)

            self.assertEqual(output["host"], "198.51.100.20")
            self.assertEqual(output["port"], 2222)
            self.assertEqual(output["user"], "ubuntu")
            self.assertEqual(output["identity_file"], str(root / "state" / "id_ed25519"))
            self.assertEqual(output["known_hosts_file"], str(root / "state" / "known_hosts"))
            self.assertIn("ssh -i", output["ssh_command"])
            self.assertIn("ubuntu@198.51.100.20", output["ssh_command"])

    def test_ssh_info_and_list_endpoints_use_virtualbox_manifest_from_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _virtualbox_manifest(root)
            identity_file = str(
                root / "wire-state" / "endpoints" / "vbox-lan-test" / "id_ed25519"
            )
            known_hosts = str(
                root / "wire-state" / "endpoints" / "vbox-lan-test" / "known_hosts"
            )

            with _wire_env(root):
                write_endpoint_manifest(manifest)

                ssh_stdout = io.StringIO()
                with contextlib.redirect_stdout(ssh_stdout):
                    ssh_exit = wire_cli.main(["ssh-info", manifest.endpoint_id, "--json"])
                ssh_output = json.loads(ssh_stdout.getvalue())

                self.assertEqual(ssh_exit, 0)
                self.assertEqual(ssh_output["provider"], "virtualbox")
                self.assertEqual(ssh_output["exposure"], "lan")
                self.assertEqual(ssh_output["host"], "127.0.0.1")
                self.assertEqual(ssh_output["port"], 25222)
                self.assertEqual(ssh_output["user"], "ubuntu")
                self.assertEqual(ssh_output["identity_file"], identity_file)
                self.assertEqual(ssh_output["known_hosts_file"], known_hosts)
                self.assertEqual(
                    ssh_output["ssh"]["command"],
                    [
                        "ssh",
                        "-i",
                        identity_file,
                        "-p",
                        "25222",
                        "-o",
                        "StrictHostKeyChecking=accept-new",
                        "-o",
                        f"UserKnownHostsFile={known_hosts}",
                        "-o",
                        "ConnectTimeout=10",
                        "-o",
                        "ServerAliveInterval=5",
                        "-o",
                        "ServerAliveCountMax=2",
                        "ubuntu@127.0.0.1",
                    ],
                )

                list_stdout = io.StringIO()
                with contextlib.redirect_stdout(list_stdout):
                    list_exit = wire_cli.main(["list-endpoints", "--json"])
                list_output = json.loads(list_stdout.getvalue())

                self.assertEqual(list_exit, 0)
                self.assertEqual(len(list_output["endpoints"]), 1)
                endpoint = list_output["endpoints"][0]
                self.assertEqual(endpoint["endpoint_id"], "vbox-lan-test")
                self.assertEqual(endpoint["provider"], "virtualbox")
                self.assertEqual(endpoint["exposure"], "lan")
                self.assertEqual(endpoint["status"], "active")
                self.assertEqual(endpoint["ssh"]["host"], "127.0.0.1")
                self.assertEqual(endpoint["ssh"]["port"], 25222)


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
            metadata={"created_by": "tools/wire-test", "provider": "virtualbox"},
        ),
        artifact_dir=str(artifact_dir),
        metadata={
            "state_dir": str(endpoint_state_dir),
            "manifest_path": str(endpoint_state_dir / "endpoint.json"),
        },
    )


@contextlib.contextmanager
def _wire_env(root: Path):
    with mock.patch.dict(
        os.environ,
        {
            "LIBCRAFTER_WIRE_STATE_ROOT": str(root / "wire-state"),
            "LIBCRAFTER_WIRE_ARTIFACT_ROOT": str(root / "wire-artifacts"),
        },
        clear=False,
    ):
        yield


if __name__ == "__main__":
    unittest.main()
