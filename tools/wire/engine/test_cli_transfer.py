"""Fake-run coverage for wire endpoint transfers."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

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
