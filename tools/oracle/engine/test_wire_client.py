"""Unit coverage for the oracle wire client."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.oracle.engine import wire_client
from tools.wire.engine.process import CommandResult


class WireClientTest(unittest.TestCase):
    def test_default_wire_path_points_to_run_entrypoint(self) -> None:
        wire_path = wire_client.default_wire_path()

        self.assertEqual(wire_path.name, "run")
        self.assertEqual(wire_path.parent.name, "wire")
        self.assertTrue(wire_path.is_file())

    def test_create_uses_absolute_wire_path_and_parses_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            calls: list[tuple[tuple[str, ...], str | None, float | None]] = []

            def fake_runner(argv: list[str], **kwargs: object) -> CommandResult:
                calls.append(
                    (
                        tuple(argv),
                        kwargs.get("cwd") if isinstance(kwargs.get("cwd"), str) else None,
                        kwargs.get("timeout") if isinstance(kwargs.get("timeout"), float) else None,
                    )
                )
                return CommandResult(
                    argv=tuple(argv),
                    redacted_argv=tuple(argv),
                    cwd=kwargs.get("cwd") if isinstance(kwargs.get("cwd"), str) else None,
                    exit_code=0,
                    stdout=json.dumps(_manifest(root)),
                    stderr="",
                    timeout=kwargs.get("timeout") if isinstance(kwargs.get("timeout"), float) else None,
                )

            client = wire_client.WireClient(runner=fake_runner, timeout=12.5)
            response = client.create(
                provider="hetzner",
                exposure="wan",
                role="oracle",
                dry_run=True,
            )

            self.assertIsNotNone(response.manifest)
            assert response.manifest is not None
            self.assertEqual(response.manifest.endpoint_id, "hetzner-wan-test")
            self.assertEqual(response.manifest.ssh.host, "198.51.100.20")
            self.assertEqual(
                calls,
                [
                    (
                        (
                            str(wire_client.default_wire_path()),
                            "create-endpoint",
                            "--provider",
                            "hetzner",
                            "--exposure",
                            "wan",
                            "--role",
                            "oracle",
                            "--json",
                            "--dry-run",
                            "--write-manifest",
                        ),
                        str(wire_client.repo_root()),
                        12.5,
                    )
                ],
            )
            metadata = response.metadata()
            self.assertEqual(metadata["operation"], "create-endpoint")
            self.assertEqual(metadata["wire_path"], str(wire_client.default_wire_path()))
            self.assertEqual(metadata["endpoint_id"], "hetzner-wan-test")
            self.assertTrue(Path(str(metadata["wire_path"])).is_absolute())

    def test_stream_helpers_record_command_metadata_without_json(self) -> None:
        calls: list[tuple[str, ...]] = []

        def fake_runner(argv: list[str], **kwargs: object) -> CommandResult:
            calls.append(tuple(argv))
            return CommandResult(
                argv=tuple(argv),
                redacted_argv=tuple(argv),
                cwd=kwargs.get("cwd") if isinstance(kwargs.get("cwd"), str) else None,
                exit_code=3,
                stdout="remote stdout\n",
                stderr="remote stderr\n",
            )

        client = wire_client.WireClient(runner=fake_runner)
        response = client.exec("endpoint-1", ["printf", "hello"])

        self.assertEqual(response.exit_code, 3)
        self.assertIsNone(response.json_data)
        self.assertEqual(
            calls,
            [
                (
                    str(wire_client.default_wire_path()),
                    "exec",
                    "endpoint-1",
                    "--",
                    "printf",
                    "hello",
                )
            ],
        )
        self.assertEqual(response.record.stdout_bytes, len("remote stdout\n".encode("utf-8")))
        self.assertEqual(response.record.stderr_bytes, len("remote stderr\n".encode("utf-8")))
        self.assertEqual(response.metadata()["command"], " ".join(calls[0]))

    def test_transfer_helpers_resolve_local_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            local = root / "payload.bin"
            local.write_text("payload", encoding="utf-8")
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

            client = wire_client.WireClient(runner=fake_runner)
            client.upload("endpoint-1", local, "/tmp/payload.bin")
            client.download("endpoint-1", "/tmp/result.bin", root / "result.bin")

            self.assertEqual(
                calls,
                [
                    (
                        str(wire_client.default_wire_path()),
                        "upload",
                        "endpoint-1",
                        str(local.resolve()),
                        "/tmp/payload.bin",
                    ),
                    (
                        str(wire_client.default_wire_path()),
                        "download",
                        "endpoint-1",
                        "/tmp/result.bin",
                        str((root / "result.bin").resolve()),
                    ),
                ],
            )

    def test_ssh_info_parses_json_object(self) -> None:
        def fake_runner(argv: list[str], **kwargs: object) -> CommandResult:
            return CommandResult(
                argv=tuple(argv),
                redacted_argv=tuple(argv),
                cwd=kwargs.get("cwd") if isinstance(kwargs.get("cwd"), str) else None,
                exit_code=0,
                stdout=json.dumps(
                    {
                        "endpoint_id": "endpoint-1",
                        "host": "198.51.100.20",
                        "user": "ubuntu",
                    }
                ),
                stderr="",
            )

        response = wire_client.WireClient(runner=fake_runner).ssh_info("endpoint-1")

        self.assertEqual(response.json_data["host"], "198.51.100.20")
        self.assertEqual(response.record.operation, "ssh-info")

    def test_invalid_json_raises_client_error(self) -> None:
        def fake_runner(argv: list[str], **_: object) -> CommandResult:
            return CommandResult(
                argv=tuple(argv),
                redacted_argv=tuple(argv),
                cwd=None,
                exit_code=0,
                stdout="not-json",
                stderr="",
            )

        with self.assertRaises(wire_client.WireClientError):
            wire_client.WireClient(runner=fake_runner).ssh_info("endpoint-1")


def _manifest(root: Path) -> dict[str, object]:
    return {
        "endpoint_id": "hetzner-wan-test",
        "provider": "hetzner",
        "exposure": "wan",
        "status": "active",
        "role": "oracle",
        "created_at": "2026-05-25T00:00:00Z",
        "ssh": {
            "host": "198.51.100.20",
            "user": "ubuntu",
            "port": 22,
            "identity_file": str(root / "id_ed25519"),
            "known_hosts_file": str(root / "known_hosts"),
        },
        "interfaces": [
            {
                "name": "public",
                "exposure": "wan",
                "ipv4": "198.51.100.20",
            }
        ],
        "provider_resources": {
            "resources": [],
            "cleanup_order": [],
        },
        "artifact_dir": str(root / "artifacts" / "hetzner-wan-test"),
    }


if __name__ == "__main__":
    unittest.main()
