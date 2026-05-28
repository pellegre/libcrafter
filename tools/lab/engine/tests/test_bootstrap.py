"""Focused coverage for the provider-neutral lab bootstrap API."""

from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from tools.lab.engine.model import LabCommandPlan, LabEndpoint, LabRole, LabSession
from tools.lab.engine.process import CommandResult
from tools.lab.engine.repo import (
    RepoBootstrapCommand,
    RepoBootstrapContext,
    RepoPushError,
    bootstrap_lab_session,
    session_with_bootstrap_records,
)


class LabBootstrapApiTest(unittest.TestCase):
    def test_bootstrap_uploads_archive_runs_role_commands_and_records_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = root / "repo.tar.gz"
            archive.write_bytes(b"archive")
            client = _FakeWireClient()
            contexts: list[RepoBootstrapContext] = []
            session = _session()

            def stimulus_bootstrap(context: RepoBootstrapContext) -> RepoBootstrapCommand:
                contexts.append(context)
                return RepoBootstrapCommand(
                    argv=[
                        "bash",
                        "-lc",
                        f"cd {context.remote_dir} && echo {context.peer_endpoints[0].ipv4}",
                    ],
                    timeout=11,
                    metadata={"workload": "oracle", "role": context.role.name},
                )

            result = bootstrap_lab_session(
                session,
                {
                    "stimulus": stimulus_bootstrap,
                    "target": ["bash", "-lc", "echo target-bootstrap"],
                },
                remote_dir="/opt/libcrafter-lab/session",
                archive=archive,
                output_dir=root / "bootstrap",
                client=client,
            )

            self.assertTrue(result.ok)
            self.assertEqual(result.remote_archive, "/opt/libcrafter-lab/repo.tar.gz")
            self.assertEqual(result.remote_dir, "/opt/libcrafter-lab/session")
            self.assertEqual(
                result.remote_artifact_root,
                "/opt/libcrafter-lab/session/artifacts",
            )
            self.assertEqual(
                [(call["endpoint_id"], call["remote_path"]) for call in client.upload_calls],
                [
                    ("endpoint-stimulus", "/opt/libcrafter-lab/repo.tar.gz"),
                    ("endpoint-target", "/opt/libcrafter-lab/repo.tar.gz"),
                ],
            )
            self.assertEqual(len(client.exec_calls), 6)
            self.assertEqual(
                [record.metadata["phase"] for record in result.command_records],
                [
                    "prepare-archive-directory",
                    "upload-repository",
                    "unpack-repository",
                    "workload-bootstrap",
                    "prepare-archive-directory",
                    "upload-repository",
                    "unpack-repository",
                    "workload-bootstrap",
                ],
            )
            self.assertEqual([context.role.name for context in contexts], ["stimulus"])
            self.assertEqual([peer.role for peer in contexts[0].peer_endpoints], ["target"])
            self.assertEqual(
                result.command_records[3].metadata["bootstrap"]["workload"],
                "oracle",
            )
            self.assertTrue(
                all(Path(artifact).exists() for artifact in result.command_records[3].artifacts)
            )
            self.assertIn(str(root / "bootstrap" / "lab-bootstrap-result.json"), result.artifacts)
            self.assertEqual(
                [endpoint["role"] for endpoint in result.endpoint_results],
                ["stimulus", "target"],
            )

            updated = session_with_bootstrap_records(session, result)
            self.assertEqual(len(updated.command_records), len(result.command_records))
            self.assertTrue(updated.metadata["lab_bootstrap"]["ok"])

    def test_bootstrap_surfaces_role_command_failure_in_structured_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = root / "repo.tar.gz"
            archive.write_bytes(b"archive")
            client = _FakeWireClient(fail_bootstrap_endpoint="endpoint-target")

            result = bootstrap_lab_session(
                _session(),
                {
                    "stimulus": ["bash", "-lc", "echo stimulus-bootstrap"],
                    "target": ["bash", "-lc", "echo target-bootstrap"],
                },
                remote_dir="/opt/libcrafter-lab/session",
                archive=archive,
                output_dir=root / "bootstrap",
                client=client,
            )

            self.assertFalse(result.ok)
            self.assertIn(
                "run workload bootstrap failed for endpoint-target: bootstrap failed",
                result.errors,
            )
            self.assertTrue(result.endpoint_results[0]["ok"])
            self.assertFalse(result.endpoint_results[1]["ok"])
            target_bootstrap = [
                record
                for record in result.command_records
                if record.role == "target"
                and record.metadata["phase"] == "workload-bootstrap"
            ][0]
            self.assertFalse(target_bootstrap.metadata["ok"])
            report_path = next(
                Path(artifact)
                for artifact in target_bootstrap.artifacts
                if artifact.endswith(".json")
            )
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertFalse(report["ok"])
            self.assertEqual(report["error"], "bootstrap failed")

    def test_bootstrap_rejects_dry_run_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = root / "repo.tar.gz"
            archive.write_bytes(b"archive")

            with self.assertRaisesRegex(RepoPushError, "live lab session"):
                bootstrap_lab_session(
                    _session(dry_run=True),
                    {"stimulus": ["true"], "target": ["true"]},
                    remote_dir="/opt/libcrafter-lab/session",
                    archive=archive,
                    output_dir=root / "bootstrap",
                    client=_FakeWireClient(),
                )


class _FakeWireClient:
    def __init__(self, *, fail_bootstrap_endpoint: str | None = None) -> None:
        self.fail_bootstrap_endpoint = fail_bootstrap_endpoint
        self.exec_calls: list[dict[str, Any]] = []
        self.upload_calls: list[dict[str, Any]] = []

    def exec(
        self,
        endpoint_id: str,
        command: object,
        *,
        timeout: float | None = None,
    ) -> "_FakeWireResponse":
        if not isinstance(command, (list, tuple)):
            raise TypeError("expected command sequence")
        command_parts = tuple(str(part) for part in command)
        argv = ["tools/wire/run", "exec", endpoint_id, "--", *command_parts]
        self.exec_calls.append(
            {
                "endpoint_id": endpoint_id,
                "command": command_parts,
                "timeout": timeout,
                "argv": tuple(argv),
            }
        )
        failure = (
            self.fail_bootstrap_endpoint == endpoint_id
            and "target-bootstrap" in " ".join(command_parts)
        )
        return _FakeWireResponse(
            operation="exec",
            endpoint_id=endpoint_id,
            argv=argv,
            exit_code=7 if failure else 0,
            stdout="" if failure else f"{endpoint_id}:ok\n",
            stderr="bootstrap failed\n" if failure else "",
            error="bootstrap failed" if failure else None,
        )

    def upload(
        self,
        endpoint_id: str,
        local_path: str | Path,
        remote_path: str,
    ) -> "_FakeWireResponse":
        argv = ["tools/wire/run", "upload", endpoint_id, str(local_path), remote_path]
        self.upload_calls.append(
            {
                "endpoint_id": endpoint_id,
                "local_path": str(local_path),
                "remote_path": remote_path,
                "argv": tuple(argv),
            }
        )
        return _FakeWireResponse(
            operation="upload",
            endpoint_id=endpoint_id,
            argv=argv,
            stdout=f"uploaded {local_path}\n",
        )


class _FakeWireResponse:
    def __init__(
        self,
        *,
        operation: str,
        endpoint_id: str,
        argv: list[str],
        exit_code: int = 0,
        stdout: str = "",
        stderr: str = "",
        error: str | None = None,
    ) -> None:
        self.operation = operation
        self.endpoint_id = endpoint_id
        self.argv = argv
        self.result = CommandResult(
            argv=tuple(argv),
            redacted_argv=tuple(argv),
            cwd=None,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            error=error,
        )
        self.ok = self.result.ok
        self.exit_code = self.result.exit_code

    def command_plan(
        self,
        *,
        purpose: str | None = None,
        role: str | None = None,
        artifacts: Sequence[str] = (),
    ) -> LabCommandPlan:
        return LabCommandPlan(
            purpose=purpose or f"wire {self.operation}",
            role=role,
            argv=self.argv,
            operation=f"wire.{self.operation}",
            dry_run=False,
            live_mutation=True,
            artifacts=list(artifacts),
            metadata={
                "endpoint_id": self.endpoint_id,
                "operation": self.operation,
                "ok": self.ok,
                "exit_code": self.exit_code,
                "error": self.result.error,
            },
        )


def _session(*, dry_run: bool = False) -> LabSession:
    return LabSession(
        provider="qemu",
        wire_provider="qemu",
        wire_exposure="private",
        session_id="lab-smoke-0001",
        roles=[
            LabRole(name="stimulus", peer_roles=["target"]),
            LabRole(name="target", peer_roles=["stimulus"]),
        ],
        endpoints=[
            LabEndpoint(
                endpoint_id="endpoint-stimulus",
                role="stimulus",
                interface="eth1",
                ipv4="10.77.0.10",
                peer_addresses={"target": {"ipv4": "10.77.0.20"}},
                wire_manifest={"endpoint_id": "endpoint-stimulus"},
            ),
            LabEndpoint(
                endpoint_id="endpoint-target",
                role="target",
                interface="eth1",
                ipv4="10.77.0.20",
                peer_addresses={"stimulus": {"ipv4": "10.77.0.10"}},
                wire_manifest={"endpoint_id": "endpoint-target"},
            ),
        ],
        remote_dir="/opt/libcrafter-lab/session",
        remote_artifact_root="/opt/libcrafter-lab/session/artifacts",
        created_endpoint_ids=["endpoint-stimulus", "endpoint-target"],
        dry_run=dry_run,
    )


if __name__ == "__main__":
    unittest.main()
