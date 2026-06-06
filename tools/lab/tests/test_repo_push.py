"""Focused coverage for lab repository archive and push helpers."""

from __future__ import annotations

import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tools.lab.engine.model import LabCommandPlan, LabEndpoint, LabRole, LabSession
from tools.lab.engine.repo import (
    RepoBootstrapCommand,
    RepoBootstrapContext,
    RepoPushError,
    create_repository_archive,
    push_repository,
    push_repository_to_session,
)


class RepositoryArchiveTest(unittest.TestCase):
    def test_archive_excludes_build_output_and_provider_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "repo"
            _write(source / "Cargo.toml", "[workspace]\n")
            _write(source / "src" / "lib.rs", "pub fn ok() {}\n")
            _write(source / "target" / "debug" / "libcrafter.rlib", "build\n")
            _write(source / "tools" / "wire" / ".state" / "endpoint.json", "{}\n")
            _write(source / "tools" / "wire" / "artifacts" / "upload.log", "wire\n")
            _write(source / "tools" / "lab" / ".state" / "session.json", "{}\n")
            _write(source / "tools" / "lab" / "artifacts" / "repo.tar.gz", "lab\n")
            _write(source / "generated" / "case.json", "{}\n")

            result = create_repository_archive(root / "out", source_root=source)

            with tarfile.open(result.archive_path, "r:gz") as archive:
                names = archive.getnames()
            self.assertTrue(_has_tar_member(names, "Cargo.toml"))
            self.assertTrue(_has_tar_member(names, "src/lib.rs"))
            self.assertFalse(_has_tar_member(names, "target/debug/libcrafter.rlib"))
            self.assertFalse(_has_tar_member(names, "tools/endpoint/.state/endpoint.json"))
            self.assertFalse(_has_tar_member(names, "tools/endpoint/artifacts/upload.log"))
            self.assertFalse(_has_tar_member(names, "tools/lab/.state/session.json"))
            self.assertFalse(_has_tar_member(names, "tools/lab/artifacts/repo.tar.gz"))
            self.assertFalse(_has_tar_member(names, "generated/case.json"))
            self.assertEqual(result.command_record.operation, "lab.repo_archive")
            self.assertIn(str(result.archive_path), result.command_record.artifacts)
            self.assertIn("tools/lab/.state", result.command_record.metadata["exclude_patterns"])
            self.assertIn("tools/lab/artifacts", result.command_record.metadata["exclude_patterns"])


class RepositoryPushTest(unittest.TestCase):
    def test_push_uploads_unpacks_and_runs_role_bootstrap_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = root / "libcrafter-repo.tar.gz"
            archive.write_bytes(b"archive")
            client = _FakeWireClient()
            contexts: list[RepoBootstrapContext] = []

            def stimulus_bootstrap(context: RepoBootstrapContext) -> RepoBootstrapCommand:
                contexts.append(context)
                return RepoBootstrapCommand(
                    argv=[
                        "bash",
                        "-lc",
                        f"cd {context.remote_dir} && echo {context.role.name}",
                    ],
                    timeout=12,
                    metadata={"workload": "unit", "role": context.role.name},
                )

            result = push_repository_to_session(
                _session(),
                archive,
                client=client,
                bootstrap_commands={
                    "stimulus": stimulus_bootstrap,
                    "target": ["bash", "-lc", "echo target-bootstrap"],
                },
            )

            self.assertTrue(result.ok)
            self.assertEqual(result.remote_dir, "/opt/libcrafter-lab/session")
            self.assertEqual(result.remote_archive, "/opt/libcrafter-lab/libcrafter-repo.tar.gz")
            self.assertEqual(
                [(call["endpoint_id"], call["remote_path"]) for call in client.upload_calls],
                [
                    ("endpoint-stimulus", "/opt/libcrafter-lab/libcrafter-repo.tar.gz"),
                    ("endpoint-target", "/opt/libcrafter-lab/libcrafter-repo.tar.gz"),
                ],
            )
            self.assertEqual(len(client.exec_calls), 6)
            self.assertEqual(
                [call["command"][0:2] for call in client.exec_calls],
                [
                    ("bash", "-lc"),
                    ("bash", "-lc"),
                    ("bash", "-lc"),
                    ("bash", "-lc"),
                    ("bash", "-lc"),
                    ("bash", "-lc"),
                ],
            )
            unpack_scripts = [
                call["command"][2]
                for call in client.exec_calls
                if "tar -xzf" in call["command"][2]
            ]
            self.assertEqual(len(unpack_scripts), 2)
            self.assertIn("rm -rf /opt/libcrafter-lab/session", unpack_scripts[0])
            self.assertIn(
                "tar -xzf /opt/libcrafter-lab/libcrafter-repo.tar.gz "
                "-C /opt/libcrafter-lab/session",
                unpack_scripts[0],
            )
            self.assertEqual([context.role.name for context in contexts], ["stimulus"])
            self.assertEqual([peer.role for peer in contexts[0].peer_endpoints], ["target"])
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
            self.assertEqual(result.command_records[3].metadata["bootstrap"]["workload"], "unit")
            self.assertEqual(
                [endpoint["role"] for endpoint in result.endpoint_results],
                ["stimulus", "target"],
            )

    def test_push_repository_appends_archive_and_remote_command_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "repo"
            _write(source / "Cargo.toml", "[workspace]\n")
            _write(source / "src" / "lib.rs", "pub fn ok() {}\n")

            updated, result = push_repository(
                _session(),
                root / "out",
                source_root=source,
                client=_FakeWireClient(),
            )

            self.assertTrue(result.ok)
            self.assertEqual(updated.command_records[0].operation, "lab.repo_archive")
            self.assertEqual(len(updated.command_records), 7)
            self.assertEqual(
                updated.metadata["repository_push"]["remote_dir"],
                "/opt/libcrafter-lab/session",
            )

    def test_push_rejects_dry_run_sessions_and_root_remote_dir(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "repo.tar.gz"
            archive.write_bytes(b"archive")

            with self.assertRaisesRegex(RepoPushError, "live lab session"):
                push_repository_to_session(
                    _session(dry_run=True),
                    archive,
                    client=_FakeWireClient(),
                )
            with self.assertRaisesRegex(RepoPushError, "must not be /"):
                push_repository_to_session(
                    _session(remote_dir="/"),
                    archive,
                    client=_FakeWireClient(),
                )


class _FakeWireClient:
    def __init__(self) -> None:
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
        argv = ["tools/endpoint/run", "exec", endpoint_id, "--", *[str(part) for part in command]]
        self.exec_calls.append(
            {
                "endpoint_id": endpoint_id,
                "command": tuple(str(part) for part in command),
                "timeout": timeout,
                "argv": tuple(argv),
            }
        )
        return _FakeWireResponse(
            operation="exec",
            endpoint_id=endpoint_id,
            argv=argv,
        )

    def upload(
        self,
        endpoint_id: str,
        local_path: str | Path,
        remote_path: str,
    ) -> "_FakeWireResponse":
        argv = ["tools/endpoint/run", "upload", endpoint_id, str(local_path), remote_path]
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
        )


class _FakeWireResponse:
    def __init__(self, *, operation: str, endpoint_id: str, argv: list[str]) -> None:
        self.operation = operation
        self.endpoint_id = endpoint_id
        self.argv = argv
        self.ok = True
        self.exit_code = 0

    def command_plan(
        self,
        *,
        purpose: str | None = None,
        role: str | None = None,
        artifacts: list[str] = (),
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
            },
        )


def _session(*, dry_run: bool = False, remote_dir: str = "/opt/libcrafter-lab/session") -> LabSession:
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
        remote_dir=remote_dir,
        remote_artifact_root=f"{remote_dir.rstrip('/')}/artifacts",
        created_endpoint_ids=["endpoint-stimulus", "endpoint-target"],
        dry_run=dry_run,
    )


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _has_tar_member(names: list[str], relative_path: str) -> bool:
    wanted = relative_path.strip("/")
    return any(name.strip("./") == wanted for name in names)


if __name__ == "__main__":
    unittest.main()
