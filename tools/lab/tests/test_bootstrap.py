"""Focused coverage for the provider-neutral lab bootstrap API."""

from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from tools.lab.engine.bootstrap import (
    BootstrapEnvArtifact,
    context_export_lines,
    render_workload_bootstrap_script,
)
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


class WorkloadBootstrapScriptHelperTest(unittest.TestCase):
    def test_render_workload_bootstrap_script_uses_unpacked_repo_context(self) -> None:
        context = _bootstrap_context("stimulus")

        script = render_workload_bootstrap_script(
            context,
            artifact_subdir=("probe", "bootstrap"),
            packages=["ca-certificates", "libpcap-dev"],
            install_rust=True,
            cargo_build_commands=[
                "cargo build -p probe-adapters --bin stimulus_endpoint",
            ],
            env_artifacts=[
                BootstrapEnvArtifact(
                    values={"repository_synced": "true"},
                    shell_values={
                        "role": "$LIBCRAFTER_ENDPOINT_ROLE",
                        "private_ipv4": "$LIBCRAFTER_PRIVATE_IPV4",
                        "peer_private_ipv4": "$LIBCRAFTER_PEER_PRIVATE_IPV4",
                        "finished_at": '$(date -u +"%Y-%m-%dT%H:%M:%SZ")',
                    },
                ),
            ],
        )
        lines = script.splitlines()

        self.assertEqual(lines[0], "set -euo pipefail")
        self.assertIn("cloud-init status --wait", lines[1])
        self.assertIn("cd /opt/libcrafter-lab/session", lines)
        self.assertLess(
            lines.index("cd /opt/libcrafter-lab/session"),
            lines.index("apt-get update"),
        )
        self.assertIn("export LIBCRAFTER_ENDPOINT_ROLE=stimulus", lines)
        self.assertIn("export LIBCRAFTER_PRIVATE_IPV4=10.77.0.10", lines)
        self.assertIn("export LIBCRAFTER_PEER_PRIVATE_IPV4=10.77.0.20", lines)
        self.assertIn("export LIBCRAFTER_PRIVATE_INTERFACE=eth1", lines)
        self.assertIn("export DEBIAN_FRONTEND=noninteractive", lines)
        self.assertIn(
            "export LIBCRAFTER_BOOTSTRAP_ARTIFACT_DIR="
            "/opt/libcrafter-lab/session/artifacts/probe/bootstrap/stimulus",
            lines,
        )
        self.assertIn('mkdir -p "$LIBCRAFTER_BOOTSTRAP_ARTIFACT_DIR"', lines)
        self.assertIn(
            "apt-get install -y --no-install-recommends "
            "ca-certificates libpcap-dev",
            lines,
        )
        self.assertIn(
            "if ! command -v cargo >/dev/null 2>&1; then "
            "curl -fsS https://sh.rustup.rs | sh -s -- -y --profile minimal; fi",
            lines,
        )
        self.assertIn(
            'if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi',
            lines,
        )
        self.assertIn(
            "cargo build -p probe-adapters --bin stimulus_endpoint",
            lines,
        )
        self.assertIn("  printf '%s\\n' repository_synced=true", lines)
        self.assertIn(
            '  printf \'%s\\n\' "role=$LIBCRAFTER_ENDPOINT_ROLE"',
            lines,
        )
        self.assertIn(
            "} > /opt/libcrafter-lab/session/artifacts/probe/bootstrap/"
            "stimulus/bootstrap.env",
            lines,
        )

        forbidden_fragments = [
            "rm -rf",
            "tar -xzf",
            "hcloud",
            "VBoxManage",
            "qemu-system",
            "tools/wire/run send",
            "tcpdump",
        ]
        for fragment in forbidden_fragments:
            self.assertNotIn(fragment, script)

    def test_context_exports_can_allow_missing_peer_for_supported_roles(self) -> None:
        session = LabSession(
            provider="qemu",
            wire_provider="qemu",
            wire_exposure="private",
            session_id="lab-smoke-solo",
            roles=[LabRole(name="observer")],
            endpoints=[
                LabEndpoint(
                    endpoint_id="endpoint-observer",
                    role="observer",
                    interface="eth1",
                    ipv4="10.77.0.30",
                    wire_manifest={"endpoint_id": "endpoint-observer"},
                ),
            ],
            remote_dir="/opt/libcrafter-lab/session",
            remote_artifact_root="/opt/libcrafter-lab/session/artifacts",
            created_endpoint_ids=["endpoint-observer"],
            dry_run=False,
        )
        context = RepoBootstrapContext(
            session=session,
            endpoint=session.endpoints[0],
            role=session.roles[0],
            remote_archive="/opt/libcrafter-lab/repo.tar.gz",
            remote_dir="/opt/libcrafter-lab/session",
            remote_artifact_root="/opt/libcrafter-lab/session/artifacts",
            endpoints_by_role={"observer": session.endpoints[0]},
        )

        with self.assertRaisesRegex(ValueError, "requires a peer endpoint"):
            context_export_lines(context)

        self.assertIn(
            "export LIBCRAFTER_PEER_PRIVATE_IPV4=''",
            context_export_lines(context, require_peer=False),
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


def _bootstrap_context(role: str) -> RepoBootstrapContext:
    session = _session()
    endpoints_by_role = {endpoint.role: endpoint for endpoint in session.endpoints}
    roles_by_name = {item.name: item for item in session.roles}
    return RepoBootstrapContext(
        session=session,
        endpoint=endpoints_by_role[role],
        role=roles_by_name[role],
        remote_archive="/opt/libcrafter-lab/repo.tar.gz",
        remote_dir="/opt/libcrafter-lab/session",
        remote_artifact_root="/opt/libcrafter-lab/session/artifacts",
        endpoints_by_role=endpoints_by_role,
    )


if __name__ == "__main__":
    unittest.main()
