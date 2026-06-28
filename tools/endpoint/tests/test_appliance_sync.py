"""Coverage for endpoint appliance workspace sync planning and fake execution."""

from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path

from tools.endpoint.engine.appliance import (
    DEFAULT_APPLIANCE_SYNC_ARTIFACT_DIRNAME,
    EndpointApplianceSyncTransferPlan,
    render_endpoint_appliance_sync_plan,
    resolve_endpoint_appliance_target,
    sync_endpoint_appliance_workspace,
)
from tools.endpoint.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResource,
    ProviderResources,
)
from tools.endpoint.engine.process import CommandResult


class EndpointApplianceSyncTest(unittest.TestCase):
    def test_sync_plan_validates_paths_and_names(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = _workspace(root)
            target = resolve_endpoint_appliance_target(_manifest(root))

            with self.assertRaisesRegex(ValueError, "source_root does not exist"):
                render_endpoint_appliance_sync_plan(
                    target,
                    source_root=root / "missing",
                    run_id="run-a",
                )
            with self.assertRaisesRegex(ValueError, "run_id must be a single remote path component"):
                render_endpoint_appliance_sync_plan(
                    target,
                    source_root=source,
                    run_id="bad/run",
                )
            with self.assertRaisesRegex(ValueError, "archive_name must be a single filename"):
                render_endpoint_appliance_sync_plan(
                    target,
                    source_root=source,
                    run_id="run-a",
                    archive_name="../workspace.tar.gz",
                )

    def test_archive_plan_ignores_build_outputs_and_sensitive_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = _workspace(root)
            target = resolve_endpoint_appliance_target(_manifest(root))

            plan = render_endpoint_appliance_sync_plan(
                target,
                source_root=source,
                run_id="run-a",
            )

        self.assertIn(".git", plan.archive_excludes)
        self.assertIn("target", plan.archive_excludes)
        self.assertIn("tools/endpoint/.state", plan.archive_excludes)
        self.assertIn("--exclude=.git", plan.archive_command_argv)
        self.assertIn("--exclude=target", plan.archive_command_argv)
        self.assertEqual(plan.archive_command_argv[:3], ["tar", "-C", str(source)])
        json.loads(plan.to_json())

    def test_sync_plan_uses_deterministic_per_run_remote_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = _workspace(root)
            target = resolve_endpoint_appliance_target(
                _manifest(
                    root,
                    metadata={
                        "appliance": {
                            "remote_work_root": "/srv/libcrafter/work",
                            "remote_artifact_root": "/srv/libcrafter/artifacts",
                        }
                    },
                )
            )

            plan = render_endpoint_appliance_sync_plan(
                target,
                source_root=source,
                run_id="stable-run",
            )

        self.assertFalse(plan.executes)
        self.assertEqual(plan.remote_run_root, "/srv/libcrafter/work/runs/stable-run")
        self.assertEqual(
            plan.remote_workspace_dir,
            "/srv/libcrafter/work/runs/stable-run/workspace",
        )
        self.assertEqual(
            plan.remote_artifact_dir,
            "/srv/libcrafter/artifacts/runs/stable-run",
        )
        self.assertEqual(
            plan.remote_archive_path,
            "/srv/libcrafter/work/runs/stable-run/workspace.tar.gz",
        )
        self.assertTrue(
            plan.local_archive_path.endswith(
                f"{DEFAULT_APPLIANCE_SYNC_ARTIFACT_DIRNAME}/stable-run/workspace.tar.gz"
            )
        )
        self.assertEqual(
            [command.kind for command in plan.commands],
            [
                "ssh-appliance-sync-mkdir",
                "ssh-appliance-sync-upload",
                "ssh-appliance-sync-unpack",
            ],
        )
        self.assertTrue(all(not command.executes for command in plan.commands))

    def test_sync_execution_uses_fake_runner_and_records_upload_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = _workspace(root)
            target = resolve_endpoint_appliance_target(_manifest(root))
            runner = RecordingRunner()

            result = sync_endpoint_appliance_workspace(
                target,
                source_root=source,
                run_id="run-a",
                runner=runner,
                timeout=15.0,
            )

            artifact_dir = (
                root
                / "artifacts"
                / "endpoint-a"
                / DEFAULT_APPLIANCE_SYNC_ARTIFACT_DIRNAME
                / "run-a"
            )
            upload_plan = result.plan.commands[1]
            self.assertIsInstance(upload_plan, EndpointApplianceSyncTransferPlan)
            self.assertTrue(Path(result.command_results[2].stdout_path).is_file())
            self.assertEqual(Path(result.command_results[2].stdout_path).read_text(), "scp\n")

        self.assertTrue(result.ok)
        self.assertEqual(
            [record.kind for record in result.command_results],
            [
                "local-appliance-sync-archive",
                "ssh-appliance-sync-mkdir",
                "ssh-appliance-sync-upload",
                "ssh-appliance-sync-unpack",
            ],
        )
        self.assertEqual([call[0] for call in runner.calls], ["tar", "ssh", "scp", "ssh"])
        self.assertIn("--exclude=.git", runner.calls[0])
        self.assertIn("--exclude=target", runner.calls[0])
        self.assertEqual(runner.kwargs[0]["cwd"], str(source))
        self.assertEqual(runner.kwargs[2]["timeout"], 15.0)
        self.assertIn(
            f"root@192.0.2.10:{result.plan.remote_archive_path}",
            runner.calls[2],
        )
        self.assertTrue(result.artifact_dir.endswith(str(artifact_dir)))
        json.loads(result.to_json())


class RecordingRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.kwargs: list[dict[str, object]] = []

    def __call__(self, argv: Sequence[object], **kwargs: object) -> CommandResult:
        normalized = tuple(str(part) for part in argv)
        self.calls.append(normalized)
        self.kwargs.append(dict(kwargs))
        return CommandResult(
            argv=normalized,
            redacted_argv=normalized,
            cwd=str(kwargs.get("cwd")) if kwargs.get("cwd") is not None else None,
            exit_code=0,
            stdout=f"{normalized[0]}\n",
            stderr="",
            timeout=kwargs.get("timeout") if isinstance(kwargs.get("timeout"), float) else None,
        )


def _workspace(root: Path) -> Path:
    source = root / "workspace"
    (source / ".git").mkdir(parents=True)
    (source / "target").mkdir()
    (source / "src").mkdir()
    (source / "src" / "lib.rs").write_text("// synthetic\n", encoding="utf-8")
    return source


def _manifest(
    root: Path,
    *,
    metadata: dict[str, object] | None = None,
) -> EndpointManifest:
    endpoint_id = "endpoint-a"
    return EndpointManifest(
        endpoint_id=endpoint_id,
        provider="qemu",
        exposure="private",
        status="active",
        role="probe",
        created_at="2026-06-28T00:00:00Z",
        ssh=EndpointSSHInfo(
            host="192.0.2.10",
            user="root",
            port=2201,
            identity_file=str(root / "state" / endpoint_id / "id_ed25519"),
            known_hosts_file=str(root / "state" / endpoint_id / "known_hosts"),
            metadata={"created_by": "tools/endpoint-test"},
        ),
        interfaces=[
            NetworkInterface(
                name="eth0",
                exposure="private",
                ipv4="192.0.2.10",
                metadata={"synthetic": True},
            )
        ],
        provider_resources=ProviderResources(
            resources=[
                ProviderResource(
                    kind="qemu-vm",
                    provider_id="qemu-endpoint-a",
                    cleanup=True,
                    metadata={"synthetic": True},
                )
            ],
            metadata={"synthetic": True},
        ),
        artifact_dir=str(root / "artifacts" / endpoint_id),
        metadata={} if metadata is None else metadata,
    )


if __name__ == "__main__":
    unittest.main()
