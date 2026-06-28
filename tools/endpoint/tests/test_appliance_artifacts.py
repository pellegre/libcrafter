"""Coverage for endpoint appliance artifact collection helpers."""

from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path

from tools.appliance.engine.profile import ApplianceProfile
from tools.endpoint.engine.appliance import (
    DEFAULT_APPLIANCE_REMOTE_ARTIFACT_DIRNAME,
    DEFAULT_APPLIANCE_RUN_ARTIFACT_DIRNAME,
    DEFAULT_APPLIANCE_RUN_MANIFEST_NAME,
    collect_endpoint_appliance_run_artifacts,
    resolve_endpoint_appliance_target,
    run_endpoint_appliance_command,
)
from tools.endpoint.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResource,
    ProviderResources,
)
from tools.endpoint.engine.process import CommandResult


class EndpointApplianceArtifactsTest(unittest.TestCase):
    def test_no_remote_artifacts_writes_manifest_without_download(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = _run_result(Path(temp_dir))
            runner = ArtifactRunner()

            output = collect_endpoint_appliance_run_artifacts(
                result,
                remote_artifact_root=None,
                runner=runner,
            )

            manifest = json.loads(
                Path(output["manifest_path"]).read_text(encoding="utf-8")  # type: ignore[arg-type]
            )

        self.assertTrue(output["ok"])
        self.assertEqual(runner.calls, [])
        self.assertFalse(output["collection"]["requested"])  # type: ignore[index]
        self.assertEqual(output["collection"]["reason"], "no-remote-artifact-root")  # type: ignore[index]
        self.assertEqual(manifest["collection"]["attempted"], False)
        json.dumps(output)

    def test_successful_fake_download_collects_remote_artifact_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            result = _run_result(root)
            runner = ArtifactRunner()

            output = collect_endpoint_appliance_run_artifacts(result, runner=runner)

            artifact_dir = Path(str(output["artifact_dir"]))
            remote_artifact_dir = artifact_dir / DEFAULT_APPLIANCE_REMOTE_ARTIFACT_DIRNAME
            manifest = json.loads(
                (artifact_dir / DEFAULT_APPLIANCE_RUN_MANIFEST_NAME).read_text(encoding="utf-8")
            )
            run_stdout = (artifact_dir / "run.stdout.txt").read_text(encoding="utf-8")
            remote_report = remote_artifact_dir.joinpath("remote-report.txt").read_text(
                encoding="utf-8"
            )

        self.assertTrue(output["ok"])
        self.assertEqual([call[0] for call in runner.calls], ["scp"])
        self.assertEqual(remote_report, "artifact\n")
        self.assertEqual(run_stdout, "container stdout\n")
        self.assertEqual(output["collection"]["local_path"], str(remote_artifact_dir))  # type: ignore[index]
        self.assertEqual(manifest["collection"]["collected"], True)
        self.assertEqual(manifest["artifacts"]["run_stdout"], str(artifact_dir / "run.stdout.txt"))

    def test_failed_download_is_reported_and_captured(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = _run_result(Path(temp_dir))
            runner = ArtifactRunner(exit_code=23, stderr="scp failed\n")

            output = collect_endpoint_appliance_run_artifacts(result, runner=runner)

            artifact_dir = Path(str(output["artifact_dir"]))
            manifest = json.loads(
                (artifact_dir / DEFAULT_APPLIANCE_RUN_MANIFEST_NAME).read_text(encoding="utf-8")
            )
            stderr = Path(str(output["collection"]["stderr_path"])).read_text(  # type: ignore[index]
                encoding="utf-8"
            )

        self.assertFalse(output["ok"])
        self.assertEqual(output["collection"]["attempted"], True)  # type: ignore[index]
        self.assertEqual(output["collection"]["exit_code"], 23)  # type: ignore[index]
        self.assertEqual(stderr, "scp failed\n")
        self.assertEqual(manifest["collection"]["ok"], False)

    def test_json_manifest_shape_reports_collection_and_cleanup_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = _run_result(Path(temp_dir))
            runner = ArtifactRunner()

            output = collect_endpoint_appliance_run_artifacts(
                result,
                runner=runner,
                cleanup_remote=True,
                timeout=12.0,
            )

            artifact_dir = Path(str(output["artifact_dir"]))
            manifest_path = artifact_dir / DEFAULT_APPLIANCE_RUN_MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertTrue(output["ok"])
        self.assertEqual([call[0] for call in runner.calls], ["scp", "ssh"])
        self.assertEqual(runner.kwargs[0]["timeout"], 12.0)
        self.assertEqual(manifest["kind"], "endpoint-appliance-run-artifacts")
        self.assertEqual(manifest["endpoint_id"], "endpoint-a")
        self.assertEqual(manifest["manifest_path"], str(manifest_path))
        self.assertEqual(manifest["run"]["profile"], "lan-raw")
        self.assertEqual(manifest["collection"]["requested"], True)
        self.assertEqual(manifest["collection"]["attempted"], True)
        self.assertEqual(manifest["cleanup"]["requested"], True)
        self.assertEqual(manifest["cleanup"]["attempted"], True)
        json.dumps(manifest)


class RunRunner:
    def __call__(self, argv: Sequence[object], **kwargs: object) -> CommandResult:
        normalized = tuple(str(part) for part in argv)
        remote_command = normalized[-1]
        if remote_command.startswith("docker-test run "):
            stdout = "container stdout\n"
        else:
            stdout = "mkdir\n"
        return CommandResult(
            argv=normalized,
            redacted_argv=normalized,
            cwd=None,
            exit_code=0,
            stdout=stdout,
            stderr="",
            timeout=kwargs.get("timeout") if isinstance(kwargs.get("timeout"), float) else None,
        )


class ArtifactRunner:
    def __init__(self, *, exit_code: int = 0, stderr: str = "") -> None:
        self.exit_code = exit_code
        self.stderr = stderr
        self.calls: list[tuple[str, ...]] = []
        self.kwargs: list[dict[str, object]] = []

    def __call__(self, argv: Sequence[object], **kwargs: object) -> CommandResult:
        normalized = tuple(str(part) for part in argv)
        self.calls.append(normalized)
        self.kwargs.append(dict(kwargs))
        if normalized[0] == "scp" and self.exit_code == 0:
            destination = Path(normalized[-1])
            destination.mkdir(parents=True, exist_ok=True)
            destination.joinpath("remote-report.txt").write_text("artifact\n", encoding="utf-8")
        return CommandResult(
            argv=normalized,
            redacted_argv=normalized,
            cwd=None,
            exit_code=self.exit_code,
            stdout=f"{normalized[0]}\n" if self.exit_code == 0 else "",
            stderr=self.stderr,
            timeout=kwargs.get("timeout") if isinstance(kwargs.get("timeout"), float) else None,
        )


def _run_result(root: Path):
    target = resolve_endpoint_appliance_target(_manifest(root))
    return run_endpoint_appliance_command(
        target,
        ApplianceProfile(name="lan-raw"),
        ["cargo", "test", "-p", "crafter"],
        run_id="run-a",
        image_tag="registry.example.invalid/libcrafter/appliance:test",
        runner=RunRunner(),
    )


def _manifest(root: Path) -> EndpointManifest:
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
        metadata={"appliance": {"docker_command": "docker-test"}},
    )


if __name__ == "__main__":
    unittest.main()
