"""Coverage for endpoint appliance remote run planning and fake execution."""

from __future__ import annotations

import json
import shlex
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path

from tools.appliance.engine.profile import ApplianceProfile, ProfileMount
from tools.endpoint.engine.appliance import (
    DEFAULT_APPLIANCE_RUN_ARTIFACT_DIRNAME,
    render_endpoint_appliance_run_plan,
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


class EndpointApplianceRunTest(unittest.TestCase):
    def test_dry_run_plan_shows_remote_docker_run_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = resolve_endpoint_appliance_target(_manifest(root))
            profile = ApplianceProfile(
                name="wan-raw",
                image="registry.example.invalid/libcrafter/appliance:profile",
                network_mode="host",
                cap_add=["NET_RAW"],
                env={"KEEP": "profile"},
                mounts=[ProfileMount(source="/opt/libcrafter/cache", target="/cache")],
            )

            plan = render_endpoint_appliance_run_plan(
                target,
                profile,
                ["bash", "-lc", "printf '%s\\n' \"$KEEP\""],
                run_id="run-a",
                image_tag="registry.example.invalid/libcrafter/appliance:test",
                env={"EXTRA": "1"},
            )

        self.assertFalse(plan.executes)
        self.assertEqual(plan.profile, "wan-raw")
        self.assertEqual(plan.image_tag, "registry.example.invalid/libcrafter/appliance:test")
        self.assertEqual(
            [command.kind for command in plan.commands],
            ["ssh-appliance-run-mkdir", "ssh-appliance-run-docker"],
        )
        self.assertEqual(
            plan.remote_work_root,
            "/var/lib/libcrafter/appliance/endpoint-a/work/runs/run-a/workspace",
        )
        self.assertEqual(
            plan.remote_artifact_root,
            "/var/lib/libcrafter/appliance/endpoint-a/artifacts/runs/run-a",
        )
        self.assertEqual(plan.docker_run.network_mode, "host")
        self.assertEqual(plan.docker_run.cap_add, ["NET_RAW"])
        self.assertEqual(plan.docker_run.env, {"EXTRA": "1", "KEEP": "profile"})
        self.assertIn("--mount", plan.docker_run.docker_argv)
        self.assertTrue(
            any(
                "source=/opt/libcrafter/cache,target=/cache" in item
                for item in plan.docker_run.docker_argv
            )
        )
        self.assertIn("docker-test run --rm", plan.commands[1].command_argv[-1])
        self.assertTrue(
            plan.local_stdout_path.endswith(
                f"{DEFAULT_APPLIANCE_RUN_ARTIFACT_DIRNAME}/run-a/run.stdout.txt"
            )
        )
        json.loads(plan.to_json())

    def test_fake_successful_run_records_outputs_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = resolve_endpoint_appliance_target(_manifest(root))
            runner = ScriptedRunRunner()

            result = run_endpoint_appliance_command(
                target,
                ApplianceProfile(name="lan-raw"),
                ["cargo", "test", "-p", "crafter"],
                run_id="run-a",
                image_tag="registry.example.invalid/libcrafter/appliance:test",
                runner=runner,
                timeout=30.0,
            )

            artifact_dir = (
                root
                / "artifacts"
                / "endpoint-a"
                / DEFAULT_APPLIANCE_RUN_ARTIFACT_DIRNAME
                / "run-a"
            )
            metadata = json.loads(Path(result.local_metadata_path).read_text(encoding="utf-8"))
            stdout = Path(result.local_stdout_path).read_text(encoding="utf-8")
            stderr = Path(result.local_stderr_path).read_text(encoding="utf-8")
            run_stdout_exists = Path(result.command_results[1].stdout_path).is_file()

        self.assertTrue(result.ok)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual([call[0] for call in runner.calls], ["ssh", "ssh"])
        self.assertEqual(runner.kinds, ["mkdir", "docker-run"])
        self.assertEqual(runner.kwargs[1]["timeout"], 30.0)
        self.assertEqual(stdout, "container stdout\n")
        self.assertEqual(stderr, "")
        self.assertTrue(run_stdout_exists)
        self.assertEqual(metadata["endpoint_id"], "endpoint-a")
        self.assertEqual(metadata["profile"], "lan-raw")
        self.assertEqual(metadata["exit_code"], 0)
        self.assertTrue(result.local_artifact_dir.endswith(str(artifact_dir)))
        json.loads(result.to_json())

    def test_failed_container_exit_is_reported_and_captured(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = resolve_endpoint_appliance_target(_manifest(Path(temp_dir)))
            runner = ScriptedRunRunner({"docker-run": [42]})

            result = run_endpoint_appliance_command(
                target,
                ApplianceProfile(name="lan-raw"),
                ["sh", "-lc", "exit 42"],
                run_id="run-fail",
                runner=runner,
            )
            stderr = Path(result.local_stderr_path).read_text(encoding="utf-8")

        self.assertFalse(result.ok)
        self.assertEqual(result.exit_code, 42)
        self.assertEqual(result.command_results[1].kind, "ssh-appliance-run-docker")
        self.assertEqual(stderr, "container failed\n")

    def test_environment_propagates_from_profile_and_run_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = resolve_endpoint_appliance_target(_manifest(Path(temp_dir)))

            plan = render_endpoint_appliance_run_plan(
                target,
                ApplianceProfile(
                    name="lan-raw",
                    env={"KEEP": "profile", "RUST_LOG": "info"},
                ),
                ["env"],
                run_id="run-env",
                env={"EXTRA": "1", "RUST_LOG": "debug"},
            )

        self.assertEqual(
            plan.docker_run.env,
            {"EXTRA": "1", "KEEP": "profile", "RUST_LOG": "debug"},
        )
        self.assertEqual(
            [
                plan.docker_run.docker_argv[index + 1]
                for index, value in enumerate(plan.docker_run.docker_argv)
                if value == "--env"
            ],
            ["EXTRA=1", "KEEP=profile", "RUST_LOG=debug"],
        )

    def test_command_argv_after_double_dash_is_preserved_before_ssh_shell_rendering(self) -> None:
        command = [
            "python3",
            "-m",
            "synthetic.tool",
            "--",
            "--literal-flag",
            "two words",
            "semi;colon",
            "quote'arg",
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            target = resolve_endpoint_appliance_target(_manifest(Path(temp_dir)))

            plan = render_endpoint_appliance_run_plan(
                target,
                ApplianceProfile(name="lan-raw"),
                command,
                run_id="run-argv",
            )

        self.assertEqual(plan.command_argv, command)
        self.assertEqual(plan.docker_run.command_argv, command)
        self.assertEqual(plan.docker_run.docker_argv[-len(command) :], command)
        self.assertIn(shlex.quote("two words"), plan.commands[1].command_argv[-1])
        self.assertIn(shlex.quote("semi;colon"), plan.commands[1].command_argv[-1])


class ScriptedRunRunner:
    def __init__(self, exit_codes: dict[str, list[int]] | None = None) -> None:
        self.exit_codes = {} if exit_codes is None else {key: list(value) for key, value in exit_codes.items()}
        self.calls: list[tuple[str, ...]] = []
        self.kwargs: list[dict[str, object]] = []
        self.kinds: list[str] = []

    def __call__(self, argv: Sequence[object], **kwargs: object) -> CommandResult:
        normalized = tuple(str(part) for part in argv)
        self.calls.append(normalized)
        self.kwargs.append(dict(kwargs))
        kind = _command_kind(normalized[-1])
        self.kinds.append(kind)
        queue = self.exit_codes.get(kind)
        exit_code = queue.pop(0) if queue else 0
        return CommandResult(
            argv=normalized,
            redacted_argv=normalized,
            cwd=None,
            exit_code=exit_code,
            stdout=_stdout(kind, exit_code),
            stderr=_stderr(kind, exit_code),
            timeout=kwargs.get("timeout") if isinstance(kwargs.get("timeout"), float) else None,
        )


def _command_kind(remote_command: str) -> str:
    if remote_command.startswith("mkdir -p "):
        return "mkdir"
    if remote_command.startswith("docker-test run "):
        return "docker-run"
    return "unknown"


def _stdout(kind: str, exit_code: int) -> str:
    if exit_code != 0:
        return ""
    if kind == "docker-run":
        return "container stdout\n"
    return f"{kind}\n"


def _stderr(kind: str, exit_code: int) -> str:
    if exit_code == 0:
        return ""
    if kind == "docker-run":
        return "container failed\n"
    return f"{kind} failed\n"


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
