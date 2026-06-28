"""Coverage for SSH-accessible appliance Docker host plans."""

from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path

from tools.appliance.engine.profile import ApplianceProfile
from tools.appliance.engine.ssh_docker import (
    RemoteArtifact,
    SSHDockerHostTarget,
    execute_command_plan,
    render_artifact_collection_plans,
    render_docker_check_plan,
    render_mkdir_plan,
    render_remote_docker_run_plan,
)
from tools.endpoint.engine.process import CommandResult


class SSHDockerHostTest(unittest.TestCase):
    def test_model_validation_and_json_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = _target(temp_dir)

            payload = target.to_dict()
            self.assertEqual(payload["host"], "appliance.example.invalid")
            self.assertEqual(payload["user"], "runner")
            self.assertEqual(payload["port"], 2202)
            self.assertEqual(payload["remote_work_root"], "/var/tmp/libcrafter/work")
            self.assertEqual(payload["remote_artifact_root"], "/var/tmp/libcrafter/artifacts")
            self.assertEqual(payload["docker_command"], "docker-test")
            json.loads(json.dumps(payload, sort_keys=True))

            with self.assertRaisesRegex(ValueError, "port"):
                SSHDockerHostTarget(
                    host="appliance.example.invalid",
                    user="runner",
                    port=0,
                    identity_file=target.identity_file,
                    known_hosts_file=target.known_hosts_file,
                )
            with self.assertRaisesRegex(ValueError, "identity_file"):
                SSHDockerHostTarget(
                    host="appliance.example.invalid",
                    user="runner",
                    identity_file="relative-key",
                    known_hosts_file=target.known_hosts_file,
                )
            with self.assertRaisesRegex(ValueError, "remote_work_root"):
                SSHDockerHostTarget(
                    host="appliance.example.invalid",
                    user="runner",
                    identity_file=target.identity_file,
                    known_hosts_file=target.known_hosts_file,
                    remote_work_root="relative-work",
                )
            with self.assertRaisesRegex(ValueError, "artifact.path"):
                RemoteArtifact("../escape")

    def test_docker_check_uses_endpoint_ssh_argv_conventions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = _target(temp_dir)
            plan = render_docker_check_plan(target)

        self.assertFalse(plan.executes)
        self.assertEqual(plan.kind, "ssh-docker-check")
        self.assertEqual(
            plan.remote_command_argv,
            ["docker-test", "info", "--format", "{{json .ServerVersion}}"],
        )
        self.assertEqual(plan.command_argv[0], "ssh")
        self.assertIn("-i", plan.command_argv)
        self.assertIn("-p", plan.command_argv)
        self.assertIn("2202", plan.command_argv)
        self.assertIn("UserKnownHostsFile=", " ".join(plan.command_argv))
        self.assertEqual(plan.command_argv[-2], "runner@appliance.example.invalid")
        self.assertEqual(
            plan.command_argv[-1],
            "docker-test info --format '{{json .ServerVersion}}'",
        )

    def test_mkdir_plan_creates_remote_work_and_artifact_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = _target(temp_dir)
            plan = render_mkdir_plan(target)

        self.assertEqual(plan.kind, "ssh-docker-mkdir")
        self.assertEqual(
            plan.remote_command_argv,
            [
                "mkdir",
                "-p",
                "/var/tmp/libcrafter/work",
                "/var/tmp/libcrafter/artifacts",
            ],
        )
        self.assertEqual(
            plan.command_argv[-1],
            "mkdir -p /var/tmp/libcrafter/work /var/tmp/libcrafter/artifacts",
        )
        self.assertEqual(
            plan.metadata,
            {"paths": ["/var/tmp/libcrafter/work", "/var/tmp/libcrafter/artifacts"]},
        )

    def test_remote_docker_run_plan_wraps_runtime_plan_over_ssh(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = _target(temp_dir)
            plan = render_remote_docker_run_plan(
                target,
                ApplianceProfile(
                    name="wan-raw",
                    network_mode="host",
                    cap_add=["NET_RAW"],
                    env={"KEEP": "profile"},
                ),
                image_tag="registry.example.invalid/libcrafter/appliance:test",
                command_argv=["bash", "-lc", "printf '%s\\n' \"$KEEP\""],
                environment={"EXTRA": "1"},
            )

        self.assertFalse(plan.executes)
        self.assertEqual(plan.kind, "ssh-docker-run")
        self.assertEqual(plan.run.work_dir, "/var/tmp/libcrafter/work")
        self.assertEqual(plan.run.artifact_dir, "/var/tmp/libcrafter/artifacts")
        self.assertEqual(plan.run.docker_command, "docker-test")
        self.assertEqual(plan.run.network_mode, "host")
        self.assertEqual(plan.run.cap_add, ["NET_RAW"])
        self.assertEqual(plan.run.env, {"EXTRA": "1", "KEEP": "profile"})
        self.assertEqual(plan.command_argv[0], "ssh")
        self.assertEqual(plan.command_argv[-2], "runner@appliance.example.invalid")
        self.assertIn("docker-test run --rm", plan.command_argv[-1])
        self.assertIn(
            "source=/var/tmp/libcrafter/work,target=/work",
            plan.command_argv[-1],
        )
        payload = plan.to_dict()
        self.assertEqual(payload["run"]["docker_argv"], plan.run.docker_argv)
        json.loads(json.dumps(payload, sort_keys=True))

    def test_artifact_collection_plans_use_scp_argv(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = _target(temp_dir)
            plans = render_artifact_collection_plans(
                target,
                [
                    "reports/summary.json",
                    {
                        "path": "logs",
                        "local_path": "run-logs",
                        "recursive": True,
                    },
                ],
                local_root=root / "collected",
            )

        self.assertEqual(len(plans), 2)
        first, second = plans
        self.assertEqual(first.command_argv[0], "scp")
        self.assertNotIn("-r", first.command_argv)
        self.assertIn("-P", first.command_argv)
        self.assertIn("2202", first.command_argv)
        self.assertEqual(
            first.command_argv[-2],
            "runner@appliance.example.invalid:/var/tmp/libcrafter/artifacts/reports/summary.json",
        )
        self.assertTrue(first.command_argv[-1].endswith("/collected/reports/summary.json"))
        self.assertEqual(second.command_argv[:2], ["scp", "-r"])
        self.assertEqual(
            second.command_argv[-2],
            "runner@appliance.example.invalid:/var/tmp/libcrafter/artifacts/logs",
        )
        self.assertTrue(second.command_argv[-1].endswith("/collected/run-logs"))
        json.loads(json.dumps([plan.to_dict() for plan in plans], sort_keys=True))

    def test_execute_command_plan_requires_injected_runner(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = _target(temp_dir)
            plan = render_docker_check_plan(target)
            runner = RecordingRunner()

            result = execute_command_plan(plan, runner=runner, timeout=12.5)

        self.assertTrue(result.ok)
        self.assertEqual(runner.calls, [(tuple(plan.command_argv), 12.5)])
        self.assertEqual(result.argv, tuple(plan.command_argv))


class RecordingRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], float | None]] = []

    def __call__(self, argv: Sequence[object], **kwargs: object) -> CommandResult:
        normalized = tuple(str(part) for part in argv)
        timeout = kwargs.get("timeout")
        self.calls.append((normalized, timeout if isinstance(timeout, float) else None))
        return CommandResult(
            argv=normalized,
            redacted_argv=normalized,
            cwd=None,
            exit_code=0,
            stdout="ok\n",
            stderr="",
            timeout=timeout if isinstance(timeout, float) else None,
        )


def _target(temp_dir: str) -> SSHDockerHostTarget:
    root = Path(temp_dir)
    return SSHDockerHostTarget(
        host="appliance.example.invalid",
        user="runner",
        port=2202,
        identity_file=root / "id_ed25519",
        known_hosts_file=root / "known_hosts",
        remote_work_root="/var/tmp/libcrafter/work/",
        remote_artifact_root="/var/tmp/libcrafter/artifacts/",
        docker_command="docker-test",
        metadata={"provider": "fake"},
    )


if __name__ == "__main__":
    unittest.main()
