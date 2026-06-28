"""Coverage for local appliance substrate planning."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from tools.appliance.engine import cli
from tools.appliance.engine.profiles import resolve_profile
from tools.appliance.engine.substrates import (
    DEFAULT_ARTIFACT_SUBDIR,
    LocalDockerHostSubstrate,
    UnsupportedSubstrateProfileError,
    render_local_run_plan,
)


class LocalSubstrateTest(unittest.TestCase):
    def test_renders_json_friendly_local_run_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plan = render_local_run_plan(
                resolve_profile("wan-raw"),
                command_argv=["echo", "ok"],
                repo_root=temp_dir,
                host_environment={},
                image_tag="registry.example/appliance:test",
                docker_command="docker-test",
            )

        payload = plan.to_dict()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["substrate"], "local")
        self.assertEqual(payload["mode"], "plan-only")
        self.assertEqual(payload["profile"], "wan-raw")
        self.assertEqual(payload["run"]["command_argv"], ["echo", "ok"])
        self.assertEqual(payload["run"]["docker_command"], "docker-test")
        self.assertEqual(payload["run"]["image_tag"], "registry.example/appliance:test")
        self.assertGreaterEqual(len(payload["checks"]), 1)
        self.assertFalse(payload["safety"]["executes"])
        json.loads(json.dumps(payload, sort_keys=True))

    def test_environment_values_drive_checks_and_devices_without_leaking_all_host_env(self) -> None:
        plan = render_local_run_plan(
            resolve_profile("whad-serial"),
            command_argv=["python3", "-m", "pytest"],
            repo_root="/tmp/libcrafter-test-root",
            environment={"EXTRA": "1"},
            host_environment={
                "LIBCRAFTER_WHAD_DEVICE": "/dev/ttyFAKE0",
                "UNRELATED_SECRET": "not-forwarded",
            },
        )

        self.assertEqual(
            plan.environment,
            {
                "EXTRA": "1",
                "LIBCRAFTER_WHAD_DEVICE": "/dev/ttyFAKE0",
            },
        )
        self.assertNotIn("UNRELATED_SECRET", plan.environment)
        self.assertEqual(plan.run.devices[0].host_path, "/dev/ttyFAKE0")
        serial_check = next(check for check in plan.checks if check.kind == "serial-device-exists")
        self.assertEqual(serial_check.command_argv[-2:], ["--device", "/dev/ttyFAKE0"])

    def test_default_and_explicit_directories_are_absolute(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            explicit_work = root / "work"
            explicit_artifacts = root / "artifacts"

            default_plan = render_local_run_plan(
                resolve_profile("lan-raw"),
                command_argv=["true"],
                repo_root=root,
                host_environment={},
            )
            explicit_plan = render_local_run_plan(
                resolve_profile("lan-raw"),
                command_argv=["true"],
                work_dir=explicit_work,
                artifact_dir=explicit_artifacts,
                repo_root=root,
                host_environment={},
            )

        self.assertEqual(default_plan.work_dir, str(root.resolve(strict=False)))
        self.assertEqual(
            default_plan.artifact_dir,
            str((root / DEFAULT_ARTIFACT_SUBDIR).resolve(strict=False)),
        )
        self.assertTrue(Path(default_plan.work_dir).is_absolute())
        self.assertTrue(Path(default_plan.artifact_dir).is_absolute())
        self.assertEqual(explicit_plan.work_dir, str(explicit_work.resolve(strict=False)))
        self.assertEqual(
            explicit_plan.artifact_dir,
            str(explicit_artifacts.resolve(strict=False)),
        )

    def test_rejects_profile_not_supported_by_selected_local_policy(self) -> None:
        substrate = LocalDockerHostSubstrate(supported_profiles=("wan-raw",))

        with self.assertRaisesRegex(UnsupportedSubstrateProfileError, "lan-raw"):
            substrate.render_run_plan(
                resolve_profile("lan-raw"),
                command_argv=["true"],
                repo_root="/tmp/libcrafter-test-root",
                host_environment={},
            )

    def test_cli_run_plan_prints_json_without_running_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = cli.main(
                    [
                        "run-plan",
                        "--substrate",
                        "local",
                        "--profile",
                        "wan-raw",
                        "--work-dir",
                        str(Path(temp_dir) / "work"),
                        "--artifact-dir",
                        str(Path(temp_dir) / "artifacts"),
                        "--env",
                        "LIBCRAFTER_IFACE=eth-test0",
                        "--",
                        "echo",
                        "ok",
                    ]
                )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["environment"]["LIBCRAFTER_IFACE"], "eth-test0")
        self.assertEqual(payload["run"]["command_argv"], ["echo", "ok"])
        self.assertEqual(payload["run"]["docker_argv"][-2:], ["echo", "ok"])


if __name__ == "__main__":
    unittest.main()
