"""Coverage for deterministic appliance Docker run plans."""

from __future__ import annotations

import json
import unittest

from tools.appliance.engine.profile import ApplianceProfile, ProfileDevice, ProfileMount
from tools.appliance.engine.runtime import render_docker_run_plan


class DockerRunPlanTest(unittest.TestCase):
    def test_shell_safe_argv_preserves_command_arguments(self) -> None:
        command = [
            "bash",
            "-lc",
            "printf '%s\\n' \"$PAYLOAD\" && touch 'artifact one'",
        ]

        plan = render_docker_run_plan(
            ApplianceProfile(name="lan-raw"),
            image_tag="registry.example/appliance:test",
            work_dir="/tmp/libcrafter-work",
            artifact_dir="/tmp/libcrafter-artifacts",
            command_argv=command,
            environment={"PAYLOAD": "quoted value; not a docker arg"},
        )

        self.assertEqual(plan.command_argv, command)
        self.assertEqual(plan.docker_argv[-len(command) :], command)
        self.assertEqual(
            plan.docker_argv[-len(command) - 1],
            "registry.example/appliance:test",
        )
        json.loads(json.dumps(plan.to_dict(), sort_keys=True))

    def test_wan_raw_host_network_style_plan(self) -> None:
        profile = ApplianceProfile(
            name="wan-raw",
            network_mode="host",
            cap_add=["NET_RAW", "NET_ADMIN"],
        )

        plan = render_docker_run_plan(
            profile,
            image_tag="libcrafter/appliance:wan",
            work_dir="/tmp/libcrafter-work",
            artifact_dir="/tmp/libcrafter-artifacts",
            command_argv=["cargo", "test", "-p", "crafter"],
        )

        self.assertEqual(plan.network_mode, "host")
        self.assertEqual(plan.cap_add, ["NET_RAW", "NET_ADMIN"])
        self.assertIn("--network", plan.docker_argv)
        self.assertEqual(plan.docker_argv[plan.docker_argv.index("--network") + 1], "host")
        self.assertEqual(
            [
                plan.docker_argv[index + 1]
                for index, value in enumerate(plan.docker_argv)
                if value == "--cap-add"
            ],
            ["NET_RAW", "NET_ADMIN"],
        )

    def test_device_passthrough_plan(self) -> None:
        plan = render_docker_run_plan(
            ApplianceProfile(name="whad-serial"),
            image_tag="libcrafter/appliance:whad",
            work_dir="/tmp/libcrafter-work",
            artifact_dir="/tmp/libcrafter-artifacts",
            command_argv=["python3", "-m", "pytest"],
            devices=[
                ProfileDevice(
                    host_path="/dev/ttyACM0",
                    container_path="/dev/whad0",
                    permissions="rw",
                )
            ],
        )

        self.assertEqual(plan.devices[0].to_dict()["host_path"], "/dev/ttyACM0")
        self.assertIn("--device", plan.docker_argv)
        self.assertIn("/dev/ttyACM0:/dev/whad0:rw", plan.docker_argv)

    def test_environment_merging(self) -> None:
        profile = ApplianceProfile(
            name="lan-raw",
            env={
                "KEEP": "profile",
                "RUST_LOG": "info",
            },
        )

        plan = render_docker_run_plan(
            profile,
            image_tag="libcrafter/appliance:env",
            work_dir="/tmp/libcrafter-work",
            artifact_dir="/tmp/libcrafter-artifacts",
            command_argv=["env"],
            environment={
                "EXTRA": "1",
                "RUST_LOG": "debug",
            },
        )

        self.assertEqual(
            plan.env,
            {
                "EXTRA": "1",
                "KEEP": "profile",
                "RUST_LOG": "debug",
            },
        )
        self.assertEqual(
            [
                plan.docker_argv[index + 1]
                for index, value in enumerate(plan.docker_argv)
                if value == "--env"
            ],
            ["EXTRA=1", "KEEP=profile", "RUST_LOG=debug"],
        )

    def test_rejects_unsafe_options(self) -> None:
        profile = ApplianceProfile(name="lan-raw")

        cases = [
            {
                "name": "privileged command token",
                "kwargs": {"command_argv": ["--privileged"]},
                "pattern": "--privileged",
            },
            {
                "name": "privileged capability",
                "kwargs": {
                    "command_argv": ["true"],
                    "cap_add": ["--privileged"],
                },
                "pattern": "cap_add",
            },
            {
                "name": "Docker socket mount",
                "kwargs": {
                    "command_argv": ["true"],
                    "mounts": [ProfileMount("/var/run/docker.sock", "/var/run/docker.sock")],
                },
                "pattern": "Docker socket",
            },
            {
                "name": "relative work path",
                "kwargs": {
                    "command_argv": ["true"],
                    "work_dir": "relative-work",
                },
                "pattern": "work_dir",
            },
            {
                "name": "relative artifact path",
                "kwargs": {
                    "command_argv": ["true"],
                    "artifact_dir": "relative-artifacts",
                },
                "pattern": "artifact_dir",
            },
            {
                "name": "empty command",
                "kwargs": {"command_argv": []},
                "pattern": "command_argv",
            },
        ]

        for case in cases:
            kwargs = {
                "image_tag": "libcrafter/appliance:reject",
                "work_dir": "/tmp/libcrafter-work",
                "artifact_dir": "/tmp/libcrafter-artifacts",
            }
            kwargs.update(case["kwargs"])
            with self.subTest(case["name"]):
                with self.assertRaisesRegex(ValueError, case["pattern"]):
                    render_docker_run_plan(profile, **kwargs)


if __name__ == "__main__":
    unittest.main()
