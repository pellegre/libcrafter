"""Coverage for endpoint appliance deploy planning and fake execution."""

from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path

from tools.endpoint.engine.appliance import (
    DEFAULT_APPLIANCE_DEPLOY_ARTIFACT_DIRNAME,
    deploy_endpoint_appliance_target,
    render_endpoint_appliance_deploy_plan,
    resolve_endpoint_appliance_target,
)
from tools.endpoint.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResource,
    ProviderResources,
)
from tools.endpoint.engine.process import CommandResult


class EndpointApplianceDeployTest(unittest.TestCase):
    def test_dry_run_plan_shows_remote_commands_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = resolve_endpoint_appliance_target(_manifest(Path(temp_dir)))
            plan = render_endpoint_appliance_deploy_plan(
                target,
                image_tag="registry.example.invalid/libcrafter/appliance:test",
                install_docker=True,
            )
            load_plan = render_endpoint_appliance_deploy_plan(
                target,
                image_tag="registry.example.invalid/libcrafter/appliance:test",
                image_archive_remote_path="/var/tmp/libcrafter/appliance.tar",
            )

        self.assertFalse(plan.executes)
        self.assertEqual(
            [command.kind for command in plan.commands],
            [
                "ssh-docker-check",
                "ssh-docker-install",
                "ssh-docker-mkdir",
                "ssh-docker-image-inspect",
                "ssh-docker-image-build",
            ],
        )
        docker_check, docker_install, mkdir, inspect, build = plan.commands
        self.assertEqual(
            docker_check.remote_command_argv,
            ["docker-test", "info", "--format", "{{json .ServerVersion}}"],
        )
        self.assertEqual(docker_install.remote_command_argv[:2], ["sh", "-lc"])
        self.assertEqual(mkdir.remote_command_argv[0:2], ["mkdir", "-p"])
        self.assertEqual(
            inspect.remote_command_argv,
            [
                "docker-test",
                "image",
                "inspect",
                "registry.example.invalid/libcrafter/appliance:test",
            ],
        )
        self.assertEqual(build.remote_command_argv[:4], ["docker-test", "build", "-t", inspect.remote_command_argv[-1]])
        self.assertIn(
            "/var/lib/libcrafter/appliance/endpoint-a/work/tools/appliance",
            build.remote_command_argv,
        )
        self.assertEqual(load_plan.commands[-1].kind, "ssh-docker-image-load")
        self.assertEqual(
            load_plan.commands[-1].remote_command_argv,
            ["docker-test", "load", "-i", "/var/tmp/libcrafter/appliance.tar"],
        )
        json.loads(plan.to_json())

    def test_fake_successful_deploy_builds_missing_image_and_writes_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = resolve_endpoint_appliance_target(_manifest(root))
            runner = ScriptedRunner({"image-inspect": [1], "image-build": [0]})

            result = deploy_endpoint_appliance_target(target, runner=runner, timeout=12.0)

            artifact_dir = root / "artifacts" / "endpoint-a" / DEFAULT_APPLIANCE_DEPLOY_ARTIFACT_DIRNAME
            self.assertTrue(Path(result.command_results[0].stdout_path).is_file())
            self.assertEqual(Path(result.command_results[0].stdout_path).read_text(), "docker-check\n")
            self.assertEqual(Path(result.command_results[2].stderr_path).read_text(), "image-inspect failed\n")

        self.assertTrue(result.ok)
        self.assertEqual(
            [record.kind for record in result.command_results],
            [
                "ssh-docker-check",
                "ssh-docker-mkdir",
                "ssh-docker-image-inspect",
                "ssh-docker-image-build",
            ],
        )
        self.assertEqual(len(runner.calls), 4)
        self.assertTrue(result.artifact_dir.endswith(str(artifact_dir)))
        json.loads(result.to_json())

    def test_missing_docker_can_be_installed_only_when_explicitly_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = resolve_endpoint_appliance_target(_manifest(Path(temp_dir)))
            runner = ScriptedRunner({"docker-check": [127, 0]})

            result = deploy_endpoint_appliance_target(
                target,
                runner=runner,
                install_docker=True,
            )

        self.assertTrue(result.ok)
        self.assertEqual(
            [record.name for record in result.command_results],
            [
                "01-docker-check",
                "02-docker-install",
                "03-docker-check-after-install",
                "04-remote-mkdir",
                "05-image-inspect",
            ],
        )
        self.assertIn("sh -lc", runner.calls[1][-1])

    def test_missing_docker_fails_when_install_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = resolve_endpoint_appliance_target(_manifest(Path(temp_dir)))
            runner = ScriptedRunner({"docker-check": [127]})

            result = deploy_endpoint_appliance_target(target, runner=runner)

        self.assertFalse(result.ok)
        self.assertEqual(len(result.command_results), 1)
        self.assertEqual(result.command_results[0].kind, "ssh-docker-check")
        self.assertEqual(runner.kinds, ["docker-check"])

    def test_docker_endpoint_without_nested_docker_rejects_deploy_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = resolve_endpoint_appliance_target(_docker_manifest(Path(temp_dir)))

            with self.assertRaisesRegex(ValueError, "does not support Docker execution"):
                render_endpoint_appliance_deploy_plan(target)


class ScriptedRunner:
    def __init__(self, exit_codes: dict[str, list[int]] | None = None) -> None:
        self.exit_codes = {} if exit_codes is None else {key: list(value) for key, value in exit_codes.items()}
        self.calls: list[tuple[str, ...]] = []
        self.kinds: list[str] = []

    def __call__(self, argv: Sequence[object], **kwargs: object) -> CommandResult:
        normalized = tuple(str(part) for part in argv)
        self.calls.append(normalized)
        kind = _command_kind(normalized[-1])
        self.kinds.append(kind)
        queue = self.exit_codes.get(kind)
        exit_code = queue.pop(0) if queue else 0
        timeout = kwargs.get("timeout")
        return CommandResult(
            argv=normalized,
            redacted_argv=normalized,
            cwd=None,
            exit_code=exit_code,
            stdout=f"{kind}\n" if exit_code == 0 else "",
            stderr="" if exit_code == 0 else f"{kind} failed\n",
            timeout=timeout if isinstance(timeout, float) else None,
        )


def _command_kind(remote_command: str) -> str:
    if " info --format " in remote_command:
        return "docker-check"
    if remote_command.startswith("sh -lc "):
        return "docker-install"
    if remote_command.startswith("mkdir -p "):
        return "remote-mkdir"
    if " image inspect " in remote_command:
        return "image-inspect"
    if " build -t " in remote_command:
        return "image-build"
    if " load -i " in remote_command:
        return "image-load"
    return "unknown"


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


def _docker_manifest(root: Path) -> EndpointManifest:
    endpoint_id = "docker-a"
    return EndpointManifest(
        endpoint_id=endpoint_id,
        provider="docker",
        exposure="private",
        status="active",
        role="oracle",
        created_at="2026-06-28T00:00:00Z",
        ssh=EndpointSSHInfo(
            host="127.0.0.1",
            user="root",
            port=27222,
            identity_file=str(root / "state" / endpoint_id / "id_ed25519"),
            known_hosts_file=str(root / "state" / endpoint_id / "known_hosts"),
            metadata={"transport": "docker-localhost-port-forward"},
        ),
        interfaces=[NetworkInterface(name="eth0", exposure="private", ipv4="198.51.100.20")],
        provider_resources=ProviderResources(
            resources=[
                ProviderResource(
                    kind="docker-container",
                    provider_id="endpoint-docker-a",
                    cleanup=True,
                    metadata={"synthetic": True},
                )
            ],
            metadata={"synthetic": True},
        ),
        artifact_dir=str(root / "artifacts" / endpoint_id),
        metadata={
            "docker": {
                "container": {
                    "type": "docker-container",
                    "container_name": "endpoint-docker-a",
                }
            }
        },
    )


if __name__ == "__main__":
    unittest.main()
