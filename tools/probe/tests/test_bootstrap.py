"""Focused coverage for probe-owned lab bootstrap hooks."""

from __future__ import annotations

import unittest

from tools.lab.engine.model import LabEndpoint, LabRole, LabSession
from tools.lab.engine.repo import RepoBootstrapCommand, RepoBootstrapContext
from tools.probe.engine import bootstrap


class ProbeBootstrapTest(unittest.TestCase):
    def test_bootstrap_commands_render_probe_role_commands(self) -> None:
        commands = bootstrap.bootstrap_commands()

        self.assertEqual(set(commands), {"stimulus", "target"})
        stimulus = commands["stimulus"](_bootstrap_context("stimulus"))
        target = commands["target"](_bootstrap_context("target"))

        self.assertIsInstance(stimulus, RepoBootstrapCommand)
        self.assertIsInstance(target, RepoBootstrapCommand)
        self.assertEqual(stimulus.metadata["workload"], "probe")
        self.assertEqual(stimulus.metadata["role"], "stimulus")
        self.assertTrue(stimulus.metadata["builds_stimulus_endpoint"])
        self.assertEqual(target.metadata["workload"], "probe")
        self.assertEqual(target.metadata["role"], "target")
        self.assertFalse(target.metadata["builds_stimulus_endpoint"])

    def test_stimulus_script_builds_endpoint_under_lab_artifacts(self) -> None:
        command = bootstrap.repo_bootstrap_command(_bootstrap_context("stimulus"))
        script = _script(command)
        lines = script.splitlines()

        self.assertEqual(lines[0], "set -euo pipefail")
        self.assertIn("cloud-init status --wait", lines[1])
        self.assertIn("cd /opt/libcrafter-lab/session", lines)
        self.assertIn("export LIBCRAFTER_ENDPOINT_ROLE=stimulus", lines)
        self.assertIn("export LIBCRAFTER_PRIVATE_IPV4=10.77.0.10", lines)
        self.assertIn("export LIBCRAFTER_PEER_PRIVATE_IPV4=10.77.0.20", lines)
        self.assertIn("export LIBCRAFTER_PRIVATE_INTERFACE=eth1", lines)
        self.assertIn(
            "export LIBCRAFTER_BOOTSTRAP_ARTIFACT_DIR="
            "/opt/libcrafter-lab/session/artifacts/probe/bootstrap/stimulus",
            lines,
        )
        self.assertIn(
            "apt-get install -y --no-install-recommends "
            "build-essential ca-certificates clang curl git iproute2 iptables "
            "iputils-ping libpcap-dev pkg-config python3",
            lines,
        )
        self.assertIn(
            "cargo build -p probe-adapters --bin stimulus_endpoint",
            lines,
        )
        self.assertIn("  printf '%s\\n' repository_synced=true", lines)
        self.assertIn("  printf '%s\\n' libcrafter_probe_bin=stimulus_endpoint", lines)
        self.assertIn("  printf '%s\\n' libcrafter_probe_bin_build=ok", lines)
        self.assertIn(
            "} > /opt/libcrafter-lab/session/artifacts/probe/bootstrap/"
            "stimulus/bootstrap.env",
            lines,
        )
        _assert_provider_neutral(self, script)

    def test_target_script_installs_controlled_service_runtime_only(self) -> None:
        command = bootstrap.repo_bootstrap_command(_bootstrap_context("target"))
        script = _script(command)
        lines = script.splitlines()

        self.assertIn("cd /opt/libcrafter-lab/session", lines)
        self.assertIn("export LIBCRAFTER_ENDPOINT_ROLE=target", lines)
        self.assertIn("export LIBCRAFTER_PRIVATE_IPV4=10.77.0.20", lines)
        self.assertIn("export LIBCRAFTER_PEER_PRIVATE_IPV4=10.77.0.10", lines)
        self.assertIn(
            "export LIBCRAFTER_BOOTSTRAP_ARTIFACT_DIR="
            "/opt/libcrafter-lab/session/artifacts/probe/bootstrap/target",
            lines,
        )
        self.assertIn(
            "apt-get install -y --no-install-recommends "
            "ca-certificates curl git iproute2 iputils-ping python3",
            lines,
        )
        self.assertIn("  printf '%s\\n' target_service_runtime=python3", lines)
        self.assertNotIn("cargo build", script)
        self.assertNotIn("rustup.rs", script)
        _assert_provider_neutral(self, script)

    def test_rejects_unknown_probe_bootstrap_role(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported probe bootstrap role"):
            bootstrap.repo_bootstrap_command(_bootstrap_context("router"))


def _script(command: RepoBootstrapCommand) -> str:
    self_check = command.argv[:2]
    if self_check != ["bash", "-lc"]:
        raise AssertionError(self_check)
    return command.argv[2]


def _assert_provider_neutral(test: unittest.TestCase, script: str) -> None:
    for fragment in (
        "rm -rf",
        "tar -xzf",
        "tools/endpoint/run",
        "hcloud",
        "VBoxManage",
        "qemu-system",
        "docker",
    ):
        test.assertNotIn(fragment, script)


def _bootstrap_context(role: str) -> RepoBootstrapContext:
    roles = [
        LabRole(name="stimulus", planned_ipv4="10.77.0.10", peer_roles=["target"]),
        LabRole(name="target", planned_ipv4="10.77.0.20", peer_roles=["stimulus"]),
    ]
    endpoints = [
        LabEndpoint(
            endpoint_id="endpoint-stimulus",
            role="stimulus",
            interface="eth1",
            ipv4="10.77.0.10",
            wire_manifest={"endpoint_id": "endpoint-stimulus"},
        ),
        LabEndpoint(
            endpoint_id="endpoint-target",
            role="target",
            interface="eth1",
            ipv4="10.77.0.20",
            wire_manifest={"endpoint_id": "endpoint-target"},
        ),
    ]
    if role == "router":
        selected_role = LabRole(name="router", planned_ipv4="10.77.0.30")
        selected_endpoint = LabEndpoint(
            endpoint_id="endpoint-router",
            role="router",
            interface="eth1",
            ipv4="10.77.0.30",
            wire_manifest={"endpoint_id": "endpoint-router"},
        )
        roles.append(selected_role)
        endpoints.append(selected_endpoint)
    session = LabSession(
        provider="qemu",
        wire_provider="qemu",
        wire_exposure="private",
        session_id="lab-qemu-probe-smoke-seed-1",
        roles=roles,
        endpoints=endpoints,
        remote_dir="/opt/libcrafter-lab/session",
        remote_artifact_root="/opt/libcrafter-lab/session/artifacts",
        created_endpoint_ids=[endpoint.endpoint_id for endpoint in endpoints],
        dry_run=False,
    )
    endpoints_by_role = {endpoint.role: endpoint for endpoint in endpoints}
    roles_by_name = {lab_role.name: lab_role for lab_role in roles}
    return RepoBootstrapContext(
        session=session,
        endpoint=endpoints_by_role[role],
        role=roles_by_name[role],
        remote_archive="/opt/libcrafter-lab/session/libcrafter-repo.tar.gz",
        remote_dir="/opt/libcrafter-lab/session",
        remote_artifact_root="/opt/libcrafter-lab/session/artifacts",
        endpoints_by_role=endpoints_by_role,
    )


if __name__ == "__main__":
    unittest.main()
