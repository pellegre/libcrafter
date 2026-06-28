"""Coverage for resolving endpoint manifests into appliance targets."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.appliance.engine.profile import ApplianceProfile
from tools.appliance.engine.ssh_docker import SSHDockerHostTarget
from tools.endpoint.engine.appliance import (
    DEFAULT_APPLIANCE_REMOTE_BASE,
    EndpointApplianceTarget,
    read_endpoint_appliance_target,
    render_endpoint_appliance_run_plan,
    resolve_endpoint_appliance_target,
)
from tools.endpoint.engine.config import WireConfig
from tools.endpoint.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResource,
    ProviderResources,
)
from tools.endpoint.engine.state import write_endpoint_manifest


class EndpointApplianceTargetTest(unittest.TestCase):
    def test_hetzner_manifest_resolves_to_ssh_docker_host_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(
                root,
                endpoint_id="hetzner-a",
                provider="hetzner",
                exposure="wan",
                ssh_host="192.0.2.10",
                interface=NetworkInterface(
                    name="eth0",
                    exposure="wan",
                    ipv4="192.0.2.10",
                    metadata={"provider": "hetzner"},
                ),
            )

            resolved = resolve_endpoint_appliance_target(manifest)

        self.assertIsInstance(resolved, EndpointApplianceTarget)
        self.assertIsInstance(resolved.target, SSHDockerHostTarget)
        self.assertEqual(resolved.target.host, "192.0.2.10")
        self.assertEqual(resolved.target.user, "root")
        self.assertEqual(
            resolved.target.remote_work_root,
            f"{DEFAULT_APPLIANCE_REMOTE_BASE}/hetzner-a/work",
        )
        self.assertEqual(
            resolved.target.remote_artifact_root,
            f"{DEFAULT_APPLIANCE_REMOTE_BASE}/hetzner-a/artifacts",
        )
        appliance = resolved.target.metadata["appliance"]
        self.assertEqual(appliance["target_kind"], "ssh-docker-host")  # type: ignore[index]
        self.assertFalse(appliance["docker_endpoint_container"])  # type: ignore[index]
        self.assertTrue(appliance["nested_docker"])  # type: ignore[index]
        self.assertTrue(appliance["docker_execution_supported"])  # type: ignore[index]
        self.assertEqual(resolved.interfaces[0].name, "eth0")
        json.loads(resolved.to_json())

    def test_qemu_manifest_can_override_remote_base_and_resolve_from_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = WireConfig(
                state_root=root / "state",
                artifact_root=root / "artifacts",
            )
            manifest = _manifest(
                root,
                endpoint_id="qemu-a",
                provider="qemu",
                exposure="private",
                ssh_host="127.0.0.1",
                ssh_port=2201,
                interface=NetworkInterface(
                    name="enp0s1",
                    exposure="private",
                    ipv4="10.42.19.10",
                    provider_network_id="qemu-private-a",
                    metadata={"source": "qemu-synthetic"},
                ),
                metadata={"appliance": {"remote_base": "/root/libcrafter-appliance"}},
            )

            write_endpoint_manifest(manifest, config)
            resolved = read_endpoint_appliance_target("qemu-a", config)

        self.assertEqual(resolved.provider, "qemu")
        self.assertEqual(resolved.target.port, 2201)
        self.assertEqual(resolved.target.remote_work_root, "/root/libcrafter-appliance/qemu-a/work")
        self.assertEqual(
            resolved.target.remote_artifact_root,
            "/root/libcrafter-appliance/qemu-a/artifacts",
        )
        self.assertEqual(
            resolved.target.metadata["interfaces"][0]["provider_network_id"],  # type: ignore[index]
            "qemu-private-a",
        )

    def test_virtualbox_manifest_can_override_remote_roots_and_docker_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            resolved = resolve_endpoint_appliance_target(
                _manifest(
                    root,
                    endpoint_id="vbox-a",
                    provider="virtualbox",
                    exposure="lan",
                    ssh_host="127.0.0.1",
                    ssh_port=2222,
                    interface=NetworkInterface(
                        name="enp0s8",
                        exposure="lan",
                        ipv4="198.51.100.20",
                        metadata={"source": "virtualbox-synthetic"},
                    ),
                    metadata={
                        "appliance": {
                            "remote_work_root": "/var/lib/libcrafter/appliance/vbox-a/w",
                            "remote_artifact_root": "/var/lib/libcrafter/appliance/vbox-a/a",
                            "docker_command": "podman",
                        }
                    },
                )
            )

        self.assertEqual(resolved.target.remote_work_root, "/var/lib/libcrafter/appliance/vbox-a/w")
        self.assertEqual(
            resolved.target.remote_artifact_root,
            "/var/lib/libcrafter/appliance/vbox-a/a",
        )
        self.assertEqual(resolved.target.docker_command, "podman")
        self.assertEqual(
            resolved.target.metadata["provider_resources"]["resources"][0]["kind"],  # type: ignore[index]
            "virtualbox-vm",
        )

    def test_docker_endpoint_container_disables_nested_docker_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            resolved = resolve_endpoint_appliance_target(
                _docker_manifest(
                    root,
                    metadata={
                        "docker": {
                            "container": {
                                "type": "docker-container",
                                "container_name": "endpoint-docker-a",
                                "hostname": "endpoint-docker-a",
                            }
                        }
                    },
                )
            )

        self.assertEqual(resolved.provider, "docker")
        self.assertEqual(resolved.target.host, "127.0.0.1")
        self.assertEqual(resolved.target.port, 27222)
        appliance = resolved.target.metadata["appliance"]
        self.assertEqual(appliance["target_kind"], "docker-endpoint-container")  # type: ignore[index]
        self.assertTrue(appliance["docker_endpoint_container"])  # type: ignore[index]
        self.assertFalse(appliance["appliance_capable"])  # type: ignore[index]
        self.assertFalse(appliance["nested_docker"])  # type: ignore[index]
        self.assertFalse(appliance["docker_execution_supported"])  # type: ignore[index]
        self.assertEqual(
            appliance["docker_execution_disabled_reason"],  # type: ignore[index]
            "endpoint is already a Docker container",
        )
        self.assertEqual(
            resolved.target.metadata["docker_container"]["container_name"],  # type: ignore[index]
            "endpoint-docker-a",
        )

    def test_docker_endpoint_appliance_container_is_explicit_without_nested_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            resolved = resolve_endpoint_appliance_target(
                _docker_manifest(
                    root,
                    metadata={
                        "appliance": {"appliance_capable": True},
                        "docker": {
                            "container": {
                                "type": "docker-container",
                                "container_name": "appliance-container-a",
                                "appliance_capable": True,
                            }
                        },
                    },
                )
            )

        appliance = resolved.target.metadata["appliance"]
        self.assertEqual(
            appliance["target_kind"],  # type: ignore[index]
            "docker-endpoint-appliance-container",
        )
        self.assertTrue(appliance["appliance_capable"])  # type: ignore[index]
        self.assertFalse(appliance["nested_docker"])  # type: ignore[index]
        self.assertFalse(appliance["docker_execution_supported"])  # type: ignore[index]

    def test_docker_endpoint_appliance_container_rejects_nested_run_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            resolved = resolve_endpoint_appliance_target(
                _docker_manifest(
                    root,
                    metadata={
                        "appliance": {"appliance_capable": True},
                        "docker": {
                            "container": {
                                "type": "docker-container",
                                "container_name": "appliance-container-a",
                                "appliance_capable": True,
                            }
                        },
                    },
                )
            )

        appliance = resolved.target.metadata["appliance"]
        self.assertEqual(
            appliance["target_kind"],  # type: ignore[index]
            "docker-endpoint-appliance-container",
        )
        self.assertFalse(appliance["nested_docker"])  # type: ignore[index]
        self.assertFalse(appliance["docker_execution_supported"])  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "endpoint is already a Docker container"):
            render_endpoint_appliance_run_plan(
                resolved,
                ApplianceProfile(
                    name="wan-raw",
                    network_mode="host",
                    cap_add=["NET_RAW"],
                ),
                ["true"],
            )

    def test_missing_ssh_identity_is_rejected_before_target_rendering(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(
                root,
                endpoint_id="missing-key",
                provider="hetzner",
                exposure="wan",
                ssh_host="192.0.2.40",
                interface=NetworkInterface(name="eth0", exposure="wan"),
            )
            manifest = EndpointManifest(
                endpoint_id=manifest.endpoint_id,
                provider=manifest.provider,
                exposure=manifest.exposure,
                status=manifest.status,
                role=manifest.role,
                created_at=manifest.created_at,
                ssh=EndpointSSHInfo(
                    host=manifest.ssh.host,
                    user=manifest.ssh.user,
                    known_hosts_file=manifest.ssh.known_hosts_file,
                ),
                interfaces=manifest.interfaces,
                provider_resources=manifest.provider_resources,
                artifact_dir=manifest.artifact_dir,
                metadata=manifest.metadata,
            )

            with self.assertRaisesRegex(ValueError, "ssh.identity_file"):
                resolve_endpoint_appliance_target(manifest)


def _manifest(
    root: Path,
    *,
    endpoint_id: str,
    provider: str,
    exposure: str,
    ssh_host: str,
    interface: NetworkInterface,
    ssh_port: int = 22,
    metadata: dict[str, object] | None = None,
) -> EndpointManifest:
    return EndpointManifest(
        endpoint_id=endpoint_id,
        provider=provider,
        exposure=exposure,
        status="active",
        role="probe",
        created_at="2026-06-28T00:00:00Z",
        ssh=EndpointSSHInfo(
            host=ssh_host,
            user="root",
            port=ssh_port,
            identity_file=str(root / "state" / endpoint_id / "id_ed25519"),
            known_hosts_file=str(root / "state" / endpoint_id / "known_hosts"),
            metadata={"created_by": "tools/endpoint-test"},
        ),
        interfaces=[interface],
        provider_resources=ProviderResources(
            resources=[
                ProviderResource(
                    kind=f"{provider}-vm",
                    provider_id=f"{provider}-{endpoint_id}",
                    cleanup=True,
                    metadata={"synthetic": True},
                )
            ],
            metadata={"synthetic": True},
        ),
        artifact_dir=str(root / "artifacts" / endpoint_id),
        metadata={} if metadata is None else metadata,
    )


def _docker_manifest(root: Path, *, metadata: dict[str, object]) -> EndpointManifest:
    return EndpointManifest(
        endpoint_id="docker-a",
        provider="docker",
        exposure="private",
        status="active",
        role="oracle",
        created_at="2026-06-28T00:00:00Z",
        ssh=EndpointSSHInfo(
            host="127.0.0.1",
            user="root",
            port=27222,
            identity_file=str(root / "state" / "docker-a" / "id_ed25519"),
            known_hosts_file=str(root / "state" / "docker-a" / "known_hosts"),
            metadata={
                "transport": "docker-localhost-port-forward",
                "container_name": "endpoint-docker-a",
            },
        ),
        interfaces=[
            NetworkInterface(
                name="eth0",
                exposure="private",
                ipv4="10.79.0.42",
                provider_network_id="wire-private-pair-a",
                metadata={"type": "docker-private-bridge", "same_segment": True},
            )
        ],
        provider_resources=ProviderResources(
            resources=[
                ProviderResource(
                    kind="docker-container",
                    provider_id="endpoint-docker-a",
                    name="endpoint-docker-a",
                    cleanup=True,
                    metadata={"synthetic": True},
                )
            ]
        ),
        artifact_dir=str(root / "artifacts" / "docker-a"),
        metadata=metadata,
    )


if __name__ == "__main__":
    unittest.main()
