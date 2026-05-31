"""Coverage for the Docker wire provider."""

from __future__ import annotations

import os
import tempfile
import unittest
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from tools.wire.engine.model import EndpointManifest
from tools.wire.engine.process import CommandResult
from tools.wire.engine.providers import docker, resolve_provider
from tools.wire.engine.providers.docker.constants import (
    DOCKER_DEFAULT_IMAGE,
    DOCKER_DEFAULT_LAN_NETWORK,
    DOCKER_DEFAULT_PRIVATE_CIDR,
    DOCKER_DEFAULT_WAN_NETWORK,
    DOCKER_LAN_NETWORK_ENV,
    DOCKER_PRIVATE_CIDR_ENV,
    DOCKER_WAN_NETWORK_ENV,
    NAT_L3_CAPABILITIES,
    PRIVATE_CAPABILITIES,
)
from tools.wire.engine.registry import ProviderExposureError


class DockerRegistryTest(unittest.TestCase):
    def test_docker_supports_private_lan_and_wan_exposures(self) -> None:
        for exposure in ("private", "lan", "wan"):
            with self.subTest(exposure=exposure):
                self.assertIs(resolve_provider("docker", exposure), docker)

    def test_docker_rejects_wifi_exposure(self) -> None:
        with self.assertRaisesRegex(ProviderExposureError, "supported exposures"):
            resolve_provider("docker", "wifi")


class DockerDoctorTest(unittest.TestCase):
    def test_doctor_reports_supported_exposures(self) -> None:
        with mock.patch(
            "tools.wire.engine.providers.docker.doctor.shutil.which",
            side_effect=lambda command: f"/usr/bin/{command}",
        ):
            for exposure in ("private", "lan", "wan"):
                with self.subTest(exposure=exposure):
                    report = docker.doctor(
                        provider="docker",
                        exposure=exposure,
                        dry_run=True,
                        env={},
                        command_runner=_successful_runner,
                    )

                self.assertTrue(report["ok"])
                self.assertEqual(report["provider"], "docker")
                self.assertEqual(report["exposure"], exposure)
                self.assertTrue(_check(report, "provider_exposure")["ok"])
                self.assertEqual(
                    report["capabilities"]["wire"]["supported_exposures"],  # type: ignore[index]
                    ["lan", "private", "wan"],
                )

    def test_doctor_rejects_unsupported_exposure_before_provider_work(self) -> None:
        with self.assertRaisesRegex(ProviderExposureError, "supported exposures"):
            docker.doctor(
                provider="docker",
                exposure="wifi",
                dry_run=True,
                env={},
                command_runner=_fail_runner,
            )

    def test_doctor_reports_missing_docker_cli_without_running_commands(self) -> None:
        calls: list[tuple[str, ...]] = []

        def fake_runner(argv: Sequence[object], **_: object) -> CommandResult:
            calls.append(tuple(str(part) for part in argv))
            return _result(argv)

        with mock.patch(
            "tools.wire.engine.providers.docker.doctor.shutil.which",
            return_value=None,
        ):
            report = docker.doctor(
                provider="docker",
                exposure="private",
                dry_run=True,
                env={},
                command_runner=fake_runner,
            )

        self.assertFalse(report["ok"])
        self.assertEqual(calls, [])
        self.assertFalse(_check(report, "docker_cli_installed")["ok"])
        self.assertFalse(_check(report, "docker_daemon_reachable")["ok"])
        self.assertFalse(report["commands"]["docker"]["installed"])  # type: ignore[index]
        self.assertIsNone(report["commands"]["docker"]["path"])  # type: ignore[index]
        self.assertFalse(report["daemon"]["checked"])  # type: ignore[index]
        self.assertFalse(report["daemon"]["reachable"])  # type: ignore[index]

    def test_doctor_reports_unreachable_daemon(self) -> None:
        calls: list[tuple[str, ...]] = []

        def fake_runner(argv: Sequence[object], **_: object) -> CommandResult:
            parts = tuple(str(part) for part in argv)
            calls.append(parts)
            return _result(parts, exit_code=1, stderr="permission denied\n")

        with mock.patch(
            "tools.wire.engine.providers.docker.doctor.shutil.which",
            side_effect=lambda command: f"/usr/bin/{command}",
        ):
            report = docker.doctor(
                provider="docker",
                exposure="lan",
                dry_run=True,
                env={},
                command_runner=fake_runner,
            )

        self.assertFalse(report["ok"])
        self.assertEqual(calls, [_docker_version_argv()])
        self.assertFalse(_check(report, "docker_daemon_reachable")["ok"])
        self.assertFalse(report["daemon"]["reachable"])  # type: ignore[index]
        self.assertEqual(report["daemon"]["exit_code"], 1)  # type: ignore[index]
        self.assertEqual(report["daemon"]["error"], "permission denied")  # type: ignore[index]

    def test_doctor_reports_reachable_daemon(self) -> None:
        calls: list[tuple[str, ...]] = []

        def fake_runner(argv: Sequence[object], **_: object) -> CommandResult:
            parts = tuple(str(part) for part in argv)
            calls.append(parts)
            return _result(parts, stdout='{"Version":"25.0.0"}\n')

        with mock.patch(
            "tools.wire.engine.providers.docker.doctor.shutil.which",
            side_effect=lambda command: f"/usr/bin/{command}",
        ):
            report = docker.doctor(
                provider="docker",
                exposure="private",
                dry_run=True,
                env={},
                command_runner=fake_runner,
            )

        self.assertTrue(report["ok"])
        self.assertEqual(calls, [_docker_version_argv()])
        self.assertTrue(_check(report, "docker_daemon_reachable")["ok"])
        self.assertTrue(report["daemon"]["reachable"])  # type: ignore[index]
        self.assertEqual(report["daemon"]["stdout"], '{"Version":"25.0.0"}')  # type: ignore[index]

    def test_doctor_reports_invalid_private_cidr_environment(self) -> None:
        with mock.patch(
            "tools.wire.engine.providers.docker.doctor.shutil.which",
            side_effect=lambda command: f"/usr/bin/{command}",
        ):
            report = docker.doctor(
                provider="docker",
                exposure="private",
                dry_run=True,
                env={DOCKER_PRIVATE_CIDR_ENV: "not-a-cidr"},
                command_runner=_successful_runner,
            )

        self.assertFalse(report["ok"])
        configuration_check = _check(report, "docker_configuration")
        self.assertFalse(configuration_check["ok"])
        self.assertIn(DOCKER_PRIVATE_CIDR_ENV, str(configuration_check["message"]))
        private_network = report["configuration"]["networks"]["private"]  # type: ignore[index]
        self.assertEqual(private_network["cidr"], "not-a-cidr")
        self.assertEqual(private_network["default_cidr"], DOCKER_DEFAULT_PRIVATE_CIDR)

    def test_doctor_reports_configured_lan_and_wan_network_metadata(self) -> None:
        env = {
            DOCKER_LAN_NETWORK_ENV: "wire-lan-net",
            DOCKER_WAN_NETWORK_ENV: "wire-wan-net",
        }

        with mock.patch(
            "tools.wire.engine.providers.docker.doctor.shutil.which",
            side_effect=lambda command: f"/usr/bin/{command}",
        ):
            lan_report = docker.doctor(
                provider="docker",
                exposure="lan",
                dry_run=True,
                env=env,
                command_runner=_successful_runner,
            )
            wan_report = docker.doctor(
                provider="docker",
                exposure="wan",
                dry_run=True,
                env=env,
                command_runner=_successful_runner,
            )

        self.assertTrue(lan_report["ok"])
        self.assertTrue(wan_report["ok"])
        lan_network = lan_report["configuration"]["networks"]["lan"]  # type: ignore[index]
        wan_network = wan_report["configuration"]["networks"]["wan"]  # type: ignore[index]
        self.assertEqual(lan_network["network"], "wire-lan-net")
        self.assertEqual(lan_network["default"], DOCKER_DEFAULT_LAN_NETWORK)
        self.assertEqual(lan_network["type"], "nat-backed-l3-lan")
        self.assertEqual(wan_network["network"], "wire-wan-net")
        self.assertEqual(wan_network["default"], DOCKER_DEFAULT_WAN_NETWORK)
        self.assertEqual(wan_network["type"], "nat-backed-l3-egress")
        self.assertEqual(lan_report["configuration"]["selected_exposure"], "lan")  # type: ignore[index]
        self.assertEqual(wan_report["configuration"]["selected_exposure"], "wan")  # type: ignore[index]

    def test_doctor_reports_private_capabilities_and_security_model(self) -> None:
        with mock.patch(
            "tools.wire.engine.providers.docker.doctor.shutil.which",
            side_effect=lambda command: f"/usr/bin/{command}",
        ):
            report = docker.doctor(
                provider="docker",
                exposure="private",
                dry_run=True,
                env={},
                command_runner=_successful_runner,
            )

        wire = report["capabilities"]["wire"]  # type: ignore[index]
        container = report["capabilities"]["container"]  # type: ignore[index]
        self.assertEqual(set(wire["capabilities"]), set(PRIVATE_CAPABILITIES))
        self.assertIn("link_layer_send", wire["capabilities"])
        self.assertIn("link_layer_capture", wire["capabilities"])
        self.assertIn("broadcast", wire["capabilities"])
        self.assertIn("provider_mac_known", wire["capabilities"])
        self.assertIn("controlled_services", wire["capabilities"])
        self.assertNotIn("controlled_router", wire["capabilities"])
        self.assertEqual(container["cap_drop"], ["ALL"])
        self.assertEqual(container["cap_add"], ["NET_RAW", "NET_ADMIN"])
        self.assertTrue(container["no_new_privileges"])
        self.assertFalse(report["security_model"]["docker_socket_mounted"])  # type: ignore[index]
        self.assertFalse(report["security_model"]["privileged"])  # type: ignore[index]
        self.assertFalse(report["security_model"]["host_network"])  # type: ignore[index]

    def test_doctor_dry_run_uses_only_non_mutating_daemon_check(self) -> None:
        calls: list[tuple[str, ...]] = []
        timeouts: list[object] = []

        def fake_runner(argv: Sequence[object], **kwargs: object) -> CommandResult:
            parts = tuple(str(part) for part in argv)
            calls.append(parts)
            timeouts.append(kwargs.get("timeout"))
            return _result(parts, stdout='{"Version":"25.0.0"}')

        with mock.patch(
            "tools.wire.engine.providers.docker.doctor.shutil.which",
            side_effect=lambda command: f"/usr/bin/{command}",
        ):
            report = docker.doctor(
                provider="docker",
                exposure="wan",
                dry_run=True,
                env={},
                command_runner=fake_runner,
            )

        self.assertTrue(report["ok"])
        self.assertTrue(report["dry_run"])
        self.assertEqual(calls, [_docker_version_argv()])
        self.assertEqual(timeouts, [30])
        self.assertTrue(report["daemon"]["non_mutating"])  # type: ignore[index]
        self.assertEqual(tuple(report["daemon"]["command"]), _docker_version_argv())  # type: ignore[index]
        self.assertNotIn("run", calls[0])
        self.assertNotIn("create", calls[0])
        self.assertNotIn("network", calls[0])


class DockerCreateEndpointDryRunTest(unittest.TestCase):
    def test_private_dry_run_manifest_has_paths_resources_and_group_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            with mock.patch(
                "tools.wire.engine.providers.docker.create.free_localhost_tcp_port",
                return_value=27222,
            ):
                output = docker.create_endpoint(
                    provider="docker",
                    exposure="private",
                    role="oracle",
                    private_group="pair-a",
                    private_ip="10.79.0.42",
                    dry_run=True,
                    env={},
                )

        manifest = _assert_common_dry_run_manifest(
            self,
            output,
            temp_root=Path(temp_dir),
            endpoint_id="planned-docker-private-oracle-pair-a",
            exposure="private",
            role="oracle",
            ssh_port=27222,
        )
        self.assertEqual(manifest.provider, "docker")
        self.assertEqual(manifest.exposure, "private")

        metadata = output["metadata"]  # type: ignore[assignment]
        self.assertEqual(metadata["private_group"], "pair-a")  # type: ignore[index]
        self.assertEqual(metadata["private_group_source"], "requested")  # type: ignore[index]
        self.assertEqual(metadata["private_ip"], "10.79.0.42")  # type: ignore[index]
        self.assertEqual(metadata["private_ip_source"], "requested")  # type: ignore[index]

        capabilities = metadata["capabilities"]  # type: ignore[index]
        self.assertEqual(set(capabilities["capabilities"]), set(PRIVATE_CAPABILITIES))  # type: ignore[index]
        self.assertTrue(capabilities["link_layer_send"])  # type: ignore[index]
        self.assertTrue(capabilities["link_layer_capture"])  # type: ignore[index]
        self.assertTrue(capabilities["broadcast"])  # type: ignore[index]
        self.assertTrue(capabilities["provider_mac_known"])  # type: ignore[index]
        self.assertFalse(capabilities["controlled_router"])  # type: ignore[index]

        private_network = metadata["private_network"]  # type: ignore[index]
        self.assertEqual(private_network["network_name"], "wire-private-pair-a")  # type: ignore[index]
        self.assertEqual(private_network["cidr"], DOCKER_DEFAULT_PRIVATE_CIDR)  # type: ignore[index]
        self.assertTrue(private_network["internal"])  # type: ignore[index]
        self.assertTrue(private_network["same_segment"])  # type: ignore[index]
        self.assertTrue(private_network["l2_segment"])  # type: ignore[index]
        self.assertFalse(private_network["controlled_router"])  # type: ignore[index]

        group_record = metadata["private_group_record"]  # type: ignore[index]
        self.assertEqual(group_record["provider"], "docker")  # type: ignore[index]
        self.assertEqual(group_record["group"], "pair-a")  # type: ignore[index]
        self.assertEqual(group_record["private_cidr"], DOCKER_DEFAULT_PRIVATE_CIDR)  # type: ignore[index]
        self.assertEqual(
            group_record["network_resource"]["network_id"],  # type: ignore[index]
            "wire-private-pair-a",
        )
        self.assertEqual(
            group_record["planned_allocation"]["endpoint_id"],  # type: ignore[index]
            "planned-docker-private-oracle-pair-a",
        )
        self.assertEqual(
            group_record["planned_allocation"]["private_ipv4"],  # type: ignore[index]
            "10.79.0.42",
        )
        self.assertTrue(Path(str(group_record["record_path"])).is_absolute())  # type: ignore[index]

        interfaces = output["interfaces"]  # type: ignore[assignment]
        self.assertEqual(len(interfaces), 1)
        interface = interfaces[0]
        self.assertEqual(interface["name"], "eth0")
        self.assertEqual(interface["exposure"], "private")
        self.assertEqual(interface["ipv4"], "10.79.0.42")
        self.assertEqual(interface["provider_network_id"], "wire-private-pair-a")
        self.assertEqual(interface["metadata"]["type"], "docker-private-bridge")  # type: ignore[index]
        self.assertEqual(interface["metadata"]["private_group"], "pair-a")  # type: ignore[index]
        self.assertTrue(interface["metadata"]["same_segment"])  # type: ignore[index]
        self.assertTrue(interface["metadata"]["l2_segment"])  # type: ignore[index]
        self.assertTrue(interface["metadata"]["provider_mac_known"])  # type: ignore[index]

        resources = _resources_by_name(output)
        self.assertTrue(resources["wire-private-pair-a"]["cleanup"])  # type: ignore[index]
        self.assertEqual(
            resources["wire-private-pair-a"]["metadata"]["private_group"],  # type: ignore[index]
            "pair-a",
        )
        container = metadata["docker"]["container"]  # type: ignore[index]
        self.assertIn("--cap-add", container["run_argv"])  # type: ignore[index]
        self.assertIn("NET_ADMIN", container["run_argv"])  # type: ignore[index]
        self.assertEqual(container["private_ipv4"], "10.79.0.42")  # type: ignore[index]
        self.assertEqual(container["private_network"], "wire-private-pair-a")  # type: ignore[index]

    def test_lan_and_wan_dry_run_manifests_are_nat_l3_and_conservative(self) -> None:
        cases = {
            "lan": {
                "role": "probe",
                "port": 27322,
                "env": {DOCKER_LAN_NETWORK_ENV: "wire-lan-test"},
                "network_key": "lan_network",
                "network_name": "wire-lan-test",
                "network_type": "docker-nat-l3-lan-network",
                "mode": "nat-backed-l3-lan",
                "capability_flag": "nat_backed_l3_lan",
                "negative_l2_flag": "true_lan_l2",
            },
            "wan": {
                "role": "client",
                "port": 27323,
                "env": {DOCKER_WAN_NETWORK_ENV: "wire-wan-test"},
                "network_key": "wan_network",
                "network_name": "wire-wan-test",
                "network_type": "docker-nat-l3-wan-network",
                "mode": "nat-backed-l3-wan-egress",
                "capability_flag": "nat_backed_l3_egress",
                "negative_l2_flag": "wan_l2",
            },
        }

        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            for exposure, case in cases.items():
                with self.subTest(exposure=exposure):
                    with mock.patch(
                        "tools.wire.engine.providers.docker.create.free_localhost_tcp_port",
                        return_value=case["port"],
                    ):
                        output = docker.create_endpoint(
                            provider="docker",
                            exposure=exposure,
                            role=str(case["role"]),
                            dry_run=True,
                            env=case["env"],  # type: ignore[arg-type]
                        )

                    endpoint_id = f"planned-docker-{exposure}-{case['role']}"
                    manifest = _assert_common_dry_run_manifest(
                        self,
                        output,
                        temp_root=Path(temp_dir),
                        endpoint_id=endpoint_id,
                        exposure=exposure,
                        role=str(case["role"]),
                        ssh_port=int(case["port"]),
                    )
                    self.assertEqual(manifest.exposure, exposure)

                    metadata = output["metadata"]  # type: ignore[assignment]
                    self.assertNotIn("private_group", metadata)
                    self.assertNotIn("private_group_record", metadata)
                    self.assertNotIn("private_ip", metadata)

                    capabilities = metadata["capabilities"]  # type: ignore[index]
                    _assert_nat_l3_capabilities(
                        self,
                        capabilities,  # type: ignore[arg-type]
                        exposure=exposure,
                        expected_flag=str(case["capability_flag"]),
                        expected_l2_false_flag=str(case["negative_l2_flag"]),
                    )

                    docker_metadata = metadata["docker"]  # type: ignore[index]
                    security = docker_metadata["security"]  # type: ignore[index]
                    self.assertEqual(security["cap_drop"], ["ALL"])  # type: ignore[index]
                    self.assertEqual(security["cap_add"], ["NET_RAW"])  # type: ignore[index]
                    self.assertTrue(security["net_raw_only"])  # type: ignore[index]
                    self.assertFalse(security["net_admin"])  # type: ignore[index]
                    self.assertFalse(security["host_network"])  # type: ignore[index]
                    self.assertFalse(security["privileged"])  # type: ignore[index]
                    self.assertFalse(security["docker_socket_mounted"])  # type: ignore[index]

                    network = metadata[case["network_key"]]  # type: ignore[index]
                    self.assertEqual(network["network_name"], case["network_name"])  # type: ignore[index]
                    self.assertEqual(network["configured_network"], case["network_name"])  # type: ignore[index]
                    self.assertEqual(network["source"], "env")  # type: ignore[index]
                    self.assertEqual(network["type"], case["network_type"])  # type: ignore[index]
                    self.assertTrue(network["nat"])  # type: ignore[index]
                    self.assertTrue(network["nat_backed_l3"])  # type: ignore[index]
                    self.assertTrue(network[case["capability_flag"]])  # type: ignore[index]
                    self.assertFalse(network["owned_by_provider"])  # type: ignore[index]
                    self.assertFalse(network["cleanup"])  # type: ignore[index]
                    self.assertFalse(network["l2"])  # type: ignore[index]
                    self.assertFalse(network["broadcast"])  # type: ignore[index]
                    self.assertFalse(network["controlled_router"])  # type: ignore[index]
                    self.assertFalse(network["public_inbound_reachability"])  # type: ignore[index]
                    self.assertEqual(network["docker_capabilities"], ["NET_RAW"])  # type: ignore[index]

                    interface = output["interfaces"][0]  # type: ignore[index]
                    self.assertEqual(interface["name"], "eth0")
                    self.assertEqual(interface["exposure"], exposure)
                    self.assertIsNone(interface["ipv4"])
                    self.assertIsNone(interface["mac"])
                    self.assertEqual(interface["provider_network_id"], case["network_name"])
                    self.assertEqual(interface["metadata"]["network_name"], case["network_name"])  # type: ignore[index]
                    self.assertTrue(interface["metadata"][case["capability_flag"]])  # type: ignore[index]
                    self.assertFalse(interface["metadata"]["link_layer_send"])  # type: ignore[index]
                    self.assertFalse(interface["metadata"]["link_layer_capture"])  # type: ignore[index]
                    self.assertFalse(interface["metadata"]["provider_mac_known"])  # type: ignore[index]
                    self.assertFalse(interface["metadata"]["broadcast"])  # type: ignore[index]
                    self.assertFalse(interface["metadata"]["controlled_router"])  # type: ignore[index]
                    self.assertFalse(interface["metadata"][case["negative_l2_flag"]])  # type: ignore[index]

                    resources = _resources_by_name(output)
                    self.assertFalse(resources[case["network_name"]]["cleanup"])  # type: ignore[index]
                    self.assertEqual(
                        output["provider_resources"]["metadata"]["mode"],  # type: ignore[index]
                        case["mode"],
                    )

    def test_lan_and_wan_reject_private_options(self) -> None:
        for exposure in ("lan", "wan"):
            with self.subTest(exposure=exposure, option="private_group"):
                with self.assertRaisesRegex(ValueError, "--private-group"):
                    docker.create_endpoint(
                        provider="docker",
                        exposure=exposure,
                        role="probe",
                        private_group="pair-a",
                        dry_run=True,
                        env={},
                    )
            with self.subTest(exposure=exposure, option="private_ip"):
                with self.assertRaisesRegex(ValueError, "--private-ip"):
                    docker.create_endpoint(
                        provider="docker",
                        exposure=exposure,
                        role="probe",
                        private_ip="10.79.0.42",
                        dry_run=True,
                        env={},
                    )


def _check(report: dict[str, object], name: str) -> dict[str, object]:
    for check in report["checks"]:  # type: ignore[union-attr]
        if check["name"] == name:
            return check
    raise AssertionError(f"missing check {name!r}")


def _assert_common_dry_run_manifest(
    case: unittest.TestCase,
    output: dict[str, object],
    *,
    temp_root: Path,
    endpoint_id: str,
    exposure: str,
    role: str,
    ssh_port: int,
) -> EndpointManifest:
    case.assertFalse(output["created"])
    case.assertTrue(output["dry_run"])
    case.assertEqual(output["status"], "planned")
    case.assertEqual(output["provider"], "docker")
    case.assertEqual(output["exposure"], exposure)
    case.assertEqual(output["role"], role)
    case.assertEqual(output["endpoint_id"], endpoint_id)

    expected_state_dir = temp_root / "wire-state" / "endpoints" / endpoint_id
    expected_artifact_dir = temp_root / "wire-artifacts" / endpoint_id
    expected_manifest_path = expected_state_dir / "endpoint.json"
    expected_private_key = expected_state_dir / "id_ed25519"
    expected_public_key = expected_state_dir / "id_ed25519.pub"
    expected_known_hosts = expected_state_dir / "known_hosts"

    case.assertEqual(Path(str(output["state_dir"])), expected_state_dir)
    case.assertEqual(Path(str(output["artifact_dir"])), expected_artifact_dir)
    case.assertEqual(Path(str(output["manifest_path"])), expected_manifest_path)
    case.assertTrue(Path(str(output["state_dir"])).is_absolute())
    case.assertTrue(Path(str(output["artifact_dir"])).is_absolute())
    case.assertTrue(Path(str(output["manifest_path"])).is_absolute())

    ssh = output["ssh"]  # type: ignore[assignment]
    case.assertEqual(ssh["host"], "127.0.0.1")  # type: ignore[index]
    case.assertEqual(ssh["user"], "root")  # type: ignore[index]
    case.assertEqual(ssh["port"], ssh_port)  # type: ignore[index]
    case.assertEqual(Path(str(ssh["identity_file"])), expected_private_key)  # type: ignore[index]
    case.assertEqual(Path(str(ssh["known_hosts_file"])), expected_known_hosts)  # type: ignore[index]
    case.assertTrue(Path(str(ssh["identity_file"])).is_absolute())  # type: ignore[index]
    case.assertTrue(Path(str(ssh["known_hosts_file"])).is_absolute())  # type: ignore[index]
    ssh_metadata = ssh["metadata"]  # type: ignore[index]
    case.assertTrue(ssh_metadata["planned"])  # type: ignore[index]
    case.assertEqual(ssh_metadata["transport"], "docker-localhost-port-forward")  # type: ignore[index]
    case.assertEqual(ssh_metadata["host"], "127.0.0.1")  # type: ignore[index]
    case.assertEqual(ssh_metadata["host_port"], ssh_port)  # type: ignore[index]
    case.assertEqual(ssh_metadata["guest_port"], 22)  # type: ignore[index]
    case.assertEqual(
        ssh_metadata["container_name"],  # type: ignore[index]
        f"wire-container-{endpoint_id}",
    )
    key_paths = ssh_metadata["endpoint_key_paths"]  # type: ignore[index]
    case.assertEqual(Path(str(key_paths["private_key"])), expected_private_key)  # type: ignore[index]
    case.assertEqual(Path(str(key_paths["public_key"])), expected_public_key)  # type: ignore[index]
    case.assertEqual(Path(str(key_paths["known_hosts"])), expected_known_hosts)  # type: ignore[index]
    for path in key_paths.values():  # type: ignore[union-attr]
        case.assertTrue(Path(str(path)).is_absolute())

    metadata = output["metadata"]  # type: ignore[assignment]
    case.assertTrue(metadata["dry_run"])  # type: ignore[index]
    case.assertFalse(metadata["created"])  # type: ignore[index]
    case.assertEqual(Path(str(metadata["state_dir"])), expected_state_dir)  # type: ignore[index]
    case.assertEqual(Path(str(metadata["manifest_path"])), expected_manifest_path)  # type: ignore[index]
    docker_metadata = metadata["docker"]  # type: ignore[index]
    case.assertEqual(docker_metadata["command"], "docker")  # type: ignore[index]

    image = metadata["docker_image"]  # type: ignore[index]
    case.assertEqual(image["tag"], DOCKER_DEFAULT_IMAGE)  # type: ignore[index]
    case.assertEqual(image["default"], DOCKER_DEFAULT_IMAGE)  # type: ignore[index]
    case.assertTrue(image["uses_default"])  # type: ignore[index]
    case.assertFalse(image["rebuild_requested"])  # type: ignore[index]
    case.assertTrue(Path(str(image["context_dir"])).is_absolute())  # type: ignore[index]
    case.assertTrue(Path(str(image["dockerfile_path"])).is_absolute())  # type: ignore[index]
    case.assertEqual(Path(str(image["command_log_path"])).parent, expected_artifact_dir)  # type: ignore[index]
    case.assertEqual(
        image["inspect_argv"],  # type: ignore[index]
        ["docker", "image", "inspect", DOCKER_DEFAULT_IMAGE],
    )
    case.assertIn(DOCKER_DEFAULT_IMAGE, image["build_argv"])  # type: ignore[index]

    provider_resources = output["provider_resources"]  # type: ignore[assignment]
    case.assertEqual(
        provider_resources["cleanup_order"],  # type: ignore[index]
        ["docker-container", "docker-network", "local-file"],
    )
    case.assertEqual(provider_resources["metadata"]["provider"], "docker")  # type: ignore[index]
    case.assertEqual(provider_resources["metadata"]["exposure"], exposure)  # type: ignore[index]
    case.assertTrue(provider_resources["metadata"]["planned"])  # type: ignore[index]

    resources = provider_resources["resources"]  # type: ignore[index]
    resource_kinds = {resource["kind"] for resource in resources}  # type: ignore[union-attr]
    case.assertIn("docker-container", resource_kinds)
    case.assertIn("docker-network", resource_kinds)
    case.assertIn("docker-image", resource_kinds)
    case.assertIn("local-file", resource_kinds)
    resource_names = {resource["name"] for resource in resources}  # type: ignore[union-attr]
    case.assertEqual(
        {
            "ssh-private-key",
            "ssh-public-key",
            "ssh-known-hosts",
            "endpoint-state-dir",
            "endpoint-manifest",
            "endpoint-artifact-dir",
        },
        resource_names
        & {
            "ssh-private-key",
            "ssh-public-key",
            "ssh-known-hosts",
            "endpoint-state-dir",
            "endpoint-manifest",
            "endpoint-artifact-dir",
        },
    )
    local_paths = [
        resource["provider_id"]
        for resource in resources
        if resource["kind"] == "local-file"  # type: ignore[index]
    ]
    for path in local_paths:
        case.assertTrue(Path(str(path)).is_absolute())

    artifact_paths = metadata["artifact_paths"]  # type: ignore[index]
    case.assertEqual(Path(str(artifact_paths["artifact_dir"])), expected_artifact_dir)  # type: ignore[index]
    artifact_names = {path["name"] for path in artifact_paths["paths"]}  # type: ignore[index]
    case.assertIn("docker-image-command-log", artifact_names)
    for path in artifact_paths["paths"]:  # type: ignore[index]
        case.assertTrue(Path(str(path["path"])).is_absolute())

    manifest = EndpointManifest.from_dict(output)
    case.assertEqual(manifest.endpoint_id, endpoint_id)
    case.assertEqual(manifest.provider, "docker")
    case.assertEqual(manifest.exposure, exposure)
    case.assertEqual(manifest.role, role)
    case.assertEqual(manifest.status, "planned")
    case.assertEqual(manifest.artifact_dir, str(expected_artifact_dir))
    return manifest


def _assert_nat_l3_capabilities(
    case: unittest.TestCase,
    capabilities: Mapping[str, object],
    *,
    exposure: str,
    expected_flag: str,
    expected_l2_false_flag: str,
) -> None:
    case.assertEqual(capabilities["provider"], "docker")
    case.assertEqual(capabilities["exposure"], exposure)
    case.assertEqual(set(capabilities["capabilities"]), set(NAT_L3_CAPABILITIES))  # type: ignore[arg-type]
    case.assertTrue(capabilities["ipv4_unicast"])
    case.assertFalse(capabilities["ipv6_unicast"])
    case.assertFalse(capabilities["link_layer_send"])
    case.assertFalse(capabilities["link_layer_capture"])
    case.assertFalse(capabilities["broadcast"])
    case.assertFalse(capabilities["provider_mac_known"])
    case.assertFalse(capabilities["controlled_services"])
    case.assertFalse(capabilities["controlled_router"])
    case.assertFalse(capabilities["same_segment_l2"])
    case.assertFalse(capabilities["same_segment_l3"])
    case.assertFalse(capabilities["l2"])
    case.assertTrue(capabilities["l3"])
    case.assertTrue(capabilities["nat_backed_l3"])
    case.assertTrue(capabilities[expected_flag])
    case.assertFalse(capabilities[expected_l2_false_flag])
    case.assertFalse(capabilities["link_layer_fidelity"])
    case.assertFalse(capabilities["public_inbound_reachability"])
    case.assertEqual(capabilities["docker_capabilities"], ["NET_RAW"])


def _resources_by_name(output: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    provider_resources = output["provider_resources"]
    if not isinstance(provider_resources, Mapping):
        raise AssertionError("provider_resources must be an object")
    resources = provider_resources["resources"]
    if not isinstance(resources, Sequence):
        raise AssertionError("provider_resources.resources must be a sequence")
    resources_by_name: dict[str, Mapping[str, object]] = {}
    for resource in resources:
        if not isinstance(resource, Mapping):
            raise AssertionError("provider resource must be an object")
        name = resource.get("name")
        if isinstance(name, str):
            resources_by_name[name] = resource
    return resources_by_name


@contextmanager
def _wire_env(root: Path, extra: Mapping[str, str] | None = None) -> Iterator[None]:
    env = {
        "LIBCRAFTER_WIRE_STATE_ROOT": str(root / "wire-state"),
        "LIBCRAFTER_WIRE_ARTIFACT_ROOT": str(root / "wire-artifacts"),
    }
    if extra is not None:
        env.update(extra)
    old_values = {key: os.environ.get(key) for key in env}
    os.environ.update(env)
    try:
        yield
    finally:
        for key, value in old_values.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _docker_version_argv() -> tuple[str, ...]:
    return ("docker", "version", "--format", "{{json .Server}}")


def _successful_runner(argv: Sequence[object], **_: object) -> CommandResult:
    return _result(argv, stdout='{"Version":"25.0.0"}')


def _fail_runner(argv: Sequence[object], **_: object) -> CommandResult:
    return _result(argv, exit_code=1, stderr="unexpected command\n")


def _result(
    argv: Sequence[object],
    *,
    exit_code: int = 0,
    stdout: str = "",
    stderr: str = "",
    error: str | None = None,
) -> CommandResult:
    parts = tuple(str(part) for part in argv)
    return CommandResult(
        argv=parts,
        redacted_argv=parts,
        cwd=None,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        error=error,
    )
