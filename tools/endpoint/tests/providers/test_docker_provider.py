"""Coverage for the Docker endpoint provider."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from unittest import mock

from tools.endpoint.engine.model import EndpointManifest
from tools.endpoint.engine.process import CommandResult
from tools.endpoint.engine.providers import docker, resolve_provider
from tools.endpoint.engine.providers.docker.constants import (
    CONFIRMATION_ERROR,
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
from tools.endpoint.engine.providers.docker.resources import docker_hostname
from tools.endpoint.engine.registry import ProviderExposureError
from tools.endpoint.engine.state import update_private_group_allocation


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
            "tools.endpoint.engine.providers.docker.doctor.shutil.which",
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
                    report["capabilities"]["packet_io"]["supported_exposures"],  # type: ignore[index]
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
            "tools.endpoint.engine.providers.docker.doctor.shutil.which",
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
            "tools.endpoint.engine.providers.docker.doctor.shutil.which",
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
            "tools.endpoint.engine.providers.docker.doctor.shutil.which",
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
            "tools.endpoint.engine.providers.docker.doctor.shutil.which",
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
            "tools.endpoint.engine.providers.docker.doctor.shutil.which",
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
            "tools.endpoint.engine.providers.docker.doctor.shutil.which",
            side_effect=lambda command: f"/usr/bin/{command}",
        ):
            report = docker.doctor(
                provider="docker",
                exposure="private",
                dry_run=True,
                env={},
                command_runner=_successful_runner,
            )

        packet_io = report["capabilities"]["packet_io"]  # type: ignore[index]
        container = report["capabilities"]["container"]  # type: ignore[index]
        self.assertEqual(set(packet_io["capabilities"]), set(PRIVATE_CAPABILITIES))
        self.assertIn("link_layer_send", packet_io["capabilities"])
        self.assertIn("link_layer_capture", packet_io["capabilities"])
        self.assertIn("broadcast", packet_io["capabilities"])
        self.assertIn("provider_mac_known", packet_io["capabilities"])
        self.assertIn("controlled_services", packet_io["capabilities"])
        self.assertNotIn("controlled_router", packet_io["capabilities"])
        self.assertEqual(container["cap_drop"], ["ALL"])
        self.assertEqual(
            container["cap_add"],
            ["NET_RAW", "NET_ADMIN", "SYS_CHROOT", "SETGID", "SETUID"],
        )
        self.assertFalse(container["no_new_privileges"])
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
            "tools.endpoint.engine.providers.docker.doctor.shutil.which",
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
                "tools.endpoint.engine.providers.docker.create.free_localhost_tcp_port",
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
        self.assertIn("SYS_CHROOT", container["run_argv"])  # type: ignore[index]
        self.assertEqual(container["private_ipv4"], "10.79.0.42")  # type: ignore[index]
        self.assertEqual(container["private_network"], "wire-private-pair-a")  # type: ignore[index]

    def test_private_dry_run_uses_bounded_hostname_for_long_endpoint_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            with mock.patch(
                "tools.endpoint.engine.providers.docker.create.free_localhost_tcp_port",
                return_value=27222,
            ):
                output = docker.create_endpoint(
                    provider="docker",
                    exposure="private",
                    role="docker-private-smoke-receiver",
                    private_group="docker-private-smoke",
                    private_ip="10.79.0.20",
                    dry_run=True,
                    env={},
                )

        endpoint_id = "planned-docker-private-docker-private-smoke-receiver-docker-private-smoke"
        self.assertEqual(output["endpoint_id"], endpoint_id)

        container = output["metadata"]["docker"]["container"]  # type: ignore[index]
        hostname = _option_values(container["run_argv"], "--hostname")[0]  # type: ignore[index]
        self.assertEqual(hostname, docker_hostname(endpoint_id))
        self.assertEqual(container["hostname"], hostname)  # type: ignore[index]
        self.assertLessEqual(len(hostname), 63)
        self.assertNotEqual(hostname, endpoint_id)

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
                        "tools.endpoint.engine.providers.docker.create.free_localhost_tcp_port",
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
                    self.assertEqual(
                        security["cap_add"],  # type: ignore[index]
                        ["NET_RAW", "SYS_CHROOT", "SETGID", "SETUID"],
                    )
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


class DockerCreateEndpointLivePrivateTest(unittest.TestCase):
    def test_private_live_create_builds_private_endpoint_and_records_allocation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            runner = _DockerLivePrivateRunner(image_exists=False, network_exists=False)

            with mock.patch(
                "tools.endpoint.engine.providers.docker.create.free_localhost_tcp_port",
                return_value=29222,
            ):
                output = docker.create_endpoint(
                    provider="docker",
                    exposure="private",
                    role="oracle",
                    private_group="pair-live",
                    private_ip="10.79.0.42",
                    dry_run=False,
                    confirm_live_run=True,
                    env={},
                    command_runner=runner,
                )
            manifest_path = Path(str(output["manifest_path"]))
            expected_manifest_path = (
                Path(temp_dir)
                / "wire-state"
                / "endpoints"
                / str(output["endpoint_id"])
                / "endpoint.json"
            )
            manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
            allocation_state = output["metadata"]["allocation_state"]  # type: ignore[index]
            record_path = Path(str(allocation_state["record_path"]))  # type: ignore[index]
            record = json.loads(record_path.read_text(encoding="utf-8"))

        self.assertTrue(output["created"])
        self.assertFalse(output["dry_run"])
        self.assertEqual(output["status"], "active")
        self.assertEqual(output["provider"], "docker")
        self.assertEqual(output["exposure"], "private")
        self.assertEqual(output["role"], "oracle")

        self.assertEqual(
            runner.calls_matching("docker", "image", "inspect"),
            [
                ("docker", "image", "inspect", DOCKER_DEFAULT_IMAGE),
                ("docker", "image", "inspect", DOCKER_DEFAULT_IMAGE),
            ],
        )
        build_calls = runner.calls_matching("docker", "build")
        self.assertEqual(len(build_calls), 1)
        self.assertIn(DOCKER_DEFAULT_IMAGE, build_calls[0])

        network_name = "wire-private-pair-live"
        network_inspects = runner.calls_matching("docker", "network", "inspect")
        self.assertEqual(
            network_inspects,
            [
                ("docker", "network", "inspect", network_name),
                ("docker", "network", "inspect", network_name),
            ],
        )
        network_create = runner.only_call_matching("docker", "network", "create")
        self.assertIn("--driver", network_create)
        self.assertIn("bridge", network_create)
        self.assertIn("--internal", network_create)
        self.assertIn("--subnet", network_create)
        self.assertIn(DOCKER_DEFAULT_PRIVATE_CIDR, network_create)
        self.assertIn(network_name, network_create)

        run_argv = runner.only_call_matching("docker", "run")
        self.assertIn("--detach", run_argv)
        self.assertIn("--network", run_argv)
        self.assertIn(network_name, run_argv)
        self.assertIn("--ip", run_argv)
        self.assertIn("10.79.0.42", run_argv)
        self.assertIn("--mac-address", run_argv)
        self.assertIn("--cap-drop", run_argv)
        self.assertIn("ALL", run_argv)
        self.assertEqual(
            _option_values(run_argv, "--cap-add"),
            ["NET_RAW", "NET_ADMIN", "SYS_CHROOT", "SETGID", "SETUID"],
        )
        self.assertEqual(_option_values(run_argv, "--security-opt"), [])
        self.assertIn("--publish", run_argv)
        self.assertIn("127.0.0.1:29222:22", run_argv)
        self.assertNotIn("--privileged", run_argv)
        self.assertNotIn("--network=host", run_argv)
        self.assertNotIn("/var/run/docker.sock", " ".join(run_argv))

        control_connect = runner.only_call_matching("docker", "network", "connect")
        self.assertEqual(
            control_connect,
            ("docker", "network", "connect", "bridge", "container-private-1"),
        )

        ssh_calls = [call for call in runner.calls if call and call[0] == "ssh"]
        self.assertGreaterEqual(len(ssh_calls), 2)
        self.assertIn("true", ssh_calls[0])
        self.assertIn("__WIRE_IP_ADDR__", ssh_calls[-1][-1])

        metadata = output["metadata"]  # type: ignore[assignment]
        self.assertEqual(metadata["private_group"], "pair-live")  # type: ignore[index]
        self.assertEqual(metadata["private_ip"], "10.79.0.42")  # type: ignore[index]
        self.assertEqual(metadata["private_ip_source"], "requested")  # type: ignore[index]
        self.assertEqual(metadata["docker_network"], network_name)  # type: ignore[index]
        self.assertTrue(metadata["discovery"]["ssh_ready"])  # type: ignore[index]
        self.assertTrue(metadata["discovery"]["interfaces"])  # type: ignore[index]

        private_network = metadata["private_network"]  # type: ignore[index]
        self.assertTrue(private_network["created"])  # type: ignore[index]
        self.assertFalse(private_network["reused"])  # type: ignore[index]
        self.assertTrue(private_network["internal"])  # type: ignore[index]
        self.assertTrue(private_network["owned_by_provider"])  # type: ignore[index]
        self.assertTrue(private_network["same_segment"])  # type: ignore[index]
        self.assertTrue(private_network["l2_segment"])  # type: ignore[index]

        docker_metadata = metadata["docker"]  # type: ignore[index]
        security = docker_metadata["security"]  # type: ignore[index]
        self.assertEqual(security["cap_drop"], ["ALL"])  # type: ignore[index]
        self.assertEqual(
            security["cap_add"],  # type: ignore[index]
            ["NET_RAW", "NET_ADMIN", "SYS_CHROOT", "SETGID", "SETUID"],
        )
        self.assertFalse(security["no_new_privileges"])  # type: ignore[index]
        self.assertFalse(security["privileged"])  # type: ignore[index]
        self.assertFalse(security["host_network"])  # type: ignore[index]
        self.assertFalse(security["docker_socket_mounted"])  # type: ignore[index]

        container = docker_metadata["container"]  # type: ignore[index]
        self.assertTrue(container["created"])  # type: ignore[index]
        self.assertEqual(container["container_id"], "container-private-1")  # type: ignore[index]
        self.assertEqual(container["ssh"]["host"], "127.0.0.1")  # type: ignore[index]
        self.assertEqual(container["ssh"]["host_port"], 29222)  # type: ignore[index]
        self.assertEqual(container["ssh"]["publish"], "127.0.0.1:29222:22")  # type: ignore[index]
        self.assertEqual(container["run_argv"], list(run_argv))  # type: ignore[index]
        self.assertEqual(container["control_network"], "bridge")  # type: ignore[index]
        self.assertTrue(container["control_network_connected"])  # type: ignore[index]

        interfaces = output["interfaces"]  # type: ignore[assignment]
        self.assertEqual(len(interfaces), 1)
        self.assertEqual(interfaces[0]["name"], "eth0")
        self.assertEqual(interfaces[0]["ipv4"], "10.79.0.42")
        self.assertEqual(interfaces[0]["mac"], runner.private_mac)
        self.assertEqual(interfaces[0]["provider_network_id"], network_name)
        self.assertTrue(interfaces[0]["metadata"]["discovery_verified"])  # type: ignore[index]

        self.assertEqual(manifest_path, expected_manifest_path)
        self.assertEqual(manifest_data["status"], "active")
        self.assertTrue(manifest_data["metadata"]["created"])

        self.assertEqual(record["provider"], "docker")
        self.assertEqual(record["group"], "pair-live")
        self.assertEqual(record["private_cidr"], DOCKER_DEFAULT_PRIVATE_CIDR)
        self.assertIn(output["endpoint_id"], record["allocated_endpoint_ids"])
        self.assertIn("10.79.0.42", record["allocated_private_ipv4s"])
        self.assertEqual(record["network_resource"]["network_name"], network_name)
        self.assertEqual(record["network_resource"]["network_id"], "network-pair-live")

    def test_private_live_create_can_reuse_existing_private_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            runner = _DockerLivePrivateRunner(image_exists=True, network_exists=True)

            with mock.patch(
                "tools.endpoint.engine.providers.docker.create.free_localhost_tcp_port",
                return_value=29223,
            ):
                output = docker.create_endpoint(
                    provider="docker",
                    exposure="private",
                    role="probe",
                    private_group="pair-live",
                    private_ip="10.79.0.43",
                    dry_run=False,
                    confirm_live_run=True,
                    env={},
                    command_runner=runner,
                )

        self.assertEqual(len(runner.calls_matching("docker", "image", "inspect")), 1)
        self.assertEqual(runner.calls_matching("docker", "build"), [])
        self.assertEqual(len(runner.calls_matching("docker", "network", "inspect")), 1)
        self.assertEqual(runner.calls_matching("docker", "network", "create"), [])
        private_network = output["metadata"]["private_network"]  # type: ignore[index]
        self.assertFalse(private_network["created"])  # type: ignore[index]
        self.assertTrue(private_network["reused"])  # type: ignore[index]

    def test_private_live_create_requires_confirmation_before_provider_commands(self) -> None:
        calls: list[tuple[str, ...]] = []

        def fake_runner(argv: Sequence[object], **_: object) -> CommandResult:
            calls.append(tuple(str(part) for part in argv))
            return _result(argv)

        with self.assertRaisesRegex(PermissionError, CONFIRMATION_ERROR):
            docker.create_endpoint(
                provider="docker",
                exposure="private",
                role="oracle",
                private_group="pair-live",
                dry_run=False,
                confirm_live_run=False,
                env={},
                command_runner=fake_runner,
            )

        self.assertEqual(calls, [])


class DockerCreateEndpointLiveNatL3Test(unittest.TestCase):
    def test_lan_and_wan_live_create_use_configured_networks_and_l3_only_capabilities(
        self,
    ) -> None:
        cases = {
            "lan": {
                "role": "probe",
                "port": 29322,
                "container_id": "container-lan-1",
                "env": {DOCKER_LAN_NETWORK_ENV: "wire-lan-live"},
                "network_key": "lan_network",
                "network_name": "wire-lan-live",
                "expected_flag": "nat_backed_l3_lan",
                "negative_l2_flag": "true_lan_l2",
                "discovered_ipv4": "172.20.0.11",
                "discovered_mac": "02:42:ac:14:00:0b",
            },
            "wan": {
                "role": "client",
                "port": 29323,
                "container_id": "container-wan-1",
                "env": {DOCKER_WAN_NETWORK_ENV: "wire-wan-live"},
                "network_key": "wan_network",
                "network_name": "wire-wan-live",
                "expected_flag": "nat_backed_l3_egress",
                "negative_l2_flag": "wan_l2",
                "discovered_ipv4": "172.21.0.12",
                "discovered_mac": "02:42:ac:15:00:0c",
            },
        }

        for exposure, case in cases.items():
            with self.subTest(exposure=exposure):
                with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
                    runner = _DockerLiveNatL3Runner(
                        container_id=str(case["container_id"]),
                        discovered_ipv4=str(case["discovered_ipv4"]),
                        discovered_mac=str(case["discovered_mac"]),
                    )

                    with mock.patch(
                        "tools.endpoint.engine.providers.docker.create.free_localhost_tcp_port",
                        return_value=case["port"],
                    ):
                        output = docker.create_endpoint(
                            provider="docker",
                            exposure=exposure,
                            role=str(case["role"]),
                            dry_run=False,
                            confirm_live_run=True,
                            env=case["env"],  # type: ignore[arg-type]
                            command_runner=runner,
                        )

                self.assertTrue(output["created"])
                self.assertFalse(output["dry_run"])
                self.assertEqual(output["status"], "active")
                self.assertEqual(output["provider"], "docker")
                self.assertEqual(output["exposure"], exposure)
                self.assertEqual(output["role"], case["role"])

                self.assertEqual(
                    runner.calls_matching("docker", "image", "inspect"),
                    [("docker", "image", "inspect", DOCKER_DEFAULT_IMAGE)],
                )
                self.assertEqual(runner.calls_matching("docker", "build"), [])
                self.assertEqual(runner.calls_matching("docker", "network", "create"), [])

                run_argv = runner.only_call_matching("docker", "run")
                self.assertIn("--detach", run_argv)
                self.assertEqual(_option_values(run_argv, "--network"), [case["network_name"]])
                self.assertNotIn("--network=host", run_argv)
                self.assertNotIn("host", _option_values(run_argv, "--network"))
                self.assertEqual(_option_values(run_argv, "--cap-drop"), ["ALL"])
                self.assertEqual(
                    _option_values(run_argv, "--cap-add"),
                    ["NET_RAW", "SYS_CHROOT", "SETGID", "SETUID"],
                )
                self.assertNotIn("NET_ADMIN", _option_values(run_argv, "--cap-add"))
                self.assertEqual(_option_values(run_argv, "--security-opt"), [])
                self.assertEqual(
                    _option_values(run_argv, "--publish"),
                    [f"127.0.0.1:{case['port']}:22"],
                )
                self.assertNotIn("--privileged", run_argv)
                self.assertNotIn("/var/run/docker.sock", " ".join(run_argv))

                ssh = output["ssh"]  # type: ignore[assignment]
                self.assertEqual(ssh["host"], "127.0.0.1")  # type: ignore[index]
                self.assertEqual(ssh["port"], case["port"])  # type: ignore[index]
                self.assertEqual(ssh["metadata"]["host"], "127.0.0.1")  # type: ignore[index]
                self.assertEqual(ssh["metadata"]["host_port"], case["port"])  # type: ignore[index]
                self.assertEqual(ssh["metadata"]["guest_port"], 22)  # type: ignore[index]

                metadata = output["metadata"]  # type: ignore[assignment]
                self.assertEqual(metadata["docker_network"], case["network_name"])  # type: ignore[index]
                self.assertEqual(metadata["docker_network_source"], "env")  # type: ignore[index]
                self.assertTrue(metadata["discovery"]["ssh_ready"])  # type: ignore[index]
                self.assertTrue(metadata["discovery"]["interfaces"])  # type: ignore[index]
                self.assertTrue(metadata["discovery"]["ipv4"])  # type: ignore[index]

                capabilities = metadata["capabilities"]  # type: ignore[index]
                _assert_nat_l3_capabilities(
                    self,
                    capabilities,  # type: ignore[arg-type]
                    exposure=exposure,
                    expected_flag=str(case["expected_flag"]),
                    expected_l2_false_flag=str(case["negative_l2_flag"]),
                )

                docker_metadata = metadata["docker"]  # type: ignore[index]
                security = docker_metadata["security"]  # type: ignore[index]
                self.assertEqual(security["cap_drop"], ["ALL"])  # type: ignore[index]
                self.assertEqual(
                    security["cap_add"],  # type: ignore[index]
                    ["NET_RAW", "SYS_CHROOT", "SETGID", "SETUID"],
                )
                self.assertTrue(security["net_raw_only"])  # type: ignore[index]
                self.assertFalse(security["net_admin"])  # type: ignore[index]
                self.assertFalse(security["no_new_privileges"])  # type: ignore[index]
                self.assertFalse(security["host_network"])  # type: ignore[index]
                self.assertFalse(security["privileged"])  # type: ignore[index]
                self.assertFalse(security["docker_socket_mounted"])  # type: ignore[index]
                self.assertFalse(security["link_layer_fidelity"])  # type: ignore[index]
                self.assertFalse(security["broadcast"])  # type: ignore[index]
                self.assertFalse(security["controlled_router"])  # type: ignore[index]
                self.assertFalse(security["public_inbound_reachability"])  # type: ignore[index]

                container = docker_metadata["container"]  # type: ignore[index]
                self.assertTrue(container["created"])  # type: ignore[index]
                self.assertEqual(container["container_id"], case["container_id"])  # type: ignore[index]
                self.assertEqual(container["network"], case["network_name"])  # type: ignore[index]
                self.assertEqual(container["docker_network"], case["network_name"])  # type: ignore[index]
                self.assertEqual(container["ssh"]["host"], "127.0.0.1")  # type: ignore[index]
                self.assertEqual(container["ssh"]["host_port"], case["port"])  # type: ignore[index]
                self.assertEqual(
                    container["ssh"]["publish"],  # type: ignore[index]
                    f"127.0.0.1:{case['port']}:22",
                )
                self.assertFalse(
                    container["ssh"]["public_inbound_reachability"]  # type: ignore[index]
                )
                self.assertEqual(container["run_argv"], list(run_argv))  # type: ignore[index]

                network = metadata[case["network_key"]]  # type: ignore[index]
                self.assertEqual(network["network_name"], case["network_name"])  # type: ignore[index]
                self.assertEqual(network["configured_network"], case["network_name"])  # type: ignore[index]
                self.assertEqual(network["source"], "env")  # type: ignore[index]
                self.assertFalse(network["planned"])  # type: ignore[index]
                self.assertFalse(network["created"])  # type: ignore[index]
                self.assertTrue(network["reused"])  # type: ignore[index]
                self.assertFalse(network["owned_by_provider"])  # type: ignore[index]
                self.assertFalse(network["cleanup"])  # type: ignore[index]
                self.assertFalse(network["l2"])  # type: ignore[index]
                self.assertFalse(network["broadcast"])  # type: ignore[index]
                self.assertFalse(network["controlled_router"])  # type: ignore[index]
                self.assertFalse(network["public_inbound_reachability"])  # type: ignore[index]
                self.assertEqual(network["docker_capabilities"], ["NET_RAW"])  # type: ignore[index]

                interfaces = output["interfaces"]  # type: ignore[assignment]
                self.assertEqual(len(interfaces), 1)
                interface = interfaces[0]
                self.assertEqual(interface["name"], "eth0")
                self.assertEqual(interface["exposure"], exposure)
                self.assertEqual(interface["ipv4"], case["discovered_ipv4"])
                self.assertEqual(interface["mac"], case["discovered_mac"])
                self.assertEqual(interface["provider_network_id"], case["network_name"])
                interface_metadata = interface["metadata"]
                self.assertEqual(
                    interface_metadata["network_name"],  # type: ignore[index]
                    case["network_name"],
                )
                self.assertEqual(
                    interface_metadata["docker_network"],  # type: ignore[index]
                    case["network_name"],
                )
                self.assertEqual(
                    interface_metadata["discovered_ipv4"],  # type: ignore[index]
                    case["discovered_ipv4"],
                )
                self.assertEqual(
                    interface_metadata["docker_network_address"]["ipv4"],  # type: ignore[index]
                    case["discovered_ipv4"],
                )
                self.assertEqual(
                    interface_metadata["address_source"],  # type: ignore[index]
                    "docker-network-discovery",
                )
                self.assertTrue(
                    interface_metadata["discovered_from_docker_network"]  # type: ignore[index]
                )
                self.assertFalse(interface_metadata["link_layer_send"])  # type: ignore[index]
                self.assertFalse(interface_metadata["link_layer_capture"])  # type: ignore[index]
                self.assertFalse(interface_metadata["provider_mac_known"])  # type: ignore[index]
                self.assertFalse(interface_metadata["broadcast"])  # type: ignore[index]
                self.assertFalse(interface_metadata["controlled_router"])  # type: ignore[index]
                self.assertFalse(
                    interface_metadata["public_inbound_reachability"]  # type: ignore[index]
                )
                self.assertFalse(interface_metadata[case["negative_l2_flag"]])  # type: ignore[index]

                resources = _resources_by_name(output)
                self.assertFalse(resources[case["network_name"]]["cleanup"])  # type: ignore[index]


class DockerDestroyEndpointTest(unittest.TestCase):
    def test_planned_only_destroy_marks_destroyed_without_docker_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            with mock.patch(
                "tools.endpoint.engine.providers.docker.create.free_localhost_tcp_port",
                return_value=29422,
            ):
                output = docker.create_endpoint(
                    provider="docker",
                    exposure="private",
                    role="oracle",
                    private_group="pair-planned",
                    private_ip="10.79.0.44",
                    dry_run=True,
                    env={},
                )

            manifest = EndpointManifest.from_dict(output)
            runner = _DockerDestroyRunner()
            destroy_output = docker.destroy_endpoint(
                manifest,
                env={},
                command_runner=runner,
            )
            manifest_path = Path(str(destroy_output["manifest_path"]))
            destroyed_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(runner.calls, [])
        self.assertTrue(destroy_output["destroyed"])
        self.assertFalse(destroy_output["already_destroyed"])
        self.assertEqual(destroy_output["status"], "destroyed")
        self.assertEqual(destroy_output["actions"], [])
        self.assertEqual(destroyed_manifest["status"], "destroyed")
        skip_reasons = _destroy_skip_reasons(destroy_output)
        self.assertIn(
            "endpoint was planned only; no Docker container was created",
            skip_reasons,
        )
        self.assertIn(
            "endpoint was planned only; no Docker network was created",
            skip_reasons,
        )
        self.assertIn("local endpoint state and artifacts are preserved", skip_reasons)

    def test_destroy_is_idempotent_for_already_destroyed_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            with mock.patch(
                "tools.endpoint.engine.providers.docker.create.free_localhost_tcp_port",
                return_value=29423,
            ):
                output = docker.create_endpoint(
                    provider="docker",
                    exposure="lan",
                    role="probe",
                    dry_run=True,
                    env={},
                )

            manifest = EndpointManifest.from_dict(output)
            first_destroy = docker.destroy_endpoint(
                manifest,
                env={},
                command_runner=_DockerDestroyRunner(),
            )
            destroyed_manifest = EndpointManifest.from_dict(
                json.loads(
                    Path(str(first_destroy["manifest_path"])).read_text(encoding="utf-8")
                )
            )
            runner = _DockerDestroyRunner()
            second_destroy = docker.destroy_endpoint(
                destroyed_manifest,
                env={},
                command_runner=runner,
            )

        self.assertEqual(runner.calls, [])
        self.assertFalse(second_destroy["destroyed"])
        self.assertTrue(second_destroy["already_destroyed"])
        self.assertEqual(second_destroy["status"], "destroyed")
        self.assertEqual(second_destroy["actions"], [])
        self.assertTrue(second_destroy["skipped"])
        self.assertEqual(
            set(_destroy_skip_reasons(second_destroy)),
            {"endpoint already destroyed"},
        )

    def test_active_private_destroy_removes_container_last_network_and_preserves_local_files(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            create_runner = _DockerLivePrivateRunner(
                image_exists=True,
                network_exists=True,
            )
            with mock.patch(
                "tools.endpoint.engine.providers.docker.create.free_localhost_tcp_port",
                return_value=29424,
            ):
                output = docker.create_endpoint(
                    provider="docker",
                    exposure="private",
                    role="oracle",
                    private_group="pair-live",
                    private_ip="10.79.0.42",
                    dry_run=False,
                    confirm_live_run=True,
                    env={},
                    command_runner=create_runner,
                )

            manifest = EndpointManifest.from_dict(output)
            state_dir = Path(str(output["state_dir"]))
            artifact_dir = Path(str(output["artifact_dir"]))
            state_sentinel = state_dir / "destroy-debug-state.txt"
            artifact_sentinel = artifact_dir / "destroy-debug-artifact.txt"
            state_sentinel.write_text("keep state\n", encoding="utf-8")
            artifact_sentinel.write_text("keep artifact\n", encoding="utf-8")

            runner = _DockerDestroyRunner()
            destroy_output = docker.destroy_endpoint(
                manifest,
                env={},
                command_runner=runner,
            )
            manifest_path = Path(str(destroy_output["manifest_path"]))
            destroyed_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            allocation_state = output["metadata"]["allocation_state"]  # type: ignore[index]
            record_path = Path(str(allocation_state["record_path"]))  # type: ignore[index]
            record = json.loads(record_path.read_text(encoding="utf-8"))
            state_sentinel_exists = state_sentinel.exists()
            artifact_sentinel_exists = artifact_sentinel.exists()
            manifest_path_exists = manifest_path.exists()

        self.assertEqual(
            runner.calls,
            [
                ("docker", "container", "rm", "--force", "container-private-1"),
                ("docker", "network", "inspect", "network-pair-live"),
                ("docker", "network", "rm", "network-pair-live"),
            ],
        )
        self.assertTrue(destroy_output["destroyed"])
        self.assertFalse(destroy_output["already_destroyed"])
        self.assertEqual(destroy_output["status"], "destroyed")
        self.assertEqual(
            [(action["kind"], action["action"]) for action in destroy_output["actions"]],  # type: ignore[index]
            [
                ("docker-container", "remove"),
                ("private-group", "remove-private-allocation"),
                ("docker-network", "inspect"),
                ("docker-network", "remove"),
            ],
        )
        self.assertTrue(destroyed_manifest["metadata"]["docker"]["container_removed"])
        private_destroy = destroyed_manifest["metadata"]["private_group_destroy"]
        self.assertTrue(private_destroy["record_found"])
        self.assertEqual(private_destroy["remaining_endpoints"], [])
        self.assertTrue(private_destroy["network_removed"])
        self.assertEqual(record["allocated_endpoint_ids"], [])
        self.assertEqual(record["allocated_private_ipv4s"], [])
        self.assertTrue(state_sentinel_exists)
        self.assertTrue(artifact_sentinel_exists)
        self.assertTrue(manifest_path_exists)
        self.assertIn(
            "local endpoint state and artifacts are preserved",
            _destroy_skip_reasons(destroy_output),
        )

    def test_missing_container_destroy_marks_container_already_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            create_runner = _DockerLiveNatL3Runner(
                container_id="container-lan-missing",
                discovered_ipv4="172.20.0.20",
                discovered_mac="02:42:ac:14:00:14",
            )
            with mock.patch(
                "tools.endpoint.engine.providers.docker.create.free_localhost_tcp_port",
                return_value=29425,
            ):
                output = docker.create_endpoint(
                    provider="docker",
                    exposure="lan",
                    role="probe",
                    dry_run=False,
                    confirm_live_run=True,
                    env={DOCKER_LAN_NETWORK_ENV: "wire-lan-destroy"},
                    command_runner=create_runner,
                )

            runner = _DockerDestroyRunner(container_missing=True)
            destroy_output = docker.destroy_endpoint(
                EndpointManifest.from_dict(output),
                env={},
                command_runner=runner,
            )
            destroyed_manifest = json.loads(
                Path(str(destroy_output["manifest_path"])).read_text(encoding="utf-8")
            )

        self.assertEqual(
            runner.calls,
            [("docker", "container", "rm", "--force", "container-lan-missing")],
        )
        self.assertTrue(destroy_output["destroyed"])
        self.assertEqual(
            [(action["kind"], action["action"]) for action in destroy_output["actions"]],  # type: ignore[index]
            [("docker-container", "already-missing")],
        )
        self.assertIn("Docker container was already missing", _destroy_action_reasons(destroy_output))
        self.assertTrue(destroyed_manifest["metadata"]["docker"]["container_removed"])

    def test_destroy_retries_after_daemon_cannot_kill_running_container(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            create_runner = _DockerLivePrivateRunner(
                image_exists=True,
                network_exists=True,
            )
            with mock.patch(
                "tools.endpoint.engine.providers.docker.create.free_localhost_tcp_port",
                return_value=29426,
            ):
                output = docker.create_endpoint(
                    provider="docker",
                    exposure="private",
                    role="oracle",
                    private_group="pair-live",
                    private_ip="10.79.0.42",
                    dry_run=False,
                    confirm_live_run=True,
                    env={},
                    command_runner=create_runner,
                )

            runner = _DockerDestroyRunner(container_kill_permission_denied=True)
            destroy_output = docker.destroy_endpoint(
                EndpointManifest.from_dict(output),
                env={},
                command_runner=runner,
            )
            destroyed_manifest = json.loads(
                Path(str(destroy_output["manifest_path"])).read_text(encoding="utf-8")
            )

        self.assertEqual(
            runner.calls[:4],
            [
                ("docker", "container", "rm", "--force", "container-private-1"),
                ("docker", "exec", "container-private-1", "sh", "-lc", "kill -TERM 1"),
                ("docker", "container", "wait", "container-private-1"),
                ("docker", "container", "rm", "--force", "container-private-1"),
            ],
        )
        self.assertEqual(
            [(action["kind"], action["action"]) for action in destroy_output["actions"][:4]],  # type: ignore[index]
            [
                ("docker-container", "remove-retry-needed"),
                ("docker-container", "terminate"),
                ("docker-container", "wait"),
                ("docker-container", "remove"),
            ],
        )
        self.assertTrue(destroy_output["destroyed"])
        self.assertTrue(destroyed_manifest["metadata"]["docker"]["container_removed"])

    def test_private_network_is_retained_while_another_allocation_remains(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            create_runner = _DockerLivePrivateRunner(
                image_exists=True,
                network_exists=True,
            )
            with mock.patch(
                "tools.endpoint.engine.providers.docker.create.free_localhost_tcp_port",
                return_value=29426,
            ):
                output = docker.create_endpoint(
                    provider="docker",
                    exposure="private",
                    role="oracle",
                    private_group="pair-live",
                    private_ip="10.79.0.42",
                    dry_run=False,
                    confirm_live_run=True,
                    env={},
                    command_runner=create_runner,
                )

            update_private_group_allocation(
                provider="docker",
                group="pair-live",
                endpoint_id="other-docker-private-probe",
                private_ipv4="10.79.0.43",
            )
            runner = _DockerDestroyRunner()
            destroy_output = docker.destroy_endpoint(
                EndpointManifest.from_dict(output),
                env={},
                command_runner=runner,
            )
            destroyed_manifest = json.loads(
                Path(str(destroy_output["manifest_path"])).read_text(encoding="utf-8")
            )
            allocation_state = output["metadata"]["allocation_state"]  # type: ignore[index]
            record_path = Path(str(allocation_state["record_path"]))  # type: ignore[index]
            record = json.loads(record_path.read_text(encoding="utf-8"))

        self.assertEqual(
            runner.calls,
            [("docker", "container", "rm", "--force", "container-private-1")],
        )
        self.assertEqual(runner.calls_matching("docker", "network", "inspect"), [])
        self.assertEqual(runner.calls_matching("docker", "network", "rm"), [])
        private_destroy = destroyed_manifest["metadata"]["private_group_destroy"]
        self.assertTrue(private_destroy["record_found"])
        self.assertFalse(private_destroy["network_removed"])
        self.assertEqual(private_destroy["remaining_endpoints"], ["other-docker-private-probe"])
        self.assertEqual(record["allocated_endpoint_ids"], ["other-docker-private-probe"])
        self.assertEqual(record["allocated_private_ipv4s"], ["10.79.0.43"])
        self.assertIn(
            "private group still has allocated endpoints; network retained",
            _destroy_skip_reasons(destroy_output),
        )

    def test_destroy_rejects_non_docker_manifest_before_provider_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _wire_env(Path(temp_dir)):
            with mock.patch(
                "tools.endpoint.engine.providers.docker.create.free_localhost_tcp_port",
                return_value=29427,
            ):
                output = docker.create_endpoint(
                    provider="docker",
                    exposure="wan",
                    role="client",
                    dry_run=True,
                    env={},
                )

            invalid_manifest = replace(EndpointManifest.from_dict(output), provider="qemu")
            runner = _DockerDestroyRunner()
            with self.assertRaisesRegex(ValueError, "manifest provider must be 'docker'"):
                docker.destroy_endpoint(
                    invalid_manifest,
                    env={},
                    command_runner=runner,
                )

        self.assertEqual(runner.calls, [])


class _DockerLivePrivateRunner:
    def __init__(self, *, image_exists: bool, network_exists: bool) -> None:
        self.image_exists = image_exists
        self.network_exists = network_exists
        self.image_built = False
        self.network_created = False
        self.private_ip = "10.79.0.42"
        self.private_mac = "02:42:0a:4f:00:2a"
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Sequence[object], **_: object) -> CommandResult:
        parts = tuple(str(part) for part in argv)
        self.calls.append(parts)

        if parts and parts[0] == "ssh-keygen":
            return _result(parts)

        if parts[:3] == ("docker", "image", "inspect"):
            if self.image_exists or self.image_built:
                return _result(parts, stdout="[]\n")
            return _result(parts, exit_code=1, stderr="No such image\n")

        if parts[:2] == ("docker", "build"):
            self.image_built = True
            return _result(parts, stdout="built\n")

        if parts[:3] == ("docker", "network", "inspect"):
            if self.network_exists or self.network_created:
                return _result(parts, stdout=_docker_private_network_inspect_stdout())
            return _result(parts, exit_code=1, stderr="No such network\n")

        if parts[:3] == ("docker", "network", "create"):
            self.network_created = True
            return _result(parts, stdout="network-pair-live\n")

        if parts[:3] == ("docker", "network", "connect"):
            return _result(parts)

        if parts[:2] == ("docker", "run"):
            self.private_ip = _option_values(parts, "--ip")[0]
            self.private_mac = _option_values(parts, "--mac-address")[0]
            return _result(parts, stdout="container-private-1\n")

        if parts and parts[0] == "ssh":
            command = parts[-1]
            if command == "true":
                return _result(parts)
            if "__WIRE_IP_ADDR__" in command:
                return _result(
                    parts,
                    stdout=_interface_discovery_stdout(
                        private_ip=self.private_ip,
                        private_mac=self.private_mac,
                    ),
                )
            return _result(parts)

        return _result(parts, exit_code=1, stderr=f"unexpected command: {parts!r}\n")

    def calls_matching(self, *prefix: str) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[: len(prefix)] == prefix]

    def only_call_matching(self, *prefix: str) -> tuple[str, ...]:
        calls = self.calls_matching(*prefix)
        if len(calls) != 1:
            raise AssertionError(f"expected one call matching {prefix!r}, got {calls!r}")
        return calls[0]


class _DockerLiveNatL3Runner:
    def __init__(
        self,
        *,
        container_id: str,
        discovered_ipv4: str,
        discovered_mac: str,
    ) -> None:
        self.container_id = container_id
        self.discovered_ipv4 = discovered_ipv4
        self.discovered_mac = discovered_mac
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Sequence[object], **_: object) -> CommandResult:
        parts = tuple(str(part) for part in argv)
        self.calls.append(parts)

        if parts and parts[0] == "ssh-keygen":
            return _result(parts)

        if parts[:3] == ("docker", "image", "inspect"):
            return _result(parts, stdout="[]\n")

        if parts[:2] == ("docker", "run"):
            return _result(parts, stdout=f"{self.container_id}\n")

        if parts and parts[0] == "ssh":
            command = parts[-1]
            if command == "true":
                return _result(parts)
            if "__WIRE_IP_ADDR__" in command:
                return _result(
                    parts,
                    stdout=_interface_discovery_stdout(
                        private_ip=self.discovered_ipv4,
                        private_mac=self.discovered_mac,
                    ),
                )
            return _result(parts)

        return _result(parts, exit_code=1, stderr=f"unexpected command: {parts!r}\n")

    def calls_matching(self, *prefix: str) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[: len(prefix)] == prefix]

    def only_call_matching(self, *prefix: str) -> tuple[str, ...]:
        calls = self.calls_matching(*prefix)
        if len(calls) != 1:
            raise AssertionError(f"expected one call matching {prefix!r}, got {calls!r}")
        return calls[0]


class _DockerDestroyRunner:
    def __init__(
        self,
        *,
        container_missing: bool = False,
        container_kill_permission_denied: bool = False,
    ) -> None:
        self.container_missing = container_missing
        self.container_kill_permission_denied = container_kill_permission_denied
        self.calls: list[tuple[str, ...]] = []
        self._remove_attempts: dict[str, int] = {}

    def __call__(self, argv: Sequence[object], **_: object) -> CommandResult:
        parts = tuple(str(part) for part in argv)
        self.calls.append(parts)

        if parts[:4] == ("docker", "container", "rm", "--force"):
            if self.container_missing:
                return _result(parts, exit_code=1, stderr="No such container\n")
            container_ref = parts[-1]
            attempts = self._remove_attempts.get(container_ref, 0)
            self._remove_attempts[container_ref] = attempts + 1
            if self.container_kill_permission_denied and attempts == 0:
                return _result(
                    parts,
                    exit_code=1,
                    stderr=(
                        "Error response from daemon: cannot remove container "
                        f"{container_ref!r}: could not kill container: permission denied\n"
                    ),
                )
            return _result(parts, stdout=f"{parts[-1]}\n")

        if parts[:2] == ("docker", "exec"):
            return _result(parts)

        if parts[:3] == ("docker", "container", "wait"):
            return _result(parts, stdout="0\n")

        if parts[:3] == ("docker", "network", "inspect"):
            return _result(parts, stdout=_docker_private_network_inspect_stdout())

        if parts[:3] == ("docker", "network", "rm"):
            return _result(parts, stdout=f"{parts[-1]}\n")

        return _result(parts, exit_code=1, stderr=f"unexpected command: {parts!r}\n")

    def calls_matching(self, *prefix: str) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[: len(prefix)] == prefix]


def _option_values(argv: Sequence[str], option: str) -> list[str]:
    values: list[str] = []
    for index, part in enumerate(argv):
        if part == option and index + 1 < len(argv):
            values.append(argv[index + 1])
    return values


def _docker_private_network_inspect_stdout() -> str:
    labels = {
        "org.libcrafter.wire.provider": "docker",
        "org.libcrafter.wire.managed": "true",
        "org.libcrafter.wire.private-group": "pair-live",
        "org.libcrafter.wire.exposure": "private",
    }
    return json.dumps(
        [
            {
                "Id": "network-pair-live",
                "Name": "wire-private-pair-live",
                "Driver": "bridge",
                "Internal": True,
                "Labels": labels,
                "IPAM": {
                    "Config": [
                        {
                            "Subnet": DOCKER_DEFAULT_PRIVATE_CIDR,
                            "Gateway": "10.79.0.1",
                        }
                    ]
                },
            }
        ]
    )


def _interface_discovery_stdout(*, private_ip: str, private_mac: str) -> str:
    addresses = [
        {
            "ifindex": 2,
            "ifname": "eth0",
            "addr_info": [
                {
                    "family": "inet",
                    "local": private_ip,
                    "prefixlen": 24,
                }
            ],
        }
    ]
    links = [
        {
            "ifindex": 2,
            "ifname": "eth0",
            "address": private_mac,
            "operstate": "UP",
            "mtu": 1500,
        }
    ]
    routes = [{"dst": "1.1.1.1", "dev": "eth0", "gateway": "10.79.0.1"}]
    return "\n".join(
        [
            "__WIRE_IP_ADDR__",
            json.dumps(addresses),
            "__WIRE_IP_LINK__",
            json.dumps(links),
            "__WIRE_IP_ROUTE__",
            json.dumps(routes),
        ]
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


def _destroy_skip_reasons(output: Mapping[str, object]) -> list[str]:
    skipped = output["skipped"]
    if not isinstance(skipped, Sequence):
        raise AssertionError("destroy skipped entries must be a sequence")
    return [
        str(entry["reason"])
        for entry in skipped
        if isinstance(entry, Mapping) and "reason" in entry
    ]


def _destroy_action_reasons(output: Mapping[str, object]) -> list[str]:
    actions = output["actions"]
    if not isinstance(actions, Sequence):
        raise AssertionError("destroy actions must be a sequence")
    return [
        str(entry["reason"])
        for entry in actions
        if isinstance(entry, Mapping) and "reason" in entry
    ]


@contextmanager
def _wire_env(root: Path, extra: Mapping[str, str] | None = None) -> Iterator[None]:
    env = {
        "LIBCRAFTER_ENDPOINT_STATE_ROOT": str(root / "wire-state"),
        "LIBCRAFTER_ENDPOINT_ARTIFACT_ROOT": str(root / "wire-artifacts"),
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
