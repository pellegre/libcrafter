"""Coverage for the Docker wire provider."""

from __future__ import annotations

import unittest
from collections.abc import Sequence
from unittest import mock

from tools.wire.engine.process import CommandResult
from tools.wire.engine.providers import docker, resolve_provider
from tools.wire.engine.providers.docker.constants import (
    DOCKER_DEFAULT_LAN_NETWORK,
    DOCKER_DEFAULT_PRIVATE_CIDR,
    DOCKER_DEFAULT_WAN_NETWORK,
    DOCKER_LAN_NETWORK_ENV,
    DOCKER_PRIVATE_CIDR_ENV,
    DOCKER_WAN_NETWORK_ENV,
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


def _check(report: dict[str, object], name: str) -> dict[str, object]:
    for check in report["checks"]:  # type: ignore[union-attr]
        if check["name"] == name:
            return check
    raise AssertionError(f"missing check {name!r}")


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
