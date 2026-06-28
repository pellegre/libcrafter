"""Safe-mode coverage for appliance readiness check scripts."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.appliance.checks import (
    docker_daemon,
    dot11_injection_smoke,
    dot11_monitor_interface,
    image_available,
    interface_exists,
    lan_reachability_plan,
    pcap_open,
    raw_socket_permission,
    whad_discovery,
)
from tools.appliance.checks.common import CommandResult


class CheckScriptTest(unittest.TestCase):
    def test_docker_daemon_uses_mocked_runner(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str]) -> CommandResult:
            calls.append(argv)
            return CommandResult(returncode=0, stdout='"24.0.0"')

        exit_code, payload = _run_script(
            docker_daemon.main,
            ["--docker", "docker-test"],
            runner=runner,
        )

        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["check"], "docker-daemon")
        self.assertEqual(calls, [["docker-test", "info", "--format", "{{json .ServerVersion}}"]])
        self.assertEqual(payload["returncode"], 0)

    def test_image_available_uses_explicit_image_and_mocked_runner(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str]) -> CommandResult:
            calls.append(argv)
            return CommandResult(returncode=0, stdout='"sha256:fake"')

        exit_code, payload = _run_script(
            image_available.main,
            ["--docker", "docker-test", "--image", "registry.example/libcrafter/appliance:test"],
            runner=runner,
        )

        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["check"], "image-available")
        self.assertEqual(payload["image"], "registry.example/libcrafter/appliance:test")
        self.assertEqual(
            calls,
            [
                [
                    "docker-test",
                    "image",
                    "inspect",
                    "registry.example/libcrafter/appliance:test",
                    "--format",
                    "{{json .Id}}",
                ]
            ],
        )

    def test_interface_exists_uses_fake_sysfs_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sysfs_root = Path(directory)
            (sysfs_root / "doc0").mkdir()

            exit_code, payload = _run_script(
                interface_exists.main,
                ["--iface", "doc0", "--sysfs-root", str(sysfs_root)],
            )

        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["check"], "interface-exists")
        self.assertEqual(payload["iface"], "doc0")
        self.assertTrue(payload["exists"])

    def test_interface_exists_reports_missing_env_without_touching_real_sysfs(self) -> None:
        exit_code, payload = _run_script(
            interface_exists.main,
            ["--iface-env", "LIBCRAFTER_TEST_IFACE", "--sysfs-root", "/tmp/fake-sysfs"],
            environ={},
        )

        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "missing_interface_env")
        self.assertEqual(payload["iface_env"], "LIBCRAFTER_TEST_IFACE")

    def test_raw_socket_permission_uses_mocked_opener(self) -> None:
        class FakeSocket:
            def __init__(self) -> None:
                self.closed = False

            def close(self) -> None:
                self.closed = True

        sockets: list[FakeSocket] = []

        def opener(family: str) -> FakeSocket:
            self.assertEqual(family, "ipv4")
            sock = FakeSocket()
            sockets.append(sock)
            return sock

        exit_code, payload = _run_script(raw_socket_permission.main, [], opener=opener)

        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["check"], "raw-socket-permission")
        self.assertFalse(payload["live_transmit"])
        self.assertTrue(sockets[0].closed)

    def test_pcap_open_uses_mocked_opener(self) -> None:
        seen: list[str] = []

        def opener(iface: str) -> dict[str, object]:
            seen.append(iface)
            return {"backend": "mock-pcap", "snaplen": 64}

        exit_code, payload = _run_script(
            pcap_open.main,
            ["--iface", "doc0"],
            opener=opener,
        )

        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["check"], "pcap-open")
        self.assertEqual(payload["iface"], "doc0")
        self.assertEqual(payload["backend"], "mock-pcap")
        self.assertFalse(payload["live_transmit"])
        self.assertEqual(seen, ["doc0"])

    def test_lan_reachability_plan_is_dry_run_only(self) -> None:
        exit_code, payload = _run_script(
            lan_reachability_plan.main,
            ["--dry-run", "--iface", "doc0", "--target", "192.0.2.55"],
        )

        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["check"], "lan-reachability-plan")
        self.assertTrue(payload["dry_run"])
        self.assertFalse(payload["live_transmit"])
        self.assertEqual(payload["target"], "192.0.2.55")

    def test_whad_discovery_uses_mocked_runner(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str]) -> CommandResult:
            calls.append(argv)
            return CommandResult(returncode=0, stdout="adapter: fake")

        exit_code, payload = _run_script(
            whad_discovery.main,
            ["--tool", "whad-test", "--device", "/dev/ttyACM-test"],
            runner=runner,
        )

        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["check"], "whad-discovery")
        self.assertFalse(payload["live_transmit"])
        self.assertEqual(calls, [["whad-test", "discover", "--device", "/dev/ttyACM-test"]])

    def test_dot11_monitor_interface_uses_fake_sysfs_type(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            interface_path = Path(directory) / "mon-doc0"
            interface_path.mkdir()
            (interface_path / "type").write_text("803\n", encoding="utf-8")

            exit_code, payload = _run_script(
                dot11_monitor_interface.main,
                ["--iface", "mon-doc0", "--sysfs-root", directory],
            )

        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["check"], "dot11-monitor-interface")
        self.assertTrue(payload["monitor_mode"])
        self.assertEqual(payload["source"], "sysfs-type")

    def test_dot11_monitor_interface_can_fallback_to_mocked_iw(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            interface_path = Path(directory) / "mon-doc0"
            interface_path.mkdir()

            def runner(argv: list[str]) -> CommandResult:
                self.assertEqual(argv, ["iw-test", "dev", "mon-doc0", "info"])
                return CommandResult(returncode=0, stdout="Interface mon-doc0\n\ttype monitor\n")

            exit_code, payload = _run_script(
                dot11_monitor_interface.main,
                ["--iface", "mon-doc0", "--sysfs-root", directory, "--iw", "iw-test"],
                runner=runner,
            )

        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["source"], "iw")
        self.assertTrue(payload["monitor_mode"])

    def test_dot11_injection_smoke_emits_dry_run_plan(self) -> None:
        exit_code, payload = _run_script(
            dot11_injection_smoke.main,
            ["--dry-run", "--iface", "mon-doc0", "--channel", "6"],
        )

        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["check"], "dot11-injection-smoke")
        self.assertTrue(payload["dry_run"])
        self.assertFalse(payload["live_transmit"])
        self.assertTrue(payload["requires_live_gate"])

    def test_dot11_injection_smoke_rejects_non_dry_run(self) -> None:
        exit_code, payload = _run_script(
            dot11_injection_smoke.main,
            ["--iface", "mon-doc0"],
        )

        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "live_check_rejected")
        self.assertFalse(payload["live_transmit"])


def _run_script(main: object, argv: list[str], **kwargs: object) -> tuple[int, dict[str, object]]:
    stdout = io.StringIO()
    exit_code = main(argv, stdout=stdout, **kwargs)  # type: ignore[operator]
    return exit_code, json.loads(stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
