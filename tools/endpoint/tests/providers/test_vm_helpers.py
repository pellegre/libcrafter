"""Unit coverage for shared local VM provider helpers."""

from __future__ import annotations

import socket
import tempfile
import unittest
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from tools.endpoint.engine.process import CommandResult
from tools.endpoint.engine.providers.vm import (
    command_error,
    endpoint_id,
    ensure_endpoint_ssh_key,
    file_resource,
    free_localhost_tcp_port,
    id_timestamp,
    path_component,
    process_resource,
    provider_resources,
    public_key_path,
    short_provider_resource_name,
    utc_now,
    vm_resource,
)


class VMHelperNamingTest(unittest.TestCase):
    def test_endpoint_id_is_single_path_component(self) -> None:
        value = endpoint_id(
            provider="VirtualBox",
            exposure="LAN",
            role="../Router Probe",
            timestamp="20260526220500",
            suffix="AB/CD",
        )

        self.assertEqual(value, "virtualbox-lan-router-probe-20260526220500-ab-cd")
        self.assertEqual(Path(value).parts, (value,))

    def test_path_component_and_short_resource_name_are_bounded(self) -> None:
        self.assertEqual(path_component(" ../Hello, LAN! "), "hello-lan")
        name = short_provider_resource_name(
            "wire",
            "virtualbox",
            "x" * 100,
            max_length=32,
        )

        self.assertLessEqual(len(name), 32)
        self.assertRegex(name, r"^[a-z0-9-]+$")
        self.assertFalse(name.endswith("-"))

    def test_utc_timestamps_are_stable_and_zulu(self) -> None:
        moment = datetime(2026, 5, 26, 1, 2, 3, 987654, tzinfo=UTC)

        self.assertEqual(utc_now(moment), "2026-05-26T01:02:03Z")
        self.assertEqual(id_timestamp(moment), "20260526010203")
        self.assertRegex(utc_now(), r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class VMHelperNetworkTest(unittest.TestCase):
    def test_free_localhost_tcp_port_returns_bindable_port(self) -> None:
        port = free_localhost_tcp_port()

        self.assertGreater(port, 0)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", port))


class VMHelperSSHKeyTest(unittest.TestCase):
    def test_public_key_path_uses_private_key_sibling(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            private_key = Path(temp_dir) / "endpoint" / "id_ed25519"

            self.assertEqual(
                public_key_path(private_key),
                private_key.with_name("id_ed25519.pub"),
            )

    def test_ensure_endpoint_ssh_key_uses_fake_keygen_runner(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            private_key = Path(temp_dir) / "endpoint" / "id_ed25519"
            calls: list[tuple[str, ...]] = []

            def fake_runner(argv: Sequence[object], **_: object) -> CommandResult:
                parts = tuple(str(part) for part in argv)
                calls.append(parts)
                key_path = Path(parts[parts.index("-f") + 1])
                key_path.write_text("private\n", encoding="utf-8")
                key_path.with_name(f"{key_path.name}.pub").write_text("public\n", encoding="utf-8")
                return CommandResult(
                    argv=parts,
                    redacted_argv=parts,
                    cwd=None,
                    exit_code=0,
                    stdout="",
                    stderr="",
                )

            key_path, pub_path = ensure_endpoint_ssh_key(
                private_key,
                "virtualbox-lan-probe",
                runner=fake_runner,
            )
            second_key_path, second_pub_path = ensure_endpoint_ssh_key(
                private_key,
                "virtualbox-lan-probe",
                runner=fake_runner,
            )

            self.assertEqual((key_path, pub_path), (private_key, private_key.with_name("id_ed25519.pub")))
            self.assertEqual((second_key_path, second_pub_path), (key_path, pub_path))
            self.assertEqual(len(calls), 1)
            self.assertIn("-C", calls[0])
            self.assertIn("libcrafter-wire virtualbox-lan-probe", calls[0])

    def test_ensure_endpoint_ssh_key_rejects_partial_key_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            private_key = Path(temp_dir) / "id_ed25519"
            private_key.write_text("private\n", encoding="utf-8")

            with self.assertRaisesRegex(FileExistsError, "incomplete"):
                ensure_endpoint_ssh_key(private_key, "endpoint-a")


class VMHelperResourceTest(unittest.TestCase):
    def test_command_error_prefers_stderr_then_stdout_then_error(self) -> None:
        stderr_result = _result(stderr="boom")
        stdout_result = _result(stdout="details")
        error_result = _result(error="missing executable")

        command = "fake --token '<redacted>'"

        self.assertEqual(command_error("failed", stderr_result), f"failed: {command}: boom")
        self.assertEqual(command_error("failed", stdout_result), f"failed: {command}: details")
        self.assertEqual(
            command_error("failed", error_result),
            f"failed: {command}: missing executable",
        )

    def test_resource_helpers_build_manifest_safe_provider_resources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "seed.iso"
            resources = provider_resources(
                [
                    vm_resource("wire-vbox-lan", kind="virtualbox-vm"),
                    process_resource(1234, name="qemu"),
                    file_resource(file_path, cleanup=False, metadata={"role": "seed"}),
                ],
                metadata={"provider": "virtualbox"},
            )

        self.assertEqual(
            resources.cleanup_order,
            ["virtualbox-vm", "process"],
        )
        self.assertEqual(resources.metadata["created_by"], "tools/endpoint")
        self.assertEqual(resources.metadata["provider"], "virtualbox")
        self.assertEqual(resources.resources[0].provider_id, "wire-vbox-lan")
        self.assertEqual(resources.resources[1].metadata["pid"], 1234)
        self.assertTrue(Path(resources.resources[2].provider_id).is_absolute())
        self.assertEqual(resources.resources[2].metadata["role"], "seed")


def _result(
    *,
    stdout: str = "",
    stderr: str = "",
    error: str | None = None,
) -> CommandResult:
    return CommandResult(
        argv=("fake", "--token", "secret"),
        redacted_argv=("fake", "--token", "<redacted>"),
        cwd=None,
        exit_code=1,
        stdout=stdout,
        stderr=stderr,
        error=error,
    )


if __name__ == "__main__":
    unittest.main()
