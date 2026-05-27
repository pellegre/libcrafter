"""Focused coverage for the lab wire client process boundary."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.lab.engine.process import CommandResult, redact_argv
from tools.lab.engine.wire_client import WireClient, WireClientError
from tools.wire.engine.model import write_json as write_wire_json


class WireClientCreateTest(unittest.TestCase):
    def test_create_builds_wire_argv_and_parses_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            runner = FakeRunner()
            manifest = _manifest(root)
            runner.enqueue(stdout=json.dumps(manifest))
            client = WireClient(
                wire_path=root / "tools" / "wire" / "run",
                runner=runner,
                cwd=root,
                timeout=30,
            )

            response = client.create(
                provider="qemu",
                exposure="private",
                role="stimulus",
                private_group="lab-smoke",
                private_ip="10.42.0.10",
                dry_run=True,
                write_manifest=True,
                confirm_live_run=True,
            )

            self.assertEqual(response.manifest.endpoint_id, "endpoint-stimulus")
            self.assertEqual(response.manifest.interfaces[0].ipv4, "192.0.2.10")
            self.assertTrue(response.ok)
            self.assertEqual(response.record.operation, "create")
            self.assertEqual(response.record.wire_command, "create-endpoint")
            self.assertTrue(response.record.dry_run)
            self.assertFalse(response.record.live_mutation)
            self.assertEqual(
                runner.calls[0]["argv"],
                (
                    str((root / "tools" / "wire" / "run").resolve()),
                    "create-endpoint",
                    "--provider",
                    "qemu",
                    "--exposure",
                    "private",
                    "--role",
                    "stimulus",
                    "--json",
                    "--private-group",
                    "lab-smoke",
                    "--private-ip",
                    "10.42.0.10",
                    "--dry-run",
                    "--write-manifest",
                    "--confirm-live-run",
                ),
            )
            self.assertEqual(runner.calls[0]["cwd"], str(root.resolve()))
            self.assertEqual(runner.calls[0]["timeout"], 30)

    def test_create_can_load_manifest_from_wire_manifest_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_path = root / "wire" / "endpoint.json"
            manifest = _manifest(root)
            write_wire_json(manifest_path, manifest)
            runner = FakeRunner()
            runner.enqueue(
                stdout=json.dumps(
                    {
                        "ok": True,
                        "endpoint_id": "endpoint-stimulus",
                        "manifest_path": str(manifest_path),
                    }
                )
            )
            client = WireClient(wire_path=root / "wire-run", runner=runner, cwd=root)

            response = client.create(provider="qemu", exposure="private", dry_run=True)

            self.assertEqual(response.manifest.endpoint_id, "endpoint-stimulus")
            self.assertEqual(response.manifest.provider, "qemu")

    def test_create_failure_raises_with_wire_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            runner = FakeRunner()
            runner.enqueue(stdout=json.dumps({"ok": False, "error": "missing token"}), exit_code=2)
            client = WireClient(wire_path=root / "wire-run", runner=runner, cwd=root)

            with self.assertRaisesRegex(WireClientError, "missing token"):
                client.create(provider="hetzner", exposure="private")


class WireClientOperationTest(unittest.TestCase):
    def test_supports_all_wire_operations(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            runner = FakeRunner()
            runner.enqueue(stdout=json.dumps({"ok": True, "provider": "qemu"}))
            runner.enqueue(stdout=json.dumps({"ok": True, "destroyed": True}))
            runner.enqueue(stdout="exec stdout\n")
            runner.enqueue(stdout="upload stdout\n")
            runner.enqueue(stdout="download stdout\n")
            runner.enqueue(stdout=json.dumps({"endpoint_id": "endpoint-stimulus", "ok": True}))
            runner.enqueue(stdout=f"{root / 'artifacts'}\n")
            client = WireClient(wire_path=root / "wire-run", runner=runner, cwd=root)

            doctor = client.doctor(provider="qemu", exposure="private", dry_run=True)
            destroy = client.destroy("endpoint-stimulus")
            exec_response = client.exec("endpoint-stimulus", ["uname", "-a"], timeout=5)
            upload = client.upload("endpoint-stimulus", root / "payload.tar", "/tmp/payload.tar")
            download = client.download("endpoint-stimulus", "/tmp/report.json", root / "report.json")
            ssh_info = client.ssh_info("endpoint-stimulus")
            collect = client.collect_artifacts("endpoint-stimulus", "/tmp/artifacts")

            self.assertEqual(doctor.json_data["ok"], True)
            self.assertEqual(destroy.json_data["destroyed"], True)
            self.assertEqual(exec_response.result.stdout, "exec stdout\n")
            self.assertEqual(upload.result.stdout, "upload stdout\n")
            self.assertEqual(download.result.stdout, "download stdout\n")
            self.assertEqual(ssh_info.json_data["endpoint_id"], "endpoint-stimulus")
            self.assertEqual(collect.result.stdout, f"{root / 'artifacts'}\n")
            self.assertEqual(
                [call["argv"][1:] for call in runner.calls],
                [
                    (
                        "doctor",
                        "--provider",
                        "qemu",
                        "--exposure",
                        "private",
                        "--json",
                        "--dry-run",
                    ),
                    ("destroy-endpoint", "endpoint-stimulus", "--json"),
                    ("exec", "endpoint-stimulus", "--", "uname", "-a"),
                    (
                        "upload",
                        "endpoint-stimulus",
                        str((root / "payload.tar").resolve()),
                        "/tmp/payload.tar",
                    ),
                    (
                        "download",
                        "endpoint-stimulus",
                        "/tmp/report.json",
                        str((root / "report.json").resolve()),
                    ),
                    ("ssh-info", "endpoint-stimulus", "--json"),
                    ("collect-artifacts", "endpoint-stimulus", "--remote", "/tmp/artifacts"),
                ],
            )
            self.assertEqual(runner.calls[2]["timeout"], 5)

    def test_record_and_command_plan_use_redacted_argv(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            runner = FakeRunner()
            runner.enqueue(stdout="ok\n")
            client = WireClient(wire_path=root / "wire-run", runner=runner, cwd=root)

            response = client.exec(
                "endpoint-stimulus",
                ["curl", "--token", "supersecret", "https://example.invalid"],
            )
            plan = response.command_plan(role="stimulus")

            record_json = json.dumps(response.record.to_dict(), sort_keys=True)
            plan_json = json.dumps(plan.to_dict(), sort_keys=True)
            self.assertIn("<redacted>", record_json)
            self.assertNotIn("supersecret", record_json)
            self.assertIn("<redacted>", plan_json)
            self.assertNotIn("supersecret", plan_json)
            self.assertEqual(plan.operation, "wire.exec")
            self.assertFalse(plan.dry_run)
            self.assertTrue(plan.live_mutation)

    def test_exec_rejects_empty_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            client = WireClient(wire_path=root / "wire-run", runner=FakeRunner(), cwd=root)

            with self.assertRaisesRegex(ValueError, "wire exec requires"):
                client.exec("endpoint-stimulus", [])

    def test_invalid_json_raises_wire_client_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            runner = FakeRunner()
            runner.enqueue(stdout="not json")
            client = WireClient(wire_path=root / "wire-run", runner=runner, cwd=root)

            with self.assertRaisesRegex(WireClientError, "invalid JSON"):
                client.doctor(provider="qemu", exposure="private")


class FakeRunner:
    def __init__(self) -> None:
        self._queued: list[dict[str, object]] = []
        self.calls: list[dict[str, object]] = []

    def enqueue(
        self,
        *,
        stdout: str = "",
        stderr: str = "",
        exit_code: int = 0,
        timed_out: bool = False,
        error: str | None = None,
    ) -> None:
        self._queued.append(
            {
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "timed_out": timed_out,
                "error": error,
            }
        )

    def __call__(
        self,
        argv: object,
        *,
        cwd: str | Path | None = None,
        timeout: float | None = None,
    ) -> CommandResult:
        if not isinstance(argv, (list, tuple)):
            raise TypeError("fake runner expected argv sequence")
        normalized_argv = tuple(str(part) for part in argv)
        cwd_text = str(cwd) if cwd is not None else None
        self.calls.append(
            {
                "argv": normalized_argv,
                "cwd": cwd_text,
                "timeout": timeout,
            }
        )
        if self._queued:
            next_result = self._queued.pop(0)
        else:
            next_result = {
                "stdout": "",
                "stderr": "",
                "exit_code": 0,
                "timed_out": False,
                "error": None,
            }
        return CommandResult(
            argv=normalized_argv,
            redacted_argv=tuple(redact_argv(normalized_argv)),
            cwd=cwd_text,
            exit_code=int(next_result["exit_code"]),
            stdout=str(next_result["stdout"]),
            stderr=str(next_result["stderr"]),
            timed_out=bool(next_result["timed_out"]),
            timeout=timeout,
            error=next_result["error"] if isinstance(next_result["error"], str) else None,
        )


def _manifest(root: Path) -> dict[str, object]:
    return {
        "endpoint_id": "endpoint-stimulus",
        "provider": "qemu",
        "exposure": "private",
        "status": "active",
        "role": "stimulus",
        "created_at": "2026-05-27T00:00:00Z",
        "ssh": {
            "host": "192.0.2.10",
            "user": "root",
            "port": 22,
            "identity_file": str(root / "id_ed25519"),
            "known_hosts_file": str(root / "known_hosts"),
            "metadata": {},
        },
        "interfaces": [
            {
                "name": "eth1",
                "exposure": "private",
                "ipv4": "192.0.2.10",
                "ipv6": "2001:db8::10",
                "mac": "02:00:00:00:00:10",
                "provider_network_id": "private-lab",
                "metadata": {},
            }
        ],
        "provider_resources": {
            "resources": [],
            "cleanup_order": [],
            "metadata": {},
        },
        "artifact_dir": str(root / "artifacts" / "endpoint-stimulus"),
        "metadata": {"private_group": "lab-smoke"},
    }


if __name__ == "__main__":
    unittest.main()
