"""Create/destroy coverage for the standalone lab CLI."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tools.lab.engine import cli
from tools.lab.engine.model import LabCommandPlan
from tools.lab.engine.paths import LAB_ARTIFACT_ROOT_ENV, LAB_STATE_ROOT_ENV
from tools.lab.engine.session import read_session_manifest
from tools.endpoint.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResources,
)


class LabCliCreateDestroyTest(unittest.TestCase):
    def test_create_refuses_live_run_without_confirmation(self) -> None:
        fake = _FakeEndpointClient()

        with _temporary_lab_state() as env:
            with patch.dict(os.environ, env, clear=False):
                with patch("tools.lab.engine.endpoint_client.EndpointClient", return_value=fake):
                    exit_code, stdout, stderr = _run_cli(
                        "create",
                        "--provider",
                        "qemu",
                        "--profile",
                        "smoke",
                        "--seed",
                        "1",
                        "--role",
                        "stimulus",
                        "--role",
                        "target",
                        "--json",
                    )

        self.assertEqual(exit_code, 2, stderr)
        payload = json.loads(stdout)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "confirm_live_run_required")
        self.assertEqual(fake.create_calls, [])

    def test_create_persists_live_session_and_inspection_commands_read_it(self) -> None:
        fake = _FakeEndpointClient()

        with _temporary_lab_state() as env:
            with patch.dict(os.environ, env, clear=False):
                with patch("tools.lab.engine.endpoint_client.EndpointClient", return_value=fake):
                    exit_code, stdout, stderr = _run_cli(
                        "create",
                        "--provider",
                        "qemu",
                        "--profile",
                        "smoke",
                        "--seed",
                        "1",
                        "--role",
                        "stimulus",
                        "--role",
                        "target",
                        "--confirm-live-run",
                        "--json",
                    )

                self.assertEqual(exit_code, 0, stderr)
                created = json.loads(stdout)
                session_id = created["session_id"]
                self.assertEqual(session_id, "lab-qemu-qemu-smoke-seed-1")
                self.assertFalse(created["dry_run"])
                self.assertEqual(
                    created["created_endpoint_ids"],
                    ["endpoint-qemu-private-stimulus", "endpoint-qemu-private-target"],
                )
                self.assertEqual([call["role"] for call in fake.create_calls], ["stimulus", "target"])
                self.assertTrue(all(call["confirm_live_run"] for call in fake.create_calls))
                self.assertTrue(all(call["write_manifest"] for call in fake.create_calls))
                self.assertTrue(all(not call["dry_run"] for call in fake.create_calls))

                persisted = read_session_manifest(session_id)
                self.assertEqual(persisted.to_dict(), created)

                list_exit, list_stdout, list_stderr = _run_cli("list-sessions", "--json")
                self.assertEqual(list_exit, 0, list_stderr)
                listed = json.loads(list_stdout)
                self.assertEqual([item["session_id"] for item in listed["sessions"]], [session_id])
                self.assertEqual(
                    listed["sessions"][0]["created_endpoint_ids"],
                    created["created_endpoint_ids"],
                )

                info_exit, info_stdout, info_stderr = _run_cli(
                    "session-info",
                    session_id,
                    "--json",
                )
                self.assertEqual(info_exit, 0, info_stderr)
                self.assertEqual(json.loads(info_stdout), created)

    def test_destroy_collects_artifacts_destroys_endpoints_and_updates_manifest(self) -> None:
        fake = _FakeEndpointClient()

        with _temporary_lab_state() as env:
            with patch.dict(os.environ, env, clear=False):
                with patch("tools.lab.engine.endpoint_client.EndpointClient", return_value=fake):
                    create_exit, create_stdout, create_stderr = _run_cli(
                        "create",
                        "--provider",
                        "qemu",
                        "--profile",
                        "smoke",
                        "--seed",
                        "1",
                        "--role",
                        "stimulus",
                        "--role",
                        "target",
                        "--confirm-live-run",
                        "--json",
                    )
                    self.assertEqual(create_exit, 0, create_stderr)
                    created = json.loads(create_stdout)

                    destroy_exit, destroy_stdout, destroy_stderr = _run_cli(
                        "destroy",
                        "--session",
                        created["session_id"],
                        "--json",
                    )

                self.assertEqual(destroy_exit, 0, destroy_stderr)
                destroyed = json.loads(destroy_stdout)
                endpoint_ids = created["created_endpoint_ids"]
                self.assertEqual(
                    fake.collect_calls,
                    [
                        {
                            "endpoint_id": endpoint_ids[0],
                            "remote_path": created["remote_artifact_root"],
                        },
                        {
                            "endpoint_id": endpoint_ids[1],
                            "remote_path": created["remote_artifact_root"],
                        },
                    ],
                )
                self.assertEqual(fake.destroy_calls, list(reversed(endpoint_ids)))
                self.assertEqual(destroyed["cleanup_state"]["status"], "completed")
                self.assertTrue(destroyed["cleanup_state"]["artifact_collection_attempted"])
                self.assertTrue(destroyed["cleanup_state"]["teardown_attempted"])
                self.assertEqual(destroyed["cleanup_state"]["errors"], [])
                self.assertEqual(len(destroyed["command_records"]), 6)

                persisted = read_session_manifest(created["session_id"])
                self.assertEqual(persisted.cleanup_state["status"], "completed")
                self.assertEqual(persisted.to_dict(), destroyed)

    def test_destroy_keeps_attempting_after_collection_failure(self) -> None:
        fake = _FakeEndpointClient()
        fake.fail_collect_for.add("endpoint-qemu-private-stimulus")

        with _temporary_lab_state() as env:
            with patch.dict(os.environ, env, clear=False):
                with patch("tools.lab.engine.endpoint_client.EndpointClient", return_value=fake):
                    create_exit, create_stdout, create_stderr = _run_cli(
                        "create",
                        "--provider",
                        "qemu",
                        "--profile",
                        "smoke",
                        "--seed",
                        "1",
                        "--role",
                        "stimulus",
                        "--role",
                        "target",
                        "--confirm-live-run",
                        "--json",
                    )
                    self.assertEqual(create_exit, 0, create_stderr)
                    created = json.loads(create_stdout)

                    destroy_exit, destroy_stdout, _destroy_stderr = _run_cli(
                        "destroy",
                        "--session",
                        created["session_id"],
                        "--json",
                    )

                endpoint_ids = created["created_endpoint_ids"]
                self.assertEqual(destroy_exit, 1)
                destroyed = json.loads(destroy_stdout)
                self.assertEqual(destroyed["cleanup_state"]["status"], "failed")
                self.assertEqual(
                    [call["endpoint_id"] for call in fake.collect_calls],
                    endpoint_ids,
                )
                self.assertEqual(fake.destroy_calls, list(reversed(endpoint_ids)))


def _run_cli(*args: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        exit_code = cli.main(list(args))
    return exit_code, stdout.getvalue(), stderr.getvalue()


class _temporary_lab_state:
    def __enter__(self) -> dict[str, str]:
        self._temp = tempfile.TemporaryDirectory()
        root = Path(self._temp.name)
        return {
            LAB_STATE_ROOT_ENV: str(root / "state"),
            LAB_ARTIFACT_ROOT_ENV: str(root / "artifacts"),
        }

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self._temp.cleanup()


class _FakeEndpointClient:
    def __init__(self) -> None:
        self.create_calls: list[dict[str, object]] = []
        self.collect_calls: list[dict[str, object]] = []
        self.destroy_calls: list[str] = []
        self.fail_collect_for: set[str] = set()

    def create(
        self,
        *,
        provider: str,
        exposure: str,
        role: str,
        private_group: str | None,
        private_ip: str | None,
        dry_run: bool,
        write_manifest: bool,
        confirm_live_run: bool,
    ) -> "_FakeEndpointResponse":
        call = {
            "provider": provider,
            "exposure": exposure,
            "role": role,
            "private_group": private_group,
            "private_ip": private_ip,
            "dry_run": dry_run,
            "write_manifest": write_manifest,
            "confirm_live_run": confirm_live_run,
        }
        self.create_calls.append(call)
        manifest = _manifest(
            provider=provider,
            exposure=exposure,
            role=role,
            private_group=private_group,
            private_ip=private_ip,
            dry_run=dry_run,
        )
        return _FakeEndpointResponse(
            operation="create",
            provider=provider,
            exposure=exposure,
            endpoint_id=manifest.endpoint_id,
            dry_run=dry_run,
            manifest=manifest,
            json_data=manifest.to_dict(),
        )

    def collect_artifacts(
        self,
        endpoint_id: str,
        remote_path: str | None = None,
    ) -> "_FakeEndpointResponse":
        self.collect_calls.append({"endpoint_id": endpoint_id, "remote_path": remote_path})
        if endpoint_id in self.fail_collect_for:
            raise RuntimeError(f"cannot collect {endpoint_id}")
        return _FakeEndpointResponse(
            operation="collect_artifacts",
            provider="qemu",
            exposure="private",
            endpoint_id=endpoint_id,
            dry_run=False,
            manifest=None,
            json_data={"ok": True, "endpoint_id": endpoint_id},
        )

    def destroy(self, endpoint_id: str) -> "_FakeEndpointResponse":
        self.destroy_calls.append(endpoint_id)
        return _FakeEndpointResponse(
            operation="destroy",
            provider="qemu",
            exposure="private",
            endpoint_id=endpoint_id,
            dry_run=False,
            manifest=None,
            json_data={"ok": True, "endpoint_id": endpoint_id, "destroyed": True},
        )


class _FakeEndpointResponse:
    def __init__(
        self,
        *,
        operation: str,
        provider: str,
        exposure: str,
        endpoint_id: str,
        dry_run: bool,
        manifest: EndpointManifest | None,
        json_data: dict[str, object],
    ) -> None:
        self.operation = operation
        self.provider = provider
        self.exposure = exposure
        self.endpoint_id = endpoint_id
        self.dry_run = dry_run
        self.manifest = manifest
        self.json_data = json_data
        self.ok = True
        self.exit_code = 0

    def command_plan(
        self,
        *,
        purpose: str | None = None,
        role: str | None = None,
        artifacts: list[str] = (),
    ) -> LabCommandPlan:
        operation = {
            "create": "endpoint.create",
            "collect_artifacts": "endpoint.collect_artifacts",
            "destroy": "endpoint.destroy",
        }[self.operation]
        argv = {
            "create": [
                "tools/endpoint/run",
                "create",
                "--provider",
                self.provider,
                "--exposure",
                self.exposure,
                "--role",
                role or "role",
                "--confirm-live-run",
                "--write-manifest",
                "--json",
            ],
            "collect_artifacts": [
                "tools/endpoint/run",
                "collect-artifacts",
                self.endpoint_id,
            ],
            "destroy": [
                "tools/endpoint/run",
                "destroy",
                self.endpoint_id,
                "--json",
            ],
        }[self.operation]
        return LabCommandPlan(
            purpose=purpose or f"endpoint {self.operation}",
            role=role,
            argv=argv,
            operation=operation,
            dry_run=self.dry_run,
            live_mutation=self.operation in {"create", "destroy"} and not self.dry_run,
            artifacts=list(artifacts),
            metadata={
                "provider": self.provider,
                "exposure": self.exposure,
                "endpoint_id": self.endpoint_id,
                "dry_run": self.dry_run,
            },
        )


def _manifest(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
    private_ip: str | None,
    dry_run: bool,
) -> EndpointManifest:
    interface_metadata: dict[str, object] = {}
    if private_group is not None:
        interface_metadata["private_group"] = private_group
    endpoint_id = f"endpoint-{provider}-{exposure}-{role}"
    return EndpointManifest(
        endpoint_id=endpoint_id,
        provider=provider,
        exposure=exposure,
        status="planned" if dry_run else "created",
        role=role,
        created_at="2026-05-27T00:00:00Z",
        ssh=EndpointSSHInfo(host="127.0.0.1", user="root", port=22),
        interfaces=[
            NetworkInterface(
                name=exposure,
                exposure=exposure,
                ipv4=private_ip,
                provider_network_id=private_group,
                metadata=interface_metadata,
            )
        ],
        provider_resources=ProviderResources(),
        artifact_dir=f"/tmp/libcrafter-lab-test/{endpoint_id}",
        metadata={"private_group": private_group} if private_group is not None else {},
    )


if __name__ == "__main__":
    unittest.main()
