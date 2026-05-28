"""Cleanup guarantees for partially created lab sessions."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.lab.engine import wire_client
from tools.lab.engine.model import (
    LabCommandPlan,
    LabEndpoint,
    LabRequest,
    LabRole,
    LabSession,
)
from tools.lab.engine.paths import LabConfig
from tools.lab.engine.session import (
    cleanup_created_endpoints,
    cleanup_lab_session,
    create_session,
)


class LabCleanupTest(unittest.TestCase):
    def test_create_failure_cleans_created_endpoint_before_reraising(self) -> None:
        client = _FakeCreateFailureWireClient(fail_role="target")
        request = LabRequest(
            provider="qemu",
            profile="smoke",
            seed=1,
            roles=[LabRole(name="stimulus"), LabRole(name="target")],
            dry_run=False,
            confirm_live_run=True,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = LabConfig(
                state_root=root / "state",
                artifact_root=root / "artifacts",
            )
            with self.assertRaisesRegex(
                wire_client.WireClientError,
                "create target failed",
            ) as raised:
                create_session(_FailingCreateAdapter(), request, client=client, config=config)

        self.assertEqual(
            client.events,
            [
                ("create", "stimulus"),
                ("create", "target"),
                ("collect", "endpoint-stimulus", None),
                ("destroy", "endpoint-stimulus"),
            ],
        )
        cleanup_state = raised.exception.lab_cleanup_state
        self.assertEqual(cleanup_state["status"], "completed")
        self.assertEqual(cleanup_state["endpoint_ids"], ["endpoint-stimulus"])
        self.assertEqual(cleanup_state["destroy_endpoint_ids"], ["endpoint-stimulus"])
        self.assertEqual(
            [record.operation for record in raised.exception.lab_cleanup_command_records],
            ["wire.create", "wire.collect_artifacts", "wire.destroy"],
        )

    def test_cleanup_session_keeps_destroying_after_failed_collect_result(self) -> None:
        client = _FakeCleanupWireClient()
        client.collect_failures["endpoint-stimulus"] = "collect failed"

        updated = cleanup_lab_session(_live_session(), client=client)

        self.assertEqual(
            client.collect_calls,
            [
                ("endpoint-stimulus", "/opt/libcrafter-lab/lab-cleanup/artifacts"),
                ("endpoint-target", "/opt/libcrafter-lab/lab-cleanup/artifacts"),
            ],
        )
        self.assertEqual(client.destroy_calls, ["endpoint-target", "endpoint-stimulus"])
        self.assertEqual(updated.cleanup_state["status"], "failed")
        self.assertIn(
            "artifact collection failed for endpoint-stimulus: collect failed",
            updated.cleanup_state["errors"],
        )
        self.assertEqual(
            [record.operation for record in updated.command_records],
            [
                "wire.collect_artifacts",
                "wire.collect_artifacts",
                "wire.destroy",
                "wire.destroy",
            ],
        )

    def test_cleanup_endpoint_list_records_failed_destroy_and_continues(self) -> None:
        client = _FakeCleanupWireClient()
        client.destroy_failures["endpoint-target"] = "destroy failed"

        result = cleanup_created_endpoints(
            ["endpoint-stimulus", "endpoint-target"],
            client=client,
            remote_artifact_root="/opt/libcrafter-lab/lab-cleanup/artifacts",
            endpoint_roles={
                "endpoint-stimulus": "stimulus",
                "endpoint-target": "target",
            },
        )

        self.assertEqual(
            client.collect_calls,
            [
                ("endpoint-stimulus", "/opt/libcrafter-lab/lab-cleanup/artifacts"),
                ("endpoint-target", "/opt/libcrafter-lab/lab-cleanup/artifacts"),
            ],
        )
        self.assertEqual(client.destroy_calls, ["endpoint-target", "endpoint-stimulus"])
        self.assertEqual(result.cleanup_state["status"], "failed")
        self.assertEqual(
            result.cleanup_state["destroy_endpoint_ids"],
            ["endpoint-target", "endpoint-stimulus"],
        )
        self.assertIn(
            "endpoint teardown failed for endpoint-target: destroy failed",
            result.cleanup_state["errors"],
        )
        self.assertEqual(len(result.command_records), 4)


class _FailingCreateAdapter:
    def plan_session(
        self,
        request: LabRequest,
        *,
        client: object,
    ) -> LabSession:
        for role in request.roles:
            client.create(
                provider="qemu",
                exposure="private",
                role=role.name,
                private_group="lab-cleanup-private",
                private_ip=None,
                dry_run=request.dry_run,
                write_manifest=not request.dry_run,
                confirm_live_run=request.confirm_live_run,
            )
        return _live_session()


class _FakeCleanupWireClient:
    def __init__(self) -> None:
        self.collect_calls: list[tuple[str, str | None]] = []
        self.destroy_calls: list[str] = []
        self.collect_failures: dict[str, str] = {}
        self.destroy_failures: dict[str, str] = {}

    def collect_artifacts(
        self,
        endpoint_id: str,
        remote_path: str | None = None,
    ) -> "_FakeWireResponse":
        self.collect_calls.append((endpoint_id, remote_path))
        error = self.collect_failures.get(endpoint_id)
        if error is not None:
            return _FakeWireResponse(
                operation="collect_artifacts",
                endpoint_id=endpoint_id,
                ok=False,
                exit_code=37,
                error=error,
            )
        return _FakeWireResponse(operation="collect_artifacts", endpoint_id=endpoint_id)

    def destroy(self, endpoint_id: str) -> "_FakeWireResponse":
        self.destroy_calls.append(endpoint_id)
        error = self.destroy_failures.get(endpoint_id)
        if error is not None:
            return _FakeWireResponse(
                operation="destroy",
                endpoint_id=endpoint_id,
                ok=False,
                exit_code=38,
                error=error,
            )
        return _FakeWireResponse(operation="destroy", endpoint_id=endpoint_id)


class _FakeCreateFailureWireClient(_FakeCleanupWireClient):
    def __init__(self, *, fail_role: str) -> None:
        super().__init__()
        self.fail_role = fail_role
        self.events: list[tuple[object, ...]] = []

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
    ) -> "_FakeWireResponse":
        del provider, exposure, private_group, private_ip, write_manifest, confirm_live_run
        self.events.append(("create", role))
        if role == self.fail_role:
            raise wire_client.WireClientError(f"create {role} failed")
        return _FakeWireResponse(
            operation="create",
            endpoint_id=f"endpoint-{role}",
            role=role,
            dry_run=dry_run,
        )

    def collect_artifacts(
        self,
        endpoint_id: str,
        remote_path: str | None = None,
    ) -> "_FakeWireResponse":
        self.events.append(("collect", endpoint_id, remote_path))
        return super().collect_artifacts(endpoint_id, remote_path)

    def destroy(self, endpoint_id: str) -> "_FakeWireResponse":
        self.events.append(("destroy", endpoint_id))
        return super().destroy(endpoint_id)


class _FakeWireResponse:
    def __init__(
        self,
        *,
        operation: str,
        endpoint_id: str,
        role: str | None = None,
        dry_run: bool = False,
        ok: bool = True,
        exit_code: int | None = None,
        error: str | None = None,
    ) -> None:
        self.operation = operation
        self.endpoint_id = endpoint_id
        self.role = role
        self.dry_run = dry_run
        self.ok = ok
        self.exit_code = 0 if exit_code is None and ok else exit_code or 1
        self.error = error
        self.json_data: dict[str, object] = {"endpoint_id": endpoint_id}
        if error is not None:
            self.json_data["error"] = error

    def command_plan(
        self,
        *,
        purpose: str | None = None,
        role: str | None = None,
        artifacts: list[str] = (),
    ) -> LabCommandPlan:
        operation = {
            "create": "wire.create",
            "collect_artifacts": "wire.collect_artifacts",
            "destroy": "wire.destroy",
        }[self.operation]
        argv = {
            "create": ["tools/wire/run", "create-endpoint", "--role", role or self.role or "role"],
            "collect_artifacts": ["tools/wire/run", "collect-artifacts", self.endpoint_id],
            "destroy": ["tools/wire/run", "destroy-endpoint", self.endpoint_id, "--json"],
        }[self.operation]
        return LabCommandPlan(
            purpose=purpose or f"wire {self.operation}",
            role=role,
            argv=argv,
            operation=operation,
            dry_run=self.dry_run,
            live_mutation=self.operation in {"create", "destroy"} and not self.dry_run,
            artifacts=list(artifacts),
            metadata={
                "endpoint_id": self.endpoint_id,
                "ok": self.ok,
                "exit_code": self.exit_code,
                "error": self.error,
            },
        )


def _live_session() -> LabSession:
    return LabSession(
        provider="qemu",
        wire_provider="qemu",
        wire_exposure="private",
        session_id="lab-cleanup",
        roles=[LabRole(name="stimulus"), LabRole(name="target")],
        endpoints=[
            LabEndpoint(
                endpoint_id="endpoint-stimulus",
                role="stimulus",
                interface="private",
                ipv4="10.77.0.10",
            ),
            LabEndpoint(
                endpoint_id="endpoint-target",
                role="target",
                interface="private",
                ipv4="10.77.0.20",
            ),
        ],
        remote_dir="/opt/libcrafter-lab/lab-cleanup",
        remote_artifact_root="/opt/libcrafter-lab/lab-cleanup/artifacts",
        created_endpoint_ids=["endpoint-stimulus", "endpoint-target"],
        dry_run=False,
    )


if __name__ == "__main__":
    unittest.main()
