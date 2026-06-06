"""Unit coverage for generic lab-backed probe live reports."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from tools.lab.engine.model import LabCommandPlan, LabEndpoint, LabRole, LabSession
from tools.lab.engine.repo import RepoBootstrapCommand, RepoBootstrapContext
from tools.probe.engine import cases as probe_cases
from tools.probe.engine import cli
from tools.probe.engine import live as probe_live
from tools.probe.engine.model import ProbeRunRequest


class ProbeLabLiveReportTest(unittest.TestCase):
    def test_guarded_live_report_uses_lab_helper_for_any_lab_provider(self) -> None:
        request, cases, plans = _request_cases_and_plans("qemu")
        sentinel = object()

        with mock.patch.object(
            cli,
            "_lab_endpoint_live_report",
            return_value=sentinel,
        ) as live_report:
            report = cli._guarded_live_report(
                request=request,
                selected_cases=cases,
                planned_cases=cases,
                probe_plans=plans,
                report_path=Path("/tmp/probe-report.json"),
                status=cli.STATUS_UNSUPPORTED,
            )

        self.assertIs(report, sentinel)
        live_report.assert_called_once()
        self.assertEqual(live_report.call_args.kwargs["request"].provider, "qemu")

    def test_lab_endpoint_live_report_uses_lab_session_bootstrap_and_cleanup(self) -> None:
        request, cases, plans = _request_cases_and_plans("qemu")
        fake_wire = _FakeWire()

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "report.json"

            with (
                mock.patch.object(cli.lab_endpoint_client, "EndpointClient", return_value=fake_wire),
                mock.patch.object(
                    cli.lab_session_state,
                    "create_session",
                    side_effect=self._create_session,
                ) as create_session,
                mock.patch.object(
                    cli.lab_session_state,
                    "cleanup_lab_session",
                    side_effect=self._cleanup_session,
                ) as cleanup_session,
                mock.patch.object(
                    cli.lab_session_state,
                    "write_session_manifest",
                ) as write_manifest,
                mock.patch.object(
                    cli.lab_repo,
                    "create_repository_archive",
                    side_effect=_create_archive,
                ) as create_archive,
                mock.patch.object(
                    cli.lab_repo,
                    "bootstrap_lab_session",
                    side_effect=_bootstrap_session,
                ) as bootstrap_session,
            ):
                report = cli._lab_endpoint_live_report(
                    request=request,
                    selected_cases=cases,
                    planned_cases=cases,
                    probe_plans=plans,
                    report_path=report_path,
                )

        self.assertEqual(report.status, cli.STATUS_PASSED)
        self.assertEqual(report.results[0].case, "icmp-echo")
        self.assertTrue(report.results[0].passed)
        self.assertEqual(report.metadata["provider"], "qemu")
        self.assertEqual(
            report.metadata["probe_plans"][0]["source_ipv4"],
            "10.77.0.10",
        )
        self.assertEqual(
            report.metadata["probe_plans"][0]["destination_ipv4"],
            "10.77.0.20",
        )
        self.assertEqual(
            report.metadata["endpoint_lifecycle"]["cleanup_state"]["status"],
            "cleaned",
        )
        self.assertEqual(report.metadata["lab_session"]["provider"], "qemu")
        self.assertTrue(create_session.called)
        self.assertTrue(create_archive.called)
        self.assertTrue(bootstrap_session.called)
        self.assertTrue(cleanup_session.called)
        self.assertGreaterEqual(write_manifest.call_count, 2)
        self.assertIn("exec", fake_wire.operations)
        self.assertIn("upload", fake_wire.operations)
        self.assertIn("download", fake_wire.operations)

    def test_lab_endpoint_live_report_accepts_pretty_endpoint_json(self) -> None:
        request, cases, plans = _request_cases_and_plans("qemu")
        fake_wire = _FakeWire(stimulus_stdout=_stimulus_response_stdout(pretty=True))

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "report.json"

            with (
                mock.patch.object(cli.lab_endpoint_client, "EndpointClient", return_value=fake_wire),
                mock.patch.object(
                    cli.lab_session_state,
                    "create_session",
                    side_effect=self._create_session,
                ),
                mock.patch.object(
                    cli.lab_session_state,
                    "cleanup_lab_session",
                    side_effect=self._cleanup_session,
                ),
                mock.patch.object(cli.lab_session_state, "write_session_manifest"),
                mock.patch.object(
                    cli.lab_repo,
                    "create_repository_archive",
                    side_effect=_create_archive,
                ),
                mock.patch.object(
                    cli.lab_repo,
                    "bootstrap_lab_session",
                    side_effect=_bootstrap_session,
                ),
            ):
                report = cli._lab_endpoint_live_report(
                    request=request,
                    selected_cases=cases,
                    planned_cases=cases,
                    probe_plans=plans,
                    report_path=report_path,
                )

        self.assertEqual(report.status, cli.STATUS_PASSED)
        self.assertEqual(report.metadata["failed_count"], 0)
        self.assertEqual(report.metadata["observed_count"], 1)
        self.assertEqual(report.results[0].metadata["failure_reason"], None)

    def test_arp_spa_variation_allows_batched_target_sender_addresses(self) -> None:
        plans = [
            {
                "case": "arp-alias-address-reply",
                "destination_ipv4": "10.77.0.20",
                "target_service": {
                    "bind_ipv4": "10.77.0.20",
                    "target_protocol_addr": "10.77.0.27",
                    "alias_ipv4": "10.77.0.27",
                },
                "validation": {
                    "sender_protocol_addr": "10.77.0.27",
                    "target_protocol_addr": "10.77.0.10",
                },
            },
            {
                "case": "arp-spa-variation",
                "destination_ipv4": "10.77.0.20",
                "target_service": {
                    "bind_ipv4": "10.77.0.20",
                    "target_protocol_addr": "10.77.0.20",
                    "alt_sender_ipv4": "10.77.0.17",
                },
                "validation": {
                    "sender_protocol_addr": "10.77.0.20",
                    "target_protocol_addr": "10.77.0.17",
                },
            },
        ]

        rewritten = probe_live.plans_with_arp_sender_protocol_candidates(plans)
        validation = rewritten[1]["validation"]

        self.assertEqual(
            validation["sender_protocol_addrs"],
            ["10.77.0.20", "10.77.0.27", "10.77.0.17"],
        )
        self.assertNotIn("sender_protocol_addrs", plans[1]["validation"])

    def _create_session(
        self,
        _adapter: object,
        lab_request: object,
        *,
        client: object,
    ) -> LabSession:
        self.assertIsNotNone(client)
        self.assertFalse(lab_request.dry_run)
        self.assertTrue(lab_request.confirm_live_run)
        self.assertEqual(lab_request.provider, "qemu")
        return _fake_session()

    def _cleanup_session(self, session: LabSession, *, client: object) -> LabSession:
        self.assertIsNotNone(client)
        cleanup_record = LabCommandPlan(
            purpose="destroy endpoint qemu-target",
            role="target",
            argv=["tools/endpoint/run", "destroy", "qemu-target", "--json"],
            operation="endpoint.destroy",
            dry_run=False,
            live_mutation=True,
            metadata={"exit_code": 0, "ok": True},
        )
        return replace(
            session,
            cleanup_state={
                "status": "cleaned",
                "artifact_collection_attempted": True,
                "teardown_attempted": True,
                "errors": [],
            },
            command_records=[*session.command_records, cleanup_record],
        )


class _FakeProcessResult:
    def __init__(self, stdout: str = "", stderr: str = "", exit_code: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.ok = exit_code == 0
        self.error = None


class _FakeWireResponse:
    def __init__(
        self,
        operation: str,
        endpoint_id: str,
        *,
        stdout: str = "",
        stderr: str = "",
        exit_code: int = 0,
    ) -> None:
        self.operation = operation
        self.endpoint_id = endpoint_id
        self.result = _FakeProcessResult(stdout, stderr, exit_code)

    def metadata(self) -> dict[str, object]:
        return {
            "operation": self.operation,
            "endpoint_id": self.endpoint_id,
            "argv": ["tools/endpoint/run", self.operation, self.endpoint_id],
            "exit_code": self.result.exit_code,
            "ok": self.result.ok,
            "artifacts": [],
        }


class _FakeWire:
    def __init__(self, *, stimulus_stdout: str | None = None) -> None:
        self.operations: list[str] = []
        self.stimulus_stdout = stimulus_stdout or _stimulus_response_stdout()

    def exec(
        self,
        endpoint_id: str,
        command: list[str],
        *,
        timeout: int | float | None = None,
    ) -> _FakeWireResponse:
        del timeout
        self.operations.append("exec")
        joined = " ".join(command)
        if "stimulus_endpoint" in joined:
            return _FakeWireResponse(
                "exec",
                endpoint_id,
                stdout=self.stimulus_stdout,
            )
        return _FakeWireResponse("exec", endpoint_id)

    def upload(
        self,
        endpoint_id: str,
        _local_path: Path,
        _remote_path: str,
    ) -> _FakeWireResponse:
        self.operations.append("upload")
        return _FakeWireResponse("upload", endpoint_id)

    def download(
        self,
        endpoint_id: str,
        _remote_path: str,
        _local_path: Path,
    ) -> _FakeWireResponse:
        self.operations.append("download")
        return _FakeWireResponse("download", endpoint_id)


def _request_cases_and_plans(
    provider: str,
) -> tuple[ProbeRunRequest, list[object], list[dict[str, object]]]:
    request = ProbeRunRequest(
        provider=provider,
        profile="smoke",
        seed=1,
        count=1,
        case_names=["icmp-echo"],
        dry_run=False,
        confirm_live_run=True,
    )
    cases = [probe_cases.PROBE_CASE_BY_NAME["icmp-echo"]]
    plans = cli._probe_plans_for_cases(request, cases)
    return request, cases, plans


def _stimulus_response_stdout(*, pretty: bool = False) -> str:
    response = {
        "results": [
            {
                "case": "icmp-echo",
                "sequence": 0,
                "status": "passed",
                "endpoint_role": "stimulus",
                "passed": True,
                "metadata": {"failure_reason": None},
                "observed_response": {
                    "case": "icmp-echo",
                    "sequence": 0,
                    "endpoint_role": "stimulus",
                    "observed": True,
                    "response_type": "icmp_echo_reply",
                    "decoded": {
                        "payload_hex": "ab" * 512,
                    },
                },
            }
        ],
        "artifacts": [],
        "artifact_paths": [],
    }
    return json.dumps(response, indent=2 if pretty else None)


def _fake_session() -> LabSession:
    roles = [
        LabRole(name="stimulus", planned_ipv4="10.77.0.10", peer_roles=["target"]),
        LabRole(name="target", planned_ipv4="10.77.0.20", peer_roles=["stimulus"]),
    ]
    endpoints = [
        _endpoint("stimulus", "10.77.0.10", "target", "10.77.0.20"),
        _endpoint("target", "10.77.0.20", "stimulus", "10.77.0.10"),
    ]
    provider_record = LabCommandPlan(
        purpose="create stimulus endpoint",
        role="stimulus",
        argv=["tools/endpoint/run", "create", "--provider", "qemu"],
        operation="endpoint.create",
        dry_run=False,
        live_mutation=True,
        metadata={"exit_code": 0, "ok": True},
    )
    return LabSession(
        provider="qemu",
        wire_provider="qemu",
        wire_exposure="private",
        session_id="lab-qemu-probe-smoke-seed-1",
        roles=roles,
        endpoints=endpoints,
        provider_capabilities={
            "provider": "qemu",
            "dry_run": False,
            "live_packet_exchange": True,
            "ipv4_unicast": True,
            "controlled_services": True,
            "controlled_router": False,
        },
        infrastructure_metadata={
            "provider": "qemu",
            "creates_infrastructure": True,
            "would_create_infrastructure": False,
        },
        provider_workflow=[provider_record],
        command_records=[provider_record],
        remote_dir="/root/libcrafter",
        remote_artifact_root="/root/libcrafter/artifacts",
        created_endpoint_ids=["qemu-stimulus", "qemu-target"],
        dry_run=False,
        cleanup_state={"status": "not_started"},
        metadata={
            "provider": "qemu",
            "private_group": "probe-smoke-seed-1",
            "private_network": True,
            "endpoint_plan": {
                "provider": "qemu",
                "wire_provider": "qemu",
                "exposure": "private",
                "endpoint_count": 2,
            },
        },
    )


def _endpoint(
    role: str,
    ipv4: str,
    peer_role: str,
    peer_ipv4: str,
) -> LabEndpoint:
    return LabEndpoint(
        endpoint_id=f"qemu-{role}",
        role=role,
        interface="private",
        ipv4=ipv4,
        peer_addresses={peer_role: {"ipv4": peer_ipv4}},
        wire_manifest={
            "endpoint_id": f"qemu-{role}",
            "provider": "qemu",
            "role": role,
        },
        metadata={
            "provider": "qemu",
            "wire_provider": "qemu",
            "wire_exposure": "private",
            "private_network": True,
        },
    )


def _create_archive(output_dir: Path, *, source_root: Path) -> object:
    del source_root
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / "libcrafter-repo.tar.gz"
    stdout_path = output_dir / "repo-archive.stdout.txt"
    stderr_path = output_dir / "repo-archive.stderr.txt"
    archive_path.write_text("", encoding="utf-8")
    stdout_path.write_text("", encoding="utf-8")
    stderr_path.write_text("", encoding="utf-8")
    return SimpleNamespace(
        archive_path=archive_path,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        command_record=LabCommandPlan(
            purpose="create repository archive",
            role=None,
            argv=["tar", "-czf", str(archive_path), "."],
            operation="lab.repo_archive",
            dry_run=False,
            artifacts=[str(archive_path), str(stdout_path), str(stderr_path)],
            metadata={"exit_code": 0, "ok": True},
        ),
    )


def _bootstrap_session(
    session: LabSession,
    bootstrap_commands: dict[str, object],
    *,
    remote_dir: str,
    archive: object,
    output_dir: Path,
    client: object,
) -> object:
    del archive, client
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "lab-bootstrap-result.json"
    summary_path.write_text("{}", encoding="utf-8")
    self_check = sorted(bootstrap_commands)
    if self_check != ["stimulus", "target"]:
        raise AssertionError(self_check)
    _assert_probe_bootstrap_command(
        session,
        bootstrap_commands["stimulus"],
        role="stimulus",
        remote_dir=remote_dir,
    )
    _assert_probe_bootstrap_command(
        session,
        bootstrap_commands["target"],
        role="target",
        remote_dir=remote_dir,
    )
    bootstrap_record = LabCommandPlan(
        purpose="run workload bootstrap",
        role="stimulus",
        argv=["tools/endpoint/run", "exec", "qemu-stimulus", "--", "bash", "-lc", "..."],
        operation="endpoint.exec",
        dry_run=False,
        live_mutation=True,
        artifacts=[str(summary_path)],
        metadata={"exit_code": 0, "ok": True},
    )
    return SimpleNamespace(
        ok=True,
        errors=[],
        artifacts=[str(summary_path)],
        remote_artifact_root=f"{remote_dir}/artifacts",
        command_records=[bootstrap_record],
        to_dict=lambda: {"ok": True, "remote_artifact_root": f"{remote_dir}/artifacts"},
    )


def _assert_probe_bootstrap_command(
    session: LabSession,
    hook: object,
    *,
    role: str,
    remote_dir: str,
) -> None:
    if not callable(hook):
        raise AssertionError(f"bootstrap hook for {role} is not callable")
    endpoints_by_role = {endpoint.role: endpoint for endpoint in session.endpoints}
    roles_by_name = {lab_role.name: lab_role for lab_role in session.roles}
    context = RepoBootstrapContext(
        session=session,
        endpoint=endpoints_by_role[role],
        role=roles_by_name[role],
        remote_archive=f"{remote_dir}/libcrafter-repo.tar.gz",
        remote_dir=remote_dir,
        remote_artifact_root=f"{remote_dir}/artifacts",
        endpoints_by_role=endpoints_by_role,
    )
    command = hook(context)
    if not isinstance(command, RepoBootstrapCommand):
        raise AssertionError(f"unexpected bootstrap command: {command!r}")
    if command.metadata.get("workload") != "probe":
        raise AssertionError(command.metadata)
    if command.metadata.get("role") != role:
        raise AssertionError(command.metadata)
    script = command.argv[2]
    if "tar -xzf" in script or "tools/endpoint/run" in script:
        raise AssertionError(script)
    if role == "stimulus" and "stimulus_endpoint" not in script:
        raise AssertionError(script)
    if role == "target" and "target_service_runtime=python3" not in script:
        raise AssertionError(script)


if __name__ == "__main__":
    unittest.main()
