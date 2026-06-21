"""Unit coverage for oracle live provider matrix report validation."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.oracle.engine import cli as oracle_cli
from tools.oracle.engine import live_provider_matrix
from tools.oracle.engine.live_provider_matrix import (
    MatrixValidationError,
    _doctor_skip_reason,
    _provider_doctor_command,
    build_matrix_summary,
    parse_provider_list,
    validate_live_report,
)
from tools.oracle.engine.providers.registry import resolve_live_provider


class LiveProviderMatrixTest(unittest.TestCase):
    def test_parse_provider_list_strips_empty_segments(self) -> None:
        self.assertEqual(
            parse_provider_list(" hetzner, qemu,,virtualbox "),
            ["hetzner", "qemu", "virtualbox"],
        )

    def test_validate_live_report_accepts_adapter_owned_metadata(self) -> None:
        adapter = resolve_live_provider("virtualbox")
        corpus_path = Path("/tmp/libcrafter-corpus/plans.json")
        report = _live_report(
            provider="virtualbox",
            wire_provider=adapter.wire_provider,
            wire_exposure=adapter.wire_exposure,
            endpoint_roles=list(adapter.endpoint_roles),
            corpus_path=corpus_path,
        )

        summary = validate_live_report(
            report,
            provider="virtualbox",
            adapter=adapter,
            corpus_id="corpus-v1-test",
            corpus_path=corpus_path,
            report_path=Path("/tmp/virtualbox/live/report.json"),
        )

        self.assertEqual(summary["provider"], "virtualbox")
        self.assertEqual(summary["wire_exposure"], "private")
        self.assertEqual(summary["endpoint_roles"], ["libcrafter", "reference_backend"])
        self.assertTrue(summary["no_live_packets_sent"])
        self.assertEqual(summary["lifecycle"]["endpoint_bootstrap_count"], 2)
        self.assertEqual(summary["lifecycle"]["lab_provider_workflow_count"], 2)
        self.assertEqual(summary["lifecycle"]["command_record_count"], 2)
        self.assertEqual(summary["lab_session"]["provider"], "virtualbox")
        self.assertEqual(summary["lab_session"]["roles"], ["libcrafter", "reference_backend"])
        self.assertEqual(summary["lab_session"]["validation_count"], 2)

    def test_validate_live_report_preserves_ip_fragment_workload_plan(self) -> None:
        adapter = resolve_live_provider("qemu")
        corpus_path = Path("/tmp/libcrafter-corpus/plans.json")
        report = _live_report(
            provider="qemu",
            wire_provider=adapter.wire_provider,
            wire_exposure=adapter.wire_exposure,
            endpoint_roles=list(adapter.endpoint_roles),
            corpus_path=corpus_path,
        )
        report["profile"] = "ip-fragment-smoke"
        metadata = report["metadata"]
        self.assertIsInstance(metadata, dict)
        metadata["workload_plan"] = _ip_fragment_workload_plan()

        summary = validate_live_report(
            report,
            provider="qemu",
            adapter=adapter,
            corpus_id="corpus-v1-test",
            corpus_path=corpus_path,
            report_path=Path("/tmp/qemu/live/report.json"),
        )

        self.assertEqual(summary["workload_plan"]["profile"], "ip-fragment-smoke")
        self.assertIn("small MTU setup", summary["workload_plan"]["steps"])
        self.assertIn("payload hash comparison", summary["workload_plan"]["steps"])

    def test_ip_fragment_workload_plan_confirms_live_send_command(self) -> None:
        adapter = resolve_live_provider("qemu")
        plan = oracle_cli._ip_fragment_workload_plan(
            argparse.Namespace(
                profile="ip-fragment-smoke",
                backend="scapy",
                provider="qemu",
                seed=1301,
                count=2,
            ),
            adapter,
            dry_run=True,
            output_dir=Path("/tmp/qemu/live"),
        )

        self.assertIsNotNone(plan)
        commands = plan["commands"]
        self.assertIsInstance(commands, list)
        send_command = next(
            command
            for command in commands
            if command["name"] == "send-oversized-payload"
        )
        self.assertIn("--backend", send_command["argv"])
        self.assertIn("scapy", send_command["argv"])
        self.assertIn("--confirm-live-run", send_command["argv"])

    def test_validate_live_report_accepts_docker_adapter_owned_metadata(self) -> None:
        adapter = resolve_live_provider("docker")
        corpus_path = Path("/tmp/libcrafter-corpus/plans.json")
        report = _live_report(
            provider="docker",
            wire_provider=adapter.wire_provider,
            wire_exposure=adapter.wire_exposure,
            endpoint_roles=list(adapter.endpoint_roles),
            corpus_path=corpus_path,
        )

        summary = validate_live_report(
            report,
            provider="docker",
            adapter=adapter,
            corpus_id="corpus-v1-test",
            corpus_path=corpus_path,
            report_path=Path("/tmp/docker/live/report.json"),
        )

        self.assertEqual(summary["provider"], "docker")
        self.assertEqual(summary["wire_provider"], "docker")
        self.assertEqual(summary["wire_exposure"], "private")
        self.assertEqual(summary["endpoint_roles"], ["libcrafter", "reference_backend"])
        self.assertTrue(summary["no_live_packets_sent"])
        self.assertEqual(summary["lifecycle"]["endpoint_bootstrap_count"], 2)
        self.assertEqual(summary["lifecycle"]["lab_provider_workflow_count"], 2)
        self.assertEqual(summary["lifecycle"]["command_record_count"], 2)
        self.assertEqual(summary["lab_session"]["provider"], "docker")
        self.assertEqual(summary["lab_session"]["wire_provider"], "docker")
        self.assertEqual(summary["lab_session"]["wire_exposure"], "private")
        self.assertEqual(summary["lab_session"]["roles"], ["libcrafter", "reference_backend"])
        self.assertEqual(summary["lab_session"]["validation_count"], 2)

    def test_validate_live_report_accepts_no_wire_eligible_dry_run_skip(self) -> None:
        adapter = resolve_live_provider("hetzner")
        corpus_path = Path("/tmp/libcrafter-corpus/plans.json")
        report = _no_wire_eligible_live_report(
            provider="hetzner",
            wire_provider=adapter.wire_provider,
            wire_exposure=adapter.wire_exposure,
            endpoint_roles=list(adapter.endpoint_roles),
            corpus_path=corpus_path,
            planned_infrastructure=adapter.planned_infrastructure(dry_run=True),
            provider_workflow=[
                command.to_dict()
                for command in adapter.provider_workflow(dry_run=True)
            ],
        )

        summary = validate_live_report(
            report,
            provider="hetzner",
            adapter=adapter,
            corpus_id="corpus-v1-test",
            corpus_path=corpus_path,
            report_path=Path("/tmp/hetzner/live/report.json"),
        )

        self.assertEqual(summary["provider"], "hetzner")
        self.assertEqual(summary["status"], "skipped")
        self.assertEqual(summary["skip_reason"], "no_wire_eligible_packets")
        self.assertEqual(summary["wire_eligible_count"], 0)
        self.assertTrue(summary["no_live_packets_sent"])
        self.assertFalse(summary["live_packet_exchange"])
        self.assertEqual(summary["lifecycle"]["endpoint_bootstrap_count"], 2)
        self.assertEqual(summary["lifecycle"]["provider_command_count"], 0)

    def test_validate_real_live_report_preserves_vm_lifecycle(self) -> None:
        adapter = resolve_live_provider("qemu")
        corpus_path = Path("/tmp/libcrafter-corpus/plans.json")
        report = _live_report(
            provider="qemu",
            wire_provider=adapter.wire_provider,
            wire_exposure=adapter.wire_exposure,
            endpoint_roles=list(adapter.endpoint_roles),
            corpus_path=corpus_path,
            dry_run=False,
            status="passed",
        )

        summary = validate_live_report(
            report,
            provider="qemu",
            adapter=adapter,
            corpus_id="corpus-v1-test",
            corpus_path=corpus_path,
            report_path=Path("/tmp/qemu/live/report.json"),
            dry_run=False,
            doctor={
                "ok": True,
                "failed_checks": [],
            },
        )

        self.assertFalse(summary["dry_run"])
        self.assertTrue(summary["live_packet_exchange"])
        self.assertEqual(
            summary["lifecycle"]["endpoint_ids"],
            ["qemu-oracle-libcrafter", "qemu-oracle-reference"],
        )
        self.assertEqual(
            summary["lifecycle"]["remote_artifact_root"],
            "/tmp/libcrafter/live-artifacts/oracle-live/exchange",
        )
        self.assertTrue(summary["lifecycle"]["artifact_collection"]["always_attempt"])
        self.assertTrue(summary["lifecycle"]["teardown"]["always_attempt"])
        self.assertEqual(summary["lab_session"]["endpoint_ids"], [
            "qemu-oracle-libcrafter",
            "qemu-oracle-reference",
        ])
        self.assertEqual(
            summary["lab_session"]["remote_artifact_root"],
            "/tmp/libcrafter/live-artifacts/oracle-live/exchange",
        )
        self.assertTrue(summary["doctor"]["ok"])

    def test_validate_live_report_rejects_missing_lab_session_metadata(self) -> None:
        adapter = resolve_live_provider("qemu")
        corpus_path = Path("/tmp/libcrafter-corpus/plans.json")
        report = _live_report(
            provider="qemu",
            wire_provider=adapter.wire_provider,
            wire_exposure=adapter.wire_exposure,
            endpoint_roles=list(adapter.endpoint_roles),
            corpus_path=corpus_path,
        )
        metadata = report["metadata"]
        self.assertIsInstance(metadata, dict)
        del metadata["lab_session"]

        with self.assertRaises(MatrixValidationError) as error:
            validate_live_report(
                report,
                provider="qemu",
                adapter=adapter,
                corpus_id="corpus-v1-test",
                corpus_path=corpus_path,
                report_path=Path("/tmp/qemu/live/report.json"),
            )

        self.assertIn("metadata.lab_session", str(error.exception))

    def test_validate_live_report_rejects_wrong_adapter_exposure(self) -> None:
        adapter = resolve_live_provider("qemu")
        corpus_path = Path("/tmp/libcrafter-corpus/plans.json")
        report = _live_report(
            provider="qemu",
            wire_provider=adapter.wire_provider,
            wire_exposure="lan",
            endpoint_roles=list(adapter.endpoint_roles),
            corpus_path=corpus_path,
        )

        with self.assertRaises(MatrixValidationError) as error:
            validate_live_report(
                report,
                provider="qemu",
                adapter=adapter,
                corpus_id="corpus-v1-test",
                corpus_path=corpus_path,
                report_path=Path("/tmp/qemu/live/report.json"),
            )

        self.assertIn("wire_exposure", str(error.exception))

    def test_build_matrix_summary_keeps_common_corpus_and_provider_summaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus_path = root / "corpus" / "plans.json"
            summary = build_matrix_summary(
                backend="scapy",
                profile="smoke",
                seed=12345,
                count=5,
                dry_run=True,
                corpus_path=corpus_path,
                corpus_report={
                    "corpus_id": "corpus-v1-test",
                    "count": 5,
                },
                offline_report_path=root / "baseline" / "offline" / "report.json",
                pcap_report_path=root / "baseline" / "pcap" / "report.json",
                providers=[
                    {
                        "provider": "hetzner",
                        "corpus_id": "corpus-v1-test",
                        "status": "dry-run",
                    },
                    {
                        "provider": "qemu",
                        "corpus_id": "corpus-v1-test",
                        "status": "dry-run",
                    },
                ],
                commands=[
                    {
                        "label": "corpus",
                        "argv": ["tools/oracle/run", "corpus"],
                        "exit_code": 0,
                    }
                ],
            )

        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["corpus"]["corpus_id"], "corpus-v1-test")
        self.assertEqual([item["provider"] for item in summary["providers"]], ["hetzner", "qemu"])
        self.assertEqual(summary["commands"][0]["label"], "corpus")

    def test_build_matrix_summary_marks_real_strict_skip_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary = build_matrix_summary(
                status="failed",
                backend="scapy",
                profile="smoke",
                seed=12345,
                count=2,
                dry_run=False,
                skip_unavailable=True,
                strict_vm_smoke=True,
                corpus_path=root / "corpus" / "plans.json",
                corpus_report={
                    "corpus_id": "corpus-v1-test",
                    "count": 2,
                },
                offline_report_path=root / "baseline" / "offline" / "report.json",
                pcap_report_path=root / "baseline" / "pcap" / "report.json",
                providers=[
                    {
                        "provider": "virtualbox",
                        "status": "skipped",
                        "skip_reason": "provider doctor failed",
                    }
                ],
                commands=[],
            )

        self.assertEqual(summary["status"], "failed")
        self.assertFalse(summary["dry_run"])
        self.assertTrue(summary["real_run"])
        self.assertTrue(summary["skip_unavailable"])
        self.assertTrue(summary["strict_vm_smoke"])
        self.assertFalse(summary["allow_vm_create"])

    def test_provider_doctor_command_uses_adapter_wire_pair(self) -> None:
        adapter = resolve_live_provider("virtualbox")

        command = _provider_doctor_command(adapter)

        self.assertEqual(command[:2], ["tools/endpoint/run", "doctor"])
        self.assertIn("virtualbox", command)
        self.assertIn("private", command)
        self.assertIn("--json", command)

    def test_doctor_skip_reason_includes_failed_checks(self) -> None:
        reason = _doctor_skip_reason(
            {
                "failed_checks": [
                    {
                        "name": "VBoxManage_installed",
                        "ok": False,
                        "message": "VBoxManage was not found on PATH",
                    }
                ],
                "command": {"exit_code": 1},
            }
        )

        self.assertIn("provider doctor failed", reason)
        self.assertIn("VBoxManage_installed", reason)

    def test_real_hetzner_doctor_failure_writes_structured_skip_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "matrix"
            labels: list[str] = []

            def fake_run_command(
                argv: list[str],
                *,
                cwd: Path,
                out_dir: Path,
                label: str,
                check: bool = True,
            ) -> dict[str, object]:
                del cwd, check
                labels.append(label)
                logs_dir = out_dir / "logs"
                logs_dir.mkdir(parents=True, exist_ok=True)
                stdout_path = logs_dir / f"{label}.stdout.txt"
                stderr_path = logs_dir / f"{label}.stderr.txt"
                stdout_path.write_text("", encoding="utf-8")
                stderr_path.write_text("", encoding="utf-8")
                exit_code = 0

                if label == "corpus":
                    corpus_out = Path(argv[argv.index("--out") + 1])
                    corpus_out.mkdir(parents=True, exist_ok=True)
                    (corpus_out / "plans.json").write_text(
                        json.dumps({"corpus_id": "corpus-v1-test", "count": 2}),
                        encoding="utf-8",
                    )
                elif label == "doctor-hetzner":
                    exit_code = 1
                    stdout_path.write_text(
                        json.dumps(
                            {
                                "ok": False,
                                "checks": [
                                    {
                                        "name": "credentials",
                                        "ok": False,
                                        "message": (
                                            "missing HETZNER_API_TOKEN or HCLOUD_TOKEN"
                                        ),
                                    }
                                ],
                            }
                        ),
                        encoding="utf-8",
                    )

                return {
                    "label": label,
                    "argv": list(argv),
                    "exit_code": exit_code,
                    "stdout_path": str(stdout_path),
                    "stderr_path": str(stderr_path),
                }

            with patch.object(
                live_provider_matrix,
                "_run_command",
                side_effect=fake_run_command,
            ):
                exit_code = live_provider_matrix.main(
                    [
                        "--providers",
                        "hetzner",
                        "--backend",
                        "scapy",
                        "--profile",
                        "ip-fragment-smoke",
                        "--seed",
                        "1305",
                        "--count",
                        "2",
                        "--real",
                        "--skip-unavailable",
                        "--confirm-live-run",
                        "--out",
                        str(out_dir),
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(labels, ["corpus", "offline", "pcap", "doctor-hetzner"])
            summary = json.loads((out_dir / "matrix-summary.json").read_text())
            provider = summary["providers"][0]
            self.assertFalse(summary["dry_run"])
            self.assertTrue(summary["real_run"])
            self.assertEqual(provider["provider"], "hetzner")
            self.assertEqual(provider["status"], "skipped")
            self.assertIn("missing HETZNER_API_TOKEN", provider["skip_reason"])
            self.assertTrue(provider["no_live_packets_sent"])

    def test_igmp_vm_live_gate_allows_real_qemu_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "matrix"
            labels: list[str] = []
            live_argv: list[str] = []

            def fake_run_command(
                argv: list[str],
                *,
                cwd: Path,
                out_dir: Path,
                label: str,
                check: bool = True,
            ) -> dict[str, object]:
                del cwd, check
                labels.append(label)
                logs_dir = out_dir / "logs"
                logs_dir.mkdir(parents=True, exist_ok=True)
                stdout_path = logs_dir / f"{label}.stdout.txt"
                stderr_path = logs_dir / f"{label}.stderr.txt"
                stdout_path.write_text("", encoding="utf-8")
                stderr_path.write_text("", encoding="utf-8")

                if label == "corpus":
                    corpus_out = Path(argv[argv.index("--out") + 1])
                    corpus_out.mkdir(parents=True, exist_ok=True)
                    (corpus_out / "plans.json").write_text(
                        json.dumps({"corpus_id": "corpus-v1-test", "count": 2}),
                        encoding="utf-8",
                    )
                elif label == "doctor-qemu":
                    stdout_path.write_text(
                        json.dumps({"ok": True, "failed_checks": []}),
                        encoding="utf-8",
                    )
                elif label == "live-qemu":
                    live_argv[:] = list(argv)
                    live_out = Path(argv[argv.index("--out") + 1])
                    corpus_path = Path(argv[argv.index("--corpus") + 1])
                    live_out.mkdir(parents=True, exist_ok=True)
                    adapter = resolve_live_provider("qemu")
                    (live_out / "report.json").write_text(
                        json.dumps(
                            _live_report(
                                provider="qemu",
                                wire_provider=adapter.wire_provider,
                                wire_exposure=adapter.wire_exposure,
                                endpoint_roles=list(adapter.endpoint_roles),
                                corpus_path=corpus_path,
                                dry_run=False,
                                status="passed",
                            )
                        ),
                        encoding="utf-8",
                    )

                return {
                    "label": label,
                    "argv": list(argv),
                    "exit_code": 0,
                    "stdout_path": str(stdout_path),
                    "stderr_path": str(stderr_path),
                }

            with patch.dict(
                os.environ,
                {
                    live_provider_matrix.IGMP_VM_LIVE_ENV: "1",
                    live_provider_matrix.ALLOW_VM_CREATE_ENV: "0",
                },
            ), patch.object(
                live_provider_matrix,
                "_run_command",
                side_effect=fake_run_command,
            ):
                exit_code = live_provider_matrix.main(
                    [
                        "--providers",
                        "qemu",
                        "--backend",
                        "scapy",
                        "--family",
                        "igmp",
                        "--profile",
                        "igmp-live-dry-run",
                        "--seed",
                        "3601",
                        "--count",
                        "2",
                        "--real",
                        "--skip-unavailable",
                        "--confirm-live-run",
                        "--out",
                        str(out_dir),
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(labels, ["corpus", "offline", "pcap", "doctor-qemu", "live-qemu"])
            self.assertIn("--confirm-live-run", live_argv)
            self.assertIn("--family", live_argv)
            self.assertIn("igmp", live_argv)
            summary = json.loads((out_dir / "matrix-summary.json").read_text())
            self.assertEqual(summary["family"], "igmp")
            self.assertTrue(summary["allow_vm_create"])
            provider = summary["providers"][0]
            self.assertEqual(provider["provider"], "qemu")
            self.assertEqual(provider["status"], "passed")
            self.assertTrue(provider["lifecycle"]["artifact_collection"]["always_attempt"])
            self.assertTrue(provider["lifecycle"]["teardown"]["always_attempt"])


def _no_wire_eligible_live_report(
    *,
    provider: str,
    wire_provider: str,
    wire_exposure: str,
    endpoint_roles: list[str],
    corpus_path: Path,
    planned_infrastructure: dict[str, object],
    provider_workflow: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "mode": "live",
        "backend": "scapy",
        "profile": "dot11-smoke",
        "seed": 1302,
        "count": 0,
        "status": "skipped",
        "artifact_paths": ["/tmp/hetzner/live/report.json"],
        "metadata": {
            "provider": provider,
            "dry_run": True,
            "skipped": True,
            "skip_reason": "no_wire_eligible_packets",
            "creates_infrastructure": False,
            "planned_live_packet_exchange": False,
            "live_packet_exchange": False,
            "no_live_packets_sent": True,
            "corpus_id": "corpus-v1-test",
            "corpus_path": str(corpus_path),
            "wire_provider": wire_provider,
            "wire_exposure": wire_exposure,
            "endpoint_roles": endpoint_roles,
            "wire_eligible_count": 0,
            "wire_skipped_count": 5,
            "wire_skip_reasons": {
                "requires_l2": 5,
                "wire_compare_root_unavailable": 5,
            },
            "planned_infrastructure_if_packets_eligible": planned_infrastructure,
            "provider_workflow_if_packets_eligible": provider_workflow,
            "endpoint_bootstrap_if_packets_eligible": [
                {"role": role, "purpose": "bootstrap"}
                for role in endpoint_roles
            ],
        },
    }


def _ip_fragment_workload_plan() -> dict[str, object]:
    return {
        "name": "ip-fragment-smoke",
        "profile": "ip-fragment-smoke",
        "provider": "qemu",
        "backend": "scapy",
        "seed": 1301,
        "count": 2,
        "dry_run": True,
        "creates_infrastructure": False,
        "no_live_packets_sent": True,
        "steps": [
            "small MTU setup",
            "offload disabling where supported",
            "oversized/crafted fragment traffic",
            "pcap capture",
            "payload hash comparison",
        ],
        "commands": [
            {"description": "small MTU setup", "argv": ["ip", "link"]},
            {"description": "offload disabling", "argv": ["ethtool"]},
            {"description": "oversized/crafted fragment traffic", "argv": ["send"]},
            {"description": "pcap capture", "argv": ["tcpdump"]},
            {"description": "payload hash comparison", "argv": ["summary"]},
        ],
    }


def _live_report(
    *,
    provider: str,
    wire_provider: str,
    wire_exposure: str,
    endpoint_roles: list[str],
    corpus_path: Path,
    dry_run: bool = True,
    status: str = "dry-run",
) -> dict[str, object]:
    endpoint_ids = (
        [f"{provider}-oracle-libcrafter", f"{provider}-oracle-reference"]
        if not dry_run
        else []
    )
    cleanup_state = {
        "status": "not_started" if dry_run else "completed",
        "artifact_collection_attempted": not dry_run,
        "teardown_attempted": not dry_run,
    }
    lifecycle = {
        "remote_dir": "/tmp/libcrafter",
        "remote_artifact_root": "/tmp/libcrafter/live-artifacts/oracle-live/exchange",
        "created_endpoint_ids": endpoint_ids,
        "keep_wire_endpoints": False,
        "cleanup_state": cleanup_state,
    }
    provider_commands = [
        {
            "label": f"02-create-{role}",
            "operation": "endpoint.create",
            "role": role,
            "exit_code": 0,
        }
        for role in endpoint_roles
    ]
    lab_provider_workflow = [
        {
            "purpose": f"check-{provider}-provider",
            "operation": "endpoint.doctor",
            "role": None,
        },
        {
            "purpose": "collect-lab-artifacts",
            "operation": "endpoint.collect_artifacts",
            "role": None,
        },
    ]
    lab_session = {
        "provider": provider,
        "wire_provider": wire_provider,
        "wire_exposure": wire_exposure,
        "session_id": f"{provider}-oracle-session",
        "roles": [{"name": role, "peer_roles": []} for role in endpoint_roles],
        "endpoints": [
            {
                "endpoint_id": f"{provider}-oracle-{role}",
                "role": role,
                "interface": "lab0",
                "address": "192.0.2.10",
            }
            for role in endpoint_roles
        ],
        "provider_capabilities": {"provider": provider, "dry_run": dry_run},
        "infrastructure_metadata": {
            "provider": provider,
            "wire_provider": wire_provider,
            "wire_exposure": wire_exposure,
            "dry_run": dry_run,
            "creates_infrastructure": not dry_run,
            "would_create_infrastructure": dry_run,
        },
        "provider_workflow": lab_provider_workflow,
        "command_records": provider_commands,
        "remote_dir": "/tmp/libcrafter",
        "remote_artifact_root": "/tmp/libcrafter/live-artifacts/oracle-live/exchange",
        "created_endpoint_ids": endpoint_ids,
        "dry_run": dry_run,
        "cleanup_state": cleanup_state,
        "validation_checks": [
            {
                "name": f"{provider}-request",
                "passed": True,
                "subject": provider,
            },
            {
                "name": f"{provider}-session",
                "passed": True,
                "subject": provider,
            },
        ],
        "schema_version": 1,
        "metadata": {"provider": provider},
    }
    return {
        "mode": "live",
        "backend": "scapy",
        "profile": "smoke",
        "seed": 12345,
        "count": 10,
        "status": status,
        "artifact_paths": [
            "/tmp/qemu/live/report.json",
            "/tmp/qemu/live/artifacts/provider/01-doctor.stdout.txt",
        ],
        "metadata": {
            "provider": provider,
            "dry_run": dry_run,
            "creates_infrastructure": not dry_run,
            "no_live_packets_sent": dry_run,
            "planned_live_packet_exchange": not dry_run,
            "live_packet_exchange": not dry_run,
            "corpus_id": "corpus-v1-test",
            "corpus_path": str(corpus_path),
            "wire_provider": wire_provider,
            "wire_exposure": wire_exposure,
            "endpoint_roles": endpoint_roles,
            "wire_eligible_count": 5,
            "wire_skipped_count": 0,
            "wire_skip_reasons": {},
            "planned_infrastructure": lab_session["infrastructure_metadata"],
            "endpoint_plan": {
                "provider": provider,
                "wire_provider": wire_provider,
                "wire_exposure": wire_exposure,
                "exposure": wire_exposure,
                "dry_run": dry_run,
                "endpoint_count": len(endpoint_roles),
                "endpoints": {
                    role: {
                        "endpoint_id": f"{provider}-oracle-{role}",
                        "role": role,
                    }
                    for role in endpoint_roles
                },
                "endpoint_plans": [
                    {
                        "endpoint_id": f"{provider}-oracle-{role}",
                        "role": role,
                    }
                    for role in endpoint_roles
                ],
                "command_records": provider_commands,
                "created_endpoint_ids": endpoint_ids,
                "lab_session_id": lab_session["session_id"],
            },
            "wire_endpoint_plan": {
                "provider": provider,
                "wire_provider": wire_provider,
                "wire_exposure": wire_exposure,
                "exposure": wire_exposure,
                "dry_run": dry_run,
                "endpoint_count": len(endpoint_roles),
                "endpoints": {
                    role: {
                        "endpoint_id": f"{provider}-oracle-{role}",
                        "role": role,
                    }
                    for role in endpoint_roles
                },
                "endpoint_plans": [
                    {
                        "endpoint_id": f"{provider}-oracle-{role}",
                        "role": role,
                    }
                    for role in endpoint_roles
                ],
                "command_records": provider_commands,
                "created_endpoint_ids": endpoint_ids,
                "lab_session_id": lab_session["session_id"],
            },
            "provider_workflow": [
                {"role": "provider", "purpose": f"check-{provider}-provider"},
            ],
            "lab_provider_workflow": lab_provider_workflow,
            "endpoint_bootstrap": [
                {"role": "libcrafter", "purpose": "bootstrap"},
                {"role": "reference_backend", "purpose": "bootstrap"},
            ],
            "artifact_collection": {"always_attempt": True},
            "teardown": {"always_attempt": True},
            "endpoint_lifecycle": lifecycle,
            "wire_endpoint_lifecycle": lifecycle,
            "provider_commands": provider_commands,
            "command_records": provider_commands,
            "lab_session": lab_session,
            "endpoint_protocol": {"batches": []},
        },
    }


if __name__ == "__main__":
    unittest.main()
