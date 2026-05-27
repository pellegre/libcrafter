"""Unit coverage for oracle live provider matrix report validation."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

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
        self.assertEqual(summary["wire_exposure"], "lan")
        self.assertEqual(summary["endpoint_roles"], ["libcrafter", "reference_backend"])
        self.assertTrue(summary["no_live_packets_sent"])
        self.assertEqual(summary["lifecycle"]["endpoint_bootstrap_count"], 2)

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
        self.assertTrue(summary["doctor"]["ok"])

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

        self.assertEqual(command[:2], ["tools/wire/run", "doctor"])
        self.assertIn("virtualbox", command)
        self.assertIn("lan", command)
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
    lifecycle = {
        "remote_dir": "/tmp/libcrafter",
        "remote_artifact_root": "/tmp/libcrafter/live-artifacts/oracle-live/exchange",
        "created_endpoint_ids": ["qemu-oracle-libcrafter", "qemu-oracle-reference"],
        "keep_wire_endpoints": False,
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
            "provider_workflow": [
                {"role": "provider", "purpose": f"check-{provider}-provider"},
            ],
            "endpoint_bootstrap": [
                {"role": "libcrafter", "purpose": "bootstrap"},
                {"role": "reference_backend", "purpose": "bootstrap"},
            ],
            "artifact_collection": {"always_attempt": True},
            "teardown": {"always_attempt": True},
            "wire_endpoint_lifecycle": lifecycle,
            "provider_commands": [
                {"label": "01-doctor", "exit_code": 0},
                {"label": "99-destroy-qemu-oracle-reference", "exit_code": 0},
            ],
            "endpoint_protocol": {"batches": []},
        },
    }


if __name__ == "__main__":
    unittest.main()
