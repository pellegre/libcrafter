"""Unit coverage for oracle live provider matrix report validation."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from tools.oracle.tests.live_provider_matrix import (
    MatrixValidationError,
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


def _live_report(
    *,
    provider: str,
    wire_provider: str,
    wire_exposure: str,
    endpoint_roles: list[str],
    corpus_path: Path,
) -> dict[str, object]:
    return {
        "mode": "live",
        "backend": "scapy",
        "profile": "smoke",
        "seed": 12345,
        "count": 10,
        "status": "dry-run",
        "metadata": {
            "provider": provider,
            "dry_run": True,
            "creates_infrastructure": False,
            "no_live_packets_sent": True,
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
            "endpoint_protocol": {"batches": []},
        },
    }


if __name__ == "__main__":
    unittest.main()
