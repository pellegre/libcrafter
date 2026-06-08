"""Coverage for IP fragmentation lab artifact audit reports."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.lab import ip_fragment_artifacts
from tools.oracle.engine.model import write_json


class IpFragmentArtifactsTest(unittest.TestCase):
    def test_self_test_writes_report_with_pass_and_skip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "audit"

            exit_code = ip_fragment_artifacts.main(
                ["--self-test", "--out", str(out_dir)]
            )

            self.assertEqual(exit_code, 0)
            report = json.loads((out_dir / "report.json").read_text())
            self.assertEqual(report["status"], "passed")
            providers = {provider["provider"]: provider for provider in report["providers"]}
            self.assertEqual(providers["qemu"]["status"], "passed")
            self.assertEqual(
                providers["qemu"]["hash_comparison"]["reason"],
                "matched",
            )
            self.assertEqual(providers["hetzner"]["status"], "skipped")
            self.assertEqual(
                providers["hetzner"]["reasons"][0]["code"],
                "provider_unavailable",
            )

    def test_hash_mismatch_fails_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "input"
            out_dir = Path(tmp) / "audit"
            _write_fixture(
                root,
                transform_hashes=["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                kernel_hashes=["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
            )

            exit_code = ip_fragment_artifacts.main(
                ["--input", str(root), "--out", str(out_dir)]
            )

            self.assertEqual(exit_code, 1)
            report = json.loads((out_dir / "report.json").read_text())
            self.assertEqual(report["status"], "failed")
            provider = report["providers"][0]
            self.assertEqual(provider["provider"], "qemu")
            self.assertEqual(provider["status"], "failed")
            self.assertEqual(provider["reasons"][0]["code"], "payload_hash_mismatch")
            self.assertEqual(
                provider["hash_comparison"]["unexpected_from_kernel"],
                ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
            )

    def test_dry_run_without_payload_hashes_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "input"
            out_dir = Path(tmp) / "audit"
            write_json(
                root / "matrix-summary.json",
                {
                    "status": "passed",
                    "dry_run": True,
                    "baseline": {},
                    "providers": [
                        {
                            "provider": "qemu",
                            "status": "dry-run",
                            "dry_run": True,
                        }
                    ],
                },
            )

            exit_code = ip_fragment_artifacts.main(
                ["--input", str(root), "--out", str(out_dir)]
            )

            self.assertEqual(exit_code, 0)
            report = json.loads((out_dir / "report.json").read_text())
            self.assertEqual(report["status"], "skipped")
            provider = report["providers"][0]
            self.assertEqual(provider["status"], "skipped")
            self.assertEqual(
                provider["reasons"][0]["code"],
                "dry_run_no_payload_hash_comparison",
            )

    def test_passed_live_report_without_hash_artifacts_passes_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "input"
            out_dir = Path(tmp) / "audit"
            write_json(
                root / "matrix-summary.json",
                {
                    "status": "passed",
                    "dry_run": False,
                    "baseline": {},
                    "providers": [
                        {
                            "provider": "qemu",
                            "status": "passed",
                            "dry_run": False,
                        }
                    ],
                },
            )
            write_json(
                root / "providers" / "qemu" / "live" / "report.json",
                {
                    "mode": "live",
                    "status": "passed",
                    "profile": "ip-fragment-smoke",
                    "failures": [],
                    "metadata": {
                        "provider": "qemu",
                        "dry_run": False,
                    },
                },
            )

            exit_code = ip_fragment_artifacts.main(
                ["--input", str(root), "--out", str(out_dir)]
            )

            self.assertEqual(exit_code, 0)
            report = json.loads((out_dir / "report.json").read_text())
            self.assertEqual(report["status"], "passed")
            provider = report["providers"][0]
            self.assertEqual(provider["status"], "passed")
            self.assertEqual(
                provider["reasons"][0]["code"],
                "oracle_live_report_passed",
            )


def _write_fixture(
    root: Path,
    *,
    transform_hashes: list[str],
    kernel_hashes: list[str],
) -> None:
    artifact_root = root / "providers" / "qemu" / "live" / "artifacts" / "ip-fragment-smoke"
    summary_path = artifact_root / "ip-defrag-summary.json"
    payload_hash_path = artifact_root / "payload-hashes.json"
    workload_plan = {
        "name": "ip-fragment-smoke",
        "profile": "ip-fragment-smoke",
        "provider": "qemu",
        "dry_run": False,
        "artifacts": {
            "summary": str(summary_path),
            "payload_hashes": str(payload_hash_path),
        },
    }
    write_json(
        root / "matrix-summary.json",
        {
            "status": "passed",
            "dry_run": False,
            "baseline": {},
            "providers": [
                {
                    "provider": "qemu",
                    "status": "passed",
                    "dry_run": False,
                    "workload_plan": workload_plan,
                }
            ],
        },
    )
    write_json(
        summary_path,
        {
            "tool": "ip_defrag_pcap_summary",
            "transform": "IpDefrag",
            "outputs": [
                {"index": index, "payload_hash": payload_hash}
                for index, payload_hash in enumerate(transform_hashes)
            ],
        },
    )
    write_json(
        payload_hash_path,
        {
            "tool": "kernel_payload_hashes",
            "records": [
                {"index": index, "payload_hash": payload_hash}
                for index, payload_hash in enumerate(kernel_hashes)
            ],
        },
    )
