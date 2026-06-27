"""Coverage for DHCPv6 oracle/probe artifact audit reports."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.oracle.engine import dhcpv6_artifacts


class Dhcpv6ArtifactsTest(unittest.TestCase):
    def test_self_test_writes_passed_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "audit"

            exit_code = dhcpv6_artifacts.main(["--self-test", "--out", str(out_dir)])

            self.assertEqual(exit_code, 0)
            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "passed")
            self.assertEqual(report["summary"]["missing_count"], 0)
            self.assertTrue(report["summary"]["live_run"])
            self.assertEqual(
                report["reasons"][0]["code"],
                "live_artifacts_complete",
            )

    def test_missing_pcap_fails_live_artifact_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "input"
            out_dir = Path(tmp) / "audit"
            dhcpv6_artifacts._write_self_test_fixture(
                root,
                include_pcap=False,
                dry_run=False,
            )

            exit_code = dhcpv6_artifacts.main(
                ["--input", str(root), "--out", str(out_dir)]
            )

            self.assertEqual(exit_code, 1)
            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "failed")
            self.assertIn("pcaps", report["missing"])
            self.assertEqual(
                report["reasons"][0]["code"],
                "missing_live_artifacts",
            )

    def test_dry_run_without_live_artifacts_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "input"
            out_dir = Path(tmp) / "audit"
            dhcpv6_artifacts._write_self_test_fixture(
                root,
                include_pcap=False,
                dry_run=True,
            )

            exit_code = dhcpv6_artifacts.main(
                ["--input", str(root), "--out", str(out_dir)]
            )

            self.assertEqual(exit_code, 0)
            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "skipped")
            self.assertTrue(report["summary"]["dry_run"])
            self.assertFalse(report["summary"]["live_run"])
            self.assertEqual(
                report["reasons"][0]["code"],
                "dry_run_no_live_artifacts",
            )


if __name__ == "__main__":
    unittest.main()
