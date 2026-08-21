"""Probe CLI coverage for the plan-only public surface."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
RUNNER = REPO_ROOT / "tools" / "probe" / "run"


class ProbeCliTest(unittest.TestCase):
    def test_help_describes_plan_only_contract(self) -> None:
        result = subprocess.run(
            [str(RUNNER), "--help"],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("never selects", result.stdout)
        self.assertIn("infrastructure or sends packets", result.stdout)
        self.assertNotIn("--live", result.stdout)

    def test_report_is_deterministic_and_non_mutating(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            roots = [Path(temp) / "report", Path(temp) / "report"]
            reports = []
            for root in roots:
                result = subprocess.run(
                    [
                        str(RUNNER),
                        "--profile",
                        "smoke",
                        "--seed",
                        "7",
                        "--count",
                        "8",
                        "--out",
                        str(root),
                    ],
                    cwd=REPO_ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                reports.append(json.loads((root / "report.json").read_text()))

        self.assertEqual(reports[0], reports[1])
        report = reports[0]
        self.assertEqual(report["mode"], "plan")
        self.assertEqual(report["status"], "planned")
        self.assertEqual(report["metadata"]["mutates_network"], False)
        self.assertEqual(report["metadata"]["selects_infrastructure"], False)
        self.assertEqual(len(report["plans"]), 8)


if __name__ == "__main__":
    unittest.main()
