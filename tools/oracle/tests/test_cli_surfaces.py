"""Subprocess coverage for the public deterministic oracle CLI."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
ORACLE_RUN = REPO_ROOT / "tools" / "oracle" / "run"


class OracleCliSurfaceTest(unittest.TestCase):
    def test_help_exposes_only_deterministic_validation_commands(self) -> None:
        result = subprocess.run(
            [str(ORACLE_RUN), "--help"],
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=180,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("offline", result.stdout)
        self.assertIn("pcap", result.stdout)
        self.assertNotIn("live", result.stdout)
        self.assertNotIn("provider", result.stdout)

    def test_removed_live_command_is_rejected(self) -> None:
        result = subprocess.run(
            [str(ORACLE_RUN), "live"],
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=180,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid choice", result.stderr)

    def test_corpus_command_materializes_a_deterministic_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = subprocess.run(
                [
                    str(ORACLE_RUN),
                    "corpus",
                    "--profile",
                    "smoke",
                    "--seed",
                    "1",
                    "--count",
                    "1",
                    "--out",
                    temp,
                ],
                cwd=REPO_ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=180,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((Path(temp) / "plans.json").read_text())
            self.assertEqual(len(report["metadata"]["packets"]), 1)
            self.assertEqual(report["metadata"]["materialization_backend"], "scapy")


if __name__ == "__main__":
    unittest.main()
