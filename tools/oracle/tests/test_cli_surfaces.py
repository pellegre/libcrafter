"""Subprocess coverage for public oracle CLI dry-run surfaces."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
ORACLE_RUN = REPO_ROOT / "tools" / "oracle" / "run"


class OracleCliSurfaceTest(unittest.TestCase):
    def test_local_dry_run_live_command_is_non_live_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir)
            result = _run_oracle(
                "live",
                "--provider",
                "local-dry-run",
                "--profile",
                "smoke",
                "--seed",
                "1",
                "--count",
                "1",
                "--out",
                str(out_dir),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))

        self.assertIn("live local-dry-run: status=passed", result.stdout)
        self.assertIn("live_packet_exchange=false", result.stdout)
        self.assertEqual(report["mode"], "live")
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["metadata"]["provider"], "local-dry-run")
        self.assertEqual(report["metadata"]["wire_provider"], "hetzner")
        self.assertEqual(report["metadata"]["generated_count"], 1)
        self.assertEqual(report["metadata"]["wire_eligible_count"], 1)
        self.assertIs(report["metadata"]["live_packet_exchange"], False)
        self.assertIs(report["metadata"]["no_live_packets_sent"], True)
        self.assertEqual(
            report["metadata"]["real_provider_backed_live_mode"],
            "not executed by local-dry-run",
        )
        self.assertNotIn("appliance_runtime", report["metadata"])


def _run_oracle(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.setdefault("UV_NO_PROGRESS", "1")
    return subprocess.run(
        [str(ORACLE_RUN), *args],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=180,
    )


if __name__ == "__main__":
    unittest.main()
