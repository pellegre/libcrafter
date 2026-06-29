"""Subprocess coverage for public probe CLI dry-run surfaces."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
PROBE_RUN = REPO_ROOT / "tools" / "probe" / "run"


class ProbeCliSurfaceTest(unittest.TestCase):
    def test_qemu_dry_run_plan_exposes_appliance_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir)
            result = _run_probe(
                "--provider",
                "qemu",
                "--dry-run",
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

        self.assertIn("probe: status=dry-run provider=qemu planned=1", result.stdout)
        self.assertEqual(report["status"], "dry-run")
        self.assertEqual(report["provider"], "qemu")
        self.assertEqual(report["profile"], "smoke")
        self.assertEqual(report["count"], 1)

        runtime = report["metadata"]["appliance_runtime"]
        self.assertEqual(runtime["profile"], "lan-raw")
        self.assertEqual(runtime["metadata"]["provider"], "qemu")
        self.assertEqual(runtime["metadata"]["execution_mode"], "ssh-docker-host")
        self.assertEqual(runtime["metadata"]["substrate"], "ssh-docker")
        self.assertEqual(report["metadata"]["session_appliance_runtime"], runtime)
        self.assertEqual(
            report["metadata"]["planned_infrastructure"]["appliance_runtime"],
            runtime,
        )
        self.assertEqual(
            sorted(report["metadata"]["endpoint_appliance_runtimes"]),
            ["stimulus", "target"],
        )
        self.assertIs(report["metadata"]["dry_run"], True)
        self.assertIs(report["metadata"]["mutates_lab"], False)


def _run_probe(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.setdefault("UV_NO_PROGRESS", "1")
    return subprocess.run(
        [str(PROBE_RUN), *args],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=120,
    )


if __name__ == "__main__":
    unittest.main()
