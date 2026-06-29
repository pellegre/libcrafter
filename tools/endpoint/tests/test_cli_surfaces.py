"""Subprocess coverage for public endpoint appliance CLI surfaces."""

from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
ENDPOINT_RUN = REPO_ROOT / "tools" / "endpoint" / "run"


class EndpointCliSurfaceTest(unittest.TestCase):
    def test_endpoint_appliance_help_exposes_runtime_workflow(self) -> None:
        result = _run_endpoint("appliance", "--help")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage: endpoint appliance", result.stdout)
        self.assertIn("plan", result.stdout)
        self.assertIn("check", result.stdout)
        self.assertIn("deploy", result.stdout)
        self.assertIn("run", result.stdout)
        self.assertIn("collect", result.stdout)

    def test_endpoint_asset_help_exposes_appliance_asset_lifecycle(self) -> None:
        result = _run_endpoint("asset", "--help")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage: endpoint asset", result.stdout)
        self.assertIn("persistent endpoint asset", result.stdout)
        self.assertIn("register", result.stdout)
        self.assertIn("list", result.stdout)
        self.assertIn("info", result.stdout)
        self.assertIn("check", result.stdout)
        self.assertIn("acquire", result.stdout)
        self.assertIn("release", result.stdout)

    def test_endpoint_virtualbox_help_exposes_group_normalization(self) -> None:
        result = _run_endpoint("virtualbox", "--help")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage: endpoint virtualbox", result.stdout)
        self.assertIn("normalize-groups", result.stdout)

        normalize = _run_endpoint("virtualbox", "normalize-groups", "--help")

        self.assertEqual(normalize.returncode, 0, normalize.stderr)
        self.assertIn("usage: endpoint virtualbox normalize-groups", normalize.stdout)
        self.assertIn("--dry-run", normalize.stdout)
        self.assertIn("--confirm-live-run", normalize.stdout)


def _run_endpoint(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.setdefault("UV_NO_PROGRESS", "1")
    return subprocess.run(
        [str(ENDPOINT_RUN), *args],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
    )


if __name__ == "__main__":
    unittest.main()
