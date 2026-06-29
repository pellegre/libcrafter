"""Subprocess coverage for public lab CLI surfaces."""

from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
LAB_RUN = REPO_ROOT / "tools" / "lab" / "run"


class LabCliSurfaceTest(unittest.TestCase):
    def test_providers_json_exposes_appliance_runtime_shape(self) -> None:
        result = _run_lab("providers", "--json")

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        providers = {provider["name"]: provider for provider in payload["providers"]}

        self.assertTrue(payload["ok"])
        self.assertEqual(sorted(providers), ["docker", "hetzner", "qemu", "virtualbox"])
        for name, provider in providers.items():
            with self.subTest(provider=name):
                runtime = provider["appliance_runtime"]
                self.assertEqual(runtime["profile"], "lan-raw")
                self.assertEqual(runtime["provider"], name)
                self.assertEqual(runtime["wire_provider"], provider["wire_provider"])
                self.assertEqual(runtime["wire_exposure"], "private")
                if name == "docker":
                    self.assertEqual(runtime["substrate"], "endpoint-container")
                    self.assertEqual(runtime["execution_mode"], "endpoint-container")
                    self.assertFalse(runtime["docker_execution_supported"])
                    self.assertFalse(runtime["nested_docker"])
                else:
                    self.assertEqual(runtime["substrate"], "ssh-docker")
                    self.assertEqual(runtime["execution_mode"], "ssh-docker-host")
                    self.assertTrue(runtime["docker_execution_supported"])
                    self.assertTrue(runtime["nested_docker"])


def _run_lab(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.setdefault("UV_NO_PROGRESS", "1")
    return subprocess.run(
        [str(LAB_RUN), *args],
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
