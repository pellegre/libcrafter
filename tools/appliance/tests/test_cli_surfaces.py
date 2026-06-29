"""Subprocess coverage for public appliance CLI surfaces."""

from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
APPLIANCE_RUN = REPO_ROOT / "tools" / "appliance" / "run"


class ApplianceCliSurfaceTest(unittest.TestCase):
    def test_run_help_exposes_runtime_registry_commands(self) -> None:
        result = _run_appliance("--help")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage: appliance", result.stdout)
        self.assertIn("profiles", result.stdout)
        self.assertIn("modules", result.stdout)
        self.assertIn("run-plan", result.stdout)

    def test_profile_and_module_lists_expose_appliance_profiles(self) -> None:
        profiles_result = _run_appliance("profiles", "list", "--json")
        modules_result = _run_appliance("modules", "list", "--json")

        self.assertEqual(profiles_result.returncode, 0, profiles_result.stderr)
        self.assertEqual(modules_result.returncode, 0, modules_result.stderr)

        profiles_payload = json.loads(profiles_result.stdout)
        modules_payload = json.loads(modules_result.stdout)
        profiles = {
            profile["name"]: profile for profile in profiles_payload["profiles"]
        }
        modules = {module["name"]: module for module in modules_payload["modules"]}

        self.assertEqual(
            sorted(profiles),
            ["dot11-monitor", "lan-raw", "wan-raw", "whad-serial"],
        )
        self.assertEqual(sorted(modules), ["base", "nrf52840-whad", "wifi-monitor"])
        self.assertEqual(profiles["lan-raw"]["network_mode"], "host")
        self.assertEqual(
            profiles["dot11-monitor"]["metadata"]["interface_env"],
            "LIBCRAFTER_DOT11_IFACE",
        )
        self.assertEqual(modules["nrf52840-whad"]["profiles"], ["whad-serial"])
        self.assertEqual(modules["wifi-monitor"]["profiles"], ["dot11-monitor"])


def _run_appliance(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.setdefault("UV_NO_PROGRESS", "1")
    return subprocess.run(
        [str(APPLIANCE_RUN), *args],
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
