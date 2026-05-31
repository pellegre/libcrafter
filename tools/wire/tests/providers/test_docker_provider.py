"""Registry coverage for the Docker wire provider."""

from __future__ import annotations

import unittest

from tools.wire.engine.providers import docker, resolve_provider
from tools.wire.engine.registry import ProviderExposureError


class DockerRegistryTest(unittest.TestCase):
    def test_docker_supports_private_lan_and_wan_exposures(self) -> None:
        for exposure in ("private", "lan", "wan"):
            with self.subTest(exposure=exposure):
                self.assertIs(resolve_provider("docker", exposure), docker)

    def test_docker_rejects_wifi_exposure(self) -> None:
        with self.assertRaisesRegex(ProviderExposureError, "supported exposures"):
            resolve_provider("docker", "wifi")
