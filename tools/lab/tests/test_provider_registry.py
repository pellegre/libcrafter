"""Coverage for the lab provider adapter registry."""

from __future__ import annotations

import unittest

from tools.lab.engine.providers import (
    DOCKER_LAB_PROVIDER_ADAPTER,
    HETZNER_LAB_PROVIDER_ADAPTER,
    LabProviderAdapter,
    QEMU_LAB_PROVIDER_ADAPTER,
    UnknownLabProviderError,
    VIRTUALBOX_LAB_PROVIDER_ADAPTER,
    registered_provider_names,
    resolve_lab_provider,
)
from tools.lab.engine.providers.registry import registered_provider_names as registry_names


class LabProviderRegistryTest(unittest.TestCase):
    def test_registry_exposes_registered_providers(self) -> None:
        self.assertEqual(
            registered_provider_names(),
            ("docker", "hetzner", "qemu", "virtualbox"),
        )
        self.assertEqual(
            registry_names(),
            ("docker", "hetzner", "qemu", "virtualbox"),
        )
        self.assertIs(resolve_lab_provider("docker"), DOCKER_LAB_PROVIDER_ADAPTER)
        self.assertIs(resolve_lab_provider("hetzner"), HETZNER_LAB_PROVIDER_ADAPTER)
        self.assertIs(resolve_lab_provider("qemu"), QEMU_LAB_PROVIDER_ADAPTER)
        self.assertIs(resolve_lab_provider("virtualbox"), VIRTUALBOX_LAB_PROVIDER_ADAPTER)

    def test_unknown_provider_error_reports_known_set(self) -> None:
        with self.assertRaisesRegex(
            UnknownLabProviderError,
            "unsupported lab provider 'unknown'; known providers: docker, hetzner, qemu, virtualbox",
        ):
            resolve_lab_provider("unknown")

    def test_provider_protocol_is_exported(self) -> None:
        self.assertEqual(LabProviderAdapter.__name__, "LabProviderAdapter")


if __name__ == "__main__":
    unittest.main()
