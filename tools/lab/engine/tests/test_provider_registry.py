"""Coverage for the lab provider adapter registry."""

from __future__ import annotations

import unittest

from tools.lab.engine.providers import (
    HETZNER_LAB_PROVIDER_ADAPTER,
    LabProviderAdapter,
    UnknownLabProviderError,
    registered_provider_names,
    resolve_lab_provider,
)
from tools.lab.engine.providers.registry import registered_provider_names as registry_names


class LabProviderRegistryTest(unittest.TestCase):
    def test_registry_exposes_hetzner_provider(self) -> None:
        self.assertEqual(registered_provider_names(), ("hetzner",))
        self.assertEqual(registry_names(), ("hetzner",))
        self.assertIs(resolve_lab_provider("hetzner"), HETZNER_LAB_PROVIDER_ADAPTER)

    def test_unknown_provider_error_reports_known_set(self) -> None:
        with self.assertRaisesRegex(
            UnknownLabProviderError,
            "unsupported lab provider 'qemu'; known providers: hetzner",
        ):
            resolve_lab_provider("qemu")

    def test_provider_protocol_is_exported(self) -> None:
        self.assertEqual(LabProviderAdapter.__name__, "LabProviderAdapter")


if __name__ == "__main__":
    unittest.main()
