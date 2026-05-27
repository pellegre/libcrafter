"""Coverage for the lab provider adapter registry."""

from __future__ import annotations

import unittest

from tools.lab.engine.providers import (
    LabProviderAdapter,
    UnknownLabProviderError,
    registered_provider_names,
    resolve_lab_provider,
)
from tools.lab.engine.providers.registry import registered_provider_names as registry_names


class LabProviderRegistryTest(unittest.TestCase):
    def test_registry_starts_empty_until_provider_modules_exist(self) -> None:
        self.assertEqual(registered_provider_names(), ())
        self.assertEqual(registry_names(), ())

    def test_unknown_provider_error_reports_empty_known_set(self) -> None:
        with self.assertRaisesRegex(
            UnknownLabProviderError,
            "unsupported lab provider 'hetzner'; known providers: <none>",
        ):
            resolve_lab_provider("hetzner")

    def test_provider_protocol_is_exported(self) -> None:
        self.assertEqual(LabProviderAdapter.__name__, "LabProviderAdapter")


if __name__ == "__main__":
    unittest.main()
