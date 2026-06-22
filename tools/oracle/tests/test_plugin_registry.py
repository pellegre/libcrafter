"""Unit coverage for the generic oracle plugin registry.

These tests exercise the shared ``PluginRegistry`` mechanism that every oracle
stage (generator sampling, Scapy encode/decode, Wireshark decode) registers its
per-protocol plugins through: registration, duplicate rejection, lookup via
``get``/``require``/``names``/``values``, the ``UnknownPluginError`` raised for a
missing name, and ``autodiscover`` importing a package's submodules so each
self-registers at import. Everything runs offline against a throwaway package
built under the test's temporary directory.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from tools.oracle.engine.plugin_registry import (
    PluginRegistry,
    UnknownPluginError,
    autodiscover,
)


class PluginRegistryTest(unittest.TestCase):
    def test_register_and_get(self) -> None:
        registry: PluginRegistry[str] = PluginRegistry("sampler")
        registry.register("arp", "arp-plugin")
        self.assertEqual(registry.get("arp"), "arp-plugin")

    def test_get_missing_returns_none(self) -> None:
        registry: PluginRegistry[str] = PluginRegistry("sampler")
        self.assertIsNone(registry.get("missing"))

    def test_register_duplicate_rejected(self) -> None:
        registry: PluginRegistry[str] = PluginRegistry("sampler")
        registry.register("arp", "first")
        with self.assertRaises(ValueError):
            registry.register("arp", "second")
        # Original registration survives the rejected duplicate.
        self.assertEqual(registry.get("arp"), "first")

    def test_require_returns_value(self) -> None:
        registry: PluginRegistry[str] = PluginRegistry("sampler")
        registry.register("arp", "arp-plugin")
        self.assertEqual(registry.require("arp"), "arp-plugin")

    def test_require_missing_raises_unknown_plugin(self) -> None:
        registry: PluginRegistry[str] = PluginRegistry("sampler")
        registry.register("arp", "arp-plugin")
        registry.register("udp", "udp-plugin")
        with self.assertRaises(UnknownPluginError) as caught:
            registry.require("missing")
        error = caught.exception
        self.assertIsInstance(error, ValueError)
        self.assertEqual(error.kind, "sampler")
        self.assertEqual(error.name, "missing")
        self.assertEqual(error.known, ("arp", "udp"))
        message = str(error)
        self.assertIn("missing", message)
        self.assertIn("sampler", message)
        self.assertIn("arp", message)
        self.assertIn("udp", message)

    def test_names_sorted(self) -> None:
        registry: PluginRegistry[str] = PluginRegistry("sampler")
        registry.register("udp", "udp-plugin")
        registry.register("arp", "arp-plugin")
        registry.register("tcp", "tcp-plugin")
        self.assertEqual(registry.names(), ("arp", "tcp", "udp"))

    def test_values_in_name_order(self) -> None:
        registry: PluginRegistry[str] = PluginRegistry("sampler")
        registry.register("udp", "udp-plugin")
        registry.register("arp", "arp-plugin")
        registry.register("tcp", "tcp-plugin")
        self.assertEqual(
            registry.values(),
            ("arp-plugin", "tcp-plugin", "udp-plugin"),
        )

    def test_kind_property(self) -> None:
        registry: PluginRegistry[str] = PluginRegistry("scapy")
        self.assertEqual(registry.kind, "scapy")


class AutodiscoverTest(unittest.TestCase):
    def test_autodiscover_imports_submodules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package_name = "_oracle_autodiscover_fixture"
            package_dir = root / package_name
            package_dir.mkdir()

            # The package shares one registry; each protocol submodule
            # self-registers under its layer name at import time. The ``base``
            # module and any ``_``-prefixed module must be skipped.
            (package_dir / "__init__.py").write_text(
                "from tools.oracle.engine.plugin_registry import PluginRegistry\n"
                "REGISTRY = PluginRegistry('fixture')\n"
            )
            (package_dir / "base.py").write_text(
                "from . import REGISTRY\n"
                "REGISTRY.register('base-should-not-run', 'base')\n"
            )
            (package_dir / "_private.py").write_text(
                "from . import REGISTRY\n"
                "REGISTRY.register('private-should-not-run', 'private')\n"
            )
            (package_dir / "arp.py").write_text(
                "from . import REGISTRY\n"
                "REGISTRY.register('arp', 'arp-plugin')\n"
            )
            (package_dir / "udp.py").write_text(
                "from . import REGISTRY\n"
                "REGISTRY.register('udp', 'udp-plugin')\n"
            )

            sys.path.insert(0, str(root))
            try:
                package = __import__(package_name)
                autodiscover(package.__name__, package.__path__)
                self.assertEqual(package.REGISTRY.names(), ("arp", "udp"))
                self.assertEqual(package.REGISTRY.get("arp"), "arp-plugin")
                self.assertEqual(package.REGISTRY.get("udp"), "udp-plugin")
            finally:
                sys.path.remove(str(root))
                for name in list(sys.modules):
                    if name == package_name or name.startswith(package_name + "."):
                        del sys.modules[name]


if __name__ == "__main__":
    unittest.main()
