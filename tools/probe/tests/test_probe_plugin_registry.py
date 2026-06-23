"""Offline unit coverage for the generic probe plugin registry utility.

These tests guard :mod:`tools.probe.engine.plugin_registry` -- the name-keyed
``PluginRegistry`` plus :func:`autodiscover` that later steps build the probe
``ProtocolPlugin`` machinery on. They register/look up plain values, exercise the
duplicate and unknown-name error paths, and prove that ``autodiscover`` imports a
throwaway package's submodules (so each protocol module can self-register at
import). Everything is offline: no Scapy, no uv, no network, no real protocol
plugins.
"""

from __future__ import annotations

import importlib
import sys
import tempfile
import unittest
from pathlib import Path

from tools.probe.engine.plugin_registry import (
    PluginRegistry,
    UnknownPluginError,
    autodiscover,
)


class PluginRegistryTests(unittest.TestCase):
    def test_register_and_get_returns_value(self) -> None:
        registry: PluginRegistry[str] = PluginRegistry("probe-protocol")
        registry.register("arp", "arp-value")

        self.assertEqual(registry.get("arp"), "arp-value")
        self.assertEqual(registry.kind, "probe-protocol")

    def test_get_unknown_returns_none(self) -> None:
        registry: PluginRegistry[str] = PluginRegistry("probe-protocol")

        self.assertIsNone(registry.get("missing"))

    def test_register_duplicate_raises_value_error(self) -> None:
        registry: PluginRegistry[str] = PluginRegistry("probe-protocol")
        registry.register("arp", "first")

        with self.assertRaises(ValueError) as ctx:
            registry.register("arp", "second")

        self.assertIn("arp", str(ctx.exception))
        # The first registration is left untouched.
        self.assertEqual(registry.get("arp"), "first")

    def test_require_returns_registered_value(self) -> None:
        registry: PluginRegistry[int] = PluginRegistry("probe-protocol")
        registry.register("dns", 42)

        self.assertEqual(registry.require("dns"), 42)

    def test_require_unknown_raises_unknown_plugin_error(self) -> None:
        registry: PluginRegistry[int] = PluginRegistry("probe-protocol")
        registry.register("dns", 1)
        registry.register("arp", 2)

        with self.assertRaises(UnknownPluginError) as ctx:
            registry.require("ospf")

        error = ctx.exception
        self.assertIsInstance(error, ValueError)
        self.assertEqual(error.kind, "probe-protocol")
        self.assertEqual(error.name, "ospf")
        # Known names are reported sorted for a deterministic message.
        self.assertEqual(error.known, ("arp", "dns"))
        message = str(error)
        self.assertIn("probe-protocol", message)
        self.assertIn("ospf", message)
        self.assertIn("arp", message)
        self.assertIn("dns", message)

    def test_unknown_plugin_error_known_empty_when_registry_empty(self) -> None:
        registry: PluginRegistry[int] = PluginRegistry("probe-protocol")

        with self.assertRaises(UnknownPluginError) as ctx:
            registry.require("anything")

        self.assertEqual(ctx.exception.known, ())
        self.assertIn("<none>", str(ctx.exception))

    def test_names_returns_sorted_tuple(self) -> None:
        registry: PluginRegistry[int] = PluginRegistry("probe-protocol")
        registry.register("udp", 1)
        registry.register("arp", 2)
        registry.register("dns", 3)

        self.assertEqual(registry.names(), ("arp", "dns", "udp"))

    def test_values_returns_values_in_name_order(self) -> None:
        registry: PluginRegistry[str] = PluginRegistry("probe-protocol")
        registry.register("udp", "udp-value")
        registry.register("arp", "arp-value")
        registry.register("dns", "dns-value")

        self.assertEqual(
            registry.values(),
            ("arp-value", "dns-value", "udp-value"),
        )


class AutodiscoverTests(unittest.TestCase):
    def _write_throwaway_package(self, root: Path) -> str:
        """Materialize a throwaway package whose submodules self-register.

        Returns the package name (importable from ``root`` once it is on
        ``sys.path``).
        """

        package_name = "probe_plugin_registry_throwaway_pkg"
        package_dir = root / package_name
        package_dir.mkdir()

        # A shared registry instance the submodules register into at import.
        (package_dir / "__init__.py").write_text(
            "from tools.probe.engine.plugin_registry import PluginRegistry\n"
            'REGISTRY = PluginRegistry("throwaway")\n',
            encoding="utf-8",
        )
        # Real protocol-like modules: each self-registers on import.
        (package_dir / "alpha.py").write_text(
            "from . import REGISTRY\n"
            'REGISTRY.register("alpha", "alpha-value")\n',
            encoding="utf-8",
        )
        (package_dir / "beta.py").write_text(
            "from . import REGISTRY\n"
            'REGISTRY.register("beta", "beta-value")\n',
            encoding="utf-8",
        )
        # A dunder/private module and a base module: both must be skipped.
        (package_dir / "_private.py").write_text(
            "from . import REGISTRY\n"
            'REGISTRY.register("private", "should-not-import")\n',
            encoding="utf-8",
        )
        (package_dir / "base.py").write_text(
            "from . import REGISTRY\n"
            'REGISTRY.register("base", "should-not-import")\n',
            encoding="utf-8",
        )
        return package_name

    def test_autodiscover_imports_submodules_skipping_private_and_base(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package_name = self._write_throwaway_package(root)

            sys.path.insert(0, str(root))
            try:
                package = importlib.import_module(package_name)
                registry = package.REGISTRY

                # Nothing has been discovered yet.
                self.assertEqual(registry.names(), ())

                autodiscover(package.__name__, package.__path__)

                # alpha and beta self-registered; _private and base were skipped.
                self.assertEqual(registry.names(), ("alpha", "beta"))
                self.assertEqual(registry.get("alpha"), "alpha-value")
                self.assertEqual(registry.get("beta"), "beta-value")
                self.assertIsNone(registry.get("private"))
                self.assertIsNone(registry.get("base"))
            finally:
                sys.path.remove(str(root))
                for name in list(sys.modules):
                    if name == package_name or name.startswith(package_name + "."):
                        del sys.modules[name]


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
