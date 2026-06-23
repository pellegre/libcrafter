"""Migration-progress coverage guard for the probe protocol-plugin refactor.

The probe refactor moves each protocol's surface out of the six central
case-name dispatchers and into one auto-discovered plugin under
``engine/protocols/``. This test reads the live :data:`PROTOCOL_REGISTRY` (via
the ``protocols`` package, so auto-discovery runs and every migrated module
self-registers) together with the full case set in
:data:`tools.probe.engine.cases.PROBE_CASE_BY_NAME` and makes migration progress
observable while tolerating the partial-migration state.

Two directions are checked:

* Strict from the start -- every plugin that *is* registered may own only real
  probe protocols/cases. A plugin whose declared case names are not a subset of
  ``PROBE_CASE_BY_NAME`` is a stray registration and fails immediately.
* Forward-looking and currently non-failing -- the set of known protocols not
  yet served by any plugin must be a subset of :data:`KNOWN_UNMIGRATED`. That
  frozenset is seeded with the full protocol list, so the assertion holds while
  the registry is empty; each migration step removes its protocol from
  ``KNOWN_UNMIGRATED`` as the plugin lands, and the strict step (43) deletes
  ``KNOWN_UNMIGRATED`` entirely and asserts full coverage.

The test is offline: pure registry/case introspection, no Scapy, uv, cargo, or
network.
"""

from __future__ import annotations

import unittest

from tools.probe.engine.cases import PROBE_CASE_BY_NAME
from tools.probe.engine.protocols import PROTOCOL_REGISTRY, registered_plugins


# The full set of probe protocols this refactor migrates, one plugin each. As
# each migration step lands its plugin, that protocol is removed from this
# frozenset; once every protocol is served, the strict step (43) deletes this
# seed and asserts full coverage directly.
KNOWN_UNMIGRATED: frozenset[str] = frozenset(
    {
        "dhcp",
        "udp",
        "ndp",
        "icmp",
        "tcp",
        "bgp",
        "rip",
        "ospf",
        "igmp",
        "ipsec",
    }
)

# The canonical, complete list of probe protocols. ``KNOWN_UNMIGRATED`` may only
# ever name protocols from this list; protocols served by a plugin are computed
# against it as the registry fills in.
ALL_PROTOCOLS: frozenset[str] = frozenset(
    {
        "arp",
        "dns",
        "dhcp",
        "udp",
        "ndp",
        "icmp",
        "tcp",
        "bgp",
        "rip",
        "ospf",
        "igmp",
        "ipsec",
    }
)


class ProbeProtocolRegistryImportTest(unittest.TestCase):
    """The registry is importable and exposes a stable shape."""

    def test_registry_names_returns_tuple(self) -> None:
        names = PROTOCOL_REGISTRY.names()
        self.assertIsInstance(names, tuple)
        # Importing the ``protocols`` package ran auto-discovery; every name is a
        # plain string and the tuple is sorted for determinism.
        self.assertTrue(all(isinstance(name, str) for name in names))
        self.assertEqual(list(names), sorted(names))


class ProbeProtocolPluginOwnershipTest(unittest.TestCase):
    """Every registered plugin owns only real probe protocols/cases."""

    def test_plugin_case_names_are_a_subset_of_real_cases(self) -> None:
        real_case_names = set(PROBE_CASE_BY_NAME)
        for plugin in registered_plugins():
            plugin_case_names = {case.name for case in plugin.cases}
            with self.subTest(plugin=plugin.name):
                stray = plugin_case_names - real_case_names
                self.assertEqual(
                    stray,
                    set(),
                    f"plugin {plugin.name!r} declares case(s) "
                    f"{sorted(stray)!r} not in PROBE_CASE_BY_NAME",
                )

    def test_registered_plugin_names_are_real_protocols(self) -> None:
        for name in PROTOCOL_REGISTRY.names():
            with self.subTest(plugin=name):
                self.assertIn(
                    name,
                    ALL_PROTOCOLS,
                    f"plugin {name!r} is not a known probe protocol",
                )


class ProbeProtocolMigrationCoverageTest(unittest.TestCase):
    """Track migration progress; strict in step 43 once the seed is gone."""

    def test_unmigrated_protocols_are_within_known_seed(self) -> None:
        served = set(PROTOCOL_REGISTRY.names())
        unmigrated = ALL_PROTOCOLS - served
        self.assertLessEqual(
            unmigrated,
            KNOWN_UNMIGRATED,
            "a protocol is unserved by any plugin yet missing from "
            "KNOWN_UNMIGRATED; remove a protocol from KNOWN_UNMIGRATED only "
            "when its plugin lands.",
        )

    def test_known_unmigrated_lists_only_real_protocols(self) -> None:
        stray = KNOWN_UNMIGRATED - ALL_PROTOCOLS
        self.assertEqual(
            stray,
            frozenset(),
            f"KNOWN_UNMIGRATED names non-protocol(s) {sorted(stray)!r}",
        )


if __name__ == "__main__":
    unittest.main()
