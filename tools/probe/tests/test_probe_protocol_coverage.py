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

from tools.probe.engine import cli
from tools.probe.engine.cases import PROBE_CASE_BY_NAME
from tools.probe.engine.protocols import (
    PROTOCOL_REGISTRY,
    all_stimulus_endpoint_cases,
    registered_plugins,
)


# The full set of probe protocols this refactor migrates, one plugin each. As
# each migration step lands its plugin, that protocol is removed from this
# frozenset; once every protocol is served, the strict step (43) deletes this
# seed and asserts full coverage directly.
KNOWN_UNMIGRATED: frozenset[str] = frozenset()

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


class ProbeMigrationParityCheckpointTest(unittest.TestCase):
    """Pin that the registry fully covers every protocol/case/route.

    This is the parity checkpoint taken once every protocol is migrated (steps
    17-36) but *before* the now-dead legacy fallback branches are stripped from
    the six central dispatchers (steps 38-42). It locks that the registry alone
    accounts for every known protocol, every case, and every stimulus-endpoint
    route, so that legacy removal cannot silently drop coverage.

    The checks are offline: pure registry/case introspection plus the module
    constant ``cli._STIMULUS_ENDPOINT_CASES``; no Scapy, uv, cargo, or network.
    """

    def test_every_known_protocol_is_registered(self) -> None:
        """(a) Each of the 12 known protocols has a registered plugin."""

        registered = set(PROTOCOL_REGISTRY.names())
        missing = ALL_PROTOCOLS - registered
        self.assertEqual(
            missing,
            set(),
            f"known protocol(s) {sorted(missing)!r} are not registered in "
            "PROTOCOL_REGISTRY; the migration is incomplete.",
        )

    def test_every_case_is_owned_by_exactly_one_plugin(self) -> None:
        """(b) Every ``PROBE_CASE_BY_NAME`` case is owned by exactly one plugin.

        Ownership is by case *name* via ``plugin.cases`` -- this is unambiguous
        regardless of a case's protocol-metadata field, so the single ``rip``
        plugin owning both ``rip`` and ``ripng`` protocol-metadata cases still
        reads as exactly one owner per case name.
        """

        owners: dict[str, list[str]] = {}
        for plugin in registered_plugins():
            for case in plugin.cases:
                owners.setdefault(case.name, []).append(plugin.name)

        for case_name in PROBE_CASE_BY_NAME:
            with self.subTest(case=case_name):
                plugin_names = owners.get(case_name, [])
                self.assertEqual(
                    len(plugin_names),
                    1,
                    f"case {case_name!r} is owned by {sorted(plugin_names)!r}; "
                    "expected exactly one registered plugin to own it.",
                )

    def test_no_plugin_owns_a_phantom_case(self) -> None:
        """(b, inverse) No plugin owns a case absent from ``PROBE_CASE_BY_NAME``."""

        real_case_names = set(PROBE_CASE_BY_NAME)
        owned: set[str] = set()
        for plugin in registered_plugins():
            owned.update(case.name for case in plugin.cases)
        phantom = owned - real_case_names
        self.assertEqual(
            phantom,
            set(),
            f"plugin(s) own case(s) {sorted(phantom)!r} absent from "
            "PROBE_CASE_BY_NAME.",
        )

    def test_every_stimulus_endpoint_case_is_contributed_by_a_plugin(self) -> None:
        """(c) Every ``cli._STIMULUS_ENDPOINT_CASES`` name is plugin-contributed."""

        contributed = set(all_stimulus_endpoint_cases())
        uncontributed = set(cli._STIMULUS_ENDPOINT_CASES) - contributed
        self.assertEqual(
            uncontributed,
            set(),
            f"stimulus-endpoint case(s) {sorted(uncontributed)!r} are routed by "
            "cli._STIMULUS_ENDPOINT_CASES but contributed by no plugin's "
            "stimulus_endpoint_cases; the legacy union still carries them.",
        )

    def test_known_unmigrated_is_empty(self) -> None:
        """(d) ``KNOWN_UNMIGRATED`` is empty -- every protocol is now served.

        The seed itself is not deleted here (the strict step 43 removes the
        mechanism); this only asserts it has been drained to empty.
        """

        self.assertEqual(
            KNOWN_UNMIGRATED,
            frozenset(),
            f"KNOWN_UNMIGRATED still names {sorted(KNOWN_UNMIGRATED)!r}; the "
            "migration parity checkpoint requires every protocol be served.",
        )


if __name__ == "__main__":
    unittest.main()
