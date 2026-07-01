"""Strict coverage guard for the probe protocol-plugin refactor.

The probe refactor moved each protocol's surface out of the six central
case-name dispatchers and into one auto-discovered plugin under
``engine/protocols/``. With every protocol migrated (steps 17-36) and the legacy
fallback dispatchers/tables removed (steps 38-42), this test no longer tracks
migration *progress* -- it locks the plug-and-play *end state* as a hard
guarantee. It reads the live :data:`PROTOCOL_REGISTRY` (via the ``protocols``
package, so auto-discovery runs and every plugin module self-registers) together
with the full case set in :data:`tools.probe.engine.cases.PROBE_CASE_BY_NAME`.

Three guarantees are asserted:

* Full registry coverage -- every one of the 19 known probe protocols
  (``arp``, ``dns``, ``dhcpv4``, ``dhcpv6``, ``udp``, ``ndp``, ``icmp``,
  ``tcp``, ``bgp``, ``rip``, ``ospf``, ``igmp``, ``ipsec``, ``mqtt``,
  ``quic``, ``snmp``, ``ssdp``, ``mdns``, ``tls``) has a registered plugin, and no
  registered plugin names a non-protocol.
* Exactly-one ownership -- every case in ``PROBE_CASE_BY_NAME`` is owned by
  exactly one plugin (by case *name* via ``plugin.cases``), and no plugin owns a
  phantom case absent from ``PROBE_CASE_BY_NAME``.
* No legacy per-protocol dispatcher/table remains -- the ``cases`` module
  exposes no per-protocol ``BEHAVIOR_<P>_CASES`` tuples (they live inside each
  plugin module now); the ``cli`` module exposes no per-protocol rewrite/failure
  branch helpers that duplicate plugin hooks; and ``lab`` capability derivation
  is registry-driven. Shared scaffolding that legitimately remains (profile
  ordering tables, ``PROBE_CAPABILITY_NAMES`` / ``capability_sources`` metadata,
  re-exported descriptor names, the registry-union ``_STIMULUS_ENDPOINT_CASES``)
  is *not* asserted gone.

The test is offline: pure registry/case/source introspection, no uv,
cargo, or network.
"""

from __future__ import annotations

import inspect
import unittest

from tools.probe.engine import cases as cases_module
from tools.probe.engine import cli, lab
from tools.probe.engine.cases import PROBE_CASE_BY_NAME
from tools.probe.engine.protocols import (
    PROTOCOL_REGISTRY,
    all_stimulus_endpoint_cases,
    registered_plugins,
)


# The canonical, complete list of probe protocols, one plugin each. The strict
# end state requires every one of these to be registered.
ALL_PROTOCOLS: frozenset[str] = frozenset(
    {
        "arp",
        "dns",
        "dhcpv4",
        "dhcpv6",
        "udp",
        "ndp",
        "icmp",
        "tcp",
        "bgp",
        "rip",
        "ospf",
        "igmp",
        "ipsec",
        "mqtt",
        "quic",
        "snmp",
        "ssdp",
        "mdns",
        "tls",
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


class ProbeProtocolFullCoverageTest(unittest.TestCase):
    """Every known protocol is registered and every plugin is a real protocol."""

    def test_every_known_protocol_is_registered(self) -> None:
        """Each of the 19 known protocols has a registered plugin."""

        registered = set(PROTOCOL_REGISTRY.names())
        missing = ALL_PROTOCOLS - registered
        self.assertEqual(
            missing,
            set(),
            f"known protocol(s) {sorted(missing)!r} are not registered in "
            "PROTOCOL_REGISTRY; the plug-and-play migration is incomplete.",
        )

    def test_registry_serves_only_known_protocols(self) -> None:
        """No registered plugin names a protocol outside the known set."""

        registered = set(PROTOCOL_REGISTRY.names())
        stray = registered - ALL_PROTOCOLS
        self.assertEqual(
            stray,
            set(),
            f"plugin(s) {sorted(stray)!r} are registered but are not known "
            "probe protocols.",
        )

    def test_registry_exactly_matches_known_protocols(self) -> None:
        """The registry is exactly the 19 known protocols -- nothing more, nothing less."""

        self.assertEqual(set(PROTOCOL_REGISTRY.names()), ALL_PROTOCOLS)


class ProbeProtocolPluginOwnershipTest(unittest.TestCase):
    """Every case is owned by exactly one plugin and no plugin owns a phantom."""

    def test_every_case_is_owned_by_exactly_one_plugin(self) -> None:
        """Every ``PROBE_CASE_BY_NAME`` case is owned by exactly one plugin.

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
        """No plugin owns a case absent from ``PROBE_CASE_BY_NAME``."""

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

    def test_every_case_is_owned(self) -> None:
        """Every real case is owned by some plugin (no orphan cases)."""

        owned: set[str] = set()
        for plugin in registered_plugins():
            owned.update(case.name for case in plugin.cases)
        orphans = set(PROBE_CASE_BY_NAME) - owned
        self.assertEqual(
            orphans,
            set(),
            f"case(s) {sorted(orphans)!r} are in PROBE_CASE_BY_NAME but owned "
            "by no plugin; every case must be plugin-served.",
        )

    def test_every_stimulus_endpoint_case_is_contributed_by_a_plugin(self) -> None:
        """Every ``cli._STIMULUS_ENDPOINT_CASES`` name is plugin-contributed.

        ``cli._STIMULUS_ENDPOINT_CASES`` legitimately remains as the
        registry-union module constant (tests and the rewrite snapshot guard
        reference it by name); this pins that its membership is wholly sourced
        from plugins, with no legacy union carrying any leftover routing.
        """

        contributed = set(all_stimulus_endpoint_cases())
        uncontributed = set(cli._STIMULUS_ENDPOINT_CASES) - contributed
        self.assertEqual(
            uncontributed,
            set(),
            f"stimulus-endpoint case(s) {sorted(uncontributed)!r} are routed by "
            "cli._STIMULUS_ENDPOINT_CASES but contributed by no plugin's "
            "stimulus_endpoint_cases.",
        )


class ProbeNoLegacyDispatcherTest(unittest.TestCase):
    """No legacy per-protocol dispatcher or table remains in the shared modules.

    These assertions encode the *true* end state, not an idealized one: shared
    scaffolding that legitimately remains is not asserted gone, only the
    per-protocol dispatchers/tables that the plugins replaced.
    """

    # Every protocol whose per-protocol case tuple moved out of ``cases`` and
    # into its plugin module. ``BEHAVIOR_<P>_CASES`` tuples now live in
    # ``engine/protocols/<p>.py``; the ``cases`` module must expose none of them.
    _MIGRATED_CASE_TUPLE_PROTOCOLS = (
        "ARP",
        "DNS",
        "DHCPv4",
        "DHCPv6",
        "UDP",
        "NDP",
        "ICMP",
        "TCP",
        "BGP",
        "RIP",
        "RIPNG",
        "OSPF",
        "IGMP",
        "IPSEC",
        "MDNS",
    )

    # Per-protocol live-path rewrite/failure branch helpers that the plugin
    # ``rewrite_endpoint_addresses`` / ``failure_reasons`` hooks replaced. The
    # central ``cli._probe_plan_with_endpoint_addresses`` /
    # ``cli._failure_reasons_for_case`` now dispatch purely through the registry,
    # so none of these per-protocol branch helpers may remain on ``cli``.
    _REMOVED_CLI_BRANCH_HELPERS = (
        # NDP carried the most explicit duplication: a dedicated rewrite helper
        # and its own case set, both folded into the NDP plugin hook.
        "_ndp_plan_with_endpoint_addresses",
        "_NDP_REWRITE_CASES",
        # Other protocols' per-protocol rewrite case sets, now plugin-owned.
        "_ARP_REWRITE_CASES",
        "_DNS_REWRITE_CASES",
        "_DHCPV4_REWRITE_CASES",
        "_UDP_REWRITE_CASES",
        "_TCP_REWRITE_CASES",
        "_ICMP_REWRITE_CASES",
    )

    def test_cases_module_exposes_no_per_protocol_case_tuples(self) -> None:
        """``cases`` exposes no per-protocol ``BEHAVIOR_<P>_CASES`` tuple.

        Those tuples migrated into the per-protocol plugin modules under
        ``engine/protocols/``. The ``cases`` module keeps only registry-sourced
        profile *ordering* scaffolding (``BEHAVIOR_PROFILE_CASE_NAMES``, the
        ``_<P>_BEHAVIOR_CASE_NAMES`` helpers, the ``SMOKE`` / ``TCP_SMOKE``
        profile names); those are shared profile tables, not per-protocol case
        data, and are intentionally *not* asserted gone.
        """

        for protocol in self._MIGRATED_CASE_TUPLE_PROTOCOLS:
            attribute = f"BEHAVIOR_{protocol}_CASES"
            with self.subTest(attribute=attribute):
                self.assertFalse(
                    hasattr(cases_module, attribute),
                    f"cases.{attribute} still exists; per-protocol case tuples "
                    "must live in the protocol's plugin module, not in cases.",
                )

    def test_cli_module_exposes_no_per_protocol_rewrite_branch_helpers(self) -> None:
        """``cli`` exposes no per-protocol rewrite/failure branch helper.

        The central ``_probe_plan_with_endpoint_addresses`` and
        ``_failure_reasons_for_case`` dispatch through the registry; the
        per-protocol if/elif branch helpers they replaced are gone. Symbols that
        legitimately remain on ``cli`` (``_eui64_link_local_ipv6``,
        ``_IPSEC_PROBE_CASES``, the registry-union ``_STIMULUS_ENDPOINT_CASES``,
        ...) are *not* asserted gone.
        """

        for helper in self._REMOVED_CLI_BRANCH_HELPERS:
            with self.subTest(helper=helper):
                self.assertFalse(
                    hasattr(cli, helper),
                    f"cli.{helper} still exists; per-protocol rewrite/failure "
                    "branch helpers must be replaced by plugin hooks dispatched "
                    "through the registry.",
                )

    def test_cli_dispatchers_consult_the_registry(self) -> None:
        """The central rewrite/failure dispatchers fold over the registry."""

        rewrite_src = inspect.getsource(cli._probe_plan_with_endpoint_addresses)
        self.assertIn(
            "_registry_rewrite_plugin_for_case",
            rewrite_src,
            "cli._probe_plan_with_endpoint_addresses must dispatch the live-path "
            "rewrite through the registry, not per-protocol branches.",
        )
        failure_src = inspect.getsource(cli._failure_reasons_for_case)
        self.assertIn(
            "_registry_failure_reasons_plugin_for_case",
            failure_src,
            "cli._failure_reasons_for_case must dispatch the failure-reason "
            "taxonomy through the registry, not per-protocol branches.",
        )

    def test_lab_capability_derivation_is_registry_driven(self) -> None:
        """``lab`` capability derivation folds over the registered plugins.

        ``PROBE_CAPABILITY_NAMES`` and the ``capability_sources`` metadata table
        legitimately remain as cross-protocol metadata; what must be gone is the
        per-protocol *derivation*, which now comes from each plugin's
        ``lab_capabilities`` hook. This source check pins that the derivation
        loops over the registered plugins and reads their hook.
        """

        source = inspect.getsource(lab.probe_capabilities_from_lab_capabilities)
        self.assertIn(
            "registered_protocol_plugins()",
            source,
            "lab.probe_capabilities_from_lab_capabilities must fold over the "
            "registered plugins to derive per-protocol capabilities.",
        )
        self.assertIn(
            "plugin.lab_capabilities(substrate)",
            source,
            "lab.probe_capabilities_from_lab_capabilities must derive "
            "per-protocol capabilities from each plugin's lab_capabilities hook.",
        )


if __name__ == "__main__":
    unittest.main()
