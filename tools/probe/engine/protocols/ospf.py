"""OSPF probe protocol plugin: cases, capability, and live surface.

OSPFv2 (RFC 2328) runs directly over IPv4 (protocol 89, no ports) and drives a
controlled OSPF neighbor: the probe places an OSPF Hello (or Database
Description) on the wire and validates the peer's adjacency-forming reply. This
is a single-step full migration. The surface this module bundles:

* the ``ospf-hello-exchange`` (live-capable) and ``ospf-dd-exchange``
  (planned-only) cases (built through the ``_behavior_case`` factory) and their
  shared ``_OSPF_CAPABILITIES`` constant (the catalog contribution),
* the plan builders (``plan_builders`` is empty: OSPF has no dedicated
  ``_ospf_*_probe_plan`` builder -- both cases fall through to
  ``planning._planned_only_probe_plan`` because no builder is registered, so
  there is no builder to move and ``planned_only_cases`` stays empty too: OSPF's
  cases were never members of ``planning.PLANNED_ONLY_REGISTERED_CASES``, and
  declaring them here would change that set and break byte-identity),
* the stimulus-endpoint contribution (only the live-capable
  ``ospf-hello-exchange`` is wired through the Rust probe adapter
  ``tools/probe/adapters/src/ospf.rs``; the planned-only ``ospf-dd-exchange`` has
  no adapter arm and is intentionally absent),
* the ``target_service`` / ``setup_script`` hooks (``None``: OSPF produced no
  ``target_service_setup_plan`` service entry and no inline setup-script block --
  there was no OSPF descriptor, frozenset, or responder heredoc in
  :mod:`tools.probe.engine.target_services`, so there is nothing to reproduce;
  the controlled OSPFv2 neighbor is a substrate capability, not a probe-owned
  responder),
* the ``rewrite_endpoint_addresses`` hook (``None``: OSPF had no dedicated
  live-path rewrite branch in ``cli._probe_plan_with_endpoint_addresses`` --
  ``ospf-hello-exchange`` rode the *shared* IPv4 rewrite tail, so leaving the
  hook ``None`` keeps it on that shared tail byte-for-byte),
* the ``failure_reasons`` hook (``None``: OSPF had no failure-reason branch in
  ``cli._failure_reasons_for_case`` and fell through to the shared default
  taxonomy), and
* the ``lab_capabilities`` hook (the ``ospf_neighbor_peer`` derived capability).

OSPF's ``profile_counts`` is intentionally empty: ``ospf-hello-exchange`` rides
the live ``behavior`` profile (after the DNS/DHCPv4/ARP/NDP/UDP groups) and
``ospf-dd-exchange`` rides the dry-run ``ospf-smoke`` profile, both in fixed
positions, and the registry-first profile merge would move the registry
contribution to the front of those profiles. The legacy ordered profile name
tables in :mod:`tools.probe.engine.cases`
(``BEHAVIOR_PROFILE_CASE_NAMES`` / ``OSPF_SMOKE_PROFILE_CASE_NAMES``, now sourced
from the registered OSPF cases) keep owning OSPF's profile membership to preserve
byte-identical selection order.

Imports are relative only so the module loads under both engine import roots
(``engine.protocols.ospf`` for the CLI and ``tools.probe.engine.protocols.ospf``
for the tests).
"""

from __future__ import annotations

from collections.abc import Mapping

from ..capability_derivation import capability, capability_default_true
from ..case_helpers import _behavior_case
from ..model import JSONValue, ProbeCase
from .base import ProtocolPlugin, register


# OSPF behavioral capability constant (moved verbatim from
# :mod:`tools.probe.engine.cases`). An OSPF-capable peer runs an OSPFv2 speaker
# (FRR/Quagga ospfd or the oracle reference peer) on the same area and segment as
# the controlled target endpoint, so the cases carry ``ospf_neighbor_peer``
# beyond the unicast IPv4 substrate. The capability name matches the probe
# capability derivation (the ``lab_capabilities`` hook below), so a provider
# without an OSPF-capable neighbor skips the cases with the stable
# capability-unavailable reason rather than failing; the offline dry-run path
# plans the exchange regardless.
_OSPF_CAPABILITIES = ["ospf_neighbor_peer"]


# OSPFv2 behavioral cases (RFC 2328) against a controlled OSPF neighbor peer
# (moved verbatim from ``cases.BEHAVIOR_OSPF_CASES``). OSPF runs directly over
# IPv4 (protocol 89) and has no ports: the Hello exchange is the
# adjacency-forming primitive. ``ospf-hello-exchange`` is wired end-to-end
# through the probe adapter (``tools/probe/adapters/src/ospf.rs``), so it both
# plans in dry-run and runs as a gated live exchange; it is the only OSPF case in
# the live ``behavior`` profile.
BEHAVIOR_OSPF_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="ospf-hello-exchange",
        description=(
            "Send an OSPFv2 Hello (RFC 2328 §A.3.2) to the controlled neighbor "
            "and validate the peer's Hello or Database Description reply that "
            "forms the adjacency."
        ),
        stimulus="ospf_hello",
        expected_response="ospf_hello_or_database_description",
        required_capabilities=_OSPF_CAPABILITIES,
        protocol="ospf",
        metadata={"layer": "network", "stateful": True},
    ),
)

# Planned-only OSPF cases (moved verbatim from ``cases.OSPF_SMOKE_CASES``). These
# plan in dry-run but have no live adapter arm yet, so -- like
# ``bgp-session-smoke`` -- they are registered in ``PROBE_CASES`` and selected
# only by the dedicated dry-run ``ospf-smoke`` profile, never by the live
# ``behavior`` profile.
OSPF_SMOKE_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="ospf-dd-exchange",
        description=(
            "Send an OSPFv2 Database Description packet (RFC 2328 §A.3.3) to the "
            "controlled neighbor and validate the peer's Database Description "
            "reply that advances database synchronization."
        ),
        stimulus="ospf_database_description",
        expected_response="ospf_database_description",
        required_capabilities=_OSPF_CAPABILITIES,
        protocol="ospf",
        metadata={
            "layer": "network",
            "stateful": True,
            # The adapter dispatch (tools/probe/adapters/src/common.rs) wires the
            # ospf-hello-exchange case today; the DD exchange plans in dry-run and
            # gains its live adapter arm in a later step, mirroring the
            # bgp-session-smoke planned-only precedent.
            "planned_only": True,
            "notes": (
                "Needs the peer to advance to the Database Description exchange "
                "state; the dry-run plans the exchange and the live adapter arm "
                "lands in a follow-on step."
            ),
        },
    ),
)


# The full OSPF case tuple in declaration order (the live Hello exchange first,
# then the planned-only Database Description exchange), the way the legacy
# ``cases._LEGACY_PROBE_CASES`` aggregation ordered ``*BEHAVIOR_OSPF_CASES`` then
# ``*OSPF_SMOKE_CASES``.
_OSPF_CASES: tuple[ProbeCase, ...] = (*BEHAVIOR_OSPF_CASES, *OSPF_SMOKE_CASES)


# OSPF is wired through the Rust probe adapter only for the live-capable Hello
# exchange; the planned-only Database Description exchange has no adapter arm yet
# and is intentionally absent (it stays a dry-run plan via the ospf-smoke
# profile). Moved verbatim from ``cli._LEGACY_STIMULUS_ENDPOINT_CASES``.
_OSPF_STIMULUS_ENDPOINT_CASES: frozenset[str] = frozenset({"ospf-hello-exchange"})


# --------------------------------------------------------------------------- #
# Lab-capability derivation (moved from lab.probe_capabilities_from_lab_capabilities)
# --------------------------------------------------------------------------- #


def ospf_lab_capabilities(substrate: Mapping[str, JSONValue]) -> Mapping[str, object]:
    """Return the OSPF plugin's derived probe-capability contribution.

    Moved verbatim from the ``ospf_neighbor_peer`` derivation in
    ``lab.probe_capabilities_from_lab_capabilities``: OSPF smoke drives a
    controlled OSPFv2 neighbor on the target endpoint. OSPF runs directly over
    IPv4 (protocol 89, no ports), so the peer needs the same IPv4-unicast +
    controlled-services substrate the DNS/UDP/BGP target services use: a
    substrate that can carry IPv4 unicast and host a controlled service can host
    the OSPF speaker too. An explicit ``ospf_peer`` substrate flag, when present,
    can deny the peer even where controlled services exist. The shared
    ``capability_names`` / ``capability_sources`` tables stay in ``lab``; this
    hook contributes only the derived ``ospf_neighbor_peer`` value, merged
    byte-identically over the legacy value.
    """

    ipv4_unicast = capability(substrate, "ipv4_unicast", "ipv4")
    controlled_services = capability(
        substrate,
        "controlled_services",
        "controlled_service",
    )
    return {
        "ospf_neighbor_peer": (
            ipv4_unicast
            and controlled_services
            and capability_default_true(substrate, "ospf_peer")
        ),
    }


register(
    ProtocolPlugin(
        name="ospf",
        cases=_OSPF_CASES,
        # OSPF has no dedicated plan builder: both cases fall through to
        # ``planning._planned_only_probe_plan`` because no builder is registered.
        # ``planned_only_cases`` stays empty too -- OSPF's cases were never in
        # ``planning.PLANNED_ONLY_REGISTERED_CASES`` (only cases with a
        # planned-only *builder* are listed there), so declaring them would change
        # that set and break byte-identity.
        plan_builders={},
        planned_only_cases=frozenset(),
        # OSPF's profile membership stays in the legacy ordered profile tables in
        # ``cases.py`` (``BEHAVIOR_PROFILE_CASE_NAMES`` /
        # ``OSPF_SMOKE_PROFILE_CASE_NAMES``, sourced from the registered OSPF
        # cases) to preserve byte-identical selection order.
        profile_counts={},
        stimulus_endpoint_cases=_OSPF_STIMULUS_ENDPOINT_CASES,
        # ``target_service`` / ``setup_script`` stay ``None``: OSPF produced no
        # ``target_service_setup_plan`` service entry and no inline setup-script
        # block (the controlled OSPFv2 neighbor is a substrate capability, not a
        # probe-owned responder). ``rewrite_endpoint_addresses`` stays ``None``:
        # ``ospf-hello-exchange`` had no dedicated live-path rewrite branch and
        # rode the shared IPv4 rewrite tail, so leaving the hook ``None`` keeps it
        # on that shared tail byte-for-byte. ``failure_reasons`` stays ``None``:
        # OSPF had no failure-reason branch and fell through to the shared
        # default. ``lab_capabilities`` contributes the ``ospf_neighbor_peer``
        # derived capability.
        target_service=None,
        setup_script=None,
        rewrite_endpoint_addresses=None,
        failure_reasons=None,
        lab_capabilities=ospf_lab_capabilities,
    )
)
