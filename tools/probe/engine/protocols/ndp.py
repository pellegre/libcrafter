"""NDP probe protocol plugin: cases, plan builders, and planning surface.

This is the NDP (IPv6 Neighbor Discovery, RFC 4861) *planning half* migration
(after the ARP vertical slice and the DNS / DHCP / UDP migrations). It bundles
NDP's planning surface in one place:

* the three NDP behavioral cases plus the NDP capability constant (the catalog
  contribution),
* the ``_ndp_*_probe_plan`` plan builders, the shared NDP wire-requirements
  helper, the deterministic link-local / target / solicited-node helpers, and the
  NDP ICMPv6 type / IPv6 multicast / unspecified-address constants (the
  plan-builder contribution),
* and the NDP stimulus-endpoint routing set.

NDP is the IPv6 analog of ARP: a Neighbor Solicitation resolves an IPv6 address
the way an ARP who-has resolves an IPv4 address, the target kernel answers a
solicited Neighbor Advertisement the way it answers an ARP is-at, a Router
Solicitation solicits a Router Advertisement from an RA-emitting router target,
and a Duplicate Address Detection probe (sourced from the unspecified address
``::``) is defended by a Neighbor Advertisement. Unlike ARP, NDP rides ICMPv6
over IPv6 (next header 58) and addresses solicitations to multicast groups rather
than the Ethernet broadcast address.

The plan builders, the shared wire-requirements helper, and the deterministic
helpers are moved verbatim from :mod:`tools.probe.engine.planning`; :mod:`planning`
re-imports the three builders so ``planning._<builder>`` /
``planning.PLAN_BUILDERS[name]`` (the NDP behavior tests' ``assertIs`` pins) keep
identical object identity, and it re-imports the NDP-only public helpers and
constants (``solicited_node_multicast`` / ``IPV6_ALL_NODES_MULTICAST`` /
``IPV6_ALL_ROUTERS_MULTICAST`` / ``IPV6_UNSPECIFIED``) so
``tools.probe.engine.cli`` (whose NDP live-path rewrite stays put until step 26)
keeps importing them from ``planning`` unchanged.

NDP carries no ``planned_only`` cases (every builder materializes a plan), and
its ``profile_counts`` is intentionally empty: the three NDP behavioral cases sit
between ARP and UDP in the ``behavior`` profile in a fixed, order-sensitive
position, and the registry-first profile merge would move the registry
contribution to the front of that profile, so the legacy ordered profile name
tables in :mod:`tools.probe.engine.cases` keep owning NDP's profile membership to
preserve byte-identical selection order.

The NDP target-service / address-rewrite / failure-reason / lab-capability hooks
land in step 26 (the special NDP early-return rewrite); they stay ``None`` here,
so NDP cases keep flowing through the legacy target / rewrite / failure /
capability paths until that step.

Imports are relative only so the module loads under both engine import roots
(``engine.protocols.ndp`` for the CLI and ``tools.probe.engine.protocols.ndp``
for the tests).
"""

from __future__ import annotations

import ipaddress

from ..case_helpers import _behavior_case
from ..model import JSONObject, ProbeCase
from ..planning_helpers import (
    deterministic_bytes,
    deterministic_documentation_mac,
)
from .base import ProtocolPlugin, register


# IPv6 Neighbor Discovery is the IPv6 analog of ARP. Unlike ARP (which rides
# Ethernet broadcast), NDP rides ICMPv6 over IPv6 and addresses solicitations to
# the solicited-node multicast group (and router solicitations to the
# all-routers multicast group), so it needs an IPv6 link-layer multicast
# substrate rather than broadcast. ``ipv6_multicast`` is derived in
# :mod:`tools.probe.engine.lab` from the same link-layer send/capture substrate
# ARP uses, so providers that carry same-segment multicast (QEMU, VirtualBox)
# plan the cases while providers without an L2 segment (Hetzner) skip cleanly
# with the stable ``requires_link_layer`` reason.
_NDP_CAPABILITIES = [
    "link_layer_send",
    "link_layer_capture",
    "ipv6_multicast",
]


# NDP (IPv6 Neighbor Discovery, RFC 4861) behavioral cases. NDP is the IPv6
# analog of ARP: a Neighbor Solicitation resolves an IPv6 address the way an ARP
# who-has resolves an IPv4 address, and the target kernel answers a solicited
# Neighbor Advertisement the way it answers an ARP is-at. The cases mirror the
# ARP set's stimulus/expected_response/required_capabilities shape; the
# ``layer`` metadata is ``network`` because NDP rides ICMPv6 over IPv6 (rather
# than directly over Ethernet like ARP). Providers that lack an IPv6 multicast
# link-layer substrate skip cleanly on ``_NDP_CAPABILITIES``.
BEHAVIOR_NDP_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="ndp-neighbor-solicitation",
        description=(
            "Send a Neighbor Solicitation (ICMPv6 type 135) to the target's "
            "solicited-node multicast group and validate the kernel's solicited "
            "Neighbor Advertisement (type 136)."
        ),
        # The kernel NA-for-NS exchange is the direct analog of ARP who-has/is-at
        # and the single most reliable NDP behavior on a bare kernel: the target
        # kernel auto-answers a solicitation for an address it owns. This is the
        # PRIMARY reliable NDP case.
        stimulus="ndp_neighbor_solicitation",
        expected_response="ndp_neighbor_advertisement",
        required_capabilities=_NDP_CAPABILITIES,
        protocol="ndp",
        metadata={"layer": "network"},
    ),
    _behavior_case(
        name="ndp-router-solicitation",
        description=(
            "Send a Router Solicitation (ICMPv6 type 133) to the all-routers "
            "multicast group and validate a Router Advertisement (type 134)."
        ),
        # A Router Advertisement only arrives when the target acts as a router and
        # sends RAs (e.g. radvd / net.ipv6.conf.*.forwarding with RA emission). A
        # bare kernel that is not configured as a router does not answer a Router
        # Solicitation, so the live runners must configure the target as an
        # RA-emitting router for this case or skip it; the plan/notes record that
        # requirement. The dry-run plan is well-formed regardless.
        stimulus="ndp_router_solicitation",
        expected_response="ndp_router_advertisement",
        required_capabilities=_NDP_CAPABILITIES,
        protocol="ndp",
        metadata={
            "layer": "network",
            "requires_router_target": True,
            "notes": (
                "Needs the target to act as a router and emit Router "
                "Advertisements; a bare kernel does not answer a Router "
                "Solicitation. Live runners configure an RA-emitting router or "
                "skip this case."
            ),
        },
    ),
    _behavior_case(
        name="ndp-duplicate-address-detection",
        description=(
            "Send a Duplicate Address Detection Neighbor Solicitation from the "
            "unspecified source (::) for an address the target owns and validate "
            "the target's defending Neighbor Advertisement."
        ),
        # DAD probe: RFC 4861 section 4.3 / RFC 4862 — the solicitation source is
        # the unspecified address (::) and carries no Source Link-Layer Address
        # option; the target, which owns the tentative address, defends it with a
        # Neighbor Advertisement to the all-nodes multicast group.
        stimulus="ndp_duplicate_address_detection",
        expected_response="ndp_neighbor_advertisement",
        required_capabilities=_NDP_CAPABILITIES,
        protocol="ndp",
        metadata={
            "layer": "network",
            "dad": True,
            "notes": (
                "Unspecified-source (::) DAD solicitation with no SLLA option; "
                "the target defends an owned address with a Neighbor "
                "Advertisement (RFC 4861 section 4.3 / RFC 4862)."
            ),
        },
    ),
)


# NDP (IPv6 Neighbor Discovery, RFC 4861) shared constants and helpers. NDP is
# the IPv6 analog of ARP: a Neighbor Solicitation resolves an IPv6 address the
# way an ARP who-has resolves an IPv4 address. NDP rides ICMPv6 over IPv6 (next
# header 58) rather than directly over Ethernet, and addresses solicitations to
# multicast groups rather than the Ethernet broadcast address.

# ICMPv6 NDP message type codepoints (RFC 4861 section 4 / IANA
# icmpv6-parameters). Mirrors the crafter ``ICMPV6_*`` constants.
NDP_ROUTER_SOLICITATION_TYPE = 133
NDP_ROUTER_ADVERTISEMENT_TYPE = 134
NDP_NEIGHBOR_SOLICITATION_TYPE = 135
NDP_NEIGHBOR_ADVERTISEMENT_TYPE = 136

# The IPv6 unspecified address (RFC 4291): the source of a Duplicate Address
# Detection Neighbor Solicitation (RFC 4861 section 4.3 / RFC 4862 section 5.4).
IPV6_UNSPECIFIED = "::"
# Well-known link-scoped multicast destinations (RFC 4291 section 2.7.1):
# all-nodes and all-routers. A Router Solicitation is sent to all-routers; a
# Neighbor Advertisement defending a DAD probe is sent to all-nodes.
IPV6_ALL_NODES_MULTICAST = "ff02::1"
IPV6_ALL_ROUTERS_MULTICAST = "ff02::2"


def deterministic_link_local_ipv6(
    profile: str,
    seed: int,
    sequence: int,
    *,
    role: str,
) -> str:
    """Return a deterministic IPv6 link-local address (``fe80::/10``).

    NDP exchanges ride link-local source/target addresses (RFC 4861 hosts use
    their link-local address as the source of solicitations). The interface id is
    derived from a per-(role, case, profile, seed, sequence) digest so the
    stimulus and target addresses are stable and distinct while staying inside
    the RFC 4291 link-local prefix used for documentation/lab traffic.
    """

    digest = deterministic_bytes(f"ndp-link-local-{role}", profile, seed, sequence)
    group_a = int.from_bytes(digest[0:2], "big")
    group_b = int.from_bytes(digest[2:4], "big")
    group_c = int.from_bytes(digest[4:6], "big")
    host = 1 + int.from_bytes(digest[6:8], "big") % 0xFFFE
    return f"fe80::{group_a:x}:{group_b:x}:{group_c:x}:{host:x}"


def deterministic_target_ipv6(profile: str, seed: int, sequence: int) -> str:
    """Return the deterministic IPv6 address an NDP exchange resolves.

    The address the Neighbor Solicitation resolves is the target endpoint's own
    link-local address (the analog of the ARP target protocol address). It is the
    same value as :func:`deterministic_link_local_ipv6` with ``role="target"`` so
    the solicitation target, the validation sender, and the solicited-node
    multicast group all agree.
    """

    return deterministic_link_local_ipv6(profile, seed, sequence, role="target")


def solicited_node_multicast(unicast_ipv6: str) -> str:
    """Return the solicited-node multicast address for a unicast IPv6 address.

    RFC 4291 section 2.7.1: the solicited-node multicast group is
    ``ff02::1:ffXX:XXXX`` where ``XX:XXXX`` are the low 24 bits of the target
    address. A Neighbor Solicitation resolving ``unicast_ipv6`` is addressed to
    this group (RFC 4861 section 4.3), so the target — which has joined the group
    for every address it owns — receives it.
    """

    packed = ipaddress.ip_address(unicast_ipv6).packed
    # RFC 4291 section 2.7.1: ff02:0:0:0:0:1:ffXX:XXXX — the ff02::1:ff00:0/104
    # prefix with the low 24 bits of the unicast address in the trailing 3 octets.
    prefix = bytes.fromhex("ff0200000000000000000001ff000000")
    solicited = bytearray(prefix)
    solicited[13:16] = packed[13:16]
    return str(ipaddress.IPv6Address(bytes(solicited)))


def _ndp_wire_requirements() -> JSONObject:
    """Return the shared NDP wire-requirements gate.

    NDP is link-scoped IPv6 multicast/unicast traffic, so it requires the same
    provider-backed link-layer send/capture substrate ARP uses plus IPv6
    multicast (solicited-node / all-routers / all-nodes groups). Providers
    without an L2 segment skip via the ``ipv6_multicast`` capability.
    """

    return {
        "requires_link_layer_send": True,
        "requires_link_layer_capture": True,
        "requires_ipv6_multicast": True,
        "note": (
            "NDP is link-scoped IPv6 multicast/unicast traffic (RFC 4861); it "
            "runs only on a provider-backed lab segment, never from privileged "
            "host raw sends."
        ),
    }


def _ndp_neighbor_solicitation_probe_plan(
    *,
    case_name: str = "ndp-neighbor-solicitation",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``ndp-neighbor-solicitation`` behavioral case.

    The primary, most reliable NDP behavior and the direct analog of ARP
    who-has/is-at: the stimulus builds a Neighbor Solicitation (ICMPv6 type 135,
    RFC 4861 section 4.3) resolving the target endpoint's link-local address,
    carrying a Source Link-Layer Address option with the sender MAC and addressed
    to the target's solicited-node multicast group (RFC 4291 section 2.7.1). The
    target kernel auto-answers with a solicited Neighbor Advertisement (type 136,
    RFC 4861 section 4.4) carrying a Target Link-Layer Address option, the
    Solicited (S) and Override (O) flags set, addressed back to the querier. The
    validation contract covers the NA type, the R/S/O flags, the resolved target
    address, and the Target Link-Layer Address option MAC.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    source_ipv6 = deterministic_link_local_ipv6(profile, seed, sequence, role="stimulus")
    target_ipv6 = deterministic_target_ipv6(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(profile, seed, sequence, role="stimulus")
    target_mac = deterministic_documentation_mac(profile, seed, sequence, role="target")
    solicited_node = solicited_node_multicast(target_ipv6)
    validation = {
        "ip_version": 6,
        "icmpv6_type": NDP_NEIGHBOR_ADVERTISEMENT_TYPE,
        "icmpv6_code": 0,
        "response_label": "neighbor-advertisement",
        "router_flag": False,
        "solicited_flag": True,
        "override_flag": True,
        "target_ipv6": target_ipv6,
        "target_link_layer_addr": target_mac,
        "source_ipv6": target_ipv6,
        "destination_ipv6": source_ipv6,
    }
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "ndp_neighbor_solicitation",
        "expected_response": "ndp_neighbor_advertisement",
        # NDP rides ICMPv6 (next header 58) over IPv6; the solicitation is sent
        # from the stimulus link-local address to the target's solicited-node
        # multicast group.
        "ip_version": 6,
        "icmpv6_type": NDP_NEIGHBOR_SOLICITATION_TYPE,
        "icmpv6_code": 0,
        "source_ipv6": source_ipv6,
        "destination_ipv6": solicited_node,
        "target_ipv6": target_ipv6,
        "solicited_node_multicast": solicited_node,
        "source_link_layer_addr": stimulus_mac,
        "ethernet_source": stimulus_mac,
        "expected_reply_source_ipv6": target_ipv6,
        "expected_reply_destination_ipv6": source_ipv6,
        # NDP cannot be selected by a host BPF on the multicast group alone; match
        # ICMPv6 plus the Neighbor Advertisement type (the ICMPv6 type byte of an
        # IPv6 packet with no extension headers is at offset 40).
        "capture_filter": "icmp6 and ip6[40] = 136",
        "target_service": {
            "required": True,
            "kind": "ndp-kernel",
            "layer": "network",
            # The target kernel answers a Neighbor Solicitation for an address it
            # owns; setup configures the link-local address and flushes the
            # neighbor cache so the kernel re-answers.
            "target_ipv6": target_ipv6,
            "target_hardware_addr": target_mac,
            "ndp_sysctls": True,
            "neighbor_cache_flush": True,
        },
        # The validation contract is emitted under both ``validation`` (parity
        # with the ARP cases for inspection and the plan echo) and
        # ``ndp_validation`` (the typed key the Rust ``ndp`` module reads, since
        # the shared ``validation`` field deserializes as the ARP contract).
        "validation": validation,
        "ndp_validation": validation,
        "wire_requirements": _ndp_wire_requirements(),
        "digest_hex": digest.hex()[:16],
    }


def _ndp_router_solicitation_probe_plan(
    *,
    case_name: str = "ndp-router-solicitation",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``ndp-router-solicitation`` behavioral case.

    The stimulus builds a Router Solicitation (ICMPv6 type 133, RFC 4861 section
    4.1) from its link-local address to the all-routers multicast group
    (``ff02::2``), carrying a Source Link-Layer Address option. A target acting as
    a router answers with a Router Advertisement (type 134, RFC 4861 section 4.2).

    A Router Advertisement only arrives when the target is configured as a router
    that emits RAs (a bare kernel does not answer a Router Solicitation), so the
    plan records ``requires_router_target`` and the live runners must configure
    an RA-emitting router or skip the case. The validation contract covers the RA
    type and the router lifetime / managed/other flags the responder reports.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    source_ipv6 = deterministic_link_local_ipv6(profile, seed, sequence, role="stimulus")
    router_ipv6 = deterministic_link_local_ipv6(profile, seed, sequence, role="target")
    stimulus_mac = deterministic_documentation_mac(profile, seed, sequence, role="stimulus")
    router_mac = deterministic_documentation_mac(profile, seed, sequence, role="target")
    validation = {
        "ip_version": 6,
        "icmpv6_type": NDP_ROUTER_ADVERTISEMENT_TYPE,
        "icmpv6_code": 0,
        "response_label": "router-advertisement",
        "managed_flag": False,
        "other_flag": False,
        "source_ipv6": router_ipv6,
        "destination_ipv6": source_ipv6,
        "router_link_layer_addr": router_mac,
    }
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "ndp_router_solicitation",
        "expected_response": "ndp_router_advertisement",
        "ip_version": 6,
        "icmpv6_type": NDP_ROUTER_SOLICITATION_TYPE,
        "icmpv6_code": 0,
        "source_ipv6": source_ipv6,
        "destination_ipv6": IPV6_ALL_ROUTERS_MULTICAST,
        "all_routers_multicast": IPV6_ALL_ROUTERS_MULTICAST,
        "source_link_layer_addr": stimulus_mac,
        "ethernet_source": stimulus_mac,
        "expected_reply_source_ipv6": router_ipv6,
        "expected_reply_destination_ipv6": source_ipv6,
        # A Router Advertisement (type 134) addressed to the soliciting host (or
        # all-nodes). Match ICMPv6 plus the RA type byte.
        "capture_filter": "icmp6 and ip6[40] = 134",
        # A Router Advertisement requires a router target; a bare kernel does not
        # answer a Router Solicitation. The live runners configure an RA-emitting
        # router for this case or skip it.
        "requires_router_target": True,
        "target_service": {
            "required": True,
            "kind": "ndp-router",
            "layer": "network",
            "router_ipv6": router_ipv6,
            "router_hardware_addr": router_mac,
            # The target must act as a router and emit Router Advertisements
            # (radvd / kernel RA emission) for this case to receive a reply.
            "router_advertisements": True,
            "requires_router_target": True,
            "ndp_sysctls": True,
        },
        "validation": validation,
        "ndp_validation": validation,
        "wire_requirements": _ndp_wire_requirements(),
        "digest_hex": digest.hex()[:16],
    }


def _ndp_duplicate_address_detection_probe_plan(
    *,
    case_name: str = "ndp-duplicate-address-detection",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``ndp-duplicate-address-detection`` behavioral case.

    A Duplicate Address Detection probe (RFC 4861 section 4.3 / RFC 4862 section
    5.4): the stimulus builds a Neighbor Solicitation (ICMPv6 type 135) for an
    address the target owns, sent from the IPv6 unspecified source (``::``) and
    carrying NO Source Link-Layer Address option (RFC 4861 section 4.3 forbids the
    option when the source is unspecified), addressed to the target's
    solicited-node multicast group. The target, which owns the tentative address,
    defends it with a Neighbor Advertisement (type 136) sent to the all-nodes
    multicast group (``ff02::1``) with the Override (O) flag set and the Solicited
    (S) flag clear (RFC 4862 section 5.4.3). The validation contract covers the
    defending NA: type, flags, the defended target address, and the destination
    all-nodes group.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    target_ipv6 = deterministic_target_ipv6(profile, seed, sequence)
    target_mac = deterministic_documentation_mac(profile, seed, sequence, role="target")
    stimulus_mac = deterministic_documentation_mac(profile, seed, sequence, role="stimulus")
    solicited_node = solicited_node_multicast(target_ipv6)
    validation = {
        "ip_version": 6,
        "icmpv6_type": NDP_NEIGHBOR_ADVERTISEMENT_TYPE,
        "icmpv6_code": 0,
        "response_label": "neighbor-advertisement",
        # A DAD defense NA is sent to all-nodes with O set and S clear
        # (RFC 4862 section 5.4.3).
        "router_flag": False,
        "solicited_flag": False,
        "override_flag": True,
        "target_ipv6": target_ipv6,
        "target_link_layer_addr": target_mac,
        "source_ipv6": target_ipv6,
        "destination_ipv6": IPV6_ALL_NODES_MULTICAST,
    }
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "ndp_duplicate_address_detection",
        "expected_response": "ndp_neighbor_advertisement",
        "ip_version": 6,
        "icmpv6_type": NDP_NEIGHBOR_SOLICITATION_TYPE,
        "icmpv6_code": 0,
        # DAD: the source is the unspecified address and the solicitation carries
        # NO Source Link-Layer Address option (RFC 4861 section 4.3).
        "source_ipv6": IPV6_UNSPECIFIED,
        "destination_ipv6": solicited_node,
        "target_ipv6": target_ipv6,
        "solicited_node_multicast": solicited_node,
        "dad": True,
        "omit_source_link_layer_addr": True,
        # The stimulus Ethernet source is still the sender's MAC even though the
        # IPv6 source is unspecified and no SLLA option is present.
        "ethernet_source": stimulus_mac,
        "expected_reply_source_ipv6": target_ipv6,
        "expected_reply_destination_ipv6": IPV6_ALL_NODES_MULTICAST,
        "capture_filter": "icmp6 and ip6[40] = 136",
        "target_service": {
            "required": True,
            "kind": "ndp-kernel",
            "layer": "network",
            "target_ipv6": target_ipv6,
            "target_hardware_addr": target_mac,
            # The target owns the tentative address and defends it on DAD; setup
            # configures the address and flushes the neighbor cache.
            "defends_address": True,
            "ndp_sysctls": True,
            "neighbor_cache_flush": True,
        },
        "validation": validation,
        "ndp_validation": validation,
        "wire_requirements": _ndp_wire_requirements(),
        "digest_hex": digest.hex()[:16],
    }


# Per-case plan-builder dispatch entries for the three NDP behavioral cases. The
# registry merge in :mod:`tools.probe.engine.planning` exposes these through
# ``PLAN_BUILDERS`` (registry-first), and ``planning`` re-imports each function
# so ``planning._<builder>`` keeps identical object identity for the pinning
# tests.
_NDP_PLAN_BUILDERS: dict[str, object] = {
    "ndp-neighbor-solicitation": _ndp_neighbor_solicitation_probe_plan,
    "ndp-router-solicitation": _ndp_router_solicitation_probe_plan,
    "ndp-duplicate-address-detection": _ndp_duplicate_address_detection_probe_plan,
}


# The three NDP behavioral cases route through the stimulus endpoint adapter.
_NDP_STIMULUS_ENDPOINT_CASES: frozenset[str] = frozenset(
    {
        "ndp-neighbor-solicitation",
        "ndp-router-solicitation",
        "ndp-duplicate-address-detection",
    }
)


register(
    ProtocolPlugin(
        name="ndp",
        # The three NDP behavioral cases in declaration order.
        cases=BEHAVIOR_NDP_CASES,
        plan_builders=_NDP_PLAN_BUILDERS,
        # NDP carries no planned-only cases (every builder materializes a plan).
        planned_only_cases=frozenset(),
        # NDP's profile membership stays in the legacy ordered profile tables in
        # ``cases.py`` to preserve byte-identical selection order (the registry-
        # first profile merge would otherwise move NDP to the front of the
        # behavior profile). Contribute nothing here.
        profile_counts={},
        stimulus_endpoint_cases=_NDP_STIMULUS_ENDPOINT_CASES,
        # NDP's target-service / address-rewrite / failure-reason / lab-capability
        # hooks land in step 26 (the special NDP early-return rewrite). They stay
        # ``None`` here, so NDP cases keep flowing through the legacy target /
        # rewrite / failure / capability paths until then.
        target_service=None,
        setup_script=None,
        rewrite_endpoint_addresses=None,
        failure_reasons=None,
        lab_capabilities=None,
    )
)
