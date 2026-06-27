"""Deterministic probe selection and per-case plan generation.

This module owns the deterministic byte/address helpers, the seed-driven
selection that cycles the requested cases into a planned sequence, and the
per-case plan generators for the existing ICMP/TCP/DNS/TTL/ARP behavioral
cases. Plan generation is dispatched through :data:`PLAN_BUILDERS`, a registry
keyed by case name. The behavior suite extends the registry with DNS, DHCPv4,
ARP, and UDP planners without touching the dispatcher or the selection logic.

The JSON shape produced here is the stable probe plan contract consumed by the
stimulus endpoint and the report builder. Existing case plans must keep their
field layout; new planners may add optional fields only.
"""

from __future__ import annotations

from collections.abc import Sequence

from .cases import PROBE_CASE_BY_NAME
from .model import JSONObject, ProbeCase, ProbeRunRequest
from .planning_helpers import (
    PlanBuilder,
    deterministic_bytes,
    deterministic_documentation_mac,
    deterministic_ipv4_pair,
    deterministic_router_ipv4,
    dns_label,
)
# Importing from the ``protocols`` package runs its auto-discovery so every
# migrated protocol module self-registers into ``PROTOCOL_REGISTRY`` before
# ``PLAN_BUILDERS`` is assembled below. Imports stay relative; the package
# autodiscovers ``__name__``-relatively, so this does not cycle back through
# ``planning``.
from .protocols import (
    all_plan_builders as _registry_plan_builders,
    all_planned_only_cases as _registry_planned_only_cases,
)
# The ARP planning surface (cases, builders, deterministic helpers) lives in the
# ARP plugin module. Re-import each moved builder and the ARP-only deterministic
# helpers so ``planning._<builder>`` resolves to the *same* function object the
# plugin registered and the merged ``PLAN_BUILDERS`` exposes -- the ARP behavior
# tests pin ``planning.PLAN_BUILDERS[name] is planning._<builder>`` via
# ``assertIs``, so object identity must be preserved.
from .protocols.arp import (  # noqa: F401  (re-exported for identity/back-compat)
    _arp_alias_address_reply_probe_plan,
    _arp_basic_who_has_probe_plan,
    _arp_broadcast_filtered_capture_probe_plan,
    _arp_cache_flush_reply_probe_plan,
    _arp_mac_validation_probe_plan,
    _arp_padding_reply_probe_plan,
    _arp_repeat_two_replies_probe_plan,
    _arp_repeat_two_replies_send,
    _arp_resolution_probe_plan,
    _arp_source_address_preserved_probe_plan,
    _arp_spa_variation_probe_plan,
    _arp_unicast_request_reply_probe_plan,
    deterministic_arp_alias_ipv4,
    deterministic_arp_alt_sender_ipv4,
)
# The DNS planning surface (cases, builders, deterministic name/string helpers)
# lives in the DNS plugin module. Re-import each moved builder, the multi-send
# helper, and the DNS-only name/string helpers so ``planning._<builder>``
# resolves to the *same* function object the plugin registered and the merged
# ``PLAN_BUILDERS`` exposes -- the DNS behavior tests pin
# ``planning.PLAN_BUILDERS[name] is planning._<builder>`` via ``assertIs`` and
# ``test_probe_planning`` pins ``cli._dns_query_name is planning.dns_query_name``,
# so object identity must be preserved.
from .protocols.dns import (  # noqa: F401  (re-exported for identity/back-compat)
    _dns_a_success_probe_plan,
    _dns_aaaa_success_probe_plan,
    _dns_cname_chain_probe_plan,
    _dns_edns_opt_probe_plan,
    _dns_mx_answer_probe_plan,
    _dns_nodata_probe_plan,
    _dns_nxdomain_probe_plan,
    _dns_query_probe_plan,
    _dns_repeat_transaction_probe_plan,
    _dns_repeat_transaction_send,
    _dns_srv_answer_probe_plan,
    _dns_txt_answer_probe_plan,
    dns_canonical_name,
    dns_edns_nsid,
    dns_exchange_name,
    dns_query_name,
    dns_service_name,
    dns_target_name,
    dns_txt_strings,
)
# The DHCPv4 planning surface (cases, builders, deterministic client identity /
# option helpers) lives in the DHCPv4 plugin module. Re-import the builders and
# helpers so identity-based behavior tests compare the same function objects that
# the registry exposes.
from .protocols.dhcpv4 import (  # noqa: F401  (re-exported for identity)
    _dhcpv4_client_identifier_probe_plan,
    _dhcpv4_discover_offer_probe_plan,
    _dhcpv4_hostname_probe_plan,
    _dhcpv4_inform_ack_probe_plan,
    _dhcpv4_lease_time_probe_plan,
    _dhcpv4_parameter_request_list_probe_plan,
    _dhcpv4_rapid_repeat_probe_plan,
    _dhcpv4_rapid_repeat_send,
    _dhcpv4_renewal_unicast_ack_probe_plan,
    _dhcpv4_request_ack_probe_plan,
    _dhcpv4_request_nak_probe_plan,
    dhcpv4_client_identifier,
    dhcpv4_client_mac,
    dhcpv4_hostname,
    dhcpv4_parameter_request_list,
)
# The UDP planning surface (cases, builders, the multi-send helper, the shared
# echo scaffolding, and the MTU/length-boundary constants) lives in the UDP
# plugin module. Re-import each moved builder, the multi-send helper, and the
# ``UDP_ECHO_LARGE_*`` / ``UDP_LENGTH_BOUNDARY_*`` constants so
# ``planning._<builder>`` resolves to the *same* function object the plugin
# registered and the merged ``PLAN_BUILDERS`` exposes -- the UDP behavior tests
# pin ``planning.PLAN_BUILDERS[name] is planning._<builder>`` via ``assertIs``
# and read ``planning.UDP_ECHO_LARGE_*`` / ``planning.UDP_LENGTH_BOUNDARY_*``, so
# object identity and the constant values must be preserved.
from .protocols.udp import (  # noqa: F401  (re-exported for identity/back-compat)
    UDP_ECHO_LARGE_IPV4_HEADER_LENGTH,
    UDP_ECHO_LARGE_IPV4_PACKET_SAFETY_LIMIT,
    UDP_ECHO_LARGE_MAX_PAYLOAD_LENGTH,
    UDP_ECHO_LARGE_UDP_HEADER_LENGTH,
    UDP_LENGTH_BOUNDARY_PAYLOAD_LENGTH,
    UDP_LENGTH_BOUNDARY_PAYLOAD_MARGIN,
    _udp_closed_port_icmp_probe_plan,
    _udp_echo_binary_probe_plan,
    _udp_echo_empty_probe_plan,
    _udp_echo_large_probe_plan,
    _udp_echo_short_probe_plan,
    _udp_length_boundary_echo_probe_plan,
    _udp_multi_shot_order_probe_plan,
    _udp_multi_shot_order_send,
    _udp_options_surplus_echo_probe_plan,
    _udp_source_port_reflection_probe_plan,
    _udp_zero_checksum_ipv4_probe_plan,
)
# The NDP planning surface (cases, builders, the shared wire-requirements helper,
# the deterministic link-local / target / solicited-node helpers, and the ICMPv6
# type / IPv6 multicast / unspecified-address constants) lives in the NDP plugin
# module. Re-import each moved builder so ``planning._<builder>`` resolves to the
# *same* function object the plugin registered and the merged ``PLAN_BUILDERS``
# exposes -- the NDP behavior tests pin ``planning.PLAN_BUILDERS[name] is
# planning._<builder>`` via ``assertIs``, so object identity must be preserved.
# Also re-import the NDP-only public helpers / constants so
# ``tools.probe.engine.cli`` (whose NDP live-path rewrite stays put until step 26)
# keeps importing ``solicited_node_multicast`` / ``IPV6_ALL_NODES_MULTICAST`` /
# ``IPV6_ALL_ROUTERS_MULTICAST`` / ``IPV6_UNSPECIFIED`` from ``planning``
# unchanged.
from .protocols.ndp import (  # noqa: F401  (re-exported for identity/back-compat)
    IPV6_ALL_NODES_MULTICAST,
    IPV6_ALL_ROUTERS_MULTICAST,
    IPV6_UNSPECIFIED,
    _ndp_duplicate_address_detection_probe_plan,
    _ndp_neighbor_solicitation_probe_plan,
    _ndp_router_solicitation_probe_plan,
    solicited_node_multicast,
)
# The ICMP planning surface (the two inline cases and their builders) lives in the
# ICMP plugin module. Re-import each moved builder so ``planning._<builder>``
# resolves to the *same* function object the plugin registered and the merged
# ``PLAN_BUILDERS`` exposes -- any pin on ``planning.PLAN_BUILDERS[name] is
# planning._<builder>`` keeps identical object identity.
from .protocols.icmp import (  # noqa: F401  (re-exported for identity/back-compat)
    _icmp_echo_probe_plan,
    _ttl_expired_probe_plan,
)
# The TCP planning surface (the three inline cases and their builders) lives in
# the TCP plugin module. Re-import each moved builder so ``planning._<builder>``
# resolves to the *same* function object the plugin registered and the merged
# ``PLAN_BUILDERS`` exposes -- any pin on ``planning.PLAN_BUILDERS[name] is
# planning._<builder>`` keeps identical object identity.
from .protocols.tcp import (  # noqa: F401  (re-exported for identity/back-compat)
    _tcp_syn_options_probe_plan,
    _tcp_syn_probe_plan,
)
# The BGP planning surface (the ``bgp-session-smoke`` case and its builder) lives
# in the BGP plugin module. Re-import the moved builder so
# ``planning._bgp_session_smoke_probe_plan`` resolves to the *same* function
# object the plugin registered and the merged ``PLAN_BUILDERS`` exposes -- any
# pin on ``planning.PLAN_BUILDERS[name] is planning._bgp_session_smoke_probe_plan``
# keeps identical object identity.
from .protocols.bgp import (  # noqa: F401  (re-exported for identity/back-compat)
    _bgp_session_smoke_probe_plan,
)
# The RIP/RIPng planning surface (the ``rip-update-v2`` / ``ripng-update`` cases
# and their builders) lives in the RIP plugin module. Re-import each moved
# builder so ``planning._rip_update_probe_plan`` / ``planning._ripng_update_probe_plan``
# resolve to the *same* function objects the plugin registered and the merged
# ``PLAN_BUILDERS`` exposes -- any pin on object identity keeps holding.
from .protocols.rip import (  # noqa: F401  (re-exported for identity/back-compat)
    _rip_update_probe_plan,
    _ripng_update_probe_plan,
)
# The SNMP planning surface (the planned-only SNMP smoke cases and their shared
# builder) lives in the SNMP plugin module. Re-import the moved builder so
# ``planning._snmp_probe_plan`` resolves to the same function object the plugin
# registered and the merged ``PLAN_BUILDERS`` exposes.
from .protocols.snmp import (  # noqa: F401  (re-exported for identity/back-compat)
    _snmp_probe_plan,
)
# The IGMP planning surface (the four IGMP cases' shared ``_igmp_probe_plan``
# builder, the ``_igmp_target_service`` plan-building helper, and the
# ``deterministic_igmp_group`` / ``deterministic_igmp_source_list`` helpers) lives
# in the IGMP plugin module. Re-import the moved builder and deterministic helpers
# so ``planning._igmp_probe_plan`` / ``planning.deterministic_igmp_group`` /
# ``planning.deterministic_igmp_source_list`` resolve to the *same* function
# objects the plugin registered and the merged ``PLAN_BUILDERS`` exposes -- any
# pin on object identity keeps holding.
from .protocols.igmp import (  # noqa: F401  (re-exported for identity/back-compat)
    _igmp_probe_plan,
    deterministic_igmp_group,
    deterministic_igmp_source_list,
)
# The IPSec planning surface (the four IPSec cases' shared ``_ipsec_probe_plan``
# planned-only builder and the IPSec ESP/AH IP-protocol numbers / IKEv2 UDP-port
# constants it references) lives in the IPSec plugin module
# (``protocols/ipsec.py``). Re-import the moved builder so
# ``planning._ipsec_probe_plan`` resolves to the *same* function object the
# plugin registered and the merged ``PLAN_BUILDERS`` exposes -- any pin on
# ``planning.PLAN_BUILDERS[name] is planning._ipsec_probe_plan`` keeps identical
# object identity.
from .protocols.ipsec import (  # noqa: F401  (re-exported for identity/back-compat)
    _ipsec_probe_plan,
)
# The MQTT planning surface (the planned-only broker-exchange smoke cases'
# shared ``_mqtt_probe_plan`` builder) lives in the MQTT plugin module. Re-import
# the moved builder so ``planning._mqtt_probe_plan`` resolves to the *same*
# function object the plugin registered and the merged ``PLAN_BUILDERS`` exposes
# -- any pin on object identity keeps holding.
from .protocols.mqtt import (  # noqa: F401  (re-exported for identity/back-compat)
    _mqtt_probe_plan,
)
from .protocols.quic import (  # noqa: F401  (re-exported for identity/back-compat)
    _quic_initial_udp_observation_probe_plan,
    _quic_protected_flow_plan_probe_plan,
    _quic_retry_observation_probe_plan,
    _quic_stateless_reset_observation_probe_plan,
    _quic_version_negotiation_observation_probe_plan,
)


def planned_cases(
    selected_cases: Sequence[ProbeCase],
    *,
    seed: int,
    count: int,
) -> list[ProbeCase]:
    """Cycle the selected cases into a deterministic planned sequence.

    The seed rotates the starting offset so different seeds plan a different
    case ordering, while the cycle keeps planning exactly ``count`` cases even
    when fewer cases were selected.
    """

    if not selected_cases:
        return []
    offset = seed % len(selected_cases)
    ordered = [*selected_cases[offset:], *selected_cases[:offset]]
    return [ordered[index % len(ordered)] for index in range(count)]


def probe_plans_for_cases(
    request: ProbeRunRequest,
    planned: Sequence[ProbeCase],
) -> list[JSONObject]:
    """Build the ordered probe plans for a planned case sequence."""

    return [
        probe_plan_for_case(request=request, case=case, sequence=sequence)
        for sequence, case in enumerate(planned)
    ]


def probe_plan_for_case(
    *,
    request: ProbeRunRequest,
    case: ProbeCase,
    sequence: int,
) -> JSONObject:
    """Dispatch a single case to its registered plan builder.

    Cases without a dedicated builder fall back to a minimal planned-only plan
    so unknown or not-yet-implemented cases still report deterministically.
    """

    builder = PLAN_BUILDERS.get(case.name)
    if builder is not None:
        return builder(
            case_name=case.name,
            profile=request.profile,
            seed=request.seed,
            sequence=sequence,
        )
    return _planned_only_probe_plan(
        case=case,
        profile=request.profile,
        seed=request.seed,
        sequence=sequence,
    )


def _planned_only_probe_plan(
    *,
    case: ProbeCase,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    return {
        "schema_version": 1,
        "case": case.name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": case.stimulus,
        "expected_response": case.expected_response,
        "planned_only": True,
    }


# The IPSec planning surface (the four IPSec cases' shared ``_ipsec_probe_plan``
# planned-only builder and the IPSec ESP/AH IP-protocol numbers / IKEv2 UDP-port
# constants it references) now lives in the IPSec plugin module
# (``protocols/ipsec.py``); the moved builder reaches ``PLAN_BUILDERS`` through
# the registry merge below and is re-imported into this module above for
# identity/back-compat.


# The RIP/RIPng plan constants (UDP ports, multicast groups, service kinds, RIB
# commands, documentation prefixes) and the ``rip_peer_service_descriptor`` the
# IPv4 plan references now live in the RIP plugin module (``protocols/rip.py``);
# the moved builders reach ``PLAN_BUILDERS`` through the registry merge below and
# are re-imported into this module above for identity/back-compat.


# The IGMP planning surface (the four IGMP cases' shared ``_igmp_probe_plan``
# builder, the ``_igmp_target_service`` plan-building helper, the
# ``deterministic_igmp_group`` / ``deterministic_igmp_source_list`` helpers, and
# the IGMP wire constants they reference) now lives in the IGMP plugin module
# (``protocols/igmp.py``); the moved builder reaches ``PLAN_BUILDERS`` through the
# registry merge below and is re-imported into this module above for
# identity/back-compat.


# The BGP plan builder (``_bgp_session_smoke_probe_plan``) now lives in the BGP
# plugin module (``protocols/bgp.py``) and reaches ``PLAN_BUILDERS`` through the
# registry merge below; it is re-imported into this module above for
# identity/back-compat.


# Per-case plan-builder dispatch table consulted by :func:`probe_plan_for_case`.
# Every protocol's builders have migrated to their plugin modules, so this table
# is sourced entirely from the protocol registry. The exact function objects are
# kept (no wrappers) so ``planning._<builder>`` and ``PLAN_BUILDERS[name] is
# _<builder>`` identity stays intact for the pinning tests; each builder is
# re-imported into this module above to preserve ``planning._<builder>`` access.
PLAN_BUILDERS: dict[str, PlanBuilder] = dict(_registry_plan_builders())


# Planned-only registered cases. A planned-only builder records the exchange
# shape without building packet bytes; every other builder produces a fully
# materialized plan. Every planned-only protocol has migrated to its plugin
# module, so this set is sourced entirely from the protocol registry (the BGP,
# RIP/RIPng, IGMP, IPSec, and MQTT planned-only cases are each contributed by
# their plugin module).
PLANNED_ONLY_REGISTERED_CASES: frozenset[str] = frozenset(
    _registry_planned_only_cases()
)


def register_plan_builder(case_name: str, builder: PlanBuilder) -> None:
    """Register a plan builder for ``case_name``.

    Used by behavior-suite case groups to add DNS, DHCPv4, ARP, and UDP planners
    without modifying the dispatcher.
    """

    if case_name not in PROBE_CASE_BY_NAME:
        raise ValueError(
            f"cannot register plan builder for unknown probe case {case_name!r}"
        )
    PLAN_BUILDERS[case_name] = builder
