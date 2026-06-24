"""Deterministic probe selection and per-case plan generation.

This module owns the deterministic byte/address helpers, the seed-driven
selection that cycles the requested cases into a planned sequence, and the
per-case plan generators for the existing ICMP/TCP/DNS/TTL/ARP behavioral
cases. Plan generation is dispatched through :data:`PLAN_BUILDERS`, a registry
keyed by case name. The behavior suite extends the registry with DNS, DHCP,
ARP, and UDP planners without touching the dispatcher or the selection logic.

The JSON shape produced here is the stable probe plan contract consumed by the
stimulus endpoint and the report builder. Existing case plans must keep their
field layout; new planners may add optional fields only.
"""

from __future__ import annotations

from collections.abc import Sequence

from .cases import PROBE_CASE_BY_NAME
from .model import JSONObject, ProbeCase, ProbeRunRequest, json_object
from .planning_helpers import (
    PlanBuilder,
    deterministic_bytes,
    deterministic_documentation_ipv6,
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
# The DHCP planning surface (cases, builders, deterministic client identity /
# option helpers) lives in the DHCP plugin module. Re-import each moved builder,
# the multi-send helper, and the DHCP-only ``dhcp_*`` helpers so
# ``planning._<builder>`` resolves to the *same* function object the plugin
# registered and the merged ``PLAN_BUILDERS`` exposes -- the DHCP behavior tests
# pin ``planning.PLAN_BUILDERS[name] is planning._<builder>`` via ``assertIs``,
# so object identity must be preserved.
from .protocols.dhcp import (  # noqa: F401  (re-exported for identity/back-compat)
    _dhcp_client_identifier_probe_plan,
    _dhcp_discover_offer_probe_plan,
    _dhcp_hostname_probe_plan,
    _dhcp_inform_ack_probe_plan,
    _dhcp_lease_time_probe_plan,
    _dhcp_parameter_request_list_probe_plan,
    _dhcp_rapid_repeat_probe_plan,
    _dhcp_rapid_repeat_send,
    _dhcp_renewal_unicast_ack_probe_plan,
    _dhcp_request_ack_probe_plan,
    _dhcp_request_nak_probe_plan,
    dhcp_client_identifier,
    dhcp_client_mac,
    dhcp_hostname,
    dhcp_parameter_request_list,
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


# IPSec ESP/AH IP protocol numbers (RFC 4303 / RFC 4302) and the IKEv2 UDP port
# (RFC 7296). Recorded in the dry-run plan so an inspecting agent sees the wire
# protocol/port the exchange rides without consulting the crate.
_IPSEC_ESP_PROTOCOL = 50
_IPSEC_AH_PROTOCOL = 51
_IKEV2_UDP_PORT = 500


# The RIP/RIPng plan constants (UDP ports, multicast groups, service kinds, RIB
# commands, documentation prefixes) and the ``rip_peer_service_descriptor`` the
# IPv4 plan references now live in the RIP plugin module (``protocols/rip.py``);
# the moved builders reach ``PLAN_BUILDERS`` through the registry merge below and
# are re-imported into this module above for identity/back-compat.


# IGMP (IPv4 protocol number 2) rides link-local IPv4 multicast with TTL 1 and
# Router Alert on real networks. The probe plans below are dry-run-only and
# provider-backed for live execution; they expose the exact message shapes an
# agent should expect before any protected live run is confirmed.
_IGMP_IP_PROTOCOL = 2
_IGMP_DEFAULT_TTL = 1
_IGMP_ALL_SYSTEMS_GROUP = "224.0.0.1"
_IGMP_ALL_ROUTERS_GROUP = "224.0.0.2"
_IGMPV3_REPORT_DESTINATION = "224.0.0.22"
_IGMP_DOCUMENTATION_MULTICAST_PREFIX = "233.252.0.0/24"
_IGMP_DOCUMENTATION_SOURCE_PREFIXES = ["192.0.2.0/24", "198.51.100.0/24"]
_IGMP_TARGET_SERVICE_DIR = "tools/probe/target_services/igmp"
_IGMP_LISTENER_SCRIPT = f"{_IGMP_TARGET_SERVICE_DIR}/provision-listener.sh"
_IGMP_ROUTER_SCRIPT = f"{_IGMP_TARGET_SERVICE_DIR}/provision-router.sh"
_IGMP_CLEANUP_SCRIPT = f"{_IGMP_TARGET_SERVICE_DIR}/cleanup.sh"


# The BGP plan builder (``_bgp_session_smoke_probe_plan``) now lives in the BGP
# plugin module (``protocols/bgp.py``) and reaches ``PLAN_BUILDERS`` through the
# registry merge below; it is re-imported into this module above for
# identity/back-compat.


def _igmp_probe_plan(
    *,
    case_name: str,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a dry-run IGMP peer-behavior case.

    IGMP probes need a provider-backed multicast segment and a controlled peer
    (listener/router) before any live traffic is useful. This builder therefore
    records packet shapes, capture filters, target-service scripts, and stable
    validation expectations while emitting no packet bytes and sending nothing.
    """

    case = PROBE_CASE_BY_NAME[case_name]
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    group_address = deterministic_igmp_group(profile, seed, sequence)
    source_list = deterministic_igmp_source_list(profile, seed, sequence)

    if case_name == "igmp-membership-query-observation":
        destination_ipv4 = _IGMP_ALL_SYSTEMS_GROUP
        sender_ipv4 = target_ipv4
        target_service = _igmp_target_service(
            kind="igmp-router",
            role="router",
            bind_ipv4=target_ipv4,
            source_ipv4=stimulus_ipv4,
            multicast_group=destination_ipv4,
            provision_script=_IGMP_ROUTER_SCRIPT,
        )
        stimulus_shape: JSONObject = {
            "direction": "observe",
            "sender_role": "router",
            "igmp_type": 0x11,
            "message": "membership_query",
            "max_response_time_tenths": 10,
            "group_address": "0.0.0.0",
        }
        expected_shape = dict(stimulus_shape)
        expected_shape["source_ipv4"] = sender_ipv4
        expected_shape["destination_ipv4"] = destination_ipv4
        validation: JSONObject = {
            "planned_only": True,
            "driver": "igmp_query_observation",
            "source_ipv4": sender_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x11,
            "group_address": "0.0.0.0",
            "max_response_time_tenths": 10,
        }
        capture_filter = (
            f"igmp and src host {sender_ipv4} and dst host {destination_ipv4}"
        )
        adapter_case = "igmp-v2-membership-query"
    elif case_name == "igmp-v2-membership-report-emission":
        destination_ipv4 = group_address
        target_service = _igmp_target_service(
            kind="igmp-listener",
            role="target",
            bind_ipv4=target_ipv4,
            source_ipv4=stimulus_ipv4,
            multicast_group=group_address,
            provision_script=_IGMP_LISTENER_SCRIPT,
        )
        stimulus_shape = {
            "direction": "emit",
            "igmp_type": 0x16,
            "message": "v2_membership_report",
            "group_address": group_address,
        }
        expected_shape = {
            "observer_role": "target",
            "expected_response": case.expected_response,
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x16,
            "group_address": group_address,
        }
        validation = {
            "planned_only": True,
            "driver": "igmp_v2_membership_report",
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x16,
            "group_address": group_address,
        }
        capture_filter = (
            f"igmp and src host {stimulus_ipv4} and dst host {destination_ipv4}"
        )
        adapter_case = "igmp-v2-membership-report"
    elif case_name == "igmp-v2-leave-group-emission":
        destination_ipv4 = _IGMP_ALL_ROUTERS_GROUP
        target_service = _igmp_target_service(
            kind="igmp-listener",
            role="target",
            bind_ipv4=target_ipv4,
            source_ipv4=stimulus_ipv4,
            multicast_group=group_address,
            provision_script=_IGMP_LISTENER_SCRIPT,
        )
        stimulus_shape = {
            "direction": "emit",
            "igmp_type": 0x17,
            "message": "v2_leave_group",
            "group_address": group_address,
        }
        expected_shape = {
            "observer_role": "target",
            "expected_response": case.expected_response,
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x17,
            "group_address": group_address,
        }
        validation = {
            "planned_only": True,
            "driver": "igmp_v2_leave_group",
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x17,
            "group_address": group_address,
        }
        capture_filter = (
            f"igmp and src host {stimulus_ipv4} and dst host {destination_ipv4}"
        )
        adapter_case = "igmp-v2-leave-group"
    elif case_name == "igmp-v3-source-list-report":
        destination_ipv4 = _IGMPV3_REPORT_DESTINATION
        target_service = _igmp_target_service(
            kind="igmp-listener",
            role="target",
            bind_ipv4=target_ipv4,
            source_ipv4=stimulus_ipv4,
            multicast_group=group_address,
            provision_script=_IGMP_LISTENER_SCRIPT,
        )
        stimulus_shape = {
            "direction": "emit",
            "igmp_type": 0x22,
            "message": "v3_membership_report",
            "record_type": "mode_is_include",
            "group_address": group_address,
            "source_addresses": source_list,
            "record_count": 1,
        }
        expected_shape = {
            "observer_role": "target",
            "expected_response": case.expected_response,
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x22,
            "group_address": group_address,
            "source_addresses": source_list,
            "record_type": "mode_is_include",
        }
        validation = {
            "planned_only": True,
            "driver": "igmp_v3_source_list_report",
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x22,
            "group_address": group_address,
            "source_addresses": source_list,
            "record_type": "mode_is_include",
            "record_count": 1,
        }
        capture_filter = (
            f"igmp and src host {stimulus_ipv4} and dst host {destination_ipv4}"
        )
        adapter_case = "igmp-v3-source-list-report"
    else:
        raise ValueError(f"unsupported IGMP probe case {case_name!r}")

    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": case.stimulus,
        "expected_response": case.expected_response,
        "planned_only": True,
        "protocol": "igmp",
        "ip_protocol": _IGMP_IP_PROTOCOL,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": destination_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "group_address": group_address,
        "multicast_group": group_address,
        "ttl": _IGMP_DEFAULT_TTL,
        "router_alert_required": True,
        "documentation_prefixes": [
            _IGMP_DOCUMENTATION_MULTICAST_PREFIX,
            *_IGMP_DOCUMENTATION_SOURCE_PREFIXES,
        ],
        "stimulus_driver": {
            "name": case.stimulus,
            "adapter_module": "tools/probe/adapters/src/igmp.rs",
            "adapter_case": adapter_case,
            "state": "planned-only",
            "planned_only": True,
        },
        "stimulus_packet_shape": {
            "ipv4": {
                "source": stimulus_ipv4,
                "destination": destination_ipv4,
                "ttl": _IGMP_DEFAULT_TTL,
                "protocol": _IGMP_IP_PROTOCOL,
                "router_alert_required": True,
            },
            "igmp": stimulus_shape,
        },
        "expected_response_packet_shape": expected_shape,
        "target_service": target_service,
        "capture_filter": capture_filter,
        "validation": validation,
        "wire_requirements": {
            "requires_ipv4_multicast": True,
            "requires_igmp_peer": True,
            "requires_provider_backing": True,
            "requires_confirm_live_run": True,
            "note": (
                "IGMP dry-run records the packet and peer-observation contract. "
                "Any live traffic must run from a provider-backed lab endpoint "
                "with explicit confirmation, never from the developer host."
            ),
        },
        "live_path": (
            "Opt-in via lab-session / providers: provision the IGMP target "
            "listener/router, run the stimulus from the provider endpoint with "
            "--confirm-live-run, collect artifacts, and tear the endpoint down."
        ),
        "digest_hex": digest.hex()[:16],
    }


def _igmp_target_service(
    *,
    kind: str,
    role: str,
    bind_ipv4: str,
    source_ipv4: str,
    multicast_group: str,
    provision_script: str,
) -> JSONObject:
    return {
        "required": True,
        "kind": kind,
        "protocol": "igmp",
        "role": role,
        "bind_ipv4": bind_ipv4,
        "source_ipv4": source_ipv4,
        "multicast_group": multicast_group,
        "runtime": "probe-target-service",
        "provision_script": provision_script,
        "cleanup_script": _IGMP_CLEANUP_SCRIPT,
        "artifact_root": "target/probe/target-services/igmp",
        "deterministic": True,
        "dry_run_safe": True,
        "live_guard": "LIBCRAFTER_PROBE_LAB_TARGET=1",
    }


def deterministic_igmp_group(profile: str, seed: int, sequence: int) -> str:
    digest = deterministic_bytes("igmp-group", profile, seed, sequence)
    host = 1 + digest[0] % 254
    return f"233.252.0.{host}"


def deterministic_igmp_source_list(profile: str, seed: int, sequence: int) -> list[str]:
    digest = deterministic_bytes("igmp-source-list", profile, seed, sequence)
    first = 1 + digest[0] % 254
    second = 1 + digest[1] % 254
    return [f"192.0.2.{first}", f"198.51.100.{second}"]


def _ipsec_probe_plan(
    *,
    case_name: str,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan an IPSec behavioral case (ESP transport/tunnel, AH, IKE_SA_INIT).

    The IPSec cases drive a controlled IPSec-capable peer (Linux xfrm /
    strongSwan / an oracle reference peer) and need libcrafter to seal/authenticate
    a datagram or build an IKE_SA_INIT against the Security Association the peer
    holds. The crate-side stimulus/response *builders* (and the cross-crypto
    parity assertion) land in the later probe steps; until then the dry-run plan
    is ``planned_only``: it records the case, the stimulus/expected-response
    packet shapes (ipsec protocol, mode, wire protocol number / UDP port, the
    deterministic SPI and peer addresses), and the live-path note, but builds no
    packet bytes. This keeps the dry-run plan well-formed and inspectable
    without requiring the crate stimulus builders or a live peer.
    """

    case = PROBE_CASE_BY_NAME[case_name]
    metadata = case.metadata or {}
    ipsec_protocol = str(metadata.get("ipsec_protocol", "ipsec"))
    mode = metadata.get("mode")
    exchange = metadata.get("exchange")
    requires_tunnel = bool(metadata.get("requires_tunnel", False))

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    # Deterministic, non-zero SPI (RFC 4303 reserves 0; the oracle SPI samplers
    # avoid it for the same NON_ESP heuristic reason). Kept in the dynamic
    # 0x1000..0xFFFFFFFF range so it never collides with the IKE/reserved low SPIs.
    spi = 0x1000 + int.from_bytes(digest[0:4], "big") % 0xFFFF_0000

    # The stimulus/response packet shape: the wire protocol the exchange rides
    # and, for ESP/AH, the mode and per-exchange SPI. This is the inspectable
    # contract the later crate stimulus builders will materialize.
    stimulus_shape: JSONObject = {
        "ipsec_protocol": ipsec_protocol,
        "stimulus": case.stimulus,
    }
    response_shape: JSONObject = {
        "ipsec_protocol": ipsec_protocol,
        "expected_response": case.expected_response,
    }
    if ipsec_protocol == "esp":
        stimulus_shape["ip_protocol"] = _IPSEC_ESP_PROTOCOL
        response_shape["ip_protocol"] = _IPSEC_ESP_PROTOCOL
        stimulus_shape["spi"] = spi
        response_shape["spi"] = spi
        if mode is not None:
            stimulus_shape["mode"] = mode
            response_shape["mode"] = mode
    elif ipsec_protocol == "ah":
        stimulus_shape["ip_protocol"] = _IPSEC_AH_PROTOCOL
        response_shape["ip_protocol"] = _IPSEC_AH_PROTOCOL
        stimulus_shape["spi"] = spi
        response_shape["spi"] = spi
        if mode is not None:
            stimulus_shape["mode"] = mode
            response_shape["mode"] = mode
    elif ipsec_protocol == "ikev2":
        stimulus_shape["udp_port"] = _IKEV2_UDP_PORT
        response_shape["udp_port"] = _IKEV2_UDP_PORT
        if exchange is not None:
            stimulus_shape["exchange"] = exchange
            response_shape["exchange"] = exchange

    plan: JSONObject = {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": case.stimulus,
        "expected_response": case.expected_response,
        # The IPSec stimulus/response builders and cross-crypto parity check land
        # in later probe steps; the dry-run plan is planned-only (no packet bytes
        # built) but still records the full exchange shape below.
        "planned_only": True,
        "ipsec_protocol": ipsec_protocol,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "stimulus_packet_shape": stimulus_shape,
        "expected_response_packet_shape": response_shape,
        # The peer that opens/answers the exchange. ESP/AH need it to hold the
        # matching SA; IKEv2 needs it to run an IKE responder. The peer is the
        # Linux xfrm / strongSwan stack or an oracle reference peer configured on
        # the controlled target endpoint -- provisioned only on the opt-in live
        # path (lab-session / providers), never for the dry-run.
        "ipsec_peer": {
            "required": True,
            "role": "ipsec_peer" if ipsec_protocol != "ikev2" else "ikev2_responder",
            "kind": (
                "ikev2-responder"
                if ipsec_protocol == "ikev2"
                else f"ipsec-{ipsec_protocol}-{mode or 'transport'}-peer"
            ),
            "peer_options": [
                "linux-xfrm",
                "strongswan",
                "oracle-reference-peer",
            ],
            "live_only": True,
        },
        "live_path": (
            "Opt-in via lab-session / providers: provision an IPSec-capable peer "
            "(Linux xfrm / strongSwan / an oracle reference peer) holding the "
            "matching SA (or running an IKE responder), run from there, collect "
            "artifacts, and tear it down. The dry-run plans this exchange without "
            "any live traffic."
        ),
        "digest_hex": digest.hex()[:16],
    }
    if mode is not None:
        plan["mode"] = mode
    if exchange is not None:
        plan["exchange"] = exchange
    if requires_tunnel:
        # Mirror the case metadata: tunnel-mode ESP needs a tunnel-mode SA on the
        # peer, so a transport-only peer skips this case while transport-mode
        # cases still plan. The shared capability is still ``ipsec_esp``.
        plan["requires_tunnel"] = True
    return plan


# Legacy per-case plan builders defined in this module. Every protocol still
# lives here until its plugin migration; the assembly below merges the protocol
# registry's contribution (empty until a protocol migrates) ahead of these so a
# migrated builder takes precedence while unmigrated cases keep their legacy
# builder. The IPSec cases register a planned-only builder that records the
# exchange shape (see :func:`_ipsec_probe_plan`).
_LEGACY_PLAN_BUILDERS: dict[str, PlanBuilder] = {
    # ICMP plan builders (``icmp-echo`` / ``ttl-expired``) now live in
    # ``protocols/icmp.py`` and reach ``PLAN_BUILDERS`` through the registry merge
    # below (re-imported into this module above for identity/back-compat).
    # TCP plan builders (``tcp-syn-open`` / ``tcp-syn-closed`` /
    # ``tcp-syn-options``) now live in ``protocols/tcp.py`` and reach
    # ``PLAN_BUILDERS`` through the registry merge below (re-imported into this
    # module above for identity/back-compat).
    # DNS plan builders now live in ``protocols/dns.py`` and reach
    # ``PLAN_BUILDERS`` through the registry merge below (re-imported into this
    # module above for identity/back-compat).
    # DHCP plan builders now live in ``protocols/dhcp.py`` and reach
    # ``PLAN_BUILDERS`` through the registry merge below (re-imported into this
    # module above for identity/back-compat).
    # ARP plan builders now live in ``protocols/arp.py`` and reach
    # ``PLAN_BUILDERS`` through the registry merge below (re-imported into this
    # module above for identity/back-compat).
    # NDP plan builders now live in ``protocols/ndp.py`` and reach
    # ``PLAN_BUILDERS`` through the registry merge below (re-imported into this
    # module above for identity/back-compat).
    # UDP plan builders now live in ``protocols/udp.py`` and reach
    # ``PLAN_BUILDERS`` through the registry merge below (re-imported into this
    # module above for identity/back-compat).
    # The BGP plan builder now lives in ``protocols/bgp.py`` and reaches
    # ``PLAN_BUILDERS`` through the registry merge below (re-imported into this
    # module above for identity/back-compat).
    # The RIP/RIPng plan builders now live in ``protocols/rip.py`` and reach
    # ``PLAN_BUILDERS`` through the registry merge below (re-imported into this
    # module above for identity/back-compat).
    "igmp-membership-query-observation": _igmp_probe_plan,
    "igmp-v2-membership-report-emission": _igmp_probe_plan,
    "igmp-v2-leave-group-emission": _igmp_probe_plan,
    "igmp-v3-source-list-report": _igmp_probe_plan,
    "esp-transport-echo": _ipsec_probe_plan,
    "esp-tunnel-echo": _ipsec_probe_plan,
    "ah-transport-verify": _ipsec_probe_plan,
    "ikev2-sa-init": _ipsec_probe_plan,
}


# Per-case plan-builder dispatch table consulted by :func:`probe_plan_for_case`.
# It is assembled registry-first: the protocol registry's contributed builders
# (empty until a protocol migrates) take precedence, then the legacy module
# builders fill in every case no plugin owns yet. The exact function objects are
# kept (no wrappers) so ``planning._<builder>`` and ``PLAN_BUILDERS[name] is
# _<builder>`` identity stays intact for the pinning tests.
PLAN_BUILDERS: dict[str, PlanBuilder] = {
    **_LEGACY_PLAN_BUILDERS,
    **_registry_plan_builders(),
}


# Legacy planned-only registered cases declared in this module. A planned-only
# builder records the exchange shape (the IPSec/BGP/RIP/IGMP cases) without
# building packet bytes; every other builder produces a fully materialized plan.
_LEGACY_PLANNED_ONLY_REGISTERED_CASES: frozenset[str] = frozenset(
    {
        "esp-transport-echo",
        "esp-tunnel-echo",
        "ah-transport-verify",
        "ikev2-sa-init",
        # ``bgp-session-smoke`` is contributed by the BGP plugin
        # (``protocols/bgp.py``) and unioned into ``PLANNED_ONLY_REGISTERED_CASES``
        # below; the ``rip-update-v2`` / ``ripng-update`` planned-only cases are
        # contributed by the RIP plugin (``protocols/rip.py``) and unioned in the
        # same way.
        "igmp-membership-query-observation",
        "igmp-v2-membership-report-emission",
        "igmp-v2-leave-group-emission",
        "igmp-v3-source-list-report",
    }
)


# The planned-only set is the union of the registry's contribution (empty until
# a protocol migrates) and the legacy frozenset above.
PLANNED_ONLY_REGISTERED_CASES: frozenset[str] = (
    _registry_planned_only_cases() | _LEGACY_PLANNED_ONLY_REGISTERED_CASES
)


def register_plan_builder(case_name: str, builder: PlanBuilder) -> None:
    """Register a plan builder for ``case_name``.

    Used by behavior-suite case groups to add DNS, DHCP, ARP, and UDP planners
    without modifying the dispatcher.
    """

    if case_name not in PROBE_CASE_BY_NAME:
        raise ValueError(
            f"cannot register plan builder for unknown probe case {case_name!r}"
        )
    PLAN_BUILDERS[case_name] = builder
