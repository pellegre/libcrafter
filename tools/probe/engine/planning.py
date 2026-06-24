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

import ipaddress
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
from .target_services import (
    BGP_DOCUMENTATION_IPV4_PREFIX,
    BGP_DOCUMENTATION_IPV6_PREFIX,
    BGP_DRIVER_AS,
    BGP_FRR_TEMPLATE,
    BGP_PEER_AS,
    BGP_PROVISION_SCRIPT,
    BGP_RIB_COMMAND,
    BGP_RUNTIME,
    BGP_SERVICE_KIND,
    BGP_SERVICE_PORT,
    RIP_CONFIG_TEMPLATE,
    RIP_DOCUMENTATION_IPV4_PREFIX,
    RIP_MULTICAST_GROUP,
    RIP_PROVISION_SCRIPT,
    RIP_RIB_COMMAND,
    RIP_RUNTIME,
    RIP_SERVICE_KIND,
    RIP_SERVICE_PORTS,
    rip_peer_service_descriptor,
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


def _icmp_echo_probe_plan(
    *,
    case_name: str = "icmp-echo",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = deterministic_bytes("icmp-echo", profile, seed, sequence)
    identifier = int.from_bytes(digest[0:2], "big") or 1
    sequence_number = int.from_bytes(digest[2:4], "big")
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    payload = (
        f"libcrafter-probe:icmp-echo:{profile}:{seed}:{sequence}:"
        f"{digest.hex()[:16]}"
    ).encode("ascii")
    return {
        "schema_version": 1,
        "case": "icmp-echo",
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "icmp_echo_request",
        "expected_response": "icmp_echo_reply",
        "identifier": identifier,
        "sequence_number": sequence_number,
        "payload_hex": payload.hex(),
        "payload_length": len(payload),
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "capture_filter": (
            f"icmp and src host {target_ipv4} and dst host {stimulus_ipv4}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "icmp_type": 0,
            "icmp_code": 0,
            "identifier": identifier,
            "sequence_number": sequence_number,
            "payload_hex": payload.hex(),
        },
    }


def _tcp_syn_probe_plan(
    *,
    case_name: str,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 61000 + int.from_bytes(digest[0:2], "big") % 4000
    destination_base = 18000 if case_name == "tcp-syn-open" else 22000
    destination_port = destination_base + int.from_bytes(digest[2:4], "big") % 3000
    sequence_number = int.from_bytes(digest[4:8], "big")
    expected_ack = (sequence_number + 1) & 0xFFFF_FFFF
    expected_response = "tcp_syn_ack" if case_name == "tcp-syn-open" else "tcp_rst"
    expected_flags = ["syn", "ack"] if case_name == "tcp-syn-open" else ["rst"]
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "tcp_syn",
        "expected_response": expected_response,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_sequence_number": sequence_number,
        "expected_acknowledgment_number": expected_ack,
        "window": 64240,
        "target_service": {
            "required": case_name == "tcp-syn-open",
            "kind": "tcp-listener" if case_name == "tcp-syn-open" else "closed-port",
            "port": destination_port,
        },
        "stimulus_rst_guard": {
            "required": True,
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": target_ipv4,
            "source_port": source_port,
            "destination_port": destination_port,
        },
        "capture_filter": (
            f"tcp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "flags": expected_flags,
            "acknowledgment_number": expected_ack,
            "allow_rst_ack": case_name == "tcp-syn-closed",
        },
    }


def _tcp_syn_options_probe_plan(
    *,
    case_name: str = "tcp-syn-options",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``tcp-syn-options`` case.

    A TCP SYN to a controlled listener that carries a representative,
    deterministic option set so the dry-run materializes a TCP segment *with
    options* and reports the planned sends, captures, and matchers. The option
    list covers the currently deployed SYN options -- MSS, Window Scale,
    SACK-Permitted, and Timestamp (RFC 9293 / RFC 7323 / RFC 2018) -- plus one
    newer typed option, User Timeout (RFC 5482, kind 28), so the stimulus
    endpoint builds them through the crafter typed ``TcpOption`` API rather than
    raw bytes. The ``tcp_options`` descriptors are the stable spec the Rust
    adapter consumes; the wire option bytes are materialized by libcrafter at
    send time (and reported as ``sent_raw_hex`` in dry-run), never hand-rolled
    here. Expected SYN/ACK validation (peer, ports, flags, ack) mirrors
    ``tcp-syn-open``.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 61000 + int.from_bytes(digest[0:2], "big") % 4000
    destination_port = 18000 + int.from_bytes(digest[2:4], "big") % 3000
    sequence_number = int.from_bytes(digest[4:8], "big")
    expected_ack = (sequence_number + 1) & 0xFFFF_FFFF
    # Representative, deterministic SYN option set. Window-scale shift is kept in
    # the RFC 7323 valid range (0..=14); the MSS rides a documentation-friendly
    # 1460 typical value; the timestamp value is deterministic with a zero echo
    # reply (SYN has nothing to echo); user-timeout carries a granularity flag
    # and a 15-bit value (RFC 5482). The order matches a typical Linux SYN:
    # MSS, SACK-Permitted, Timestamp, NOP, Window Scale, then User Timeout.
    window_scale_shift = digest[8] % 15
    mss_value = 1460
    timestamp_value = int.from_bytes(digest[9:13], "big")
    user_timeout_value = 1 + int.from_bytes(digest[13:15], "big") % 0x7FFE
    tcp_options = [
        {"kind": "mss", "kind_value": 2, "mss": mss_value},
        {"kind": "sack_permitted", "kind_value": 4},
        {
            "kind": "timestamp",
            "kind_value": 8,
            "timestamp_value": timestamp_value,
            "timestamp_echo_reply": 0,
        },
        {"kind": "nop", "kind_value": 1},
        {
            "kind": "window_scale",
            "kind_value": 3,
            "window_scale_shift": window_scale_shift,
        },
        {
            "kind": "user_timeout",
            "kind_value": 28,
            "user_timeout_granularity": False,
            "user_timeout_value": user_timeout_value,
        },
    ]
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "tcp_syn",
        "expected_response": "tcp_syn_ack",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_sequence_number": sequence_number,
        "expected_acknowledgment_number": expected_ack,
        "window": 64240,
        # The representative typed option descriptors the stimulus endpoint
        # builds with the crafter TcpOption API. Materialized option bytes are
        # reported by libcrafter at send time; they are not hand-encoded here.
        "tcp_options": tcp_options,
        "target_service": {
            "required": True,
            "kind": "tcp-listener",
            "port": destination_port,
        },
        "stimulus_rst_guard": {
            "required": True,
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": target_ipv4,
            "source_port": source_port,
            "destination_port": destination_port,
        },
        "capture_filter": (
            f"tcp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "flags": ["syn", "ack"],
            "acknowledgment_number": expected_ack,
            "allow_rst_ack": False,
        },
    }


def _ttl_expired_probe_plan(
    *,
    case_name: str = "ttl-expired",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = deterministic_bytes("ttl-expired", profile, seed, sequence)
    stimulus_ipv4, destination_ipv4 = deterministic_ipv4_pair(
        profile,
        seed,
        sequence,
    )
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    identifier = int.from_bytes(digest[0:2], "big") or 1
    sequence_number = int.from_bytes(digest[2:4], "big")
    payload = (
        f"libcrafter-probe:ttl-expired:{profile}:{seed}:{sequence}:"
        f"{digest.hex()[:16]}"
    ).encode("ascii")
    embedded_prefix_length = 28
    return {
        "schema_version": 1,
        "case": "ttl-expired",
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "low_ttl_probe",
        "expected_response": "icmp_ttl_expired",
        "ttl": 1,
        "identifier": identifier,
        "sequence_number": sequence_number,
        "payload_hex": payload.hex(),
        "payload_length": len(payload),
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": destination_ipv4,
        "controlled_router_ipv4": router_ipv4,
        "expected_reply_source_ipv4": router_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "expected_icmp_type": 11,
        "expected_icmp_code": 0,
        "expected_embedded_prefix_length": embedded_prefix_length,
        "capture_filter": (
            f"icmp and src host {router_ipv4} and dst host {stimulus_ipv4}"
        ),
        "validation": {
            "source_ipv4": router_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "icmp_type": 11,
            "icmp_code": 0,
            "embedded_prefix": {
                "source": "stimulus_sent_bytes",
                "length": embedded_prefix_length,
                "meaning": "original IPv4 header plus first eight bytes of payload",
            },
        },
    }


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


# IPSec ESP/AH IP protocol numbers (RFC 4303 / RFC 4302) and the IKEv2 UDP port
# (RFC 7296). Recorded in the dry-run plan so an inspecting agent sees the wire
# protocol/port the exchange rides without consulting the crate.
_IPSEC_ESP_PROTOCOL = 50
_IPSEC_AH_PROTOCOL = 51
_IKEV2_UDP_PORT = 500


# RIPv2 rides UDP/520 (RFC 2453 sec. 3.9.1) and advertises to the all-RIP-routers
# multicast group 224.0.0.9 (RFC 2453 sec. 3.5). The unicast target stays in
# documentation address space; the probe-owned RIP daemon is FRR ``ripd`` (the
# same FRR/vtysh runtime as the BGP target service), inspected with
# ``show ip rip``. These are recorded in the dry-run plan so an inspecting agent
# sees the wire port, multicast group, and RIB command without consulting the
# crate. No packets are sent: the plan is planned-only.
# RIP target-service constants are owned by :mod:`target_services` (the same
# module that owns the BGP service constants the BGP plan references); the plan
# pulls them in so the wire port, multicast group, runtime, provision assets,
# and RIB command match the ``rip_peer_service_descriptor`` the live target
# setup renders.
_RIP_UDP_PORT = RIP_SERVICE_PORTS[0]
_RIP_MULTICAST_GROUP = RIP_MULTICAST_GROUP
_RIP_SERVICE_KIND = RIP_SERVICE_KIND
_RIP_RUNTIME = RIP_RUNTIME
_RIP_RIB_COMMAND = RIP_RIB_COMMAND


# RIPng (RFC 2080) rides UDP/521 and advertises to the all-RIPng-routers IPv6
# multicast group ff02::9 (RFC 2080 sec. 2.1). It reuses the same FRR runtime as
# the IPv4 RIP target service (FRR's ``ripngd`` daemon), inspected with
# ``show ipv6 ripng``. The documentation prefix stays in the RFC 3849 block
# (2001:db8::/32). These mirror the IPv4 RIP plan constants for the IPv6 path so
# an inspecting agent sees the wire port, multicast group, and RIB command
# without consulting the crate; the plan is planned-only and sends no packets.
_RIPNG_UDP_PORT = 521
_RIPNG_MULTICAST_GROUP = "ff02::9"
_RIPNG_SERVICE_KIND = "frr-ripngd"
_RIPNG_RIB_COMMAND = "vtysh -c 'show ipv6 ripng'"
_RIPNG_DOCUMENTATION_IPV6_PREFIX = "2001:db8::/32"


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


def _bgp_session_smoke_probe_plan(
    *,
    case_name: str = "bgp-session-smoke",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a probe-owned BGP smoke exchange against an FRR peer service."""

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 42000 + int.from_bytes(digest[0:2], "big") % 10000
    documentation_prefixes = [
        BGP_DOCUMENTATION_IPV4_PREFIX,
        BGP_DOCUMENTATION_IPV6_PREFIX,
    ]
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "bgp_session",
        "expected_response": "bgp_peer_session",
        "planned_only": True,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": BGP_SERVICE_PORT,
        "driver_as": BGP_DRIVER_AS,
        "peer_as": BGP_PEER_AS,
        "documentation_prefixes": documentation_prefixes,
        "stimulus_driver": {
            "name": "bgp_session",
            "cargo_example": "bgp_session",
            "driver_source": "crafter/examples/bgp_session.rs",
            "state": "planned-only",
            "planned_only": True,
        },
        "target_service": {
            "required": True,
            "kind": BGP_SERVICE_KIND,
            "protocol": "tcp",
            "port": BGP_SERVICE_PORT,
            "bind_ipv4": target_ipv4,
            "source_ipv4": stimulus_ipv4,
            "runtime": BGP_RUNTIME,
            "driver_as": BGP_DRIVER_AS,
            "peer_as": BGP_PEER_AS,
            "documentation_prefixes": documentation_prefixes,
            "provision_script": BGP_PROVISION_SCRIPT,
            "frr_template": BGP_FRR_TEMPLATE,
            "rib_command": BGP_RIB_COMMAND,
            "deterministic": True,
        },
        "capture_filter": (
            f"tcp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {BGP_SERVICE_PORT} and dst port {source_port}"
        ),
        "validation": {
            "planned_only": True,
            "driver": "bgp_session",
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": BGP_SERVICE_PORT,
            "destination_port": source_port,
            "driver_as": BGP_DRIVER_AS,
            "peer_as": BGP_PEER_AS,
            "rib_command": BGP_RIB_COMMAND,
        },
        "wire_requirements": {
            "requires_ipv4_unicast": True,
            "requires_controlled_service": True,
            "requires_bgp_peer": True,
            "note": (
                "BGP smoke dry-run exposes the bgp_session stimulus intent and "
                "probe-owned FRR target-service setup without opening TCP "
                "sessions or installing FRR."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _rip_update_probe_plan(
    *,
    case_name: str = "rip-update-v2",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a probe-owned RIPv2 update exchange against an FRR ``ripd`` service.

    The probe sends a RIPv2 request on UDP/520 to the documentation-range
    unicast target running the RIP daemon and expects the daemon's RIPv2
    response (advertised to the all-RIP-routers multicast group 224.0.0.9 per
    RFC 2453). The crate-side ``rip_request`` stimulus driver lands with the
    endpoint runner; until then the dry-run plan is ``planned_only`` -- it
    records the stimulus driver intent, the FRR ``ripd`` target-service setup,
    the UDP port, multicast group, and the ``show ip rip`` RIB command, but
    builds no packet bytes and sends nothing.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 42000 + int.from_bytes(digest[0:2], "big") % 10000
    documentation_prefixes = [
        RIP_DOCUMENTATION_IPV4_PREFIX,
    ]
    # The plan references the same probe-owned FRR ``ripd`` descriptor the live
    # target setup renders (mirroring how the BGP plan references its peer
    # descriptor), so the provision script and config template stay in sync.
    rip_service = rip_peer_service_descriptor(
        bind_ipv4=target_ipv4,
        source_ipv4=stimulus_ipv4,
    )
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "rip_request",
        "expected_response": "rip_peer_update",
        "planned_only": True,
        "protocol": "rip",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "multicast_group": _RIP_MULTICAST_GROUP,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": _RIP_UDP_PORT,
        "documentation_prefixes": documentation_prefixes,
        "stimulus_driver": {
            "name": "rip_request",
            "cargo_example": "rip_request",
            "driver_source": "crafter/examples/rip_request.rs",
            "state": "planned-only",
            "planned_only": True,
        },
        "target_service": {
            "required": True,
            "kind": _RIP_SERVICE_KIND,
            "protocol": "udp",
            "port": _RIP_UDP_PORT,
            "multicast_group": _RIP_MULTICAST_GROUP,
            "bind_ipv4": target_ipv4,
            "source_ipv4": stimulus_ipv4,
            "runtime": _RIP_RUNTIME,
            "documentation_prefixes": documentation_prefixes,
            "provision_script": rip_service.metadata["provision_script"],
            "config_template": rip_service.metadata["config_template"],
            "rib_command": _RIP_RIB_COMMAND,
            "deterministic": True,
        },
        "capture_filter": (
            f"udp and src host {target_ipv4} "
            f"and src port {_RIP_UDP_PORT} and dst port {_RIP_UDP_PORT}"
        ),
        "validation": {
            "planned_only": True,
            "driver": "rip_request",
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": _RIP_UDP_PORT,
            "destination_port": _RIP_UDP_PORT,
            "multicast_group": _RIP_MULTICAST_GROUP,
            "rib_command": _RIP_RIB_COMMAND,
        },
        "wire_requirements": {
            "requires_ipv4_unicast": True,
            "requires_controlled_service": True,
            "requires_rip_peer": True,
            "note": (
                "RIP smoke dry-run exposes the rip_request stimulus intent and "
                "probe-owned FRR ripd target-service setup without sending "
                "UDP/520 datagrams or installing FRR."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _ripng_update_probe_plan(
    *,
    case_name: str = "ripng-update",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a probe-owned RIPng update exchange against an FRR ``ripngd`` service.

    The IPv6 analog of :func:`_rip_update_probe_plan`: the probe sends a RIPng
    request on UDP/521 to the documentation-range unicast target running the
    RIPng daemon and expects the daemon's RIPng response (advertised to the
    all-RIPng-routers multicast group ``ff02::9`` per RFC 2080). The crate-side
    ``ripng_request`` stimulus driver lands with the endpoint runner; until then
    the dry-run plan is ``planned_only`` -- it records the stimulus driver
    intent, the FRR ``ripngd`` target-service setup, the UDP port, multicast
    group, and the ``show ipv6 ripng`` RIB command, but builds no packet bytes
    and sends nothing.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv6 = deterministic_documentation_ipv6(digest)
    target_ipv6 = deterministic_documentation_ipv6(digest[::-1])
    source_port = 42000 + int.from_bytes(digest[0:2], "big") % 10000
    documentation_prefixes = [
        _RIPNG_DOCUMENTATION_IPV6_PREFIX,
    ]
    # The RIPng path reuses the same probe-owned FRR runtime assets as the IPv4
    # RIP target service (FRR's ``ripngd`` daemon shares the ``ripd.conf``
    # runtime), so the provision script and config template stay in sync with
    # the IPv4 plan while the wire details (port, multicast group, RIB command)
    # are IPv6-specific.
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "ripng_request",
        "expected_response": "ripng_peer_update",
        "planned_only": True,
        "protocol": "ripng",
        "source_ipv6": stimulus_ipv6,
        "destination_ipv6": target_ipv6,
        "multicast_group": _RIPNG_MULTICAST_GROUP,
        "expected_reply_source_ipv6": target_ipv6,
        "expected_reply_destination_ipv6": stimulus_ipv6,
        "source_port": source_port,
        "destination_port": _RIPNG_UDP_PORT,
        "documentation_prefixes": documentation_prefixes,
        "stimulus_driver": {
            "name": "ripng_request",
            "cargo_example": "ripng_request",
            "driver_source": "crafter/examples/ripng_request.rs",
            "state": "planned-only",
            "planned_only": True,
        },
        "target_service": {
            "required": True,
            "kind": _RIPNG_SERVICE_KIND,
            "protocol": "udp",
            "port": _RIPNG_UDP_PORT,
            "multicast_group": _RIPNG_MULTICAST_GROUP,
            "bind_ipv6": target_ipv6,
            "source_ipv6": stimulus_ipv6,
            "runtime": _RIP_RUNTIME,
            "documentation_prefixes": documentation_prefixes,
            "provision_script": RIP_PROVISION_SCRIPT,
            "config_template": RIP_CONFIG_TEMPLATE,
            "rib_command": _RIPNG_RIB_COMMAND,
            "deterministic": True,
        },
        "capture_filter": (
            f"udp and src host {target_ipv6} "
            f"and src port {_RIPNG_UDP_PORT} and dst port {_RIPNG_UDP_PORT}"
        ),
        "validation": {
            "planned_only": True,
            "driver": "ripng_request",
            "source_ipv6": target_ipv6,
            "destination_ipv6": stimulus_ipv6,
            "source_port": _RIPNG_UDP_PORT,
            "destination_port": _RIPNG_UDP_PORT,
            "multicast_group": _RIPNG_MULTICAST_GROUP,
            "rib_command": _RIPNG_RIB_COMMAND,
        },
        "wire_requirements": {
            "requires_ipv6_unicast": True,
            "requires_controlled_service": True,
            "requires_rip_peer": True,
            "note": (
                "RIPng smoke dry-run exposes the ripng_request stimulus intent "
                "and probe-owned FRR ripngd target-service setup without sending "
                "UDP/521 datagrams or installing FRR."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


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
    "icmp-echo": _icmp_echo_probe_plan,
    "tcp-syn-open": _tcp_syn_probe_plan,
    "tcp-syn-closed": _tcp_syn_probe_plan,
    "tcp-syn-options": _tcp_syn_options_probe_plan,
    # DNS plan builders now live in ``protocols/dns.py`` and reach
    # ``PLAN_BUILDERS`` through the registry merge below (re-imported into this
    # module above for identity/back-compat).
    # DHCP plan builders now live in ``protocols/dhcp.py`` and reach
    # ``PLAN_BUILDERS`` through the registry merge below (re-imported into this
    # module above for identity/back-compat).
    "ttl-expired": _ttl_expired_probe_plan,
    # ARP plan builders now live in ``protocols/arp.py`` and reach
    # ``PLAN_BUILDERS`` through the registry merge below (re-imported into this
    # module above for identity/back-compat).
    "ndp-neighbor-solicitation": _ndp_neighbor_solicitation_probe_plan,
    "ndp-router-solicitation": _ndp_router_solicitation_probe_plan,
    "ndp-duplicate-address-detection": _ndp_duplicate_address_detection_probe_plan,
    # UDP plan builders now live in ``protocols/udp.py`` and reach
    # ``PLAN_BUILDERS`` through the registry merge below (re-imported into this
    # module above for identity/back-compat).
    "bgp-session-smoke": _bgp_session_smoke_probe_plan,
    "rip-update-v2": _rip_update_probe_plan,
    "ripng-update": _ripng_update_probe_plan,
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
        "bgp-session-smoke",
        "rip-update-v2",
        "ripng-update",
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
