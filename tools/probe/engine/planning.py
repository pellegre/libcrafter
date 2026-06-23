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

from .cases import PROBE_CASE_BY_NAME, UDP_ECHO_LARGE_PAYLOAD_LENGTH
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


def dhcp_client_mac(profile: str, seed: int, sequence: int) -> str:
    """Return the deterministic DHCP client Ethernet MAC for a probe case.

    Uses the RFC 7042 documentation unicast range (``00:00:5e:00:53:00-ff``)
    derived from the case digest so the client hardware address (BOOTP
    ``chaddr``) is stable per (case, profile, seed, sequence) and stays inside
    the documentation MAC block.
    """

    digest = deterministic_bytes(f"dhcp-client-mac-{profile}", profile, seed, sequence)
    return f"00:00:5e:00:53:{digest[0]:02x}"


def dhcp_hostname(profile: str, seed: int, sequence: int) -> str:
    """Return the deterministic DHCP client hostname (option 12) for a probe case."""

    label = dns_label(profile)
    return f"probe-{label}-{seed}-{sequence}"


def dhcp_client_identifier(profile: str, seed: int, sequence: int) -> str:
    """Return the deterministic DHCP client identifier (option 61) payload hex.

    Builds an RFC 4361 node-specific identifier: the type octet ``0xff``, a
    deterministic 4-octet IAID, and a deterministic DUID-LL (DUID type 3,
    hardware type 1) over an RFC 7042 documentation MAC. This is a stable client
    identity distinct from ``chaddr`` so the controlled responder can record and
    the validator can confirm option 61 specifically (RFC 2132 section 9.14).

    The returned value is the lowercase hex of the encoded option-61 payload
    (type octet plus identifier, without the option code or length), which is
    exactly what the libcrafter ``DhcpClientIdentifier`` decoder re-encodes.
    """

    digest = deterministic_bytes("dhcp-client-identifier", profile, seed, sequence)
    # RFC 4361 type octet 0xff, then a 4-octet IAID derived from the digest.
    payload = bytearray()
    payload.append(0xFF)
    payload.extend(digest[0:4])
    # DUID-LL (RFC 3315 / RFC 4361): DUID type 3, hardware type 1 (Ethernet),
    # followed by a documentation MAC (RFC 7042 00:00:5e:00:53:00-ff).
    payload.extend((0x00, 0x03))  # DUID type 3 (DUID-LL)
    payload.extend((0x00, 0x01))  # hardware type 1 (Ethernet)
    payload.extend((0x00, 0x00, 0x5E, 0x00, 0x53, digest[4]))
    return payload.hex()


def dhcp_parameter_request_list(profile: str, seed: int, sequence: int) -> list[int]:
    """Return the deterministic DHCP parameter request list (option 55) codes.

    Source: RFC 2132 section 9.8. The list names the option codes the client asks
    the server to return. The probe uses a stable, RFC-correct set so the
    controlled responder can return exactly those options and the validator can
    confirm both the option presence and the returned values: subnet mask (1),
    router (3), DNS server (6), IP address lease time (51), renewal T1 (58), and
    rebinding T2 (59). The list is fixed (not digest-derived) so the requested
    parameters stay aligned with the expected-response option fields the plan
    carries; the digest only varies the per-case identity values elsewhere.
    """

    return [1, 3, 6, 51, 58, 59]


def _dhcp_parameter_request_list_probe_plan(
    *,
    case_name: str = "dhcp-parameter-request-list",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dhcp-parameter-request-list`` behavioral case.

    The stimulus is a BOOTP/DHCP Discover (message type 1) built by libcrafter
    that carries a parameter request list (option 55, RFC 2132 section 9.8) naming
    the option codes the client wants the server to return: subnet mask (1),
    router (3), DNS server (6), lease time (51), renewal T1 (58), and rebinding
    T2 (59). The controlled responder returns those requested options in its
    Offer, so this case exercises option-list construction in the outgoing
    Discover and response option parsing in the Offer.

    The validation contract covers the decoded UDP/BOOTP/DHCP Offer: the BOOTP
    opcode (reply), message type Offer, the echoed transaction id (xid), the
    client hardware address (chaddr), the offered address (yiaddr), the server
    identifier (option 54), and the requested configuration/lease options the
    responder returned (subnet mask 1, router 3, DNS 6, lease 51, renewal 58,
    rebinding 59), plus the response direction (server -> client over ports
    67 -> 68). Addresses stay in documentation space: the offered address and the
    returned DNS server are in ``198.51.100.0/24`` and the lab transport uses the
    private endpoint pair.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    client_mac = dhcp_client_mac(profile, seed, sequence)
    parameter_request_list = dhcp_parameter_request_list(profile, seed, sequence)
    transaction_id = int.from_bytes(digest[0:4], "big") or 1
    # DHCP uses fixed privileged ports: client 68 -> server 67.
    source_port = 68
    destination_port = 67
    offered_ipv4 = f"198.51.100.{1 + digest[4] % 250}"
    subnet_mask = "255.255.255.0"
    server_identifier = target_ipv4
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    # A DNS server option (6) the responder hands back in documentation space.
    dns_server_ipv4 = f"198.51.100.{1 + digest[6] % 250}"
    lease_time = 3600 + 60 * (digest[5] % 60)
    renewal_time = lease_time // 2
    rebinding_time = (lease_time * 7) // 8
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcp_discover",
        "expected_response": "dhcp_offer",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "parameter_request_list": parameter_request_list,
        "transaction_id": transaction_id,
        "expected_message_type": "offer",
        "expected_message_type_value": 2,
        "expected_yiaddr": offered_ipv4,
        "expected_server_identifier": server_identifier,
        "expected_parameter_request_list": parameter_request_list,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_dns_ipv4": dns_server_ipv4,
        "expected_lease_time": lease_time,
        "expected_renewal_time": renewal_time,
        "expected_rebinding_time": rebinding_time,
        "target_service": {
            "required": True,
            "kind": "dhcp-responder",
            "port": destination_port,
            "client_port": source_port,
            "client_mac": client_mac,
            "parameter_request_list": parameter_request_list,
            "transaction_id": transaction_id,
            "yiaddr": offered_ipv4,
            "server_identifier": server_identifier,
            "subnet_mask": subnet_mask,
            "router_ipv4": router_ipv4,
            "dns_ipv4": dns_server_ipv4,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
        },
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "offer",
            "message_type_value": 2,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "yiaddr": offered_ipv4,
            "server_identifier": server_identifier,
            "subnet_mask": subnet_mask,
            "router_ipv4": router_ipv4,
            "dns_ipv4": dns_server_ipv4,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
            "requested_parameters": parameter_request_list,
            "direction": "server_to_client",
        },
    }


def _dhcp_lease_time_probe_plan(
    *,
    case_name: str = "dhcp-lease-time",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dhcp-lease-time`` behavioral case.

    The stimulus is a BOOTP/DHCP Discover (message type 1) built by libcrafter
    and sent from the DHCP client port (68) to the server port (67) against a
    controlled DHCP responder on a private L2 lab segment. The controlled
    responder answers with an Offer (message type 2) carrying the three DHCP
    timing options as 32-bit second counts: the IP address lease time
    (option 51, RFC 2132 section 9.2), the renewal (T1) time value (option 58,
    RFC 2132 section 9.11), and the rebinding (T2) time value (option 59, RFC
    2132 section 9.12). This case focuses on parsing each timing option as a
    structured numeric value while still confirming the response identity and
    direction.

    The validation contract covers the decoded UDP/BOOTP/DHCP Offer: the BOOTP
    opcode (reply), message type Offer, the echoed transaction id (xid), the
    client hardware address (chaddr), the offered address (yiaddr), the server
    identifier (option 54), and each of the three timing option values (lease 51,
    renewal 58, rebinding 59), plus the response direction (server -> client over
    ports 67 -> 68). Addresses stay in documentation space: the offered address
    is in ``198.51.100.0/24`` and the lab transport uses the private endpoint
    pair.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    client_mac = dhcp_client_mac(profile, seed, sequence)
    transaction_id = int.from_bytes(digest[0:4], "big") or 1
    # DHCP uses fixed privileged ports: client 68 -> server 67.
    source_port = 68
    destination_port = 67
    offered_ipv4 = f"198.51.100.{1 + digest[4] % 250}"
    subnet_mask = "255.255.255.0"
    server_identifier = target_ipv4
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    # RFC 2131 section 4.4.5: T1 defaults to 0.5 * lease and T2 to 0.875 * lease,
    # so the planned values keep T1 < T2 < lease for any lease the digest picks.
    lease_time = 3600 + 60 * (digest[5] % 60)
    renewal_time = lease_time // 2
    rebinding_time = (lease_time * 7) // 8
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcp_discover",
        "expected_response": "dhcp_offer",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "transaction_id": transaction_id,
        "expected_message_type": "offer",
        "expected_message_type_value": 2,
        "expected_yiaddr": offered_ipv4,
        "expected_server_identifier": server_identifier,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_lease_time": lease_time,
        "expected_renewal_time": renewal_time,
        "expected_rebinding_time": rebinding_time,
        "target_service": {
            "required": True,
            "kind": "dhcp-responder",
            "port": destination_port,
            "client_port": source_port,
            "client_mac": client_mac,
            "transaction_id": transaction_id,
            "yiaddr": offered_ipv4,
            "server_identifier": server_identifier,
            "subnet_mask": subnet_mask,
            "router_ipv4": router_ipv4,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
        },
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "offer",
            "message_type_value": 2,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "yiaddr": offered_ipv4,
            "server_identifier": server_identifier,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
            "direction": "server_to_client",
        },
    }


def _dhcp_discover_offer_probe_plan(
    *,
    case_name: str = "dhcp-discover-offer",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dhcp-discover-offer`` behavioral case.

    The stimulus is a BOOTP/DHCP Discover (message type 1) built by libcrafter
    and sent from the DHCP client port (68) to the server port (67) against a
    controlled DHCP responder on a private L2 lab segment. The responder answers
    with an Offer (message type 2) carrying the offered address in ``yiaddr``,
    the server identifier (option 54), and lease timing options (51/58/59).

    The validation contract covers the decoded UDP/BOOTP/DHCP response: the
    BOOTP opcode (reply), message type Offer, the echoed transaction id (xid),
    the client hardware address (chaddr), the offered address (yiaddr), the
    server identifier, the lease time option, and the response direction
    (server -> client over ports 67 -> 68). Addresses stay in documentation
    space: the offered address is in ``198.51.100.0/24`` and the lab transport
    uses the private endpoint pair.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    client_mac = dhcp_client_mac(profile, seed, sequence)
    transaction_id = int.from_bytes(digest[0:4], "big") or 1
    # DHCP uses fixed privileged ports: client 68 -> server 67.
    source_port = 68
    destination_port = 67
    offered_ipv4 = f"198.51.100.{1 + digest[4] % 250}"
    subnet_mask = "255.255.255.0"
    server_identifier = target_ipv4
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    lease_time = 3600 + 60 * (digest[5] % 60)
    renewal_time = lease_time // 2
    rebinding_time = (lease_time * 7) // 8
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcp_discover",
        "expected_response": "dhcp_offer",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "transaction_id": transaction_id,
        "expected_message_type": "offer",
        "expected_message_type_value": 2,
        "expected_yiaddr": offered_ipv4,
        "expected_server_identifier": server_identifier,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_lease_time": lease_time,
        "expected_renewal_time": renewal_time,
        "expected_rebinding_time": rebinding_time,
        "target_service": {
            "required": True,
            "kind": "dhcp-responder",
            "port": destination_port,
            "client_port": source_port,
            "client_mac": client_mac,
            "transaction_id": transaction_id,
            "yiaddr": offered_ipv4,
            "server_identifier": server_identifier,
            "subnet_mask": subnet_mask,
            "router_ipv4": router_ipv4,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
        },
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "offer",
            "message_type_value": 2,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "yiaddr": offered_ipv4,
            "server_identifier": server_identifier,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
            "direction": "server_to_client",
        },
    }


def _dhcp_rapid_repeat_send(
    *,
    profile: str,
    seed: int,
    sequence: int,
    digest: bytes,
    index: int,
    stimulus_ipv4: str,
    target_ipv4: str,
    transaction_id: int,
    client_mac: str,
    source_port: int,
    destination_port: int,
    offered_ipv4: str,
    subnet_mask: str,
    server_identifier: str,
    router_ipv4: str,
    lease_time: int,
    renewal_time: int,
    rebinding_time: int,
) -> JSONObject:
    """Build one of the two Discover->Offer sends for ``dhcp-rapid-repeat``.

    Each send owns a distinct deterministic transaction id (xid) AND a distinct
    deterministic client identity (the ``chaddr`` client MAC), so the controlled
    responder answers each Discover with its own Offer keyed by xid/chaddr and
    the validator matches every decoded Offer back to *its* Discover by the
    echoed transaction id. Each send also carries its own deterministic offered
    address (``yiaddr``) so the two Offers are recognizably different and a
    response is never confused with the sibling send's Offer. The per-send
    capture filter and full validation contract (BOOTP reply, message type Offer,
    echoed xid/chaddr, offered address, server identifier, lease/renewal/rebinding
    options, server -> client direction over ports 67 -> 68) round-trip through
    libcrafter decode for this send alone.
    """

    return {
        "index": index,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "transaction_id": transaction_id,
        "expected_message_type": "offer",
        "expected_message_type_value": 2,
        "expected_yiaddr": offered_ipv4,
        "expected_server_identifier": server_identifier,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_lease_time": lease_time,
        "expected_renewal_time": renewal_time,
        "expected_rebinding_time": rebinding_time,
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "target_service": {
            "required": True,
            "kind": "dhcp-responder",
            "port": destination_port,
            "client_port": source_port,
            "client_mac": client_mac,
            "transaction_id": transaction_id,
            "yiaddr": offered_ipv4,
            "server_identifier": server_identifier,
            "subnet_mask": subnet_mask,
            "router_ipv4": router_ipv4,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
        },
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "offer",
            "message_type_value": 2,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "yiaddr": offered_ipv4,
            "server_identifier": server_identifier,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
            "direction": "server_to_client",
        },
    }


def _dhcp_rapid_repeat_probe_plan(
    *,
    case_name: str = "dhcp-rapid-repeat",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dhcp-rapid-repeat`` behavioral case.

    Two BOOTP/DHCP Discovers (message type 1) built by libcrafter and sent in
    quick succession from the DHCP client port (68) to the server port (67)
    against a controlled DHCP responder on a private L2 lab segment. Unlike the
    single-send ``dhcp-discover-offer`` case, the two Discovers carry *distinct*
    deterministic transaction ids (xids) and *distinct* deterministic client
    identities (``chaddr`` client MACs), so the responder returns one Offer per
    Discover (each keyed by its xid/chaddr) and the endpoint must receive two
    Offers, decode each independently, and match every Offer back to *its*
    Discover by the echoed transaction id — never confusing the two Offers.

    The plan carries a ``dhcp_sends`` array (one entry per send) plus the
    conventional single-send top-level fields (mirroring the first send) so the
    generic plan echo and any single-send consumer keep working unchanged; the
    DHCP dispatch detects ``dhcp_sends`` and drives both sends. Addresses stay in
    documentation space: each offered address is in ``198.51.100.0/24`` and the
    lab transport uses the private endpoint pair.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    # DHCP uses fixed privileged ports: client 68 -> server 67.
    source_port = 68
    destination_port = 67
    subnet_mask = "255.255.255.0"
    server_identifier = target_ipv4
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    base_client_mac = dhcp_client_mac(profile, seed, sequence)

    # Two distinct deterministic transaction ids: the case point is that the two
    # Discovers are independently identifiable. Derive each from a different slice
    # of the digest and keep them distinct.
    first_xid = int.from_bytes(digest[0:4], "big") or 1
    second_xid = int.from_bytes(digest[4:8], "big") or 2
    if second_xid == first_xid:
        second_xid = (first_xid ^ 0xFFFFFFFF) or (first_xid + 1)
    transaction_ids = (first_xid, second_xid)

    # Two distinct deterministic client identities (chaddr). The shared client MAC
    # derives from the documentation MAC block (RFC 7042 00:00:5e:00:53:00-ff);
    # vary the final octet per send so each Discover names a distinct client and
    # the responder keys its Offer to that client.
    mac_prefix = base_client_mac.rsplit(":", 1)[0]
    first_mac_octet = digest[8]
    second_mac_octet = digest[9]
    if second_mac_octet == first_mac_octet:
        second_mac_octet = (first_mac_octet + 1) & 0xFF
    client_macs = (
        f"{mac_prefix}:{first_mac_octet:02x}",
        f"{mac_prefix}:{second_mac_octet:02x}",
    )

    # Two distinct deterministic offered addresses in documentation space so each
    # Offer carries a recognizably different yiaddr.
    first_offer_host = 1 + digest[10] % 250
    second_offer_host = 1 + digest[11] % 250
    if second_offer_host == first_offer_host:
        second_offer_host = 1 + (first_offer_host % 250)
    offered_ipv4s = (
        f"198.51.100.{first_offer_host}",
        f"198.51.100.{second_offer_host}",
    )

    # One shared deterministic lease schedule across both sends (the lease timing
    # is not the case variable; the per-send identity is).
    lease_time = 3600 + 60 * (digest[12] % 60)
    renewal_time = lease_time // 2
    rebinding_time = (lease_time * 7) // 8

    sends = [
        _dhcp_rapid_repeat_send(
            profile=profile,
            seed=seed,
            sequence=sequence,
            digest=digest,
            index=index,
            stimulus_ipv4=stimulus_ipv4,
            target_ipv4=target_ipv4,
            transaction_id=transaction_ids[index],
            client_mac=client_macs[index],
            source_port=source_port,
            destination_port=destination_port,
            offered_ipv4=offered_ipv4s[index],
            subnet_mask=subnet_mask,
            server_identifier=server_identifier,
            router_ipv4=router_ipv4,
            lease_time=lease_time,
            renewal_time=renewal_time,
            rebinding_time=rebinding_time,
        )
        for index in range(2)
    ]
    first = sends[0]

    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcp_discover",
        "expected_response": "dhcp_offer",
        # Conventional single-send top-level fields mirror the first send so the
        # generic plan echo / capture filter / single-send consumers keep working.
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": first["client_mac"],
        "transaction_id": first["transaction_id"],
        "expected_message_type": "offer",
        "expected_message_type_value": 2,
        "expected_yiaddr": first["expected_yiaddr"],
        "expected_server_identifier": server_identifier,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_lease_time": lease_time,
        "expected_renewal_time": renewal_time,
        "expected_rebinding_time": rebinding_time,
        # The rapid-repeat contract: two independent Discover->Offer sends, each
        # with its own deterministic xid, client identity, and offered address,
        # validated separately.
        "send_count": len(sends),
        "dhcp_sends": sends,
        "target_service": {
            "required": True,
            "kind": "dhcp-responder",
            "port": destination_port,
            "client_port": source_port,
            "client_mac": first["client_mac"],
            "transaction_id": first["transaction_id"],
            "yiaddr": first["expected_yiaddr"],
            "server_identifier": server_identifier,
            "subnet_mask": subnet_mask,
            "router_ipv4": router_ipv4,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
            "rapid_repeat": {
                "sends": [
                    {
                        "transaction_id": send["transaction_id"],
                        "client_mac": send["client_mac"],
                        "yiaddr": send["expected_yiaddr"],
                    }
                    for send in sends
                ],
            },
        },
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": first["validation"],
    }


def _dhcp_client_identifier_probe_plan(
    *,
    case_name: str = "dhcp-client-identifier",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dhcp-client-identifier`` behavioral case.

    The stimulus is a BOOTP/DHCP Discover (message type 1) built by libcrafter
    that carries a client identifier option (option 61, RFC 2132 section 9.14)
    in addition to the client hardware address (``chaddr``). DHCP clients may
    identify themselves with option 61 instead of relying only on ``chaddr``, so
    the controlled responder records the offered client identity and echoes the
    client identifier back in its Offer (RFC 6842 makes echoing the option a MUST
    for compliant servers).

    The validation contract covers the decoded UDP/BOOTP/DHCP Offer: the BOOTP
    opcode (reply), message type Offer, the echoed transaction id (xid), the
    client hardware address (chaddr), the offered address (yiaddr), the server
    identifier (option 54), the echoed client identifier (option 61), and the
    response direction (server -> client over ports 67 -> 68). Addresses stay in
    documentation space: the offered address is in ``198.51.100.0/24`` and the
    lab transport uses the private endpoint pair.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    client_mac = dhcp_client_mac(profile, seed, sequence)
    client_identifier_hex = dhcp_client_identifier(profile, seed, sequence)
    transaction_id = int.from_bytes(digest[0:4], "big") or 1
    # DHCP uses fixed privileged ports: client 68 -> server 67.
    source_port = 68
    destination_port = 67
    offered_ipv4 = f"198.51.100.{1 + digest[4] % 250}"
    subnet_mask = "255.255.255.0"
    server_identifier = target_ipv4
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    lease_time = 3600 + 60 * (digest[5] % 60)
    renewal_time = lease_time // 2
    rebinding_time = (lease_time * 7) // 8
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcp_discover",
        "expected_response": "dhcp_offer",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "client_identifier_hex": client_identifier_hex,
        "transaction_id": transaction_id,
        "expected_message_type": "offer",
        "expected_message_type_value": 2,
        "expected_yiaddr": offered_ipv4,
        "expected_server_identifier": server_identifier,
        "expected_client_identifier_hex": client_identifier_hex,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_lease_time": lease_time,
        "expected_renewal_time": renewal_time,
        "expected_rebinding_time": rebinding_time,
        "target_service": {
            "required": True,
            "kind": "dhcp-responder",
            "port": destination_port,
            "client_port": source_port,
            "client_mac": client_mac,
            "client_identifier_hex": client_identifier_hex,
            "transaction_id": transaction_id,
            "yiaddr": offered_ipv4,
            "server_identifier": server_identifier,
            "subnet_mask": subnet_mask,
            "router_ipv4": router_ipv4,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
        },
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "offer",
            "message_type_value": 2,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "client_identifier_hex": client_identifier_hex,
            "yiaddr": offered_ipv4,
            "server_identifier": server_identifier,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
            "direction": "server_to_client",
        },
    }


def _dhcp_hostname_probe_plan(
    *,
    case_name: str = "dhcp-hostname",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dhcp-hostname`` behavioral case.

    The stimulus is a BOOTP/DHCP Discover (message type 1) built by libcrafter
    that carries a hostname option (option 12, RFC 2132 section 3.14) in
    addition to the client hardware address (``chaddr``). The hostname is a
    string option, so this case exercises string option encode (in the outgoing
    Discover) and decode (in the response) through libcrafter. The controlled
    responder records the offered hostname and echoes it back in its Offer so
    the validator can confirm the string option round-trips.

    The dry-run metadata carries the planned outgoing hostname option so the
    endpoint can validate the option it built into the Discover, and the
    validation contract covers the decoded UDP/BOOTP/DHCP Offer: the BOOTP
    opcode (reply), message type Offer, the echoed transaction id (xid), the
    client hardware address (chaddr), the offered address (yiaddr), the server
    identifier (option 54), the echoed hostname (option 12), and the response
    direction (server -> client over ports 67 -> 68). Addresses stay in
    documentation space: the offered address is in ``198.51.100.0/24`` and the
    lab transport uses the private endpoint pair.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    client_mac = dhcp_client_mac(profile, seed, sequence)
    hostname = dhcp_hostname(profile, seed, sequence)
    transaction_id = int.from_bytes(digest[0:4], "big") or 1
    # DHCP uses fixed privileged ports: client 68 -> server 67.
    source_port = 68
    destination_port = 67
    offered_ipv4 = f"198.51.100.{1 + digest[4] % 250}"
    subnet_mask = "255.255.255.0"
    server_identifier = target_ipv4
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    lease_time = 3600 + 60 * (digest[5] % 60)
    renewal_time = lease_time // 2
    rebinding_time = (lease_time * 7) // 8
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcp_discover",
        "expected_response": "dhcp_offer",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "hostname": hostname,
        "transaction_id": transaction_id,
        "expected_message_type": "offer",
        "expected_message_type_value": 2,
        "expected_yiaddr": offered_ipv4,
        "expected_server_identifier": server_identifier,
        "expected_hostname": hostname,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_lease_time": lease_time,
        "expected_renewal_time": renewal_time,
        "expected_rebinding_time": rebinding_time,
        "target_service": {
            "required": True,
            "kind": "dhcp-responder",
            "port": destination_port,
            "client_port": source_port,
            "client_mac": client_mac,
            "hostname": hostname,
            "transaction_id": transaction_id,
            "yiaddr": offered_ipv4,
            "server_identifier": server_identifier,
            "subnet_mask": subnet_mask,
            "router_ipv4": router_ipv4,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
        },
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "offer",
            "message_type_value": 2,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "hostname": hostname,
            "yiaddr": offered_ipv4,
            "server_identifier": server_identifier,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
            "direction": "server_to_client",
        },
    }


def _dhcp_request_ack_probe_plan(
    *,
    case_name: str = "dhcp-request-ack",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dhcp-request-ack`` behavioral case.

    The stimulus is a BOOTP/DHCP Request (message type 3) built by libcrafter
    and sent from the DHCP client port (68) to the server port (67) against a
    controlled DHCP responder on a private L2 lab segment. The Request names the
    address the client wants to commit in the requested-IP option (50) and the
    chosen server in the server-identifier option (54), echoing the transaction
    id (xid) and client hardware address (chaddr) from the prior Discover/Offer
    exchange. The responder answers with an Ack (message type 5) that commits the
    binding: the assigned address in ``yiaddr``, the server identifier (option
    54), and the configuration/lease options (subnet 1, router 3, DNS 6, lease
    51, renewal 58, rebinding 59).

    The validation contract covers the decoded UDP/BOOTP/DHCP response: the
    BOOTP opcode (reply), message type Ack, the echoed transaction id and client
    hardware address, the assigned address (yiaddr), the server identifier, the
    subnet mask, router, DNS, and lease timing options, and the response
    direction (server -> client over ports 67 -> 68). Addresses stay in
    documentation space: the assigned/requested address is in ``198.51.100.0/24``
    and the lab transport uses the private endpoint pair.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    client_mac = dhcp_client_mac(profile, seed, sequence)
    transaction_id = int.from_bytes(digest[0:4], "big") or 1
    # DHCP uses fixed privileged ports: client 68 -> server 67.
    source_port = 68
    destination_port = 67
    # The client requests the address it was previously offered; the responder
    # commits the same address in the Ack ``yiaddr``.
    assigned_ipv4 = f"198.51.100.{1 + digest[4] % 250}"
    requested_ipv4 = assigned_ipv4
    subnet_mask = "255.255.255.0"
    server_identifier = target_ipv4
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    # A DNS server option (6) the responder hands back in documentation space.
    dns_server_ipv4 = f"198.51.100.{1 + digest[6] % 250}"
    lease_time = 3600 + 60 * (digest[5] % 60)
    renewal_time = lease_time // 2
    rebinding_time = (lease_time * 7) // 8
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcp_request",
        "expected_response": "dhcp_ack",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "transaction_id": transaction_id,
        "requested_ipv4": requested_ipv4,
        "server_identifier": server_identifier,
        "expected_message_type": "ack",
        "expected_message_type_value": 5,
        "expected_yiaddr": assigned_ipv4,
        "expected_server_identifier": server_identifier,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_dns_ipv4": dns_server_ipv4,
        "expected_lease_time": lease_time,
        "expected_renewal_time": renewal_time,
        "expected_rebinding_time": rebinding_time,
        "target_service": {
            "required": True,
            "kind": "dhcp-responder",
            "port": destination_port,
            "client_port": source_port,
            "client_mac": client_mac,
            "transaction_id": transaction_id,
            "requested_ipv4": requested_ipv4,
            "server_identifier": server_identifier,
            "yiaddr": assigned_ipv4,
            "subnet_mask": subnet_mask,
            "router_ipv4": router_ipv4,
            "dns_ipv4": dns_server_ipv4,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
        },
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "ack",
            "message_type_value": 5,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "yiaddr": assigned_ipv4,
            "server_identifier": server_identifier,
            "subnet_mask": subnet_mask,
            "router_ipv4": router_ipv4,
            "dns_ipv4": dns_server_ipv4,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
            "direction": "server_to_client",
        },
    }


def _dhcp_renewal_unicast_ack_probe_plan(
    *,
    case_name: str = "dhcp-renewal-unicast-ack",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dhcp-renewal-unicast-ack`` behavioral case.

    The stimulus is a RENEWING-state BOOTP/DHCP Request (message type 3) built
    by libcrafter and *unicast* directly to the leasing server. RFC 2131 section
    4.3.6 (table 4) and section 4.4.5 say that a client in the RENEWING state
    sends its DHCPREQUEST as a unicast to the server that leased its address: it
    fills ``ciaddr`` with the address it is already bound to, leaves the
    broadcast flag clear, and omits both the server-identifier option (54) and
    the requested-IP option (50), because the request is addressed to the one
    server directly rather than broadcast to all servers. This is the key
    difference from the SELECTING-state ``dhcp-request-ack`` Request, which
    broadcasts and names the chosen server and requested address in options.

    The controlled responder answers with a *unicast* Ack (message type 5) that
    renews the binding: the bound address in ``yiaddr`` (equal to the client's
    ``ciaddr``), the server identifier (option 54), and the configuration/lease
    options (subnet 1, router 3, DNS 6, lease 51, renewal 58, rebinding 59).

    The validation contract covers the decoded UDP/BOOTP/DHCP response: the
    BOOTP opcode (reply), message type Ack, the echoed transaction id and client
    hardware address, the renewed address (yiaddr) matching the bound address,
    the server identifier, the subnet/router/DNS and lease timing options, and
    the response direction (server -> client over ports 67 -> 68). Addresses
    stay in documentation space: the bound/renewed address is in
    ``198.51.100.0/24`` and the lab transport uses the private endpoint pair,
    where the destination is the *unicast* server address (never the broadcast
    ``255.255.255.255``).
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    client_mac = dhcp_client_mac(profile, seed, sequence)
    transaction_id = int.from_bytes(digest[0:4], "big") or 1
    # DHCP uses fixed privileged ports: client 68 -> server 67.
    source_port = 68
    destination_port = 67
    # The client is already bound to this address; it carries it in ``ciaddr``
    # and the server renews the same address in the Ack ``yiaddr``.
    bound_ipv4 = f"198.51.100.{1 + digest[4] % 250}"
    assigned_ipv4 = bound_ipv4
    subnet_mask = "255.255.255.0"
    server_identifier = target_ipv4
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    dns_server_ipv4 = f"198.51.100.{1 + digest[6] % 250}"
    lease_time = 3600 + 60 * (digest[5] % 60)
    renewal_time = lease_time // 2
    rebinding_time = (lease_time * 7) // 8
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcp_request",
        "expected_response": "dhcp_ack",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "transaction_id": transaction_id,
        # RENEWING state: the bound address is carried in ciaddr; no broadcast
        # flag, no requested-IP (50) or server-identifier (54) options. The
        # parameter request list (option 55) asks the server to return the
        # subnet (1), router (3), DNS (6), lease (51), renewal T1 (58), and
        # rebinding T2 (59) options the unicast Ack confirms.
        "client_ciaddr": bound_ipv4,
        "renewal_state": "renewing",
        "renewal_unicast": True,
        "broadcast": False,
        "parameter_request_list": [1, 3, 6, 51, 58, 59],
        "expected_message_type": "ack",
        "expected_message_type_value": 5,
        "expected_yiaddr": assigned_ipv4,
        "expected_server_identifier": server_identifier,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_dns_ipv4": dns_server_ipv4,
        "expected_lease_time": lease_time,
        "expected_renewal_time": renewal_time,
        "expected_rebinding_time": rebinding_time,
        "target_service": {
            "required": True,
            "kind": "dhcp-responder",
            "port": destination_port,
            "client_port": source_port,
            "client_mac": client_mac,
            "transaction_id": transaction_id,
            "client_ciaddr": bound_ipv4,
            "renewal_state": "renewing",
            "renewal_unicast": True,
            "yiaddr": assigned_ipv4,
            "server_identifier": server_identifier,
            "subnet_mask": subnet_mask,
            "router_ipv4": router_ipv4,
            "dns_ipv4": dns_server_ipv4,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
        },
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "ack",
            "message_type_value": 5,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "client_ciaddr": bound_ipv4,
            "renewal_unicast": True,
            "yiaddr": assigned_ipv4,
            "server_identifier": server_identifier,
            "subnet_mask": subnet_mask,
            "router_ipv4": router_ipv4,
            "dns_ipv4": dns_server_ipv4,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
            "direction": "server_to_client",
        },
    }


def _dhcp_inform_ack_probe_plan(
    *,
    case_name: str = "dhcp-inform-ack",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dhcp-inform-ack`` behavioral case.

    The stimulus is a BOOTP/DHCP Inform (message type 8) built by libcrafter and
    sent from the DHCP client port (68) to the server port (67) against a
    controlled DHCP responder on a private L2 lab segment. RFC 2131 section 3.4
    and section 4.4.3 say that a client that already has an externally configured
    IP address uses a DHCPINFORM to ask only for local configuration parameters:
    it fills ``ciaddr`` with the address it is already using and names the wanted
    options in the parameter request list (option 55), but it does NOT request a
    lease, so it omits the requested-IP option (50). Because no lease is being
    granted, the request list names only configuration options (subnet 1, router
    3, DNS 6) and not the lease timing options (51/58/59).

    The controlled responder answers with an Ack (message type 5) that carries
    the requested configuration options (subnet mask 1, router 3, DNS 6) and the
    server identifier (option 54). Critically, RFC 2131 section 4.3.5 says the
    server MUST NOT allocate a new address in response to a DHCPINFORM: ``yiaddr``
    MUST be 0.0.0.0 and the Ack MUST NOT carry an IP-address-lease-time option
    (51). The validation contract therefore asserts the decoded message type Ack,
    the echoed transaction id and client hardware address, the configuration
    options and their values, the server identifier, the client's ``ciaddr``,
    and the two negative invariants that distinguish an Inform Ack from a lease
    Ack: ``yiaddr`` is zero (no allocation) and there is no lease-time option.

    Addresses stay in documentation space: the client's already-configured
    address (``ciaddr``) is in ``198.51.100.0/24`` and the lab transport uses the
    private endpoint pair.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    client_mac = dhcp_client_mac(profile, seed, sequence)
    transaction_id = int.from_bytes(digest[0:4], "big") or 1
    # DHCP uses fixed privileged ports: client 68 -> server 67.
    source_port = 68
    destination_port = 67
    # The client already holds this address (configured externally) and carries
    # it in ``ciaddr``; the Inform asks only for configuration parameters.
    configured_ipv4 = f"198.51.100.{1 + digest[4] % 250}"
    subnet_mask = "255.255.255.0"
    server_identifier = target_ipv4
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    dns_server_ipv4 = f"198.51.100.{1 + digest[6] % 250}"
    # Configuration-only parameter request list: subnet mask (1), router (3), and
    # DNS server (6). An Inform does not request a lease, so the list omits the
    # lease timing options (51/58/59).
    parameter_request_list = [1, 3, 6]
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcp_inform",
        "expected_response": "dhcp_ack",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "transaction_id": transaction_id,
        # INFORM: the externally-configured address is carried in ciaddr; the
        # parameter request list (option 55) names the configuration options the
        # Ack must return. No requested-IP (50) option, because no lease is asked.
        "client_ciaddr": configured_ipv4,
        "parameter_request_list": parameter_request_list,
        "expected_message_type": "ack",
        "expected_message_type_value": 5,
        # RFC 2131 section 4.3.5: an Inform Ack allocates no address. yiaddr is
        # 0.0.0.0 and there is no lease-time (51) option.
        "expected_yiaddr_zero": True,
        "expected_no_lease_time": True,
        "expected_server_identifier": server_identifier,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_dns_ipv4": dns_server_ipv4,
        "target_service": {
            "required": True,
            "kind": "dhcp-responder",
            "port": destination_port,
            "client_port": source_port,
            "client_mac": client_mac,
            "transaction_id": transaction_id,
            "client_ciaddr": configured_ipv4,
            "parameter_request_list": parameter_request_list,
            "inform": True,
            "yiaddr_zero": True,
            "no_lease_time": True,
            "server_identifier": server_identifier,
            "subnet_mask": subnet_mask,
            "router_ipv4": router_ipv4,
            "dns_ipv4": dns_server_ipv4,
        },
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "ack",
            "message_type_value": 5,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "client_ciaddr": configured_ipv4,
            # The Inform Ack allocates no address and grants no lease.
            "yiaddr_zero": True,
            "no_lease_time": True,
            "server_identifier": server_identifier,
            "subnet_mask": subnet_mask,
            "router_ipv4": router_ipv4,
            "dns_ipv4": dns_server_ipv4,
            "requested_parameters": parameter_request_list,
            "direction": "server_to_client",
        },
    }


def _dhcp_request_nak_probe_plan(
    *,
    case_name: str = "dhcp-request-nak",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dhcp-request-nak`` behavioral case.

    The stimulus is a BOOTP/DHCP Request (message type 3) built by libcrafter and
    sent from the DHCP client port (68) to the server port (67) against a
    controlled DHCP responder on a private L2 lab segment. Unlike the
    ``dhcp-request-ack`` Request, the requested-IP option (50) names an address
    *outside* the responder's controlled lease pool: the responder's pool lives in
    ``198.51.100.0/24`` (the address it would otherwise commit), while the
    requested address is placed in a different documentation subnet
    (``192.0.2.0/24``) that the server does not serve. RFC 2131 section 4.3.2 says
    that when the address the client asks for is invalid or unacceptable the server
    refuses the binding with a DHCPNAK (message type 6). The Request still names
    the chosen server in the server-identifier option (54) and echoes the
    transaction id (xid) and client hardware address (chaddr).

    The controlled responder answers with a Nak (message type 6). RFC 2131 section
    4.3.2 and table 3 say a DHCPNAK is a BOOTREPLY that refuses the request: it
    carries no allocation (``yiaddr`` is 0.0.0.0), grants no lease (no
    IP-address-lease-time option 51), names the responding server in the
    server-identifier option (54), and MAY include a text message option (56)
    explaining the refusal (RFC 2132 section 9.9).

    The validation contract covers the decoded UDP/BOOTP/DHCP response: the BOOTP
    opcode (reply), message type Nak, the echoed transaction id and client hardware
    address, the server identifier, the optional message text, the response
    direction (server -> client over ports 67 -> 68), and the two negative
    invariants that distinguish a Nak from a lease Ack: ``yiaddr`` is zero (no
    allocation) and there is no lease-time option. Addresses stay in documentation
    space: the rejected requested address is in ``192.0.2.0/24`` and the lab
    transport uses the private endpoint pair.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    client_mac = dhcp_client_mac(profile, seed, sequence)
    transaction_id = int.from_bytes(digest[0:4], "big") or 1
    # DHCP uses fixed privileged ports: client 68 -> server 67.
    source_port = 68
    destination_port = 67
    # The client asks for an address the responder cannot grant: the responder
    # serves the 198.51.100.0/24 pool, so a requested address in a *different*
    # documentation subnet (192.0.2.0/24) is invalid for this server and triggers a
    # DHCPNAK (RFC 2131 section 4.3.2).
    requested_ipv4 = f"192.0.2.{1 + digest[4] % 250}"
    server_identifier = target_ipv4
    # RFC 2132 section 9.9: the optional DHCP message option (56) the responder
    # returns to explain the refusal.
    message_text = (
        f"requested address {requested_ipv4} is not on this network "
        f"({profile}:{seed}:{sequence})"
    )
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcp_request",
        "expected_response": "dhcp_nak",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "transaction_id": transaction_id,
        # The SELECTING/INIT-REBOOT-style Request names the address it wants in
        # option 50 (invalid for this server) and the chosen server in option 54.
        "requested_ipv4": requested_ipv4,
        "server_identifier": server_identifier,
        "expected_message_type": "nak",
        "expected_message_type_value": 6,
        # RFC 2131 section 4.3.2: a DHCPNAK allocates no address (yiaddr 0.0.0.0)
        # and grants no lease (no option 51).
        "expected_yiaddr_zero": True,
        "expected_no_lease_time": True,
        "expected_server_identifier": server_identifier,
        "expected_message": message_text,
        "target_service": {
            "required": True,
            "kind": "dhcp-responder",
            "port": destination_port,
            "client_port": source_port,
            "client_mac": client_mac,
            "transaction_id": transaction_id,
            "requested_ipv4": requested_ipv4,
            "server_identifier": server_identifier,
            # The requested address is outside the served pool, so the responder
            # refuses with a Nak rather than committing a binding.
            "nak": True,
            "yiaddr_zero": True,
            "no_lease_time": True,
            "message": message_text,
        },
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "nak",
            "message_type_value": 6,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            # The Nak allocates no address and grants no lease.
            "yiaddr_zero": True,
            "no_lease_time": True,
            "server_identifier": server_identifier,
            "message": message_text,
            "direction": "server_to_client",
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


UDP_ECHO_LARGE_IPV4_HEADER_LENGTH = 20
UDP_ECHO_LARGE_UDP_HEADER_LENGTH = 8
UDP_ECHO_LARGE_IPV4_PACKET_SAFETY_LIMIT = 1400
UDP_ECHO_LARGE_MAX_PAYLOAD_LENGTH = (
    UDP_ECHO_LARGE_IPV4_PACKET_SAFETY_LIMIT
    - UDP_ECHO_LARGE_IPV4_HEADER_LENGTH
    - UDP_ECHO_LARGE_UDP_HEADER_LENGTH
)
UDP_LENGTH_BOUNDARY_PAYLOAD_MARGIN = 1
UDP_LENGTH_BOUNDARY_PAYLOAD_LENGTH = (
    UDP_ECHO_LARGE_MAX_PAYLOAD_LENGTH - UDP_LENGTH_BOUNDARY_PAYLOAD_MARGIN
)


def _deterministic_udp_payload(
    *,
    label: str,
    profile: str,
    seed: int,
    sequence: int,
    length: int,
) -> bytes:
    payload = bytearray()
    counter = 0
    while len(payload) < length:
        payload.extend(
            deterministic_bytes(
                f"{label}:{counter}",
                profile,
                seed,
                sequence,
            )
        )
        counter += 1
    return bytes(payload[:length])


def _udp_echo_probe_plan(
    *,
    case_name: str,
    profile: str,
    seed: int,
    sequence: int,
    payload: bytes,
    payload_metadata: JSONObject | None = None,
    source_port: int | None = None,
) -> JSONObject:
    """Plan a UDP datagram echoed by a controlled UDP responder."""

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    planned_source_port = source_port
    if planned_source_port is None:
        planned_source_port = 46000 + int.from_bytes(digest[0:2], "big") % 8000
    destination_port = 30000 + int.from_bytes(digest[2:4], "big") % 8000
    payload_hex = payload.hex()
    payload_length = len(payload)
    expected_udp_length = 8 + payload_length
    checksum_statuses = ["valid", "ipv4_no_checksum"]
    extra_payload_metadata = dict(payload_metadata or {})
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "udp_datagram",
        "expected_response": "udp_response",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": planned_source_port,
        "destination_port": destination_port,
        "payload_hex": payload_hex,
        "payload_length": payload_length,
        "expected_payload_hex": payload_hex,
        "expected_payload_length": payload_length,
        "expected_udp_length": expected_udp_length,
        "expected_udp_checksum_present": True,
        "expected_udp_checksum_statuses": checksum_statuses,
        **extra_payload_metadata,
        "target_service": {
            "required": True,
            "kind": "udp-responder",
            "mode": "echo",
            "port": destination_port,
            "bind_ipv4": target_ipv4,
            "source_ipv4": stimulus_ipv4,
            "payload_hex": payload_hex,
            "payload_length": payload_length,
            **extra_payload_metadata,
            "deterministic": True,
        },
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {planned_source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": planned_source_port,
            "payload_hex": payload_hex,
            "payload_length": payload_length,
            "udp_length": expected_udp_length,
            "checksum_present": True,
            "checksum_statuses": checksum_statuses,
            **extra_payload_metadata,
        },
        "wire_requirements": {
            "requires_udp_service": True,
            "requires_ipv4_unicast": True,
            "requires_controlled_service": True,
            "note": (
                "UDP echo behavior runs against a controlled responder on the "
                "target endpoint, never a public service."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _udp_echo_empty_probe_plan(
    *,
    case_name: str = "udp-echo-empty",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan an empty UDP datagram echoed by a controlled UDP responder."""

    return _udp_echo_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
        payload=b"",
    )


def _udp_echo_short_probe_plan(
    *,
    case_name: str = "udp-echo-short",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a short ASCII UDP payload echoed by a controlled UDP responder."""

    digest = deterministic_bytes("udp-echo-short-payload", profile, seed, sequence)
    payload = f"udp-echo:{digest.hex()[:8]}".encode("ascii")
    return _udp_echo_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
        payload=payload,
    )


def _udp_echo_binary_probe_plan(
    *,
    case_name: str = "udp-echo-binary",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a binary UDP payload echoed by a controlled UDP responder."""

    digest = deterministic_bytes("udp-echo-binary-payload", profile, seed, sequence)
    payload = bytes(
        [
            0x00,
            digest[0],
            0x7F,
            0x80,
            digest[1],
            0xFF,
            digest[2],
            0x00,
            digest[3],
            0xC3,
            digest[4],
            0xFE,
        ]
    )
    return _udp_echo_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
        payload=payload,
    )


def _udp_echo_large_probe_plan(
    *,
    case_name: str = "udp-echo-large",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a large UDP payload that stays below the private-network MTU limit."""

    if UDP_ECHO_LARGE_PAYLOAD_LENGTH > UDP_ECHO_LARGE_MAX_PAYLOAD_LENGTH:
        raise ValueError("large UDP echo payload exceeds the MTU safety limit")
    payload = _deterministic_udp_payload(
        label="udp-echo-large-payload",
        profile=profile,
        seed=seed,
        sequence=sequence,
        length=UDP_ECHO_LARGE_PAYLOAD_LENGTH,
    )
    payload_metadata: JSONObject = {
        "payload_size_policy": "large_non_fragmenting",
        "payload_mtu_safety_limit": UDP_ECHO_LARGE_IPV4_PACKET_SAFETY_LIMIT,
        "payload_mtu_header_overhead": (
            UDP_ECHO_LARGE_IPV4_HEADER_LENGTH + UDP_ECHO_LARGE_UDP_HEADER_LENGTH
        ),
        "max_non_fragmenting_payload_length": UDP_ECHO_LARGE_MAX_PAYLOAD_LENGTH,
    }
    return _udp_echo_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
        payload=payload,
        payload_metadata=payload_metadata,
    )


def _udp_length_boundary_echo_probe_plan(
    *,
    case_name: str = "udp-length-boundary-echo",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a UDP echo payload one byte below the IPv4 packet safety limit."""

    if UDP_LENGTH_BOUNDARY_PAYLOAD_LENGTH >= UDP_ECHO_LARGE_MAX_PAYLOAD_LENGTH:
        raise ValueError("boundary UDP echo payload must stay below the safety limit")
    payload = _deterministic_udp_payload(
        label="udp-length-boundary-echo-payload",
        profile=profile,
        seed=seed,
        sequence=sequence,
        length=UDP_LENGTH_BOUNDARY_PAYLOAD_LENGTH,
    )
    expected_ipv4_total_length = (
        UDP_ECHO_LARGE_IPV4_HEADER_LENGTH
        + UDP_ECHO_LARGE_UDP_HEADER_LENGTH
        + UDP_LENGTH_BOUNDARY_PAYLOAD_LENGTH
    )
    payload_metadata: JSONObject = {
        "payload_size_policy": "near_boundary_non_fragmenting",
        "payload_boundary_margin": UDP_LENGTH_BOUNDARY_PAYLOAD_MARGIN,
        "payload_mtu_safety_limit": UDP_ECHO_LARGE_IPV4_PACKET_SAFETY_LIMIT,
        "payload_mtu_header_overhead": (
            UDP_ECHO_LARGE_IPV4_HEADER_LENGTH + UDP_ECHO_LARGE_UDP_HEADER_LENGTH
        ),
        "max_non_fragmenting_payload_length": UDP_ECHO_LARGE_MAX_PAYLOAD_LENGTH,
        "expected_ipv4_total_length": expected_ipv4_total_length,
    }
    plan = _udp_echo_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
        payload=payload,
        payload_metadata=payload_metadata,
    )
    wire_requirements = json_object(
        plan["wire_requirements"],
        "udp_length_boundary.wire_requirements",
    )
    wire_requirements.update(
        {
            "requires_udp_large_payload": True,
            "note": (
                "UDP length-boundary behavior sends one datagram just below "
                "the configured IPv4 no-fragment safety limit through a "
                "controlled echo responder."
            ),
        }
    )
    plan["wire_requirements"] = wire_requirements
    return plan


def _udp_source_port_reflection_probe_plan(
    *,
    case_name: str = "udp-source-port-reflection",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a UDP echo response that must target the stimulus source port."""

    payload_digest = deterministic_bytes(
        "udp-source-port-reflection-payload",
        profile,
        seed,
        sequence,
    )
    port_digest = deterministic_bytes(
        "udp-source-port-reflection-source-port",
        profile,
        seed,
        sequence,
    )
    payload = f"udp-source-port:{payload_digest.hex()[:8]}".encode("ascii")
    source_port = 60000 + int.from_bytes(port_digest[0:2], "big") % 4000
    payload_metadata: JSONObject = {
        "source_port_policy": "deterministic_high",
        "source_port_reflection": True,
    }
    return _udp_echo_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
        payload=payload,
        payload_metadata=payload_metadata,
        source_port=source_port,
    )


def _udp_multi_shot_order_send(
    *,
    index: int,
    source_ipv4: str,
    target_ipv4: str,
    source_port: int,
    destination_port: int,
    payload: bytes,
    sequence_marker: str,
    checksum_statuses: list[str],
) -> JSONObject:
    payload_hex = payload.hex()
    payload_length = len(payload)
    expected_udp_length = 8 + payload_length
    return {
        "index": index,
        "sequence_marker": sequence_marker,
        "source_ipv4": source_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": source_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "payload_hex": payload_hex,
        "payload_length": payload_length,
        "expected_payload_hex": payload_hex,
        "expected_payload_length": payload_length,
        "expected_udp_length": expected_udp_length,
        "expected_udp_checksum_present": True,
        "expected_udp_checksum_statuses": checksum_statuses,
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {source_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": source_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "sequence_marker": sequence_marker,
            "payload_hex": payload_hex,
            "payload_length": payload_length,
            "udp_length": expected_udp_length,
            "checksum_present": True,
            "checksum_statuses": checksum_statuses,
        },
    }


def _udp_multi_shot_order_probe_plan(
    *,
    case_name: str = "udp-multi-shot-order",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan three ordered UDP datagrams echoed by one controlled responder."""

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 50000 + int.from_bytes(digest[0:2], "big") % 6000
    destination_port = 32000 + int.from_bytes(digest[2:4], "big") % 6000
    checksum_statuses = ["valid", "ipv4_no_checksum"]
    sends = []
    for index in range(3):
        payload_digest = deterministic_bytes(
            f"{case_name}:payload:{index}",
            profile,
            seed,
            sequence,
        )
        sequence_marker = f"shot-{index:02d}"
        payload = (
            f"udp-multi-shot-order:{sequence_marker}:{payload_digest.hex()[:12]}"
        ).encode("ascii")
        sends.append(
            _udp_multi_shot_order_send(
                index=index,
                source_ipv4=stimulus_ipv4,
                target_ipv4=target_ipv4,
                source_port=source_port,
                destination_port=destination_port,
                payload=payload,
                sequence_marker=sequence_marker,
                checksum_statuses=checksum_statuses,
            )
        )

    first = sends[0]
    sequence_markers = [str(send["sequence_marker"]) for send in sends]
    ordered_payloads = [
        {
            "index": send["index"],
            "sequence_marker": send["sequence_marker"],
            "payload_hex": send["payload_hex"],
            "payload_length": send["payload_length"],
        }
        for send in sends
    ]
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "udp_datagram",
        "expected_response": "udp_response",
        # Conventional single-send top-level fields mirror the first datagram so
        # the generic plan echo, capture filter, and single-send consumers keep
        # working while the UDP dispatch detects `udp_sends` and drives all sends.
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "sequence_marker": first["sequence_marker"],
        "sequence_markers": sequence_markers,
        "payload_hex": first["payload_hex"],
        "payload_length": first["payload_length"],
        "expected_payload_hex": first["expected_payload_hex"],
        "expected_payload_length": first["expected_payload_length"],
        "expected_udp_length": first["expected_udp_length"],
        "expected_udp_checksum_present": True,
        "expected_udp_checksum_statuses": checksum_statuses,
        "multi_shot_order": True,
        "send_count": len(sends),
        "udp_sends": sends,
        "target_service": {
            "required": True,
            "kind": "udp-responder",
            "mode": "echo",
            "port": destination_port,
            "bind_ipv4": target_ipv4,
            "source_ipv4": stimulus_ipv4,
            "multi_shot_order": True,
            "send_count": len(sends),
            "sequence_markers": sequence_markers,
            "ordered_payloads": ordered_payloads,
            "deterministic": True,
        },
        "capture_filter": first["capture_filter"],
        "validation": first["validation"],
        "wire_requirements": {
            "requires_udp_service": True,
            "requires_ipv4_unicast": True,
            "requires_controlled_service": True,
            "note": (
                "UDP multi-shot order behavior runs against a controlled echo "
                "responder on the target endpoint, never a public service."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _udp_closed_port_icmp_probe_plan(
    *,
    case_name: str = "udp-closed-port-icmp",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a UDP datagram whose closed target port triggers ICMP port-unreachable."""

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 47000 + int.from_bytes(digest[0:2], "big") % 7000
    destination_port = 38000 + int.from_bytes(digest[2:4], "big") % 7000
    payload = (
        f"udp-closed-port-icmp:{profile}:{seed}:{sequence}:"
        f"{digest.hex()[:16]}"
    ).encode("ascii")
    payload_hex = payload.hex()
    payload_length = len(payload)
    embedded_prefix_length = 28
    expected_udp_length = 8 + payload_length
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "udp_datagram",
        "expected_response": "icmp_port_unreachable",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "payload_hex": payload_hex,
        "payload_length": payload_length,
        "expected_payload_hex": payload_hex,
        "expected_payload_length": payload_length,
        "expected_udp_length": expected_udp_length,
        "expected_icmp_type": 3,
        "expected_icmp_code": 3,
        "expected_embedded_prefix_length": embedded_prefix_length,
        "target_service": {
            "required": False,
            "kind": "closed-udp-port",
            "port": destination_port,
            "bind_ipv4": target_ipv4,
            "source_ipv4": stimulus_ipv4,
            "state": "planned-unbound",
            "expects": "icmp_port_unreachable",
            "deterministic": True,
        },
        "capture_filter": (
            f"icmp and src host {target_ipv4} and dst host {stimulus_ipv4}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "icmp_type": 3,
            "icmp_code": 3,
            "embedded_prefix": {
                "source": "stimulus_sent_bytes",
                "length": embedded_prefix_length,
                "meaning": "original IPv4 header plus first eight bytes of UDP datagram",
            },
            "embedded_udp": {
                "source_port": source_port,
                "destination_port": destination_port,
                "udp_length": expected_udp_length,
            },
        },
        "wire_requirements": {
            "requires_ipv4_unicast": True,
            "requires_closed_udp_port": True,
            "requires_no_udp_service": True,
            "note": (
                "UDP closed-port behavior is target kernel ICMP generation. "
                "Target setup verifies the UDP port is unbound and starts no "
                "responder."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _udp_zero_checksum_ipv4_probe_plan(
    *,
    case_name: str = "udp-zero-checksum-ipv4",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan an IPv4 UDP datagram with an explicit zero checksum override."""

    digest = deterministic_bytes("udp-zero-checksum-ipv4-payload", profile, seed, sequence)
    payload = f"udp-zero-checksum-ipv4:{digest.hex()[:12]}".encode("ascii")
    plan = _udp_echo_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
        payload=payload,
    )
    checksum_metadata: JSONObject = {
        "stimulus_udp_checksum": 0,
        "stimulus_udp_checksum_override": True,
        "stimulus_udp_checksum_policy": "ipv4_zero_checksum_override",
    }
    plan.update(checksum_metadata)
    target_service = json_object(plan["target_service"], "udp_zero_checksum.target_service")
    target_service.update(
        {
            **checksum_metadata,
            "kernel_acceptance": "provider_dependent",
        }
    )
    plan["target_service"] = target_service
    validation = json_object(plan["validation"], "udp_zero_checksum.validation")
    validation.update(checksum_metadata)
    plan["validation"] = validation
    wire_requirements = json_object(
        plan["wire_requirements"],
        "udp_zero_checksum.wire_requirements",
    )
    wire_requirements.update(
        {
            "requires_udp_ipv4_zero_checksum": True,
            "note": (
                "IPv4 permits UDP checksum zero. The stimulus intentionally "
                "sets checksum 0; providers that drop such datagrams must "
                "skip via the udp_ipv4_zero_checksum capability."
            ),
        }
    )
    plan["wire_requirements"] = wire_requirements
    return plan


def _udp_options_surplus_echo_probe_plan(
    *,
    case_name: str = "udp-options-surplus-echo",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a UDP echo stimulus with deterministic UDP surplus option bytes."""

    payload_digest = deterministic_bytes(
        "udp-options-surplus-echo-payload",
        profile,
        seed,
        sequence,
    )
    option_digest = deterministic_bytes(
        "udp-options-surplus-echo-options",
        profile,
        seed,
        sequence,
    )
    payload = f"udp-options-surplus-echo:{payload_digest.hex()[:12]}".encode("ascii")
    mds_size = 1200 + option_digest[4] % 48
    req_token = int.from_bytes(option_digest[0:4], "big")
    req_token_bytes = req_token.to_bytes(4, "big")
    # Option bytes after the UDP Option Checksum field. UdpOptions::from_bytes
    # preserves this exact option stream while compile() adds the RFC surplus
    # alignment and OCS envelope.
    option_bytes = bytes(
        [
            0x01,  # NOP
            0x04,  # MDS
            0x04,
            *mds_size.to_bytes(2, "big"),
            0x06,  # REQ
            0x06,
            *req_token_bytes,
            0x00,  # EOL
        ]
    )
    option_summary = [
        "NOP",
        f"MDS(size={mds_size})",
        f"REQ(token=0x{req_token:08x})",
        "EOL",
    ]
    plan = _udp_echo_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
        payload=payload,
    )
    expected_udp_length = int(plan["expected_udp_length"])
    surplus_alignment_length = (UDP_ECHO_LARGE_IPV4_HEADER_LENGTH + expected_udp_length) & 1
    expected_surplus_length = surplus_alignment_length + 2 + len(option_bytes)
    surplus_metadata: JSONObject = {
        "udp_options_surplus": True,
        "stimulus_udp_options_hex": option_bytes.hex(),
        "stimulus_udp_options_policy": "deterministic_valid_surplus_options",
        "expected_udp_options_hex": option_bytes.hex(),
        "expected_udp_options_status": "valid",
        "expected_udp_options_summary": option_summary,
        "expected_udp_option_count": len(option_summary),
        "expected_udp_surplus_alignment_length": surplus_alignment_length,
        "expected_udp_surplus_length": expected_surplus_length,
        "expected_ipv4_total_length": (
            UDP_ECHO_LARGE_IPV4_HEADER_LENGTH
            + expected_udp_length
            + expected_surplus_length
        ),
    }
    plan.update(surplus_metadata)
    target_service = json_object(
        plan["target_service"],
        "udp_options_surplus.target_service",
    )
    target_service.update(
        {
            **surplus_metadata,
            "kernel_acceptance": "provider_dependent",
        }
    )
    plan["target_service"] = target_service
    validation = json_object(plan["validation"], "udp_options_surplus.validation")
    validation.update(surplus_metadata)
    plan["validation"] = validation
    wire_requirements = json_object(
        plan["wire_requirements"],
        "udp_options_surplus.wire_requirements",
    )
    wire_requirements.update(
        {
            "requires_udp_options_surplus": True,
            "note": (
                "UDP options are carried as surplus after the UDP payload length. "
                "Providers that drop such datagrams must skip via the "
                "udp_options_surplus capability."
            ),
        }
    )
    plan["wire_requirements"] = wire_requirements
    return plan


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
    "dhcp-discover-offer": _dhcp_discover_offer_probe_plan,
    "dhcp-request-ack": _dhcp_request_ack_probe_plan,
    "dhcp-client-identifier": _dhcp_client_identifier_probe_plan,
    "dhcp-hostname": _dhcp_hostname_probe_plan,
    "dhcp-parameter-request-list": _dhcp_parameter_request_list_probe_plan,
    "dhcp-lease-time": _dhcp_lease_time_probe_plan,
    "dhcp-renewal-unicast-ack": _dhcp_renewal_unicast_ack_probe_plan,
    "dhcp-inform-ack": _dhcp_inform_ack_probe_plan,
    "dhcp-request-nak": _dhcp_request_nak_probe_plan,
    "dhcp-rapid-repeat": _dhcp_rapid_repeat_probe_plan,
    "ttl-expired": _ttl_expired_probe_plan,
    # ARP plan builders now live in ``protocols/arp.py`` and reach
    # ``PLAN_BUILDERS`` through the registry merge below (re-imported into this
    # module above for identity/back-compat).
    "ndp-neighbor-solicitation": _ndp_neighbor_solicitation_probe_plan,
    "ndp-router-solicitation": _ndp_router_solicitation_probe_plan,
    "ndp-duplicate-address-detection": _ndp_duplicate_address_detection_probe_plan,
    "udp-echo-empty": _udp_echo_empty_probe_plan,
    "udp-echo-short": _udp_echo_short_probe_plan,
    "udp-echo-binary": _udp_echo_binary_probe_plan,
    "udp-echo-large": _udp_echo_large_probe_plan,
    "udp-length-boundary-echo": _udp_length_boundary_echo_probe_plan,
    "udp-source-port-reflection": _udp_source_port_reflection_probe_plan,
    "udp-multi-shot-order": _udp_multi_shot_order_probe_plan,
    "udp-closed-port-icmp": _udp_closed_port_icmp_probe_plan,
    "udp-zero-checksum-ipv4": _udp_zero_checksum_ipv4_probe_plan,
    "udp-options-surplus-echo": _udp_options_surplus_echo_probe_plan,
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
