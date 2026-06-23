"""DHCP probe protocol plugin: cases, plan builders, and planning surface.

This is the DHCP *planning half* migration (after the ARP vertical slice and the
DNS migration). It bundles DHCP's planning surface in one place:

* the ten DHCP behavioral cases plus the DHCP capability constant (the catalog
  contribution),
* the ``_dhcp_*_probe_plan`` plan builders, the multi-send
  ``_dhcp_rapid_repeat_send`` helper, and the DHCP-only deterministic client
  identity / option helpers (the plan-builder contribution),
* and the DHCP stimulus-endpoint routing set.

The plan builders and the deterministic helpers are moved verbatim from
:mod:`tools.probe.engine.planning`; :mod:`planning` re-imports the builders, the
multi-send helper, and the ``dhcp_*`` identity/option helpers so
``planning._<builder>`` / ``planning.PLAN_BUILDERS[name]`` (the DHCP behavior
tests' ``assertIs`` pins) keep identical object identity. DHCP carries no
``planned_only`` cases, and its ``profile_counts`` is intentionally empty: the
ten DHCP behavioral cases sit between DNS and ARP in the ``behavior`` profile in
a fixed, order-sensitive position, and the registry-first profile merge would
move the registry contribution to the front of that profile, so the legacy
ordered profile name tables in :mod:`tools.probe.engine.cases` keep owning
DHCP's profile membership to preserve byte-identical selection order.

The DHCP target-service / address-rewrite / failure-reason / lab-capability
hooks are deferred to the second half of the migration (step 22); they are
``None`` here.

Imports are relative only so the module loads under both engine import roots
(``engine.protocols.dhcp`` for the CLI and ``tools.probe.engine.protocols.dhcp``
for the tests).
"""

from __future__ import annotations

from ..case_helpers import _behavior_case
from ..model import JSONObject, ProbeCase
from ..planning_helpers import (
    deterministic_bytes,
    deterministic_ipv4_pair,
    deterministic_router_ipv4,
    dns_label,
)
from .base import ProtocolPlugin, register


# Capabilities required by each DHCP behavioral case. DHCP needs IPv4 unicast
# plus a controlled DHCP responder; the capability name matches the probe
# capability derivation in :mod:`tools.probe.engine.lab`, so the behavior-suite
# cases skip with stable reasons on providers that cannot support them.
_DHCP_CAPABILITIES = ["dhcp_service"]


# Ten DHCP behavioral cases (DHCP/BOOTP client messages against a controlled
# DHCP responder on a private L2 segment).
BEHAVIOR_DHCP_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="dhcp-discover-offer",
        description="Send a DHCP Discover and validate the Offer.",
        stimulus="dhcp_discover",
        expected_response="dhcp_offer",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-request-ack",
        description="Send a DHCP Request and validate the Ack.",
        stimulus="dhcp_request",
        expected_response="dhcp_ack",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-client-identifier",
        description=(
            "Send a Discover carrying a client identifier (option 61) and validate "
            "the matching Offer that records the client identity."
        ),
        stimulus="dhcp_discover",
        expected_response="dhcp_offer",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-hostname",
        description="Send a Discover with a hostname option and validate the Offer.",
        stimulus="dhcp_discover",
        expected_response="dhcp_offer",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-parameter-request-list",
        description=(
            "Send a Discover with a parameter request list and validate the "
            "requested options in the Offer."
        ),
        stimulus="dhcp_discover",
        expected_response="dhcp_offer",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-lease-time",
        description=(
            "Send a Discover and validate the lease time (51), renewal T1 (58), "
            "and rebinding T2 (59) timing options in the Offer."
        ),
        stimulus="dhcp_discover",
        expected_response="dhcp_offer",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-renewal-unicast-ack",
        description="Send a unicast renewal Request and validate the unicast Ack.",
        stimulus="dhcp_request",
        expected_response="dhcp_ack",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-inform-ack",
        description="Send a DHCP Inform and validate the Ack with config options.",
        stimulus="dhcp_inform",
        expected_response="dhcp_ack",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-request-nak",
        description="Request an invalid address and validate the Nak.",
        stimulus="dhcp_request",
        expected_response="dhcp_nak",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-rapid-repeat",
        description=(
            "Send repeated Discovers and validate each independently decoded Offer."
        ),
        stimulus="dhcp_discover",
        expected_response="dhcp_offer",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
)


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


# Map each DHCP case name to its plan builder. ``planning.PLAN_BUILDERS`` merges
# this (via the registry) and ``planning`` re-imports each builder so
# ``planning._<builder>`` and ``PLAN_BUILDERS[name] is _<builder>`` keep object
# identity (the DHCP behavior tests pin them via ``assertIs``).
_DHCP_PLAN_BUILDERS: dict[str, object] = {
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
}


# The ten DHCP behavioral cases route through the stimulus endpoint adapter.
_DHCP_STIMULUS_ENDPOINT_CASES: frozenset[str] = frozenset(
    {
        "dhcp-discover-offer",
        "dhcp-request-ack",
        "dhcp-client-identifier",
        "dhcp-hostname",
        "dhcp-parameter-request-list",
        "dhcp-lease-time",
        "dhcp-renewal-unicast-ack",
        "dhcp-inform-ack",
        "dhcp-request-nak",
        "dhcp-rapid-repeat",
    }
)


register(
    ProtocolPlugin(
        name="dhcp",
        # The ten DHCP behavioral cases in declaration order.
        cases=BEHAVIOR_DHCP_CASES,
        plan_builders=_DHCP_PLAN_BUILDERS,
        # DHCP carries no planned-only cases (every builder materializes a plan).
        planned_only_cases=frozenset(),
        # DHCP's profile membership stays in the legacy ordered profile tables in
        # ``cases.py`` to preserve byte-identical selection order (the registry-
        # first profile merge would otherwise move DHCP to the front of the
        # behavior profile). Contribute nothing here.
        profile_counts={},
        stimulus_endpoint_cases=_DHCP_STIMULUS_ENDPOINT_CASES,
        # DHCP target-service / address-rewrite / failure-reason / lab-capability
        # hooks are deferred to the second half of the migration (step 22); they
        # are ``None`` here, so DHCP's cases stay on the legacy target/rewrite/
        # failure/capability paths until that step.
        target_service=None,
        setup_script=None,
        rewrite_endpoint_addresses=None,
        failure_reasons=None,
        lab_capabilities=None,
    )
)
