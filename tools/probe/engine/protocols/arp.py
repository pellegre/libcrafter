"""ARP probe protocol plugin: cases, plan builders, and planning surface.

This is the first protocol migrated onto the :class:`ProtocolPlugin` contract
(the ARP vertical-slice proof). It bundles ARP's full *planning* surface in one
place:

* the ARP behavioral case tuple plus the inline ``arp-resolution`` case and the
  ARP capability constants (the catalog contribution),
* the ``_arp_*_probe_plan`` plan builders, the multi-send
  ``_arp_repeat_two_replies_send`` helper, and the ARP-only deterministic
  address helpers (the plan-builder contribution),
* and the ARP stimulus-endpoint routing set.

The plan builders and the deterministic helpers are moved verbatim from
:mod:`tools.probe.engine.planning`; :mod:`planning` re-imports the builders so
``planning._<builder>`` and ``planning.PLAN_BUILDERS[name]`` keep identical
object identity for the ARP behavior tests' ``assertIs`` pins. ARP carries no
``planned_only`` cases, and its ``profile_counts`` is intentionally empty: ARP's
membership in the ``smoke`` and ``behavior`` profiles is order-sensitive
(``arp-resolution`` is last in ``smoke``; the ARP behavioral cases sit between
DHCP and NDP in ``behavior``), and the registry-first profile merge would move
the registry contribution to the front of those profiles, so the legacy
ordered profile name tables in :mod:`tools.probe.engine.cases` keep owning ARP's
profile membership to preserve byte-identical selection order.

The ARP target-service / address-rewrite / failure-reason / lab-capability
hooks are deferred to the second half of the slice (step 18); they are ``None``
here.

Imports are relative only so the module loads under both engine import roots
(``engine.protocols.arp`` for the CLI and ``tools.probe.engine.protocols.arp``
for the tests).
"""

from __future__ import annotations

from ..case_helpers import _behavior_case
from ..model import JSONObject, ProbeCase
from ..planning_helpers import (
    deterministic_bytes,
    deterministic_documentation_mac,
    deterministic_ipv4_pair,
)
from .base import ProtocolPlugin, register


# Capabilities required by each ARP behavioral case. ARP needs a link-layer
# (Ethernet/broadcast) substrate beyond the base ARP resolution capability. The
# capability names match the probe capability derivation in
# :mod:`tools.probe.engine.lab`, so the behavior-suite cases skip with stable
# reasons on providers that cannot support them.
_ARP_CAPABILITIES = [
    "arp_resolution",
    "link_layer_send",
    "link_layer_capture",
    "broadcast",
]
# Some ARP cases need the *target MAC* (provider metadata): a unicast request is
# addressed to it rather than the broadcast address, and the MAC-validation case
# ties the decoded reply to it. Either way the case can only run once the
# target's MAC is known, so it adds ``provider_mac`` to the base ARP
# capabilities. A provider that cannot supply target-MAC metadata must skip with
# the stable ``requires_provider_mac`` reason.
_ARP_PROVIDER_MAC_CAPABILITIES = [
    *_ARP_CAPABILITIES,
    "provider_mac",
]
# Backwards-compatible alias: the unicast case introduced this list.
_ARP_UNICAST_CAPABILITIES = _ARP_PROVIDER_MAC_CAPABILITIES


# Ten ARP behavioral cases (Ethernet/ARP who-has and is-at exchanges on a
# private L2 segment with provider MAC knowledge).
BEHAVIOR_ARP_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="arp-basic-who-has",
        description="Broadcast a who-has request and validate the is-at reply.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-repeat-two-replies",
        description="Repeat a who-has request and validate two parseable replies.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-source-address-preserved",
        description=(
            "Validate that the reply is addressed to the request's sender "
            "hardware/protocol address."
        ),
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-alias-address-reply",
        description="Query a target alias address and validate the reply.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-unicast-request-reply",
        description=(
            "Send the ARP request to the known target MAC (not broadcast) and "
            "validate the reply."
        ),
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_UNICAST_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-padding-reply",
        description="Send a request with Ethernet padding and validate the reply.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-cache-flush-reply",
        description="Flush the neighbor cache, then validate a fresh who-has reply.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-mac-validation",
        description=(
            "Validate that the reply Ethernet source and ARP sender hardware "
            "address both equal the target endpoint MAC."
        ),
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        # The reply is validated against the target endpoint's MAC (provider
        # metadata), so the case requires provider_mac: MAC-less providers skip
        # with the stable requires_provider_mac reason.
        required_capabilities=_ARP_PROVIDER_MAC_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-spa-variation",
        description="Send a request from an alternate sender protocol address and validate the reply.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-broadcast-filtered-capture",
        description=(
            "Capture ARP replies on a noisy segment and validate only the "
            "matching target reply."
        ),
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
)


# The inline ``arp-resolution`` smoke case (the legacy per-protocol aggregation
# carried this directly rather than through the ``_behavior_case`` factory).
ARP_RESOLUTION_CASE: ProbeCase = ProbeCase(
    name="arp-resolution",
    description=(
        "Broadcast an ARP who-has request on the lab segment and validate the "
        "target's unicast is-at reply."
    ),
    stimulus="arp_who_has",
    expected_response="arp_is_at",
    required_capabilities=[
        "arp_resolution",
        "link_layer_send",
        "link_layer_capture",
        "broadcast",
    ],
    endpoint_roles=["stimulus", "target"],
    metadata={"protocol": "arp", "service": "kernel", "layer": "link"},
)


def _arp_resolution_probe_plan(
    *,
    case_name: str = "arp-resolution",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = deterministic_bytes("arp-resolution", profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(profile, seed, sequence, role="stimulus")
    target_mac = deterministic_documentation_mac(profile, seed, sequence, role="target")
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    zero_mac = "00:00:00:00:00:00"
    return {
        "schema_version": 1,
        "case": "arp-resolution",
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "arp_who_has",
        "expected_response": "arp_is_at",
        # ARP rides Ethernet directly; these are link-layer documentation values.
        "ethertype": 0x0806,
        "hardware_type": 1,
        "protocol_type": 0x0800,
        "hardware_length": 6,
        "protocol_length": 4,
        "operation": 1,
        "operation_label": "request",
        "sender_hardware_addr": stimulus_mac,
        "sender_protocol_addr": stimulus_ipv4,
        "target_hardware_addr": zero_mac,
        "target_protocol_addr": target_ipv4,
        "ethernet_source": stimulus_mac,
        "ethernet_destination": broadcast_mac,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        # ARP cannot be selected by host/IP BPF; match on the protocol + opcode.
        "capture_filter": "arp and arp[6:2] = 2",
        "validation": {
            "ethertype": 0x0806,
            "operation": 2,
            "operation_label": "reply",
            "sender_hardware_addr": target_mac,
            "sender_protocol_addr": target_ipv4,
            "target_hardware_addr": stimulus_mac,
            "target_protocol_addr": stimulus_ipv4,
            "ethernet_destination": stimulus_mac,
        },
        "wire_requirements": {
            "requires_link_layer_send": True,
            "requires_link_layer_capture": True,
            "requires_broadcast": True,
            "note": (
                "ARP resolution is L2 broadcast/unicast traffic; it runs only on a "
                "provider-backed lab segment, never from privileged host raw sends."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _arp_basic_who_has_probe_plan(
    *,
    case_name: str = "arp-basic-who-has",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``arp-basic-who-has`` behavioral case.

    The baseline ARP behavioral check: an Ethernet-broadcast ARP who-has request
    (operation 1) resolving the target endpoint's IPv4 address, answered by the
    target kernel with a unicast is-at reply (operation 2). ARP rides Ethernet
    directly (no IP/UDP), so the plan carries link-layer documentation values: a
    sender hardware address in the RFC 7042 documentation MAC range, a sender
    protocol address (the stimulus IPv4), the target protocol address to resolve
    (the target IPv4), the request operation, and an Ethernet frame addressed
    from the sender MAC to the broadcast address ``ff:ff:ff:ff:ff:ff``. The
    capture filter is link-layer (ARP plus the reply opcode); the target service
    is the target kernel answering ARP for its own configured address (no
    daemon), with ARP sysctls and a neighbor-cache flush as setup. The validation
    contract covers the is-at operation, the reply sender hardware/protocol
    address (the resolved target MAC/IPv4), the reply target hardware/protocol
    address (the original sender), and the Ethernet source/destination of the
    unicast reply.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(profile, seed, sequence, role="stimulus")
    target_mac = deterministic_documentation_mac(profile, seed, sequence, role="target")
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    zero_mac = "00:00:00:00:00:00"
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "arp_who_has",
        "expected_response": "arp_is_at",
        # ARP rides Ethernet directly; these are link-layer documentation values.
        "ethertype": 0x0806,
        "hardware_type": 1,
        "protocol_type": 0x0800,
        "hardware_length": 6,
        "protocol_length": 4,
        "operation": 1,
        "operation_label": "request",
        "sender_hardware_addr": stimulus_mac,
        "sender_protocol_addr": stimulus_ipv4,
        "target_hardware_addr": zero_mac,
        "target_protocol_addr": target_ipv4,
        "ethernet_source": stimulus_mac,
        "ethernet_destination": broadcast_mac,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        # ARP cannot be selected by host/IP BPF; match on the protocol + opcode.
        "capture_filter": "arp and arp[6:2] = 2",
        "target_service": {
            "required": True,
            "kind": "arp-kernel",
            "layer": "link",
            # The target kernel answers ARP who-has for its own configured
            # address; setup tunes ARP sysctls and flushes the neighbor cache.
            "target_protocol_addr": target_ipv4,
            "target_hardware_addr": target_mac,
            "arp_sysctls": True,
            "neighbor_cache_flush": True,
        },
        "validation": {
            "ethertype": 0x0806,
            "operation": 2,
            "operation_label": "reply",
            "sender_hardware_addr": target_mac,
            "sender_protocol_addr": target_ipv4,
            "target_hardware_addr": stimulus_mac,
            "target_protocol_addr": stimulus_ipv4,
            "ethernet_source": target_mac,
            "ethernet_destination": stimulus_mac,
        },
        "wire_requirements": {
            "requires_link_layer_send": True,
            "requires_link_layer_capture": True,
            "requires_broadcast": True,
            "note": (
                "ARP resolution is L2 broadcast/unicast traffic; it runs only on a "
                "provider-backed lab segment, never from privileged host raw sends."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _arp_repeat_two_replies_send(
    *,
    index: int,
    stimulus_ipv4: str,
    target_ipv4: str,
    stimulus_mac: str,
    target_mac: str,
    broadcast_mac: str,
    zero_mac: str,
) -> JSONObject:
    """Build one of the two who-has -> is-at sends for ``arp-repeat-two-replies``.

    Both sends resolve the *same* target protocol address: the case point is that
    a repeated who-has receives two parseable replies, so the sender hardware /
    protocol address and the target the kernel answers stay constant across the
    two sends. Each send carries its own broadcast who-has stimulus (operation 1)
    and its own full is-at validation contract (operation 2, the resolved target
    MAC/IPv4 as the reply sender, the original querier as the reply target, and
    the unicast Ethernet framing) so the endpoint validates each decoded reply
    independently and matches it back to its send.
    """

    return {
        "index": index,
        "ethertype": 0x0806,
        "hardware_type": 1,
        "protocol_type": 0x0800,
        "hardware_length": 6,
        "protocol_length": 4,
        "operation": 1,
        "operation_label": "request",
        "sender_hardware_addr": stimulus_mac,
        "sender_protocol_addr": stimulus_ipv4,
        "target_hardware_addr": zero_mac,
        "target_protocol_addr": target_ipv4,
        "ethernet_source": stimulus_mac,
        "ethernet_destination": broadcast_mac,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        # ARP cannot be selected by host/IP BPF; match on the protocol + opcode.
        "capture_filter": "arp and arp[6:2] = 2",
        "validation": {
            "ethertype": 0x0806,
            "operation": 2,
            "operation_label": "reply",
            "sender_hardware_addr": target_mac,
            "sender_protocol_addr": target_ipv4,
            "target_hardware_addr": stimulus_mac,
            "target_protocol_addr": stimulus_ipv4,
            "ethernet_source": target_mac,
            "ethernet_destination": stimulus_mac,
        },
    }


def _arp_repeat_two_replies_probe_plan(
    *,
    case_name: str = "arp-repeat-two-replies",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``arp-repeat-two-replies`` behavioral case.

    Two Ethernet-broadcast ARP who-has requests (operation 1) for the *same*
    target endpoint IPv4, answered by the target kernel with two unicast is-at
    replies (operation 2). Unlike the single-send ``arp-basic-who-has`` case, the
    plan carries an ``arp_sends`` array (one entry per who-has -> is-at send) so
    the endpoint sends the who-has twice, captures two replies, decodes each
    independently, and validates two is-at contracts. Repeated who-has exercises
    capture matching and is-at parsing more than once for the same target; ARP
    relies primarily on the target kernel answering for its own configured
    address, so a neighbor-cache flush between sends keeps the kernel re-answering
    rather than the client caching the first reply.

    ARP rides Ethernet directly (no IP/UDP), so the plan carries link-layer
    documentation values: a sender hardware address in the RFC 7042 documentation
    MAC range, a sender protocol address (the stimulus IPv4), the target protocol
    address to resolve (the target IPv4), and an Ethernet frame addressed from the
    sender MAC to the broadcast address. The capture filter is link-layer (ARP
    plus the reply opcode); the target service is the target kernel answering ARP
    for its own configured address (no daemon). The conventional single-send
    top-level fields mirror the first send so the generic plan echo and any
    single-send consumer keep working unchanged; the ARP dispatch detects
    ``arp_sends`` and drives both sends.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(profile, seed, sequence, role="stimulus")
    target_mac = deterministic_documentation_mac(profile, seed, sequence, role="target")
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    zero_mac = "00:00:00:00:00:00"

    sends = [
        _arp_repeat_two_replies_send(
            index=index,
            stimulus_ipv4=stimulus_ipv4,
            target_ipv4=target_ipv4,
            stimulus_mac=stimulus_mac,
            target_mac=target_mac,
            broadcast_mac=broadcast_mac,
            zero_mac=zero_mac,
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
        "stimulus": "arp_who_has",
        "expected_response": "arp_is_at",
        # ARP rides Ethernet directly; these are link-layer documentation values.
        # The conventional single-send top-level fields mirror the first send so
        # the generic plan echo / capture filter / single-send consumers keep
        # working unchanged.
        "ethertype": 0x0806,
        "hardware_type": 1,
        "protocol_type": 0x0800,
        "hardware_length": 6,
        "protocol_length": 4,
        "operation": 1,
        "operation_label": "request",
        "sender_hardware_addr": stimulus_mac,
        "sender_protocol_addr": stimulus_ipv4,
        "target_hardware_addr": zero_mac,
        "target_protocol_addr": target_ipv4,
        "ethernet_source": stimulus_mac,
        "ethernet_destination": broadcast_mac,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "capture_filter": "arp and arp[6:2] = 2",
        # The repeat contract: two independent who-has -> is-at sends for the same
        # target, validated separately.
        "send_count": len(sends),
        "arp_sends": sends,
        "target_service": {
            "required": True,
            "kind": "arp-kernel",
            "layer": "link",
            # The target kernel answers ARP who-has for its own configured
            # address; setup tunes ARP sysctls and flushes the neighbor cache.
            # The repeated who-has resolves the same target twice, so a flush
            # between sends keeps the kernel re-answering rather than the client
            # short-circuiting on a cached entry.
            "target_protocol_addr": target_ipv4,
            "target_hardware_addr": target_mac,
            "arp_sysctls": True,
            "neighbor_cache_flush": True,
            "repeat": {
                "sends": [
                    {
                        "target_protocol_addr": send["target_protocol_addr"],
                        "sender_hardware_addr": send["validation"]["sender_hardware_addr"],
                        "sender_protocol_addr": send["validation"]["sender_protocol_addr"],
                    }
                    for send in sends
                ],
            },
        },
        "validation": first["validation"],
        "wire_requirements": {
            "requires_link_layer_send": True,
            "requires_link_layer_capture": True,
            "requires_broadcast": True,
            "note": (
                "ARP resolution is L2 broadcast/unicast traffic; it runs only on a "
                "provider-backed lab segment, never from privileged host raw sends."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _arp_source_address_preserved_probe_plan(
    *,
    case_name: str = "arp-source-address-preserved",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``arp-source-address-preserved`` behavioral case.

    A who-has request (operation 1) carrying *deterministic* sender hardware and
    sender protocol addresses (the stimulus endpoint's own MAC/IPv4), answered by
    the target kernel with a unicast is-at reply (operation 2). The point of this
    case is address *preservation*: the reply must be addressed back to the
    requester, so the reply's TARGET hardware/protocol address must equal the
    request's SENDER hardware/protocol address, and the reply's SENDER
    hardware/protocol address must be the target endpoint's own MAC/IPv4. This
    catches mismatches in ARP field construction and parsing where a stack
    mishandles the sender/target swap.

    The plan shape mirrors ``arp-basic-who-has`` (ARP rides Ethernet directly, no
    IP/UDP; documentation MACs; broadcast who-has; ARP-answering target kernel),
    but the validation contract is the explicit preservation contract: its target
    hardware/protocol fields are pinned to the *planned request* sender values so
    the endpoint asserts the reply addresses the original requester, and its
    sender hardware/protocol fields are pinned to the target endpoint's own
    addresses.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(profile, seed, sequence, role="stimulus")
    target_mac = deterministic_documentation_mac(profile, seed, sequence, role="target")
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    zero_mac = "00:00:00:00:00:00"
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "arp_who_has",
        "expected_response": "arp_is_at",
        # ARP rides Ethernet directly; these are link-layer documentation values.
        "ethertype": 0x0806,
        "hardware_type": 1,
        "protocol_type": 0x0800,
        "hardware_length": 6,
        "protocol_length": 4,
        "operation": 1,
        "operation_label": "request",
        # The request carries deterministic sender hardware AND protocol addresses
        # (the stimulus endpoint's own); the preservation check asserts the reply
        # is addressed back to exactly these.
        "sender_hardware_addr": stimulus_mac,
        "sender_protocol_addr": stimulus_ipv4,
        "target_hardware_addr": zero_mac,
        "target_protocol_addr": target_ipv4,
        "ethernet_source": stimulus_mac,
        "ethernet_destination": broadcast_mac,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        # ARP cannot be selected by host/IP BPF; match on the protocol + opcode.
        "capture_filter": "arp and arp[6:2] = 2",
        "target_service": {
            "required": True,
            "kind": "arp-kernel",
            "layer": "link",
            "target_protocol_addr": target_ipv4,
            "target_hardware_addr": target_mac,
            "arp_sysctls": True,
            "neighbor_cache_flush": True,
        },
        "validation": {
            "ethertype": 0x0806,
            "operation": 2,
            "operation_label": "reply",
            # Reply SENDER fields == the target endpoint's own HW/proto.
            "sender_hardware_addr": target_mac,
            "sender_protocol_addr": target_ipv4,
            # Reply TARGET fields == the request's SENDER HW/proto (preserved).
            "target_hardware_addr": stimulus_mac,
            "target_protocol_addr": stimulus_ipv4,
            "ethernet_source": target_mac,
            "ethernet_destination": stimulus_mac,
        },
        "wire_requirements": {
            "requires_link_layer_send": True,
            "requires_link_layer_capture": True,
            "requires_broadcast": True,
            "note": (
                "ARP resolution is L2 broadcast/unicast traffic; it runs only on a "
                "provider-backed lab segment, never from privileged host raw sends."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _arp_alias_address_reply_probe_plan(
    *,
    case_name: str = "arp-alias-address-reply",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``arp-alias-address-reply`` behavioral case.

    A who-has request (operation 1) resolving a *configured secondary IPv4 alias*
    on the target interface, answered by the target kernel with a unicast is-at
    reply (operation 2). The point of this case is target *interface preparation*:
    the target setup adds a deterministic secondary IPv4 address (an alias,
    distinct from the endpoint's primary IPv4) to the private interface before the
    run and removes it during cleanup, and the case validates that the kernel
    answers ARP for that alias. The validation contract therefore pins the reply's
    SENDER protocol address to the alias (the resolved address) and the reply's
    SENDER hardware address to the target endpoint's own MAC.

    The plan shape mirrors ``arp-basic-who-has`` (ARP rides Ethernet directly, no
    IP/UDP; documentation MACs; broadcast who-has), but the resolved target
    protocol address is the alias rather than the endpoint's primary IPv4, and the
    target service is an ``arp-kernel`` setup that adds/removes the alias (plus the
    usual ARP sysctls and neighbor-cache flush).
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    alias_ipv4 = deterministic_arp_alias_ipv4(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(profile, seed, sequence, role="stimulus")
    target_mac = deterministic_documentation_mac(profile, seed, sequence, role="target")
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    zero_mac = "00:00:00:00:00:00"
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "arp_who_has",
        "expected_response": "arp_is_at",
        # ARP rides Ethernet directly; these are link-layer documentation values.
        "ethertype": 0x0806,
        "hardware_type": 1,
        "protocol_type": 0x0800,
        "hardware_length": 6,
        "protocol_length": 4,
        "operation": 1,
        "operation_label": "request",
        "sender_hardware_addr": stimulus_mac,
        "sender_protocol_addr": stimulus_ipv4,
        "target_hardware_addr": zero_mac,
        # The who-has resolves the configured ALIAS address (not the endpoint's
        # primary IPv4); the kernel answers for the secondary address it owns.
        "target_protocol_addr": alias_ipv4,
        "ethernet_source": stimulus_mac,
        "ethernet_destination": broadcast_mac,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": alias_ipv4,
        "alias_ipv4": alias_ipv4,
        "expected_reply_source_ipv4": alias_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        # ARP cannot be selected by host/IP BPF; match on the protocol + opcode.
        "capture_filter": "arp and arp[6:2] = 2",
        "target_service": {
            "required": True,
            "kind": "arp-kernel",
            "layer": "link",
            # Target setup adds the secondary IPv4 alias to the private interface
            # (and removes it during cleanup); the kernel then answers ARP for the
            # alias. Setup also tunes ARP sysctls and flushes the neighbor cache.
            "target_protocol_addr": alias_ipv4,
            "target_hardware_addr": target_mac,
            "alias_ipv4": alias_ipv4,
            "alias_address": True,
            "arp_sysctls": True,
            "neighbor_cache_flush": True,
        },
        "validation": {
            "ethertype": 0x0806,
            "operation": 2,
            "operation_label": "reply",
            # Reply SENDER fields == the target endpoint's own HW + the ALIAS proto.
            "sender_hardware_addr": target_mac,
            "sender_protocol_addr": alias_ipv4,
            # Reply TARGET fields == the request's SENDER HW/proto.
            "target_hardware_addr": stimulus_mac,
            "target_protocol_addr": stimulus_ipv4,
            "ethernet_source": target_mac,
            "ethernet_destination": stimulus_mac,
        },
        "wire_requirements": {
            "requires_link_layer_send": True,
            "requires_link_layer_capture": True,
            "requires_broadcast": True,
            "note": (
                "ARP resolution is L2 broadcast/unicast traffic; it runs only on a "
                "provider-backed lab segment, never from privileged host raw sends."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _arp_spa_variation_probe_plan(
    *,
    case_name: str = "arp-spa-variation",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``arp-spa-variation`` behavioral case.

    A who-has request (operation 1) whose *sender protocol address* (SPA) is an
    **alternate** address, distinct from the stimulus endpoint's primary IPv4,
    answered by the target kernel with a unicast is-at reply (operation 2). The
    point of this case is that ARP field handling and reply matching must not
    assume a single hard-coded source address: a generated tool that sends from a
    configured or alias source address still gets a reply, and the target
    addresses the reply back to exactly that planned SPA (reply target protocol
    address == the alternate SPA) and the planned sender hardware address (reply
    target hardware address == the probe MAC).

    The plan shape mirrors ``arp-basic-who-has`` (ARP rides Ethernet directly, no
    IP/UDP; documentation MACs; broadcast who-has; ARP-answering target kernel),
    but the request's sender protocol address is the alternate SPA rather than the
    endpoint's primary IPv4. The SPA is a single source of truth: the request's
    ``sender_protocol_addr`` and the validation contract's expected reply
    ``target_protocol_addr`` are the same alternate address. For live execution
    the target kernel may need that SPA configured as a secondary sender address
    so it accepts and answers the request; the target service records the
    alternate SPA (``alt_sender_ipv4`` / ``alt_sender_address``) so target setup
    can add (and cleanup remove) the secondary sender address. The endpoint pair's
    primary stimulus IPv4 stays the on-segment endpoint address (``source_ipv4``).
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    alt_sender_ipv4 = deterministic_arp_alt_sender_ipv4(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(profile, seed, sequence, role="stimulus")
    target_mac = deterministic_documentation_mac(profile, seed, sequence, role="target")
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    zero_mac = "00:00:00:00:00:00"
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "arp_who_has",
        "expected_response": "arp_is_at",
        # ARP rides Ethernet directly; these are link-layer documentation values.
        "ethertype": 0x0806,
        "hardware_type": 1,
        "protocol_type": 0x0800,
        "hardware_length": 6,
        "protocol_length": 4,
        "operation": 1,
        "operation_label": "request",
        # The request's SENDER protocol address is the ALTERNATE SPA (distinct from
        # the endpoint's primary IPv4); the reply must be addressed back to it.
        "sender_hardware_addr": stimulus_mac,
        "sender_protocol_addr": alt_sender_ipv4,
        "target_hardware_addr": zero_mac,
        "target_protocol_addr": target_ipv4,
        "ethernet_source": stimulus_mac,
        "ethernet_destination": broadcast_mac,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "alt_sender_ipv4": alt_sender_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": alt_sender_ipv4,
        # ARP cannot be selected by host/IP BPF; match on the protocol + opcode.
        "capture_filter": "arp and arp[6:2] = 2",
        "target_service": {
            "required": True,
            "kind": "arp-kernel",
            "layer": "link",
            "target_protocol_addr": target_ipv4,
            "target_hardware_addr": target_mac,
            # For live execution the kernel may need the alternate SPA configured as
            # a secondary sender address so it accepts/answers the who-has; record it
            # so target setup adds (and cleanup removes) the secondary address.
            "alt_sender_ipv4": alt_sender_ipv4,
            "alt_sender_address": True,
            "arp_sysctls": True,
            "neighbor_cache_flush": True,
        },
        "validation": {
            "ethertype": 0x0806,
            "operation": 2,
            "operation_label": "reply",
            # Reply SENDER fields == the target endpoint's own HW/proto.
            "sender_hardware_addr": target_mac,
            "sender_protocol_addr": target_ipv4,
            # Reply TARGET fields == the request's SENDER HW + the ALTERNATE SPA: the
            # target addresses the reply back to the planned sender hardware and the
            # planned alternate sender protocol address.
            "target_hardware_addr": stimulus_mac,
            "target_protocol_addr": alt_sender_ipv4,
            "ethernet_source": target_mac,
            "ethernet_destination": stimulus_mac,
        },
        "wire_requirements": {
            "requires_link_layer_send": True,
            "requires_link_layer_capture": True,
            "requires_broadcast": True,
            "note": (
                "ARP resolution is L2 broadcast/unicast traffic; it runs only on a "
                "provider-backed lab segment, never from privileged host raw sends."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _arp_unicast_request_reply_probe_plan(
    *,
    case_name: str = "arp-unicast-request-reply",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``arp-unicast-request-reply`` behavioral case.

    Once the target's MAC is known (from provider metadata or a prior exchange),
    the ARP request no longer has to be broadcast: it is sent *unicast* directly
    to the target MAC, and the target still replies. The only behavioral
    difference from ``arp-basic-who-has`` is the Ethernet **destination** of the
    request: it is the target endpoint's MAC (the resolved address the reply also
    carries) rather than the broadcast address ``ff:ff:ff:ff:ff:ff``. The
    ARP-layer fields are an ordinary who-has (operation 1, sender hardware/protocol
    = the probe's own, target hardware = all-zero, target protocol = the target
    IPv4). The validation contract is the standard is-at (operation 2, reply
    sender = the target MAC/IPv4, reply target = the querier MAC/IPv4) so the
    endpoint validates the decoded reply.

    Because the request frame cannot be addressed without the target MAC, the
    case requires ``provider_mac`` (set on the catalog case); a provider that
    cannot supply target-MAC metadata skips with the stable
    ``requires_provider_mac`` reason.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(profile, seed, sequence, role="stimulus")
    target_mac = deterministic_documentation_mac(profile, seed, sequence, role="target")
    zero_mac = "00:00:00:00:00:00"
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "arp_who_has",
        "expected_response": "arp_is_at",
        # ARP rides Ethernet directly; these are link-layer documentation values.
        "ethertype": 0x0806,
        "hardware_type": 1,
        "protocol_type": 0x0800,
        "hardware_length": 6,
        "protocol_length": 4,
        "operation": 1,
        "operation_label": "request",
        "sender_hardware_addr": stimulus_mac,
        "sender_protocol_addr": stimulus_ipv4,
        "target_hardware_addr": zero_mac,
        "target_protocol_addr": target_ipv4,
        # The unicast difference: the request's Ethernet destination is the known
        # target MAC, not the broadcast address.
        "ethernet_source": stimulus_mac,
        "ethernet_destination": target_mac,
        "request_is_unicast": True,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        # ARP cannot be selected by host/IP BPF; match on the protocol + opcode.
        "capture_filter": "arp and arp[6:2] = 2",
        "target_service": {
            "required": True,
            "kind": "arp-kernel",
            "layer": "link",
            # The target kernel answers ARP who-has for its own configured
            # address; setup tunes ARP sysctls and flushes the neighbor cache.
            "target_protocol_addr": target_ipv4,
            "target_hardware_addr": target_mac,
            "arp_sysctls": True,
            "neighbor_cache_flush": True,
        },
        "validation": {
            "ethertype": 0x0806,
            "operation": 2,
            "operation_label": "reply",
            "sender_hardware_addr": target_mac,
            "sender_protocol_addr": target_ipv4,
            "target_hardware_addr": stimulus_mac,
            "target_protocol_addr": stimulus_ipv4,
            "ethernet_source": target_mac,
            "ethernet_destination": stimulus_mac,
        },
        "wire_requirements": {
            "requires_link_layer_send": True,
            "requires_link_layer_capture": True,
            "requires_broadcast": True,
            # The request is addressed to the known target MAC, so target-MAC
            # metadata is mandatory; providers without it skip the case.
            "requires_provider_mac": True,
            "note": (
                "ARP resolution is L2 broadcast/unicast traffic; it runs only on a "
                "provider-backed lab segment, never from privileged host raw sends."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _arp_padding_reply_probe_plan(
    *,
    case_name: str = "arp-padding-reply",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``arp-padding-reply`` behavioral case.

    An Ethernet frame carrying ARP has a 28-byte ARP payload; with the 14-byte
    Ethernet header that is a 42-byte frame, below the 60-byte (sans FCS)
    Ethernet minimum. Such short frames are commonly padded with trailing zero
    bytes up to the minimum. This case sends an ordinary broadcast who-has
    (operation 1) whose Ethernet frame is **deterministically padded** with
    trailing zero bytes up to the 60-byte minimum (``ethernet_min_frame_len``),
    so the stimulus exercises libcrafter's ability to emit the padded frame
    (the padding is an honored override that ``compile()`` preserves) and still
    parse the target's unicast is-at reply. The padding is carried as plan
    metadata: ``ethernet_min_frame_len`` (the L2 minimum the frame is padded up
    to) and ``expected_request_frame_len`` (the resulting sent frame length the
    endpoint records). The is-at validation contract is the standard reply
    contract (operation 2, resolved sender hardware/protocol address, the
    original sender as the reply target, unicast Ethernet framing).
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(profile, seed, sequence, role="stimulus")
    target_mac = deterministic_documentation_mac(profile, seed, sequence, role="target")
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    zero_mac = "00:00:00:00:00:00"
    # The classic Ethernet minimum payload (sans 4-byte FCS) is 60 bytes; a
    # 14-byte header + 28-byte ARP payload (42 bytes) is padded up to it.
    min_frame_len = 60
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "arp_who_has",
        "expected_response": "arp_is_at",
        # ARP rides Ethernet directly; these are link-layer documentation values.
        "ethertype": 0x0806,
        "hardware_type": 1,
        "protocol_type": 0x0800,
        "hardware_length": 6,
        "protocol_length": 4,
        "operation": 1,
        "operation_label": "request",
        "sender_hardware_addr": stimulus_mac,
        "sender_protocol_addr": stimulus_ipv4,
        "target_hardware_addr": zero_mac,
        "target_protocol_addr": target_ipv4,
        "ethernet_source": stimulus_mac,
        "ethernet_destination": broadcast_mac,
        # Deterministic Ethernet padding: pad the frame up to the 60-byte
        # minimum with trailing zero bytes. The endpoint records the resulting
        # sent frame length so the padded send is inspectable.
        "ethernet_min_frame_len": min_frame_len,
        "expected_request_frame_len": min_frame_len,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        # ARP cannot be selected by host/IP BPF; match on the protocol + opcode.
        "capture_filter": "arp and arp[6:2] = 2",
        "target_service": {
            "required": True,
            "kind": "arp-kernel",
            "layer": "link",
            # The target kernel answers ARP who-has for its own configured
            # address; setup tunes ARP sysctls and flushes the neighbor cache.
            "target_protocol_addr": target_ipv4,
            "target_hardware_addr": target_mac,
            "arp_sysctls": True,
            "neighbor_cache_flush": True,
        },
        "validation": {
            "ethertype": 0x0806,
            "operation": 2,
            "operation_label": "reply",
            "sender_hardware_addr": target_mac,
            "sender_protocol_addr": target_ipv4,
            "target_hardware_addr": stimulus_mac,
            "target_protocol_addr": stimulus_ipv4,
            "ethernet_source": target_mac,
            "ethernet_destination": stimulus_mac,
        },
        "wire_requirements": {
            "requires_link_layer_send": True,
            "requires_link_layer_capture": True,
            "requires_broadcast": True,
            "note": (
                "ARP resolution is L2 broadcast/unicast traffic; it runs only on a "
                "provider-backed lab segment, never from privileged host raw sends."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _arp_cache_flush_reply_probe_plan(
    *,
    case_name: str = "arp-cache-flush-reply",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``arp-cache-flush-reply`` behavioral case.

    A who-has request (operation 1) resolving the target endpoint's IPv4 address,
    answered by the target kernel with a unicast is-at reply (operation 2), made
    reproducible by an explicit *pre-stimulus neighbor-cache flush*. Provider VMs
    can carry neighbor state across packets in a session: a target that already
    holds a fresh entry for the querier (or that the querier already resolved) can
    short-circuit a clean who-has -> is-at exchange. The point of this case is
    therefore controlled cache cleanup: the target setup flushes the relevant
    neighbor entries *before* the stimulus who-has is sent, so the request
    triggers a fresh resolution, and cleanup leaves neighbor state in the normal
    provider-controlled (flushed) state.

    The wire shape mirrors ``arp-basic-who-has`` (ARP rides Ethernet directly, no
    IP/UDP; documentation MACs; broadcast who-has; ARP-answering target kernel;
    same is-at validation contract). The behavioral distinction lives entirely in
    the target service: a ``flush_neighbor`` marker plus the explicit
    ``neighbor_flush_commands`` (setup, run before the stimulus) and
    ``neighbor_flush_cleanup_commands`` (cleanup, leaving state normal) so the
    dry-run target_service plan surfaces the cleanup contract rather than just the
    implicit sysctl flush every ARP case already carries.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(profile, seed, sequence, role="stimulus")
    target_mac = deterministic_documentation_mac(profile, seed, sequence, role="target")
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    zero_mac = "00:00:00:00:00:00"
    # The target/stimulus host flushes the relevant neighbor entries before the
    # who-has so resolution starts cold. The interface is rewritten onto the lab
    # segment in the live path; the descriptor below documents the deterministic
    # flush/cleanup contract the dry-run target_service plan surfaces.
    flush_interface = "eth0"
    flush_commands = [
        f"ip neigh flush dev {flush_interface} || true",
        f"ip neigh del {stimulus_ipv4} dev {flush_interface} || true",
    ]
    flush_cleanup_commands = [
        f"ip neigh flush dev {flush_interface} || true",
    ]
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "arp_who_has",
        "expected_response": "arp_is_at",
        # ARP rides Ethernet directly; these are link-layer documentation values.
        "ethertype": 0x0806,
        "hardware_type": 1,
        "protocol_type": 0x0800,
        "hardware_length": 6,
        "protocol_length": 4,
        "operation": 1,
        "operation_label": "request",
        "sender_hardware_addr": stimulus_mac,
        "sender_protocol_addr": stimulus_ipv4,
        "target_hardware_addr": zero_mac,
        "target_protocol_addr": target_ipv4,
        "ethernet_source": stimulus_mac,
        "ethernet_destination": broadcast_mac,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        # The behavioral distinction surfaced at the top level (mirrored into the
        # target_service below) so the stimulus endpoint reads it via the flattened
        # plan fields: an explicit pre-stimulus neighbor flush.
        "flush_neighbor": True,
        "neighbor_flush_interface": flush_interface,
        "neighbor_flush_commands": flush_commands,
        "neighbor_flush_cleanup_commands": flush_cleanup_commands,
        # ARP cannot be selected by host/IP BPF; match on the protocol + opcode.
        "capture_filter": "arp and arp[6:2] = 2",
        "target_service": {
            "required": True,
            "kind": "arp-kernel",
            "layer": "link",
            "target_protocol_addr": target_ipv4,
            "target_hardware_addr": target_mac,
            "arp_sysctls": True,
            "neighbor_cache_flush": True,
            # The behavioral distinction: an explicit pre-stimulus neighbor flush
            # (setup) and a cleanup that leaves neighbor state in a normal,
            # provider-controlled (flushed) state.
            "flush_neighbor": True,
            "neighbor_flush_interface": flush_interface,
            "neighbor_flush_commands": flush_commands,
            "neighbor_flush_cleanup_commands": flush_cleanup_commands,
        },
        "validation": {
            "ethertype": 0x0806,
            "operation": 2,
            "operation_label": "reply",
            "sender_hardware_addr": target_mac,
            "sender_protocol_addr": target_ipv4,
            "target_hardware_addr": stimulus_mac,
            "target_protocol_addr": stimulus_ipv4,
            "ethernet_source": target_mac,
            "ethernet_destination": stimulus_mac,
        },
        "wire_requirements": {
            "requires_link_layer_send": True,
            "requires_link_layer_capture": True,
            "requires_broadcast": True,
            "note": (
                "ARP resolution is L2 broadcast/unicast traffic; it runs only on a "
                "provider-backed lab segment, never from privileged host raw sends."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _arp_mac_validation_probe_plan(
    *,
    case_name: str = "arp-mac-validation",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``arp-mac-validation`` behavioral case.

    A broadcast ARP who-has request (operation 1) resolving the target endpoint's
    IPv4 address, answered by the target kernel with a unicast is-at reply
    (operation 2). The wire shape is identical to ``arp-basic-who-has`` (ARP rides
    Ethernet directly, no IP/UDP; documentation MACs; broadcast who-has;
    ARP-answering target kernel). The behavioral point is the *validation*: the
    reply must be tied to the intended target endpoint, not merely to any is-at on
    the segment. The validation contract therefore asserts that **both** the
    decoded reply's Ethernet source **and** its ARP sender hardware address equal
    the target endpoint's MAC (the address the live path threads in from provider
    metadata; here the deterministic documentation ``target_mac`` stands in for
    it). The MAC is the single source of truth: the reply sender hardware address,
    the reply Ethernet source, and the target kernel's configured hardware address
    are all the same target MAC.

    Because the validation pins the reply to the target endpoint's MAC, the case
    requires ``provider_mac`` (set on the catalog case and flagged in the wire
    requirements); a provider that cannot supply target-MAC metadata skips with
    the stable ``requires_provider_mac`` reason.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(profile, seed, sequence, role="stimulus")
    target_mac = deterministic_documentation_mac(profile, seed, sequence, role="target")
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    zero_mac = "00:00:00:00:00:00"
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "arp_who_has",
        "expected_response": "arp_is_at",
        # ARP rides Ethernet directly; these are link-layer documentation values.
        "ethertype": 0x0806,
        "hardware_type": 1,
        "protocol_type": 0x0800,
        "hardware_length": 6,
        "protocol_length": 4,
        "operation": 1,
        "operation_label": "request",
        "sender_hardware_addr": stimulus_mac,
        "sender_protocol_addr": stimulus_ipv4,
        "target_hardware_addr": zero_mac,
        "target_protocol_addr": target_ipv4,
        "ethernet_source": stimulus_mac,
        "ethernet_destination": broadcast_mac,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        # ARP cannot be selected by host/IP BPF; match on the protocol + opcode.
        "capture_filter": "arp and arp[6:2] = 2",
        "target_service": {
            "required": True,
            "kind": "arp-kernel",
            "layer": "link",
            # The target kernel answers ARP who-has for its own configured
            # address; setup tunes ARP sysctls and flushes the neighbor cache. The
            # configured hardware address is the target endpoint MAC the reply
            # sender hardware address and Ethernet source are validated against.
            "target_protocol_addr": target_ipv4,
            "target_hardware_addr": target_mac,
            "arp_sysctls": True,
            "neighbor_cache_flush": True,
        },
        "validation": {
            "ethertype": 0x0806,
            "operation": 2,
            "operation_label": "reply",
            # The reply must be tied to the target endpoint: BOTH the ARP sender
            # hardware address and the Ethernet source equal the target MAC.
            "sender_hardware_addr": target_mac,
            "sender_protocol_addr": target_ipv4,
            "target_hardware_addr": stimulus_mac,
            "target_protocol_addr": stimulus_ipv4,
            "ethernet_source": target_mac,
            "ethernet_destination": stimulus_mac,
            # The single source of truth the reply sender HW and Ethernet source
            # are both asserted against (the target endpoint's MAC).
            "provider_mac": target_mac,
        },
        "wire_requirements": {
            "requires_link_layer_send": True,
            "requires_link_layer_capture": True,
            "requires_broadcast": True,
            # The reply is validated against the target endpoint's MAC, so
            # target-MAC metadata is mandatory; providers without it skip.
            "requires_provider_mac": True,
            "note": (
                "ARP resolution is L2 broadcast/unicast traffic; it runs only on a "
                "provider-backed lab segment, never from privileged host raw sends."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _arp_broadcast_filtered_capture_probe_plan(
    *,
    case_name: str = "arp-broadcast-filtered-capture",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``arp-broadcast-filtered-capture`` behavioral case.

    A broadcast who-has request (operation 1) resolves the target endpoint's IPv4
    address, while the target setup may also emit an unrelated ARP is-at event on
    the same segment. The capture filter intentionally stays broad (ARP replies:
    ``arp and arp[6:2] = 2``), so the stimulus endpoint must decode every
    captured ARP reply, ignore the setup decoy whose target protocol address is
    not the planned querier address, and pass only when the decoded reply matches
    the primary is-at validation contract.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    decoy_sender_ipv4 = deterministic_arp_alias_ipv4(profile, seed, sequence)
    decoy_target_ipv4 = deterministic_arp_alt_sender_ipv4(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(profile, seed, sequence, role="stimulus")
    target_mac = deterministic_documentation_mac(profile, seed, sequence, role="target")
    decoy_sender_mac = deterministic_documentation_mac(
        profile, seed, sequence, role="decoy-sender"
    )
    decoy_target_mac = deterministic_documentation_mac(
        profile, seed, sequence, role="decoy-target"
    )
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    zero_mac = "00:00:00:00:00:00"
    decoy_arp_event: JSONObject = {
        "present": True,
        "kind": "arp-is-at",
        "setup_origin": "target",
        "operation": 2,
        "operation_label": "reply",
        "sender_hardware_addr": decoy_sender_mac,
        "sender_protocol_addr": decoy_sender_ipv4,
        "target_hardware_addr": decoy_target_mac,
        "target_protocol_addr": decoy_target_ipv4,
        "ethernet_source": decoy_sender_mac,
        "ethernet_destination": decoy_target_mac,
        "expected_endpoint_action": "ignore",
    }
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "arp_who_has",
        "expected_response": "arp_is_at",
        # ARP rides Ethernet directly; these are link-layer documentation values.
        "ethertype": 0x0806,
        "hardware_type": 1,
        "protocol_type": 0x0800,
        "hardware_length": 6,
        "protocol_length": 4,
        "operation": 1,
        "operation_label": "request",
        "sender_hardware_addr": stimulus_mac,
        "sender_protocol_addr": stimulus_ipv4,
        "target_hardware_addr": zero_mac,
        "target_protocol_addr": target_ipv4,
        "ethernet_source": stimulus_mac,
        "ethernet_destination": broadcast_mac,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "primary_target": {
            "target_protocol_addr": target_ipv4,
            "target_hardware_addr": target_mac,
        },
        # The capture stays broad enough to see unrelated is-at replies; decoded
        # reply matching filters them by the validation target protocol address.
        "capture_filter": "arp and arp[6:2] = 2",
        "ignore_unmatched_arp_replies": True,
        "decoy_arp_event": decoy_arp_event,
        "target_service": {
            "required": True,
            "kind": "arp-kernel",
            "layer": "link",
            "target_protocol_addr": target_ipv4,
            "target_hardware_addr": target_mac,
            "arp_sysctls": True,
            "neighbor_cache_flush": True,
            # Setup may emit unrelated ARP traffic on shared/private segments.
            # The endpoint should ignore this decoded decoy and keep waiting for
            # the primary target reply.
            "decoy_arp_event": decoy_arp_event,
        },
        "validation": {
            "ethertype": 0x0806,
            "operation": 2,
            "operation_label": "reply",
            "sender_hardware_addr": target_mac,
            "sender_protocol_addr": target_ipv4,
            "target_hardware_addr": stimulus_mac,
            "target_protocol_addr": stimulus_ipv4,
            "ethernet_source": target_mac,
            "ethernet_destination": stimulus_mac,
        },
        "wire_requirements": {
            "requires_link_layer_send": True,
            "requires_link_layer_capture": True,
            "requires_broadcast": True,
            "note": (
                "ARP resolution is L2 broadcast/unicast traffic; it runs only on a "
                "provider-backed lab segment, never from privileged host raw sends."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def deterministic_arp_alias_ipv4(profile: str, seed: int, sequence: int) -> str:
    """Return a deterministic secondary IPv4 alias for the target interface.

    The alias rides the same /24 lab segment as the endpoint pair from
    :func:`deterministic_ipv4_pair` (``10.{second}.{third}.10`` /
    ``10.{second}.{third}.20``) but resolves to a *distinct* host so the case
    proves the target kernel answers ARP for a configured secondary address, not
    just its primary. The host octet is derived from a dedicated digest and kept
    clear of the ``.10``/``.20`` endpoint hosts, the ``.1`` router, broadcast, and
    the network address.
    """

    digest = deterministic_bytes("endpoint-addresses", profile, seed, sequence)
    second = 64 + digest[0] % 64
    third = digest[1]
    alias_digest = deterministic_bytes("arp-alias-host", profile, seed, sequence)
    reserved = {0, 1, 10, 20, 255}
    host = 2 + alias_digest[0] % 252
    while host in reserved:
        host = 2 + (host - 1) % 252
    return f"10.{second}.{third}.{host}"


def deterministic_arp_alt_sender_ipv4(profile: str, seed: int, sequence: int) -> str:
    """Return a deterministic *alternate* sender protocol address (SPA).

    The SPA rides the same /24 lab segment as the endpoint pair from
    :func:`deterministic_ipv4_pair` (``10.{second}.{third}.10`` /
    ``10.{second}.{third}.20``) but is a *distinct* host from both endpoints so
    the case proves a who-has from an alternate sender address is still answered.
    The host octet is derived from a dedicated digest and kept clear of the
    ``.10``/``.20`` endpoint hosts, any configured alias host, the ``.1`` router,
    broadcast, and the network address.
    """

    digest = deterministic_bytes("endpoint-addresses", profile, seed, sequence)
    second = 64 + digest[0] % 64
    third = digest[1]
    alias_host = int(deterministic_arp_alias_ipv4(profile, seed, sequence).split(".")[3])
    spa_digest = deterministic_bytes("arp-alt-sender-host", profile, seed, sequence)
    reserved = {0, 1, 10, 20, 255, alias_host}
    host = 2 + spa_digest[0] % 252
    while host in reserved:
        host = 2 + (host - 1) % 252
    return f"10.{second}.{third}.{host}"


# The ARP plan-builder dispatch contribution: each case name maps to the exact
# function object above. ``planning`` re-imports these so its module-level names
# and ``PLAN_BUILDERS`` entries are the same objects (identity-pinned by the ARP
# behavior tests).
_ARP_PLAN_BUILDERS: dict[str, object] = {
    "arp-resolution": _arp_resolution_probe_plan,
    "arp-basic-who-has": _arp_basic_who_has_probe_plan,
    "arp-repeat-two-replies": _arp_repeat_two_replies_probe_plan,
    "arp-source-address-preserved": _arp_source_address_preserved_probe_plan,
    "arp-alias-address-reply": _arp_alias_address_reply_probe_plan,
    "arp-unicast-request-reply": _arp_unicast_request_reply_probe_plan,
    "arp-padding-reply": _arp_padding_reply_probe_plan,
    "arp-cache-flush-reply": _arp_cache_flush_reply_probe_plan,
    "arp-mac-validation": _arp_mac_validation_probe_plan,
    "arp-spa-variation": _arp_spa_variation_probe_plan,
    "arp-broadcast-filtered-capture": _arp_broadcast_filtered_capture_probe_plan,
}


# The ARP cases routed through the stimulus endpoint adapter. ``arp-resolution``
# is the inline smoke case and is intentionally absent (it has no stimulus-
# endpoint adapter arm), matching the legacy routing set exactly.
_ARP_STIMULUS_ENDPOINT_CASES: frozenset[str] = frozenset(
    {
        "arp-basic-who-has",
        "arp-repeat-two-replies",
        "arp-source-address-preserved",
        "arp-alias-address-reply",
        "arp-unicast-request-reply",
        "arp-padding-reply",
        "arp-cache-flush-reply",
        "arp-mac-validation",
        "arp-spa-variation",
        "arp-broadcast-filtered-capture",
    }
)


register(
    ProtocolPlugin(
        name="arp",
        # The inline ``arp-resolution`` smoke case is declared first to match its
        # legacy position in the per-protocol aggregation, followed by the ten
        # behavioral cases in declaration order.
        cases=(ARP_RESOLUTION_CASE, *BEHAVIOR_ARP_CASES),
        plan_builders=_ARP_PLAN_BUILDERS,
        # ARP carries no planned-only cases (every builder materializes a plan).
        planned_only_cases=frozenset(),
        # ARP's profile membership stays in the legacy ordered profile tables in
        # ``cases.py`` to preserve byte-identical selection order (the registry-
        # first profile merge would otherwise move ARP to the front of the smoke
        # and behavior profiles). Contribute nothing here.
        profile_counts={},
        stimulus_endpoint_cases=_ARP_STIMULUS_ENDPOINT_CASES,
        # The target-service / address-rewrite / failure-reason / lab-capability
        # hooks are added in the second half of the ARP slice (step 18).
        target_service=None,
        setup_script=None,
        rewrite_endpoint_addresses=None,
        failure_reasons=None,
        lab_capabilities=None,
    )
)
