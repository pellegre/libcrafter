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

import json
import posixpath
import shlex
from collections.abc import Mapping, Sequence

from ..capability_derivation import capability
from ..case_helpers import _behavior_case
from ..endpoint_addressing import (
    FAILURE_DECODE_FAILED,
    FAILURE_TARGET_SETUP_FAILED,
    FAILURE_TIMEOUT,
    FAILURE_WRONG_PAYLOAD,
    FAILURE_WRONG_PEER,
    _lab_arp_alias_ipv4,
)
from ..model import JSONObject, JSONValue, ProbeCase, json_object
from ..planning_helpers import (
    deterministic_bytes,
    deterministic_documentation_mac,
    deterministic_ipv4_pair,
)
from ..target_service_helpers import (
    KernelStateDescriptor,
    dedupe_ints,
)
from ..target_service_helpers import json_mapping as _json_mapping
from ..target_service_helpers import string_or as _string_or
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


# --------------------------------------------------------------------------- #
# Target-service descriptors and case selector (moved from target_services.py)
# --------------------------------------------------------------------------- #
#
# Probe cases whose target is primarily the kernel answering ARP who-has on a
# private L2 segment. ``arp-resolution`` is the legacy smoke case;
# ``arp-basic-who-has`` is the baseline ARP behavioral case. Both rely on the
# target kernel answering ARP for its own configured address, with ARP sysctl
# tuning and a neighbor-cache flush as setup (no listening daemon). Providers
# without link-layer/broadcast capability skip these cases.
_ARP_KERNEL_CASES: frozenset[str] = frozenset(
    {
        "arp-resolution",
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


def arp_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return the ARP probe plans in order."""

    return [plan for plan in probe_plans if plan.get("case") in _ARP_KERNEL_CASES]


def arp_alias_descriptor(
    *,
    bind_ipv4: str,
    source_ipv4: str,
    alias_ipv4: str,
    interface: str,
) -> KernelStateDescriptor:
    """Describe an ARP alias address added to the target interface."""

    quoted_alias = shlex.quote(f"{alias_ipv4}/32")
    quoted_iface = shlex.quote(interface)
    return KernelStateDescriptor(
        name="arp-alias",
        purpose="arp-alias-address",
        bind_ipv4=bind_ipv4,
        source_ipv4=source_ipv4,
        setup_commands=[
            f"ip addr add {quoted_alias} dev {quoted_iface}",
        ],
        cleanup_commands=[
            f"ip addr del {quoted_alias} dev {quoted_iface} || true",
        ],
        metadata={
            "alias_ipv4": alias_ipv4,
            "interface": interface,
            "layer": "link",
            "deterministic": True,
        },
    )


def arp_sysctl_descriptor(
    *,
    bind_ipv4: str,
    source_ipv4: str,
    interface: str,
) -> KernelStateDescriptor:
    """Describe ARP sysctl tuning and neighbor-cache flush for the target."""

    quoted_iface = shlex.quote(interface)
    arp_ignore = f"net.ipv4.conf.{interface}.arp_ignore"
    arp_announce = f"net.ipv4.conf.{interface}.arp_announce"
    return KernelStateDescriptor(
        name="arp-sysctl",
        purpose="arp-neighbor-setup",
        bind_ipv4=bind_ipv4,
        source_ipv4=source_ipv4,
        setup_commands=[
            f"sysctl -w {shlex.quote(arp_ignore + '=0')}",
            f"sysctl -w {shlex.quote(arp_announce + '=0')}",
            f"ip neigh flush dev {quoted_iface} || true",
        ],
        cleanup_commands=[
            f"ip neigh flush dev {quoted_iface} || true",
        ],
        metadata={"interface": interface, "layer": "link", "deterministic": True},
    )


def arp_extra_addresses(probe_plans: Sequence[JSONObject]) -> list[str]:
    """Return secondary IPv4 addresses that ARP live setup must add."""

    addresses: list[str] = []
    for plan in probe_plans:
        service = _json_mapping(
            plan.get("target_service", {}),
            "probe_plan.target_service",
        )
        for key in ("alias_ipv4", "alt_sender_ipv4"):
            value = _string_or(service.get(key), "")
            if value:
                addresses.append(value)
    return list(dict.fromkeys(addresses))


def arp_decoy_events(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return ARP decoy events that live setup should emit during capture."""

    events: list[JSONObject] = []
    for plan in probe_plans:
        service = _json_mapping(
            plan.get("target_service", {}),
            "probe_plan.target_service",
        )
        event = service.get("decoy_arp_event")
        if isinstance(event, Mapping):
            events.append(json_object(event, "probe_plan.decoy_arp_event"))
    return events


def arp_kernel_state_plan(
    *,
    probe_plans: Sequence[JSONObject],
    dry_run: bool,
) -> JSONObject:
    """Return the inspectable ARP kernel setup contract for planned ARP cases."""

    if not probe_plans:
        return {
            "planned": False,
            "state": "not-required",
            "cases": [],
            "alias_addresses": [],
            "alt_sender_addresses": [],
            "decoy_events": [],
        }

    alias_addresses: list[str] = []
    alt_sender_addresses: list[str] = []
    decoy_events: list[JSONObject] = []
    interfaces: list[str] = []
    for plan in probe_plans:
        service = _json_mapping(
            plan.get("target_service", {}),
            "probe_plan.target_service",
        )
        alias_ipv4 = _string_or(service.get("alias_ipv4"), "")
        if alias_ipv4:
            alias_addresses.append(alias_ipv4)
        alt_sender_ipv4 = _string_or(service.get("alt_sender_ipv4"), "")
        if alt_sender_ipv4:
            alt_sender_addresses.append(alt_sender_ipv4)
        decoy = service.get("decoy_arp_event")
        if isinstance(decoy, Mapping):
            decoy_events.append(json_object(decoy, "probe_plan.decoy_arp_event"))
        interface = _string_or(service.get("interface"), "")
        if not interface:
            interface = _string_or(service.get("neighbor_flush_interface"), "")
        if interface:
            interfaces.append(interface)

    state = "planned" if dry_run else "configured"
    return {
        "planned": True,
        "state": state,
        "case_count": len(probe_plans),
        "cases": [str(plan.get("case", "")) for plan in probe_plans],
        "requires_link_layer": True,
        "arp_sysctls": True,
        "neighbor_cache_flush": True,
        "interfaces": list(dict.fromkeys(interfaces)),
        "alias_addresses": list(dict.fromkeys(alias_addresses)),
        "alt_sender_addresses": list(dict.fromkeys(alt_sender_addresses)),
        "decoy_events": decoy_events,
    }


def arp_target_service_contribution(
    probe_plans: Sequence[JSONObject],
    *,
    dry_run: bool,
) -> JSONObject:
    """Return the ARP plugin's ``target_service_setup_plan`` contribution.

    ARP stands up no listening daemon; its only target-service contribution is
    the inspectable ``arp_kernel_state`` contract (the central plan's
    ``arp_kernel_state`` key). The registry merge overwrites the central plan's
    default (``not-required``) key with this contract, byte-identical to the
    legacy per-protocol path that built it inline.
    """

    return {
        "arp_kernel_state": arp_kernel_state_plan(
            probe_plans=arp_probe_plans(probe_plans),
            dry_run=dry_run,
        ),
    }


def arp_target_setup_lines(
    *,
    artifact_root: str,
    arp_plans: Sequence[JSONObject],
) -> list[str]:
    """Render the ARP kernel-state setup block for the target setup script.

    Moved verbatim from the inline ``if arp_plans:`` block of
    ``target_services.target_service_setup_script``; the orchestrator calls this
    with the planned ARP plans so the rendered script bytes stay byte-identical.
    """

    arp_decoy_events_json = json.dumps(
        arp_decoy_events(arp_plans),
        sort_keys=True,
    )
    arp_addresses = arp_extra_addresses(arp_plans)
    lines: list[str] = [
        'if [ -z "$target_interface" ]; then',
        "  echo arp_target_interface=missing >&2",
        "  exit 73",
        "fi",
        'ip link show dev "$target_interface" >/dev/null',
        'printf \'%s\\n\' "ip neigh flush dev $target_interface || true" >> "$cleanup"',
        'for key in arp_ignore arp_announce; do',
        '  sysctl_name="net.ipv4.conf.${target_interface}.${key}"',
        '  before_path="$artifact_root/arp-${key}.before"',
        '  sysctl -n "$sysctl_name" > "$before_path" 2>/dev/null || true',
        '  before_value=""',
        '  if [ -s "$before_path" ]; then before_value="$(cat "$before_path")"; fi',
        '  if [ -n "$before_value" ]; then',
        '    printf \'%s\\n\' "sysctl -w ${sysctl_name}=${before_value} >/dev/null 2>&1 || true" >> "$cleanup"',
        "  fi",
        '  sysctl -w "${sysctl_name}=0"',
        "done",
        'ip neigh flush dev "$target_interface" || true',
        "echo arp_kernel_state=configured",
    ]
    for address in arp_addresses:
        quoted_address = shlex.quote(address)
        lines.extend(
            [
                (
                    "if ! ip -4 addr show dev \"$target_interface\" "
                    f"| grep -Fq {shlex.quote(address + '/32')}; then"
                ),
                f"  ip addr add {quoted_address}/32 dev \"$target_interface\"",
                "fi",
                (
                    f"printf '%s\\n' \"ip addr del {quoted_address}/32 dev "
                    "$target_interface 2>/dev/null || true\" >> \"$cleanup\""
                ),
                f"echo arp_extra_address_{address}=configured",
            ]
        )
    if arp_decoy_events_json != "[]":
        decoy_path = posixpath.join(artifact_root, "arp-decoy-events.json")
        decoy_script = posixpath.join(artifact_root, "arp-decoy-emitter.py")
        stdout_path = posixpath.join(artifact_root, "arp-decoy-emitter.stdout.txt")
        stderr_path = posixpath.join(artifact_root, "arp-decoy-emitter.stderr.txt")
        pid_path = posixpath.join(artifact_root, "arp-decoy-emitter.pid")
        lines.extend(
            [
                f"cat > {shlex.quote(decoy_path)} <<'JSON'",
                arp_decoy_events_json,
                "JSON",
                f"cat > {shlex.quote(decoy_script)} <<'PY'",
                "import ipaddress",
                "import json",
                "import signal",
                "import socket",
                "import struct",
                "import sys",
                "import time",
                "",
                "stop = False",
                "",
                "def handle_stop(_signum, _frame):",
                "    global stop",
                "    stop = True",
                "",
                "signal.signal(signal.SIGTERM, handle_stop)",
                "signal.signal(signal.SIGINT, handle_stop)",
                "",
                "events_path, iface = sys.argv[1:3]",
                "events = json.load(open(events_path, encoding='utf-8'))",
                "",
                "def mac_bytes(value):",
                "    return bytes(int(part, 16) for part in str(value).split(':'))",
                "",
                "def ip_bytes(value):",
                "    return ipaddress.IPv4Address(str(value)).packed",
                "",
                "def frame(event):",
                "    ethernet_dst = mac_bytes(event['ethernet_destination'])",
                "    ethernet_src = mac_bytes(event['ethernet_source'])",
                "    sender_hw = mac_bytes(event['sender_hardware_addr'])",
                "    target_hw = mac_bytes(event['target_hardware_addr'])",
                "    arp = struct.pack(",
                "        '!HHBBH6s4s6s4s',",
                "        1,",
                "        0x0800,",
                "        6,",
                "        4,",
                "        int(event.get('operation', 2)),",
                "        sender_hw,",
                "        ip_bytes(event['sender_protocol_addr']),",
                "        target_hw,",
                "        ip_bytes(event['target_protocol_addr']),",
                "    )",
                "    return ethernet_dst + ethernet_src + struct.pack('!H', 0x0806) + arp",
                "",
                "frames = [(event, frame(event)) for event in events if event.get('present', True)]",
                "sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)",
                "sock.bind((iface, 0))",
                "deadline = time.time() + 30.0",
                "print(json.dumps({'event': 'listening', 'interface': iface, 'decoy_count': len(frames)}), flush=True)",
                "while not stop and time.time() < deadline:",
                "    for event, raw in frames:",
                "        sock.send(raw)",
                "        print(json.dumps({'event': 'sent', 'sender_protocol_addr': event.get('sender_protocol_addr'), 'target_protocol_addr': event.get('target_protocol_addr')}, sort_keys=True), flush=True)",
                "    time.sleep(0.25)",
                "sock.close()",
                "print(json.dumps({'event': 'stopped', 'ts': time.time()}), flush=True)",
                "PY",
                (
                    f"python3 {shlex.quote(decoy_script)} {shlex.quote(decoy_path)} "
                    f"\"$target_interface\" >{shlex.quote(stdout_path)} "
                    f"2>{shlex.quote(stderr_path)} &"
                ),
                "pid=$!",
                f"echo \"$pid\" > {shlex.quote(pid_path)}",
                "printf '%s\\n' \"kill $pid 2>/dev/null || true\" >> \"$cleanup\"",
                f"printf '%s\\n' \"rm -f {shlex.quote(pid_path)}\" >> \"$cleanup\"",
                "sleep 0.2",
                "if ! kill -0 \"$pid\" 2>/dev/null; then",
                f"  cat {shlex.quote(stderr_path)} >&2 || true",
                "  echo arp_decoy_emitter=failed >&2",
                "  exit 73",
                "fi",
                "echo arp_decoy_emitter=running",
            ]
        )
    return lines


# --------------------------------------------------------------------------- #
# Live-path address rewrite (moved from cli._probe_plan_with_endpoint_addresses)
# --------------------------------------------------------------------------- #


def arp_rewrite_endpoint_addresses(
    plan: JSONObject,
    *,
    source_ipv4: str,
    target_ipv4: str,
    source_mac: str | None = None,
    target_mac: str | None = None,
    target_interface: str | None = None,
    rewrite_source: str = "wire_endpoint_plan",
) -> JSONObject:
    """Rewrite an ARP probe plan onto the live lab-segment addresses.

    Moved verbatim from the ARP branch of
    ``cli._probe_plan_with_endpoint_addresses`` (including the shared
    transport-IPv4 pre-sets that ran before the per-protocol if/elif). ARP rides
    Ethernet directly, so this returns the rewritten plan rather than falling
    into the shared IPv4-layer tail.
    """

    updated = dict(plan)
    updated["source_ipv4"] = source_ipv4
    updated["destination_ipv4"] = target_ipv4
    updated["expected_reply_source_ipv4"] = target_ipv4
    updated["expected_reply_destination_ipv4"] = source_ipv4
    case_name = str(updated.get("case", ""))
    # ARP rides Ethernet directly (no IP/UDP), so the lab rewrite touches the
    # ARP protocol addresses rather than transport IPs: the stimulus resolves
    # the target endpoint's IPv4 (target protocol address) from its own IPv4
    # (sender protocol address). The Ethernet source stays the stimulus MAC
    # and the request is broadcast; the target hardware/protocol addresses the
    # reply resolves are the target endpoint's on-segment MAC/IPv4. The
    # capture filter is link-layer (ARP plus the reply opcode), so it carries
    # no host/IP terms to rewrite. ARP carries no transport source/destination
    # IPv4 to overwrite, so this branch returns directly rather than falling
    # into the shared IP-layer validation tail.
    #
    # arp-alias-address-reply is the exception: the kernel answers for a
    # *configured secondary* IPv4 alias, not its primary on-segment address.
    # The resolved target protocol address (and the expected reply sender
    # protocol address) is therefore a distinct alias host in the lab subnet,
    # derived deterministically from the target endpoint's IPv4 and threaded
    # into the target_service setup/cleanup (alias add/del) and the expected
    # reply sender-proto.
    is_alias_case = case_name == "arp-alias-address-reply"
    is_spa_case = case_name == "arp-spa-variation"
    is_filtered_capture_case = case_name == "arp-broadcast-filtered-capture"
    resolved_source_mac = _string_or(source_mac, "")
    resolved_target_mac = _string_or(target_mac, "")
    resolved_target_interface = _string_or(target_interface, "")
    resolved_ipv4 = (
        _lab_arp_alias_ipv4(target_ipv4, source_ipv4)
        if is_alias_case
        else target_ipv4
    )
    # arp-spa-variation is the sender-side exception: the who-has carries an
    # ALTERNATE sender protocol address (SPA), distinct from the stimulus
    # endpoint's primary on-segment IPv4 (``source_ipv4``). The SPA is a single
    # source of truth: the request's sender_protocol_addr and the expected
    # reply target_protocol_addr are both the alternate SPA. Derive it as a
    # distinct host on the lab segment (reuse the alias-style host derivation,
    # which already avoids the source/target/router/broadcast hosts).
    sender_proto = (
        _lab_arp_alias_ipv4(source_ipv4, target_ipv4)
        if is_spa_case
        else source_ipv4
    )
    updated["source_ipv4"] = source_ipv4
    updated["destination_ipv4"] = resolved_ipv4
    updated["expected_reply_source_ipv4"] = resolved_ipv4
    updated["expected_reply_destination_ipv4"] = sender_proto
    updated["sender_protocol_addr"] = sender_proto
    updated["target_protocol_addr"] = resolved_ipv4
    if resolved_source_mac:
        updated["sender_hardware_addr"] = resolved_source_mac
        updated["ethernet_source"] = resolved_source_mac
    if resolved_target_mac and case_name == "arp-unicast-request-reply":
        updated["ethernet_destination"] = resolved_target_mac
    if is_alias_case:
        updated["alias_ipv4"] = resolved_ipv4
    if is_spa_case:
        updated["alt_sender_ipv4"] = sender_proto
    target_service = dict(
        json_object(updated.get("target_service", {}), "probe_plan.target_service")
    )
    target_service.update(
        {
            # The kernel's primary on-segment address is the endpoint IPv4; the
            # alias is added on top of it, so the interface still binds the
            # endpoint address.
            "bind_ipv4": target_ipv4,
            "source_ipv4": source_ipv4,
            "target_protocol_addr": resolved_ipv4,
        }
    )
    if resolved_target_mac:
        target_service["target_hardware_addr"] = resolved_target_mac
        repeat = target_service.get("repeat")
        if isinstance(repeat, dict) and isinstance(repeat.get("sends"), list):
            repeat["sends"] = [
                {
                    **json_object(send, "probe_plan.target_service.repeat.send"),
                    "sender_hardware_addr": resolved_target_mac,
                }
                for send in repeat["sends"]
                if isinstance(send, Mapping)
            ]
            target_service["repeat"] = repeat
    if resolved_target_interface:
        target_service["interface"] = resolved_target_interface
    if is_alias_case:
        # Target setup adds the secondary alias to the private interface (and
        # removes it during cleanup); rewrite the alias onto the lab segment so
        # the live setup configures the on-segment alias the who-has resolves.
        target_service["alias_ipv4"] = resolved_ipv4
        target_service["alias_address"] = True
    if is_spa_case:
        # For live execution the target kernel may need the alternate SPA
        # configured as a secondary sender address so it accepts/answers the
        # who-has; thread the on-segment SPA into the target service so setup
        # adds (and cleanup removes) the secondary sender address.
        target_service["alt_sender_ipv4"] = sender_proto
        target_service["alt_sender_address"] = True
    if is_filtered_capture_case:
        decoy_sender_ipv4 = _lab_arp_alias_ipv4(target_ipv4, source_ipv4)
        decoy_target_ipv4 = _lab_arp_alias_ipv4(source_ipv4, target_ipv4)

        def _rewrite_decoy_arp_event(raw_event: object) -> JSONObject:
            event = dict(json_object(raw_event, "probe_plan.decoy_arp_event"))
            event["sender_protocol_addr"] = decoy_sender_ipv4
            event["target_protocol_addr"] = decoy_target_ipv4
            if resolved_target_mac:
                event["ethernet_source"] = resolved_target_mac
                event["sender_hardware_addr"] = resolved_target_mac
            if resolved_source_mac:
                event["ethernet_destination"] = resolved_source_mac
                event["target_hardware_addr"] = resolved_source_mac
            return event

        if isinstance(updated.get("decoy_arp_event"), dict):
            updated["decoy_arp_event"] = _rewrite_decoy_arp_event(
                updated["decoy_arp_event"]
            )
        target_service["decoy_arp_event"] = updated.get("decoy_arp_event")
    updated["target_service"] = target_service
    arp_validation = dict(
        json_object(updated.get("validation", {}), "probe_plan.validation")
    )
    arp_validation["sender_protocol_addr"] = resolved_ipv4
    # The reply is addressed back to the request's sender protocol address: the
    # alternate SPA for arp-spa-variation, the stimulus IPv4 otherwise.
    arp_validation["target_protocol_addr"] = sender_proto
    if resolved_target_mac:
        arp_validation["sender_hardware_addr"] = resolved_target_mac
        arp_validation["ethernet_source"] = resolved_target_mac
        if "provider_mac" in arp_validation:
            arp_validation["provider_mac"] = resolved_target_mac
    if resolved_source_mac:
        arp_validation["target_hardware_addr"] = resolved_source_mac
        arp_validation["ethernet_destination"] = resolved_source_mac
    updated["validation"] = arp_validation
    if case_name == "arp-unicast-request-reply":
        # The unicast case sends the request directly to the known target MAC
        # rather than the broadcast address. Pin the request's Ethernet
        # destination to the target endpoint's hardware address (the resolved
        # target MAC the reply also carries) so the request stays unicast and
        # the target MAC remains a single source of truth across the request
        # frame, the target service, and the is-at validation contract.
        target_mac_value = target_service.get("target_hardware_addr")
        if isinstance(target_mac_value, str) and target_mac_value:
            updated["ethernet_destination"] = target_mac_value
    if case_name == "arp-cache-flush-reply":
        # The cache-flush case carries an explicit pre-stimulus neighbor flush
        # (a `flush_neighbor` marker plus the setup/cleanup `ip neigh` commands)
        # both at the top level (read by the endpoint via the flattened plan)
        # and mirrored into the target service. The documentation-space commands
        # name the stimulus IPv4; rewrite that onto the lab segment so the live
        # setup flushes the querier the on-segment who-has actually resolves.
        doc_stimulus_ipv4 = str(plan.get("source_ipv4", ""))

        def _rewrite_flush(commands: object) -> object:
            if not isinstance(commands, list):
                return commands
            rewritten = [
                command.replace(doc_stimulus_ipv4, source_ipv4)
                if isinstance(command, str) and doc_stimulus_ipv4
                else command
                for command in commands
            ]
            if resolved_target_interface:
                old_interface = _string_or(
                    updated.get("neighbor_flush_interface"),
                    _string_or(target_service.get("neighbor_flush_interface"), "eth0"),
                )
                rewritten = [
                    command.replace(
                        f" dev {old_interface}",
                        f" dev {resolved_target_interface}",
                    )
                    if isinstance(command, str)
                    else command
                    for command in rewritten
                ]
            return rewritten

        for key in ("neighbor_flush_commands", "neighbor_flush_cleanup_commands"):
            if key in updated:
                updated[key] = _rewrite_flush(updated[key])
            if key in target_service:
                target_service[key] = _rewrite_flush(target_service[key])
        if resolved_target_interface:
            updated["neighbor_flush_interface"] = resolved_target_interface
            target_service["neighbor_flush_interface"] = resolved_target_interface
        updated["target_service"] = target_service
    # arp-repeat-two-replies carries a per-send array: rewrite each who-has
    # send's ARP protocol addresses and is-at validation contract onto the lab
    # segment so every send resolves the same target and each decoded is-at
    # reply is validated against its own send. The two sends share the target
    # (the case point is a repeated who-has for one target), so they all
    # resolve the same on-segment protocol addresses.
    arp_sends = updated.get("arp_sends")
    if isinstance(arp_sends, list):
        rewritten_arp_sends: list[JSONObject] = []
        for raw_send in arp_sends:
            send = dict(json_object(raw_send, "probe_plan.arp_send"))
            send["source_ipv4"] = source_ipv4
            send["destination_ipv4"] = target_ipv4
            send["expected_reply_source_ipv4"] = target_ipv4
            send["expected_reply_destination_ipv4"] = source_ipv4
            send["sender_protocol_addr"] = source_ipv4
            send["target_protocol_addr"] = target_ipv4
            if resolved_source_mac:
                send["sender_hardware_addr"] = resolved_source_mac
                send["ethernet_source"] = resolved_source_mac
            send_validation = dict(
                json_object(send.get("validation", {}), "probe_plan.arp_send.validation")
            )
            send_validation["sender_protocol_addr"] = target_ipv4
            send_validation["target_protocol_addr"] = source_ipv4
            if resolved_target_mac:
                send_validation["sender_hardware_addr"] = resolved_target_mac
                send_validation["ethernet_source"] = resolved_target_mac
            if resolved_source_mac:
                send_validation["target_hardware_addr"] = resolved_source_mac
                send_validation["ethernet_destination"] = resolved_source_mac
            send["validation"] = send_validation
            rewritten_arp_sends.append(send)
        updated["arp_sends"] = rewritten_arp_sends
    live_rewrite: JSONObject = {
        "source": rewrite_source,
        "stimulus_ipv4": source_ipv4,
        "target_ipv4": target_ipv4,
    }
    if is_alias_case:
        live_rewrite["alias_ipv4"] = resolved_ipv4
    if is_filtered_capture_case:
        decoy_arp_event = updated.get("decoy_arp_event")
        if isinstance(decoy_arp_event, dict):
            live_rewrite["decoy_sender_ipv4"] = decoy_arp_event.get(
                "sender_protocol_addr"
            )
            live_rewrite["decoy_target_ipv4"] = decoy_arp_event.get(
                "target_protocol_addr"
            )
    updated["live_address_rewrite"] = live_rewrite
    return updated


# --------------------------------------------------------------------------- #
# Failure-reason taxonomy (moved from cli._failure_reasons_for_case)
# --------------------------------------------------------------------------- #


_ARP_SETUP_SENSITIVE_CASES: frozenset[str] = frozenset(
    {
        "arp-alias-address-reply",
        "arp-cache-flush-reply",
        "arp-spa-variation",
        "arp-broadcast-filtered-capture",
    }
)
_ARP_PLAIN_CASES: frozenset[str] = frozenset(
    {
        "arp-resolution",
        "arp-basic-who-has",
        "arp-repeat-two-replies",
        "arp-source-address-preserved",
        "arp-unicast-request-reply",
        "arp-padding-reply",
        "arp-mac-validation",
    }
)


def arp_failure_reasons(case_name: str) -> list[str] | None:
    """Return the ordered ARP failure-reason taxonomy for ``case_name``.

    Moved verbatim from the two ARP branches of
    ``cli._failure_reasons_for_case``. Returns ``None`` for a non-ARP case so
    the central dispatcher falls through to the next branch.
    """

    if case_name in _ARP_SETUP_SENSITIVE_CASES:
        # The alias case adds (and removes) a secondary IPv4 on the target
        # interface as part of target setup; the cache-flush case flushes the
        # neighbor cache before the stimulus as part of target setup; the
        # spa-variation case may configure a secondary *sender* IPv4 so the kernel
        # accepts the reply addressed to the alternate SPA; the filtered-capture
        # case may emit a decoy ARP setup event. Any setup step failing is a
        # distinct failure mode on top of the shared ARP reasons.
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_DECODE_FAILED,
            FAILURE_TARGET_SETUP_FAILED,
        ]
    if case_name in _ARP_PLAIN_CASES:
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_DECODE_FAILED,
        ]
    return None


# --------------------------------------------------------------------------- #
# Lab-capability derivation (moved from lab.probe_capabilities_from_lab_capabilities)
# --------------------------------------------------------------------------- #


def arp_lab_capabilities(substrate: Mapping[str, JSONValue]) -> Mapping[str, object]:
    """Return the ARP plugin's derived probe-capability contribution.

    Moved verbatim from the ARP boolean derivation in
    ``lab.probe_capabilities_from_lab_capabilities``: ``arp_resolution`` needs a
    same-segment link-layer substrate (send/capture + broadcast), and
    ``link_layer_arp`` additionally needs the provider's target MAC. The
    ``capability_names``/``capability_sources`` tables stay in ``lab`` (they are
    the shared cross-protocol structure); this hook contributes only the two
    derived booleans, merged byte-identically over the legacy values.
    """

    link_layer_send = capability(substrate, "link_layer_send")
    link_layer_capture = capability(substrate, "link_layer_capture")
    broadcast = capability(substrate, "broadcast")
    provider_mac = capability(substrate, "provider_mac_known", "provider_mac")
    arp_resolution = link_layer_send and link_layer_capture and broadcast
    link_layer_arp = arp_resolution and provider_mac
    return {
        "arp_resolution": arp_resolution,
        "link_layer_arp": link_layer_arp,
    }


# --------------------------------------------------------------------------- #
# Live-plan candidate annotation (moved from
# live.plans_with_arp_sender_protocol_candidates)
# --------------------------------------------------------------------------- #


def _dedupe_strings(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def arp_live_plan_candidates(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Make batched live ARP validation explicit about local sender IP choices.

    Full-suite target setup batches every ARP case onto one VM. Some cases add
    secondary IPv4 addresses to the target interface; Linux may use any matching
    local address as the ARP reply sender protocol while still replying to the
    planned querier SPA. The SPA-variation assertion is about the reply target
    protocol, so keep the possible sender protocol values explicit in its plan.

    Moved verbatim from ``live.plans_with_arp_sender_protocol_candidates`` so the
    live path stays protocol-agnostic and consults this ARP plugin contribution
    through the generic ``live_plan_candidates`` hook.
    """

    target_sender_protocols: list[str] = []
    for plan in probe_plans:
        service = _json_mapping(
            plan.get("target_service", {}),
            "probe_plan.target_service",
        )
        for key in (
            "bind_ipv4",
            "target_protocol_addr",
            "alias_ipv4",
            "alt_sender_ipv4",
        ):
            value = _string_or(service.get(key), "")
            if value:
                target_sender_protocols.append(value)
        destination = _string_or(plan.get("destination_ipv4"), "")
        if destination:
            target_sender_protocols.append(destination)
    target_sender_protocols = _dedupe_strings(target_sender_protocols)

    rewritten: list[JSONObject] = []
    for plan in probe_plans:
        if plan.get("case") != "arp-spa-variation":
            rewritten.append(dict(plan))
            continue
        updated = dict(plan)
        validation = dict(
            _json_mapping(updated.get("validation", {}), "probe_plan.validation")
        )
        canonical = _string_or(validation.get("sender_protocol_addr"), "")
        candidates = _dedupe_strings([canonical, *target_sender_protocols])
        if candidates:
            validation["sender_protocol_addrs"] = candidates
            updated["validation"] = validation
        rewritten.append(updated)
    return rewritten


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
        # ARP target-service / address-rewrite / failure-reason / lab-capability
        # hooks (step 18). ``target_service`` contributes the ``arp_kernel_state``
        # plan key (and diverts the ARP cases off the legacy target path).
        # ``setup_script`` stays ``None``: ARP's setup-script block needs the
        # planned ARP plans, which the plugin ``setup_script`` hook does not
        # receive, so ``target_services.target_service_setup_script`` renders the
        # block by calling :func:`arp_target_setup_lines` directly (the same way
        # the legacy code rendered it, byte-identically).
        target_service=arp_target_service_contribution,
        setup_script=None,
        rewrite_endpoint_addresses=arp_rewrite_endpoint_addresses,
        failure_reasons=arp_failure_reasons,
        lab_capabilities=arp_lab_capabilities,
        # ARP is the only protocol that annotates batched live plans with
        # alternate sender-protocol candidates; the live path folds this through
        # the generic ``live_plan_candidates`` hook instead of an ARP-specific
        # branch in ``live.py``.
        live_plan_candidates=arp_live_plan_candidates,
    )
)
