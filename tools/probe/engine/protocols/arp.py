"""Deterministic ARP probe cases and packet plans."""

from __future__ import annotations
from ..case_helpers import _behavior_case
from ..validation import (
    FAILURE_DECODE_FAILED,
    FAILURE_TIMEOUT,
    FAILURE_WRONG_PAYLOAD,
    FAILURE_WRONG_PEER,
)
from ..model import JSONObject, ProbeCase
from ..planning_helpers import (
    deterministic_bytes,
    deterministic_documentation_mac,
    deterministic_ipv4_pair,
)
from .base import ProtocolPlugin, register

_ARP_CAPABILITIES = [
    "arp_resolution",
    "link_layer_send",
    "link_layer_capture",
    "broadcast",
]
_ARP_PEER_MAC_CAPABILITIES = [*_ARP_CAPABILITIES, "peer_mac"]
_ARP_UNICAST_CAPABILITIES = _ARP_PEER_MAC_CAPABILITIES
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
        description="Validate that the reply is addressed to the request's sender hardware/protocol address.",
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
        description="Send the ARP request to the known target MAC (not broadcast) and validate the reply.",
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
        description="Validate that the reply Ethernet source and ARP sender hardware address both equal the target endpoint MAC.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_PEER_MAC_CAPABILITIES,
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
        description="Capture ARP replies on a noisy segment and validate only the matching target reply.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
)
ARP_RESOLUTION_CASE: ProbeCase = ProbeCase(
    name="arp-resolution",
    description="Broadcast an ARP who-has request on the isolated segment and validate the target's unicast is-at reply.",
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
    *, case_name: str = "arp-resolution", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes("arp-resolution", profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(
        profile, seed, sequence, role="stimulus"
    )
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
        "ethertype": 2054,
        "hardware_type": 1,
        "protocol_type": 2048,
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
        "validation": {
            "ethertype": 2054,
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
            "note": "ARP resolution is L2 broadcast/unicast traffic; it runs only on an externally managed isolated segment, never from privileged host raw sends.",
        },
        "digest_hex": digest.hex()[:16],
    }


def _arp_basic_who_has_probe_plan(
    *, case_name: str = "arp-basic-who-has", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(
        profile, seed, sequence, role="stimulus"
    )
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
        "ethertype": 2054,
        "hardware_type": 1,
        "protocol_type": 2048,
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
        "validation": {
            "ethertype": 2054,
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
            "note": "ARP resolution is L2 broadcast/unicast traffic; it runs only on an externally managed isolated segment, never from privileged host raw sends.",
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
    return {
        "index": index,
        "ethertype": 2054,
        "hardware_type": 1,
        "protocol_type": 2048,
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
        "validation": {
            "ethertype": 2054,
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
    *, case_name: str = "arp-repeat-two-replies", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(
        profile, seed, sequence, role="stimulus"
    )
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
        "ethertype": 2054,
        "hardware_type": 1,
        "protocol_type": 2048,
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
        "send_count": len(sends),
        "arp_sends": sends,
        "validation": first["validation"],
        "wire_requirements": {
            "requires_link_layer_send": True,
            "requires_link_layer_capture": True,
            "requires_broadcast": True,
            "note": "ARP resolution is L2 broadcast/unicast traffic; it runs only on an externally managed isolated segment, never from privileged host raw sends.",
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
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(
        profile, seed, sequence, role="stimulus"
    )
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
        "ethertype": 2054,
        "hardware_type": 1,
        "protocol_type": 2048,
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
        "validation": {
            "ethertype": 2054,
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
            "note": "ARP resolution is L2 broadcast/unicast traffic; it runs only on an externally managed isolated segment, never from privileged host raw sends.",
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
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    alias_ipv4 = deterministic_arp_alias_ipv4(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(
        profile, seed, sequence, role="stimulus"
    )
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
        "ethertype": 2054,
        "hardware_type": 1,
        "protocol_type": 2048,
        "hardware_length": 6,
        "protocol_length": 4,
        "operation": 1,
        "operation_label": "request",
        "sender_hardware_addr": stimulus_mac,
        "sender_protocol_addr": stimulus_ipv4,
        "target_hardware_addr": zero_mac,
        "target_protocol_addr": alias_ipv4,
        "ethernet_source": stimulus_mac,
        "ethernet_destination": broadcast_mac,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": alias_ipv4,
        "alias_ipv4": alias_ipv4,
        "expected_reply_source_ipv4": alias_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "capture_filter": "arp and arp[6:2] = 2",
        "validation": {
            "ethertype": 2054,
            "operation": 2,
            "operation_label": "reply",
            "sender_hardware_addr": target_mac,
            "sender_protocol_addr": alias_ipv4,
            "target_hardware_addr": stimulus_mac,
            "target_protocol_addr": stimulus_ipv4,
            "ethernet_source": target_mac,
            "ethernet_destination": stimulus_mac,
        },
        "wire_requirements": {
            "requires_link_layer_send": True,
            "requires_link_layer_capture": True,
            "requires_broadcast": True,
            "note": "ARP resolution is L2 broadcast/unicast traffic; it runs only on an externally managed isolated segment, never from privileged host raw sends.",
        },
        "digest_hex": digest.hex()[:16],
    }


def _arp_spa_variation_probe_plan(
    *, case_name: str = "arp-spa-variation", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    alt_sender_ipv4 = deterministic_arp_alt_sender_ipv4(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(
        profile, seed, sequence, role="stimulus"
    )
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
        "ethertype": 2054,
        "hardware_type": 1,
        "protocol_type": 2048,
        "hardware_length": 6,
        "protocol_length": 4,
        "operation": 1,
        "operation_label": "request",
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
        "capture_filter": "arp and arp[6:2] = 2",
        "validation": {
            "ethertype": 2054,
            "operation": 2,
            "operation_label": "reply",
            "sender_hardware_addr": target_mac,
            "sender_protocol_addr": target_ipv4,
            "target_hardware_addr": stimulus_mac,
            "target_protocol_addr": alt_sender_ipv4,
            "ethernet_source": target_mac,
            "ethernet_destination": stimulus_mac,
        },
        "wire_requirements": {
            "requires_link_layer_send": True,
            "requires_link_layer_capture": True,
            "requires_broadcast": True,
            "note": "ARP resolution is L2 broadcast/unicast traffic; it runs only on an externally managed isolated segment, never from privileged host raw sends.",
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
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(
        profile, seed, sequence, role="stimulus"
    )
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
        "ethertype": 2054,
        "hardware_type": 1,
        "protocol_type": 2048,
        "hardware_length": 6,
        "protocol_length": 4,
        "operation": 1,
        "operation_label": "request",
        "sender_hardware_addr": stimulus_mac,
        "sender_protocol_addr": stimulus_ipv4,
        "target_hardware_addr": zero_mac,
        "target_protocol_addr": target_ipv4,
        "ethernet_source": stimulus_mac,
        "ethernet_destination": target_mac,
        "request_is_unicast": True,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "capture_filter": "arp and arp[6:2] = 2",
        "validation": {
            "ethertype": 2054,
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
            "note": "ARP resolution is L2 broadcast/unicast traffic; it runs only on an externally managed isolated segment, never from privileged host raw sends.",
        },
        "digest_hex": digest.hex()[:16],
    }


def _arp_padding_reply_probe_plan(
    *, case_name: str = "arp-padding-reply", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(
        profile, seed, sequence, role="stimulus"
    )
    target_mac = deterministic_documentation_mac(profile, seed, sequence, role="target")
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    zero_mac = "00:00:00:00:00:00"
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
        "ethertype": 2054,
        "hardware_type": 1,
        "protocol_type": 2048,
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
        "ethernet_min_frame_len": min_frame_len,
        "expected_request_frame_len": min_frame_len,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "capture_filter": "arp and arp[6:2] = 2",
        "validation": {
            "ethertype": 2054,
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
            "note": "ARP resolution is L2 broadcast/unicast traffic; it runs only on an externally managed isolated segment, never from privileged host raw sends.",
        },
        "digest_hex": digest.hex()[:16],
    }


def _arp_cache_flush_reply_probe_plan(
    *, case_name: str = "arp-cache-flush-reply", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(
        profile, seed, sequence, role="stimulus"
    )
    target_mac = deterministic_documentation_mac(profile, seed, sequence, role="target")
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    zero_mac = "00:00:00:00:00:00"
    flush_interface = "eth0"
    flush_commands = [
        f"ip neigh flush dev {flush_interface} || true",
        f"ip neigh del {stimulus_ipv4} dev {flush_interface} || true",
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
        "ethertype": 2054,
        "hardware_type": 1,
        "protocol_type": 2048,
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
        "flush_neighbor": True,
        "neighbor_flush_interface": flush_interface,
        "neighbor_flush_commands": flush_commands,
        "capture_filter": "arp and arp[6:2] = 2",
        "validation": {
            "ethertype": 2054,
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
            "note": "ARP resolution is L2 broadcast/unicast traffic; it runs only on an externally managed isolated segment, never from privileged host raw sends.",
        },
        "digest_hex": digest.hex()[:16],
    }


def _arp_mac_validation_probe_plan(
    *, case_name: str = "arp-mac-validation", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(
        profile, seed, sequence, role="stimulus"
    )
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
        "ethertype": 2054,
        "hardware_type": 1,
        "protocol_type": 2048,
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
        "validation": {
            "ethertype": 2054,
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
            "note": "ARP resolution is L2 broadcast/unicast traffic; it runs only on an externally managed isolated segment, never from privileged host raw sends.",
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
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    decoy_sender_ipv4 = deterministic_arp_alias_ipv4(profile, seed, sequence)
    decoy_target_ipv4 = deterministic_arp_alt_sender_ipv4(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(
        profile, seed, sequence, role="stimulus"
    )
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
        "ethertype": 2054,
        "hardware_type": 1,
        "protocol_type": 2048,
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
        "capture_filter": "arp and arp[6:2] = 2",
        "ignore_unmatched_arp_replies": True,
        "decoy_arp_event": decoy_arp_event,
        "validation": {
            "ethertype": 2054,
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
            "note": "ARP resolution is L2 broadcast/unicast traffic; it runs only on an externally managed isolated segment, never from privileged host raw sends.",
        },
        "digest_hex": digest.hex()[:16],
    }


def deterministic_arp_alias_ipv4(profile: str, seed: int, sequence: int) -> str:
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
    digest = deterministic_bytes("endpoint-addresses", profile, seed, sequence)
    second = 64 + digest[0] % 64
    third = digest[1]
    alias_host = int(
        deterministic_arp_alias_ipv4(profile, seed, sequence).split(".")[3]
    )
    spa_digest = deterministic_bytes("arp-alt-sender-host", profile, seed, sequence)
    reserved = {0, 1, 10, 20, 255, alias_host}
    host = 2 + spa_digest[0] % 252
    while host in reserved:
        host = 2 + (host - 1) % 252
    return f"10.{second}.{third}.{host}"


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
    if case_name in _ARP_PLAIN_CASES:
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_DECODE_FAILED,
        ]
    return None


register(
    ProtocolPlugin(
        name="arp",
        cases=(ARP_RESOLUTION_CASE, *BEHAVIOR_ARP_CASES),
        plan_builders=_ARP_PLAN_BUILDERS,
        planned_only_cases=frozenset(),
        profile_counts={},
        stimulus_endpoint_cases=_ARP_STIMULUS_ENDPOINT_CASES,
        failure_reasons=arp_failure_reasons,
    )
)
