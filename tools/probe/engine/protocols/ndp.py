"""Deterministic NDP probe cases and packet plans."""

from __future__ import annotations
import ipaddress
from ..case_helpers import _behavior_case
from ..model import JSONObject, ProbeCase
from ..planning_helpers import deterministic_bytes, deterministic_documentation_mac
from .base import ProtocolPlugin, register

_NDP_CAPABILITIES = ["link_layer_send", "link_layer_capture", "ipv6_multicast"]
BEHAVIOR_NDP_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="ndp-neighbor-solicitation",
        description="Send a Neighbor Solicitation (ICMPv6 type 135) to the target's solicited-node multicast group and validate the kernel's solicited Neighbor Advertisement (type 136).",
        stimulus="ndp_neighbor_solicitation",
        expected_response="ndp_neighbor_advertisement",
        required_capabilities=_NDP_CAPABILITIES,
        protocol="ndp",
        metadata={"layer": "network"},
    ),
    _behavior_case(
        name="ndp-router-solicitation",
        description="Send a Router Solicitation (ICMPv6 type 133) to the all-routers multicast group and validate a Router Advertisement (type 134).",
        stimulus="ndp_router_solicitation",
        expected_response="ndp_router_advertisement",
        required_capabilities=_NDP_CAPABILITIES,
        protocol="ndp",
        metadata={
            "layer": "network",
            "requires_router_target": True,
            "notes": "Needs the target to act as a router and emit Router Advertisements; a bare kernel does not answer a Router Solicitation. Live runners configure an RA-emitting router or skip this case.",
        },
    ),
    _behavior_case(
        name="ndp-duplicate-address-detection",
        description="Send a Duplicate Address Detection Neighbor Solicitation from the unspecified source (::) for an address the target owns and validate the target's defending Neighbor Advertisement.",
        stimulus="ndp_duplicate_address_detection",
        expected_response="ndp_neighbor_advertisement",
        required_capabilities=_NDP_CAPABILITIES,
        protocol="ndp",
        metadata={
            "layer": "network",
            "dad": True,
            "notes": "Unspecified-source (::) DAD solicitation with no SLLA option; the target defends an owned address with a Neighbor Advertisement (RFC 4861 section 4.3 / RFC 4862).",
        },
    ),
)
NDP_ROUTER_SOLICITATION_TYPE = 133
NDP_ROUTER_ADVERTISEMENT_TYPE = 134
NDP_NEIGHBOR_SOLICITATION_TYPE = 135
NDP_NEIGHBOR_ADVERTISEMENT_TYPE = 136
IPV6_UNSPECIFIED = "::"
IPV6_ALL_NODES_MULTICAST = "ff02::1"
IPV6_ALL_ROUTERS_MULTICAST = "ff02::2"


def deterministic_link_local_ipv6(
    profile: str, seed: int, sequence: int, *, role: str
) -> str:
    digest = deterministic_bytes(f"ndp-link-local-{role}", profile, seed, sequence)
    group_a = int.from_bytes(digest[0:2], "big")
    group_b = int.from_bytes(digest[2:4], "big")
    group_c = int.from_bytes(digest[4:6], "big")
    host = 1 + int.from_bytes(digest[6:8], "big") % 65534
    return f"fe80::{group_a:x}:{group_b:x}:{group_c:x}:{host:x}"


def deterministic_target_ipv6(profile: str, seed: int, sequence: int) -> str:
    return deterministic_link_local_ipv6(profile, seed, sequence, role="target")


def solicited_node_multicast(unicast_ipv6: str) -> str:
    packed = ipaddress.ip_address(unicast_ipv6).packed
    prefix = bytes.fromhex("ff0200000000000000000001ff000000")
    solicited = bytearray(prefix)
    solicited[13:16] = packed[13:16]
    return str(ipaddress.IPv6Address(bytes(solicited)))


def _ndp_wire_requirements() -> JSONObject:
    return {
        "requires_link_layer_send": True,
        "requires_link_layer_capture": True,
        "requires_ipv6_multicast": True,
        "note": "NDP is link-scoped IPv6 multicast/unicast traffic (RFC 4861); it runs only on an externally managed isolated segment, never from privileged host raw sends.",
    }


def _ndp_neighbor_solicitation_probe_plan(
    *,
    case_name: str = "ndp-neighbor-solicitation",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    source_ipv6 = deterministic_link_local_ipv6(
        profile, seed, sequence, role="stimulus"
    )
    target_ipv6 = deterministic_target_ipv6(profile, seed, sequence)
    stimulus_mac = deterministic_documentation_mac(
        profile, seed, sequence, role="stimulus"
    )
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
        "capture_filter": "icmp6 and ip6[40] = 136",
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
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    source_ipv6 = deterministic_link_local_ipv6(
        profile, seed, sequence, role="stimulus"
    )
    router_ipv6 = deterministic_link_local_ipv6(profile, seed, sequence, role="target")
    stimulus_mac = deterministic_documentation_mac(
        profile, seed, sequence, role="stimulus"
    )
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
        "capture_filter": "icmp6 and ip6[40] = 134",
        "requires_router_target": True,
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
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    target_ipv6 = deterministic_target_ipv6(profile, seed, sequence)
    target_mac = deterministic_documentation_mac(profile, seed, sequence, role="target")
    stimulus_mac = deterministic_documentation_mac(
        profile, seed, sequence, role="stimulus"
    )
    solicited_node = solicited_node_multicast(target_ipv6)
    validation = {
        "ip_version": 6,
        "icmpv6_type": NDP_NEIGHBOR_ADVERTISEMENT_TYPE,
        "icmpv6_code": 0,
        "response_label": "neighbor-advertisement",
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
        "source_ipv6": IPV6_UNSPECIFIED,
        "destination_ipv6": solicited_node,
        "target_ipv6": target_ipv6,
        "solicited_node_multicast": solicited_node,
        "dad": True,
        "omit_source_link_layer_addr": True,
        "ethernet_source": stimulus_mac,
        "expected_reply_source_ipv6": target_ipv6,
        "expected_reply_destination_ipv6": IPV6_ALL_NODES_MULTICAST,
        "capture_filter": "icmp6 and ip6[40] = 136",
        "validation": validation,
        "ndp_validation": validation,
        "wire_requirements": _ndp_wire_requirements(),
        "digest_hex": digest.hex()[:16],
    }


_NDP_PLAN_BUILDERS: dict[str, object] = {
    "ndp-neighbor-solicitation": _ndp_neighbor_solicitation_probe_plan,
    "ndp-router-solicitation": _ndp_router_solicitation_probe_plan,
    "ndp-duplicate-address-detection": _ndp_duplicate_address_detection_probe_plan,
}
_NDP_STIMULUS_ENDPOINT_CASES: frozenset[str] = frozenset(
    {
        "ndp-neighbor-solicitation",
        "ndp-router-solicitation",
        "ndp-duplicate-address-detection",
    }
)


def ndp_failure_reasons(case_name: str) -> list[str] | None:
    return None


register(
    ProtocolPlugin(
        name="ndp",
        cases=BEHAVIOR_NDP_CASES,
        plan_builders=_NDP_PLAN_BUILDERS,
        planned_only_cases=frozenset(),
        profile_counts={},
        stimulus_endpoint_cases=_NDP_STIMULUS_ENDPOINT_CASES,
        failure_reasons=ndp_failure_reasons,
    )
)
