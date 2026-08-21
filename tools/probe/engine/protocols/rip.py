"""Deterministic RIP probe cases and packet plans."""

from __future__ import annotations
from ..case_helpers import _behavior_case
from ..model import JSONObject, ProbeCase
from ..planning_helpers import (
    deterministic_bytes,
    deterministic_documentation_ipv6,
    deterministic_ipv4_pair,
)
from .base import ProtocolPlugin, register

RIP_SERVICE_KIND = "frr-ripd"
RIP_SERVICE_PORTS = [520]
RIP_MULTICAST_GROUP = "224.0.0.9"
RIP_DOCUMENTATION_IPV4_PREFIX = "198.51.100.0/24"
RIP_RIB_COMMAND = "vtysh -c 'show ip rip'"
_RIP_UDP_PORT = RIP_SERVICE_PORTS[0]
_RIP_MULTICAST_GROUP = RIP_MULTICAST_GROUP
_RIP_RIB_COMMAND = RIP_RIB_COMMAND
_RIPNG_UDP_PORT = 521
_RIPNG_MULTICAST_GROUP = "ff02::9"
_RIPNG_RIB_COMMAND = "vtysh -c 'show ipv6 ripng'"
_RIPNG_DOCUMENTATION_IPV6_PREFIX = "2001:db8::/32"
_RIP_CAPABILITIES = ["rip_peer"]
RIP_SMOKE_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="rip-update-v2",
        description="Plan a RIPv2 update exchange against a controlled RIP daemon.",
        stimulus="rip_request",
        expected_response="rip_peer_update",
        required_capabilities=_RIP_CAPABILITIES,
        protocol="rip",
        metadata={"service": "frr-ripd", "stateful": True, "planned_only": True},
    ),
    _behavior_case(
        name="ripng-update",
        description="Plan a RIPng update exchange against a controlled RIPng daemon over UDP/521 to the ff02::9 multicast group.",
        stimulus="ripng_request",
        expected_response="ripng_peer_update",
        required_capabilities=_RIP_CAPABILITIES,
        protocol="ripng",
        metadata={"service": "frr-ripngd", "stateful": True, "planned_only": True},
    ),
)


def _rip_update_probe_plan(
    *, case_name: str = "rip-update-v2", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 42000 + int.from_bytes(digest[0:2], "big") % 10000
    documentation_prefixes = [RIP_DOCUMENTATION_IPV4_PREFIX]
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
        "capture_filter": f"udp and src host {target_ipv4} and src port {_RIP_UDP_PORT} and dst port {_RIP_UDP_PORT}",
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
            "note": "RIP smoke dry-run exposes the rip_request stimulus intent and controlled FRR ripd peer precondition without sending UDP/520 datagrams or installing FRR.",
        },
        "digest_hex": digest.hex()[:16],
    }


def _ripng_update_probe_plan(
    *, case_name: str = "ripng-update", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv6 = deterministic_documentation_ipv6(digest)
    target_ipv6 = deterministic_documentation_ipv6(digest[::-1])
    source_port = 42000 + int.from_bytes(digest[0:2], "big") % 10000
    documentation_prefixes = [_RIPNG_DOCUMENTATION_IPV6_PREFIX]
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
        "capture_filter": f"udp and src host {target_ipv6} and src port {_RIPNG_UDP_PORT} and dst port {_RIPNG_UDP_PORT}",
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
            "note": "RIPng smoke dry-run exposes the ripng_request stimulus intent and controlled FRR ripngd peer precondition without sending UDP/521 datagrams or installing FRR.",
        },
        "digest_hex": digest.hex()[:16],
    }


_RIP_PLAN_BUILDERS: dict[str, object] = {
    "rip-update-v2": _rip_update_probe_plan,
    "ripng-update": _ripng_update_probe_plan,
}
_RIP_PLANNED_ONLY_CASES: frozenset[str] = frozenset({"rip-update-v2", "ripng-update"})
register(
    ProtocolPlugin(
        name="rip",
        cases=RIP_SMOKE_CASES,
        plan_builders=_RIP_PLAN_BUILDERS,
        planned_only_cases=_RIP_PLANNED_ONLY_CASES,
        profile_counts={},
        stimulus_endpoint_cases=frozenset(),
        failure_reasons=None,
    )
)
