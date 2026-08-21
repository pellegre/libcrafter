"""Deterministic BGP probe cases and packet plans."""

from __future__ import annotations
from ..case_helpers import _behavior_case
from ..model import JSONObject, ProbeCase
from ..planning_helpers import deterministic_bytes, deterministic_ipv4_pair
from .base import ProtocolPlugin, register

BGP_SERVICE_PORT = 179
BGP_DRIVER_AS = 65000
BGP_PEER_AS = 65001
BGP_DOCUMENTATION_IPV4_PREFIX = "198.51.100.0/24"
BGP_DOCUMENTATION_IPV6_PREFIX = "2001:db8::/32"
BGP_RIB_COMMAND = "vtysh -c 'show bgp ipv4 unicast'"
_BGP_CAPABILITIES = ["bgp_peer"]
BGP_SESSION_SMOKE_CASE: ProbeCase = _behavior_case(
    name="bgp-session-smoke",
    description="Plan a BGP session exchange against a controlled FRR peer peer.",
    stimulus="bgp_session",
    expected_response="bgp_peer_session",
    required_capabilities=_BGP_CAPABILITIES,
    protocol="bgp",
    metadata={"service": "frr-bgp-peer", "stateful": True, "planned_only": True},
)


def _bgp_session_smoke_probe_plan(
    *, case_name: str = "bgp-session-smoke", profile: str, seed: int, sequence: int
) -> JSONObject:
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
        "capture_filter": f"tcp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {BGP_SERVICE_PORT} and dst port {source_port}",
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
            "note": "BGP smoke dry-run exposes the bgp_session stimulus intent and controlled FRR peer precondition without opening TCP sessions or installing FRR.",
        },
        "digest_hex": digest.hex()[:16],
    }


_BGP_PLAN_BUILDERS: dict[str, object] = {
    "bgp-session-smoke": _bgp_session_smoke_probe_plan
}
_BGP_PLANNED_ONLY_CASES: frozenset[str] = frozenset({"bgp-session-smoke"})
register(
    ProtocolPlugin(
        name="bgp",
        cases=(BGP_SESSION_SMOKE_CASE,),
        plan_builders=_BGP_PLAN_BUILDERS,
        planned_only_cases=_BGP_PLANNED_ONLY_CASES,
        profile_counts={},
        stimulus_endpoint_cases=frozenset(),
        failure_reasons=None,
    )
)
