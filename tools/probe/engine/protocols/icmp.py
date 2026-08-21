"""Deterministic ICMP probe cases and packet plans."""

from __future__ import annotations
from ..validation import (
    FAILURE_DECODE_FAILED,
    FAILURE_TIMEOUT,
    FAILURE_WRONG_PAYLOAD,
    FAILURE_WRONG_PEER,
)
from ..model import JSONObject, ProbeCase
from ..planning_helpers import (
    deterministic_bytes,
    deterministic_ipv4_pair,
    deterministic_router_ipv4,
)
from .base import ProtocolPlugin, register

ICMP_ECHO_CASE: ProbeCase = ProbeCase(
    name="icmp-echo",
    description="Send ICMP echo request and validate echo reply from peer kernel.",
    stimulus="icmp_echo_request",
    expected_response="icmp_echo_reply",
    required_capabilities=["icmp_echo"],
    endpoint_roles=["stimulus", "target"],
    metadata={"protocol": "icmp", "service": "kernel"},
)
TTL_EXPIRED_CASE: ProbeCase = ProbeCase(
    name="ttl-expired",
    description="Send low-TTL packet and validate ICMP TTL-expired from controlled hop.",
    stimulus="low_ttl_probe",
    expected_response="icmp_ttl_expired",
    required_capabilities=["controlled_router"],
    endpoint_roles=["stimulus", "router"],
    metadata={"protocol": "icmp", "service": "controlled_router"},
)


def _icmp_echo_probe_plan(
    *, case_name: str = "icmp-echo", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes("icmp-echo", profile, seed, sequence)
    identifier = int.from_bytes(digest[0:2], "big") or 1
    sequence_number = int.from_bytes(digest[2:4], "big")
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    payload = f"libcrafter-probe:icmp-echo:{profile}:{seed}:{sequence}:{digest.hex()[:16]}".encode(
        "ascii"
    )
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
        "capture_filter": f"icmp and src host {target_ipv4} and dst host {stimulus_ipv4}",
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


def _ttl_expired_probe_plan(
    *, case_name: str = "ttl-expired", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes("ttl-expired", profile, seed, sequence)
    stimulus_ipv4, destination_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    identifier = int.from_bytes(digest[0:2], "big") or 1
    sequence_number = int.from_bytes(digest[2:4], "big")
    payload = f"libcrafter-probe:ttl-expired:{profile}:{seed}:{sequence}:{digest.hex()[:16]}".encode(
        "ascii"
    )
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
        "capture_filter": f"icmp and src host {router_ipv4} and dst host {stimulus_ipv4}",
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


_ICMP_PLAN_BUILDERS: dict[str, object] = {
    "icmp-echo": _icmp_echo_probe_plan,
    "ttl-expired": _ttl_expired_probe_plan,
}
_ICMP_STIMULUS_ENDPOINT_CASES: frozenset[str] = frozenset({"icmp-echo", "ttl-expired"})


def icmp_failure_reasons(case_name: str) -> list[str] | None:
    if case_name in _ICMP_STIMULUS_ENDPOINT_CASES:
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_DECODE_FAILED,
        ]
    return None


register(
    ProtocolPlugin(
        name="icmp",
        cases=(ICMP_ECHO_CASE, TTL_EXPIRED_CASE),
        plan_builders=_ICMP_PLAN_BUILDERS,
        planned_only_cases=frozenset(),
        profile_counts={},
        stimulus_endpoint_cases=_ICMP_STIMULUS_ENDPOINT_CASES,
        failure_reasons=icmp_failure_reasons,
    )
)
