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

import hashlib
from collections.abc import Callable, Sequence

from .cases import PROBE_CASE_BY_NAME
from .model import JSONObject, ProbeCase, ProbeRunRequest


# A plan builder takes the deterministic planning inputs (profile, seed,
# sequence) plus the case name and returns the case's stable plan object.
PlanBuilder = Callable[..., JSONObject]


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


def _dns_query_probe_plan(
    *,
    case_name: str = "dns-query",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = deterministic_bytes("dns-query", profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    query_type_value = 1 if sequence % 2 == 0 else 28
    query_type = "A" if query_type_value == 1 else "AAAA"
    query_name = dns_query_name(profile=profile, seed=seed, sequence=sequence, digest=digest)
    if query_type == "A":
        answer_data = f"203.0.113.{1 + digest[4] % 250}"
    else:
        answer_data = (
            "2001:db8:"
            f"{int.from_bytes(digest[4:6], 'big'):x}:"
            f"{int.from_bytes(digest[6:8], 'big'):x}::"
            f"{1 + digest[8] % 65534:x}"
        )
    destination_port = 53
    answer_ttl = 60 + digest[9] % 180
    return {
        "schema_version": 1,
        "case": "dns-query",
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dns_query",
        "expected_response": "dns_response",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "query_id": query_id,
        "query_name": query_name,
        "query_type": query_type,
        "query_type_value": query_type_value,
        "query_class": "IN",
        "query_class_value": 1,
        "expected_answer_name": query_name,
        "expected_answer_type": query_type,
        "expected_answer_type_value": query_type_value,
        "expected_answer_data": answer_data,
        "expected_response_code": 0,
        "answer_ttl": answer_ttl,
        "target_service": {
            "required": True,
            "kind": "udp-dns-responder",
            "port": destination_port,
            "query_name": query_name,
            "query_type": query_type,
            "answer_data": answer_data,
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
            "query_id": query_id,
            "qr": True,
            "response_code": 0,
            "question": {
                "name": query_name,
                "type": query_type,
                "class": "IN",
            },
            "answer": {
                "name": query_name,
                "type": query_type,
                "data": answer_data,
                "ttl": answer_ttl,
            },
        },
    }


def _dns_a_success_probe_plan(
    *,
    case_name: str = "dns-a-success",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dns-a-success`` behavioral case.

    Always an A (QTYPE 1) query against the controlled UDP DNS responder on
    port 53, with a deterministic documentation-space IPv4 answer. The validation
    contract covers transaction id, QR, rcode, question (name/type/class), and
    answer (name/type/class/data/ttl) plus peer addresses and ports.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    destination_port = 53
    query_name = dns_query_name(profile=profile, seed=seed, sequence=sequence, digest=digest)
    answer_data = f"203.0.113.{1 + digest[4] % 250}"
    answer_ttl = 60 + digest[9] % 180
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dns_query",
        "expected_response": "dns_response",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "query_id": query_id,
        "query_name": query_name,
        "query_type": "A",
        "query_type_value": 1,
        "query_class": "IN",
        "query_class_value": 1,
        "expected_answer_name": query_name,
        "expected_answer_type": "A",
        "expected_answer_type_value": 1,
        "expected_answer_class": "IN",
        "expected_answer_class_value": 1,
        "expected_answer_data": answer_data,
        "expected_response_code": 0,
        "expected_response_flags": ["qr", "aa"],
        "answer_ttl": answer_ttl,
        "target_service": {
            "required": True,
            "kind": "udp-dns-responder",
            "port": destination_port,
            "query_name": query_name,
            "query_type": "A",
            "answer_data": answer_data,
            "answer_ttl": answer_ttl,
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
            "query_id": query_id,
            "qr": True,
            "response_code": 0,
            "question": {
                "name": query_name,
                "type": "A",
                "type_value": 1,
                "class": "IN",
                "class_value": 1,
            },
            "answer": {
                "name": query_name,
                "type": "A",
                "type_value": 1,
                "class": "IN",
                "class_value": 1,
                "data": answer_data,
                "ttl": answer_ttl,
            },
        },
    }


def _dns_aaaa_success_probe_plan(
    *,
    case_name: str = "dns-aaaa-success",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dns-aaaa-success`` behavioral case.

    Always an AAAA (QTYPE 28) query against the controlled UDP DNS responder on
    port 53, with a deterministic documentation-space IPv6 answer
    (``2001:db8::/32``). The lab transport stays IPv4; only the DNS payload
    carries the AAAA answer. The validation contract covers transaction id, QR,
    rcode, question (name/type/class), and answer (name/type/class/data/ttl)
    plus peer addresses and ports.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    destination_port = 53
    query_name = dns_query_name(profile=profile, seed=seed, sequence=sequence, digest=digest)
    answer_data = deterministic_documentation_ipv6(digest)
    answer_ttl = 60 + digest[9] % 180
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dns_query",
        "expected_response": "dns_response",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "query_id": query_id,
        "query_name": query_name,
        "query_type": "AAAA",
        "query_type_value": 28,
        "query_class": "IN",
        "query_class_value": 1,
        "expected_answer_name": query_name,
        "expected_answer_type": "AAAA",
        "expected_answer_type_value": 28,
        "expected_answer_class": "IN",
        "expected_answer_class_value": 1,
        "expected_answer_data": answer_data,
        "expected_response_code": 0,
        "expected_response_flags": ["qr", "aa"],
        "answer_ttl": answer_ttl,
        "target_service": {
            "required": True,
            "kind": "udp-dns-responder",
            "port": destination_port,
            "query_name": query_name,
            "query_type": "AAAA",
            "answer_data": answer_data,
            "answer_ttl": answer_ttl,
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
            "query_id": query_id,
            "qr": True,
            "response_code": 0,
            "question": {
                "name": query_name,
                "type": "AAAA",
                "type_value": 28,
                "class": "IN",
                "class_value": 1,
            },
            "answer": {
                "name": query_name,
                "type": "AAAA",
                "type_value": 28,
                "class": "IN",
                "class_value": 1,
                "data": answer_data,
                "ttl": answer_ttl,
            },
        },
    }


def _dns_cname_chain_probe_plan(
    *,
    case_name: str = "dns-cname-chain",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dns-cname-chain`` behavioral case.

    An A (QTYPE 1) query whose answer section is a two-record chain: a CNAME
    (QTYPE 5) record whose RDATA is the canonical domain name, followed by a
    terminal A record for that canonical name with a deterministic
    documentation-space IPv4 answer. The validation contract preserves the
    *original* question (the queried name and QTYPE A), confirms the response
    flags (QR/rcode), and asserts both answers are present with an expected
    answer count of two. ``data`` on the CNAME answer is the canonical name so
    the controlled responder's domain-name RDATA round-trips through libcrafter.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    destination_port = 53
    query_name = dns_query_name(profile=profile, seed=seed, sequence=sequence, digest=digest)
    canonical_name = dns_canonical_name(
        profile=profile, seed=seed, sequence=sequence, digest=digest
    )
    terminal_ipv4 = f"203.0.113.{1 + digest[4] % 250}"
    cname_ttl = 60 + digest[9] % 180
    address_ttl = 60 + digest[10] % 180
    expected_answer_count = 2
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dns_query",
        "expected_response": "dns_response",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "query_id": query_id,
        "query_name": query_name,
        "query_type": "A",
        "query_type_value": 1,
        "query_class": "IN",
        "query_class_value": 1,
        # The CNAME answer is the canonical name; the terminal A answer carries
        # the documentation-space IPv4 address. ``expected_answer_*`` keeps the
        # legacy single-answer fields pointed at the terminal A record so the
        # endpoint's shared answer match continues to find the address answer.
        "original_name": query_name,
        "canonical_name": canonical_name,
        "terminal_ipv4": terminal_ipv4,
        "expected_answer_count": expected_answer_count,
        "expected_answer_name": canonical_name,
        "expected_answer_type": "A",
        "expected_answer_type_value": 1,
        "expected_answer_class": "IN",
        "expected_answer_class_value": 1,
        "expected_answer_data": terminal_ipv4,
        "expected_cname_answer": {
            "name": query_name,
            "type": "CNAME",
            "type_value": 5,
            "class": "IN",
            "class_value": 1,
            "data": canonical_name,
            "ttl": cname_ttl,
        },
        "expected_response_code": 0,
        "expected_response_flags": ["qr", "aa"],
        "answer_ttl": address_ttl,
        "target_service": {
            "required": True,
            "kind": "udp-dns-responder",
            "port": destination_port,
            "query_name": query_name,
            "query_type": "A",
            "answer_data": terminal_ipv4,
            "answer_ttl": address_ttl,
            "cname_chain": {
                "canonical_name": canonical_name,
                "cname_ttl": cname_ttl,
                "address_ttl": address_ttl,
            },
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
            "query_id": query_id,
            "qr": True,
            "response_code": 0,
            "question": {
                "name": query_name,
                "type": "A",
                "type_value": 1,
                "class": "IN",
                "class_value": 1,
            },
            "answer_count": expected_answer_count,
            "cname_answer": {
                "name": query_name,
                "type": "CNAME",
                "type_value": 5,
                "class": "IN",
                "class_value": 1,
                "data": canonical_name,
                "ttl": cname_ttl,
            },
            "answer": {
                "name": canonical_name,
                "type": "A",
                "type_value": 1,
                "class": "IN",
                "class_value": 1,
                "data": terminal_ipv4,
                "ttl": address_ttl,
            },
        },
    }


def _dns_nxdomain_probe_plan(
    *,
    case_name: str = "dns-nxdomain",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dns-nxdomain`` behavioral case.

    An A (QTYPE 1) query for a deterministically planned *absent* name. The
    controlled UDP DNS responder has no record for the name, so it returns a
    negative response: rcode 3 (NXDOMAIN), QR set, the original question echoed,
    and an empty answer section (ancount 0). The validation contract asserts the
    transaction id, QR flag, rcode NXDOMAIN, the preserved question
    (name/type/class), an answer count of zero, plus the peer addresses and
    ports. ``target_service`` marks the name ``absent`` so the responder leaves
    it unregistered and answers NXDOMAIN.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    destination_port = 53
    query_name = dns_query_name(profile=profile, seed=seed, sequence=sequence, digest=digest)
    expected_answer_count = 0
    expected_response_code = 3
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dns_query",
        "expected_response": "dns_response",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "query_id": query_id,
        "query_name": query_name,
        "query_type": "A",
        "query_type_value": 1,
        "query_class": "IN",
        "query_class_value": 1,
        # NXDOMAIN carries no answer; the queried name is absent. The expected
        # answer count is zero and the rcode is 3 (NXDOMAIN). The legacy
        # ``expected_answer_*`` fields are intentionally omitted so the endpoint
        # does not look for an answer record.
        "absent_name": query_name,
        "expected_answer_count": expected_answer_count,
        "expected_response_code": expected_response_code,
        "expected_response_flags": ["qr"],
        "target_service": {
            "required": True,
            "kind": "udp-dns-responder",
            "port": destination_port,
            "query_name": query_name,
            "query_type": "A",
            "absent": True,
            "expected_response_code": expected_response_code,
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
            "query_id": query_id,
            "qr": True,
            "response_code": expected_response_code,
            "question": {
                "name": query_name,
                "type": "A",
                "type_value": 1,
                "class": "IN",
                "class_value": 1,
            },
            "answer_count": expected_answer_count,
        },
    }


def _dns_nodata_probe_plan(
    *,
    case_name: str = "dns-nodata",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dns-nodata`` behavioral case.

    An A (QTYPE 1) query for a name that *exists* in the controlled zone but only
    under a different record type (AAAA/28). The responder therefore returns a
    NODATA answer: rcode 0 (NOERROR) — not 3 (NXDOMAIN) — with the original
    question echoed and an empty answer section (ancount 0). This is behaviorally
    distinct from NXDOMAIN: the name is present, only the requested type is
    absent. The validation contract asserts the transaction id, QR flag, rcode 0
    (NOERROR), the preserved question (name/type/class), an answer count of zero,
    plus the peer addresses and ports. ``target_service`` registers the name
    under its present type and marks it ``nodata`` so the responder answers
    NODATA for the queried type without falling into the NXDOMAIN path.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    destination_port = 53
    query_name = dns_query_name(profile=profile, seed=seed, sequence=sequence, digest=digest)
    # The name exists, but only under AAAA (type 28); the A query has no record.
    present_type = "AAAA"
    present_type_value = 28
    expected_answer_count = 0
    expected_response_code = 0
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dns_query",
        "expected_response": "dns_response",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "query_id": query_id,
        "query_name": query_name,
        "query_type": "A",
        "query_type_value": 1,
        "query_class": "IN",
        "query_class_value": 1,
        # NODATA carries no answer for the queried type, even though the name
        # exists. The expected answer count is zero and the rcode is 0 (NOERROR).
        # The legacy ``expected_answer_*`` fields are intentionally omitted so the
        # endpoint does not look for an answer record.
        "present_name": query_name,
        "present_type": present_type,
        "present_type_value": present_type_value,
        "expected_answer_count": expected_answer_count,
        "expected_response_code": expected_response_code,
        "expected_response_flags": ["qr"],
        "target_service": {
            "required": True,
            "kind": "udp-dns-responder",
            "port": destination_port,
            "query_name": query_name,
            "query_type": "A",
            "nodata": True,
            "present_type": present_type,
            "present_type_value": present_type_value,
            "expected_response_code": expected_response_code,
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
            "query_id": query_id,
            "qr": True,
            "response_code": expected_response_code,
            "question": {
                "name": query_name,
                "type": "A",
                "type_value": 1,
                "class": "IN",
                "class_value": 1,
            },
            "answer_count": expected_answer_count,
        },
    }


def _dns_txt_answer_probe_plan(
    *,
    case_name: str = "dns-txt-answer",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dns-txt-answer`` behavioral case.

    A TXT (QTYPE 16) query against the controlled UDP DNS responder on port 53.
    The answer carries one or more deterministic DNS character-strings (each a
    length-prefixed byte string, 1 length octet + up to 255 bytes) so the case
    exercises variable-length RDATA: string-length encoding on the wire and the
    decoded RDATA character-string list. The validation contract covers the
    transaction id, QR, rcode, question (name/type/class), and the TXT answer
    (name/type/class, the full ordered list of character-strings, and the TTL)
    plus peer addresses and ports.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    destination_port = 53
    query_name = dns_query_name(profile=profile, seed=seed, sequence=sequence, digest=digest)
    txt_strings = dns_txt_strings(profile=profile, seed=seed, sequence=sequence, digest=digest)
    answer_ttl = 60 + digest[9] % 180
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dns_query",
        "expected_response": "dns_response",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "query_id": query_id,
        "query_name": query_name,
        "query_type": "TXT",
        "query_type_value": 16,
        "query_class": "IN",
        "query_class_value": 1,
        "expected_answer_name": query_name,
        "expected_answer_type": "TXT",
        "expected_answer_type_value": 16,
        "expected_answer_class": "IN",
        "expected_answer_class_value": 1,
        # The TXT RDATA is a list of character-strings. ``expected_txt_strings``
        # is the ordered, deterministic content the responder emits and the
        # endpoint compares the decoded character-string list against.
        "expected_txt_strings": txt_strings,
        "expected_response_code": 0,
        "expected_response_flags": ["qr", "aa"],
        "answer_ttl": answer_ttl,
        "target_service": {
            "required": True,
            "kind": "udp-dns-responder",
            "port": destination_port,
            "query_name": query_name,
            "query_type": "TXT",
            "txt_strings": txt_strings,
            "answer_ttl": answer_ttl,
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
            "query_id": query_id,
            "qr": True,
            "response_code": 0,
            "question": {
                "name": query_name,
                "type": "TXT",
                "type_value": 16,
                "class": "IN",
                "class_value": 1,
            },
            "answer": {
                "name": query_name,
                "type": "TXT",
                "type_value": 16,
                "class": "IN",
                "class_value": 1,
                "txt_strings": txt_strings,
                "ttl": answer_ttl,
            },
        },
    }


def dns_txt_strings(*, profile: str, seed: int, sequence: int, digest: bytes) -> list[str]:
    """Return the deterministic TXT character-strings for a TXT-answer case.

    Two character-strings are returned so the case exercises a multi-string TXT
    RDATA (each string is length-prefixed on the wire). The content is stable per
    (case, profile, seed, sequence) and stays within the controlled
    ``libcrafter.test`` namespace; each string is well under the 255-octet
    per-character-string limit.
    """

    label = dns_label(profile)
    return [
        f"libcrafter-probe-txt={label}-{seed}-{sequence}",
        f"v=libcrafter1 id={digest.hex()[:16]}",
    ]


def dns_canonical_name(*, profile: str, seed: int, sequence: int, digest: bytes) -> str:
    """Return the deterministic canonical (CNAME target) name for a chain case.

    The canonical name shares the controlled ``libcrafter.test.`` suffix as the
    queried name but uses a distinct ``canonical-`` label so the chain has two
    different owner names (the queried CNAME and its terminal A target).
    """

    label = dns_label(profile)
    suffix = digest.hex()[10:20]
    return f"canonical-{seed}-{sequence}-{suffix}.{label}.libcrafter.test."


def deterministic_documentation_ipv6(digest: bytes) -> str:
    """Return a deterministic IPv6 address in the ``2001:db8::/32`` block.

    The four trailing hextets are derived from the case digest so the answer is
    stable per (case, profile, seed, sequence) while staying inside the RFC 3849
    documentation prefix.
    """

    group_e = int.from_bytes(digest[4:6], "big")
    group_f = int.from_bytes(digest[6:8], "big")
    group_g = int.from_bytes(digest[8:10], "big")
    host = 1 + int.from_bytes(digest[10:12], "big") % 0xFFFE
    return f"2001:db8:{group_e:x}:{group_f:x}:0:{group_g:x}:0:{host:x}"


def dns_query_name(*, profile: str, seed: int, sequence: int, digest: bytes) -> str:
    label = dns_label(profile)
    suffix = digest.hex()[:10]
    return f"probe-{seed}-{sequence}-{suffix}.{label}.libcrafter.test."


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


def deterministic_documentation_mac(
    profile: str,
    seed: int,
    sequence: int,
    *,
    role: str,
) -> str:
    digest = deterministic_bytes(f"arp-mac-{role}", profile, seed, sequence)
    # RFC 7042 reserves 00:00:5e:00:53:00-ff for documentation unicast MACs.
    return f"00:00:5e:00:53:{digest[0]:02x}"


def dns_label(value: str) -> str:
    label = "".join(char.lower() if char.isalnum() else "-" for char in value)
    label = "-".join(part for part in label.split("-") if part)
    return (label or "profile")[:32].strip("-") or "profile"


def deterministic_bytes(case: str, profile: str, seed: int, sequence: int) -> bytes:
    material = f"{case}\0{profile}\0{seed}\0{sequence}".encode("utf-8")
    return hashlib.sha256(material).digest()


def deterministic_ipv4_pair(profile: str, seed: int, sequence: int) -> tuple[str, str]:
    digest = deterministic_bytes("endpoint-addresses", profile, seed, sequence)
    second = 64 + digest[0] % 64
    third = digest[1]
    return f"10.{second}.{third}.10", f"10.{second}.{third}.20"


def deterministic_router_ipv4(profile: str, seed: int, sequence: int) -> str:
    digest = deterministic_bytes("endpoint-addresses", profile, seed, sequence)
    second = 64 + digest[0] % 64
    third = digest[1]
    return f"10.{second}.{third}.1"


# Registry of per-case plan builders. The dispatcher in
# :func:`probe_plan_for_case` looks up a builder by case name; cases without an
# entry fall back to a minimal planned-only plan. DNS, DHCP, ARP, and UDP case
# groups extend the behavior suite by registering builders here.
PLAN_BUILDERS: dict[str, PlanBuilder] = {
    "icmp-echo": _icmp_echo_probe_plan,
    "tcp-syn-open": _tcp_syn_probe_plan,
    "tcp-syn-closed": _tcp_syn_probe_plan,
    "dns-query": _dns_query_probe_plan,
    "dns-a-success": _dns_a_success_probe_plan,
    "dns-aaaa-success": _dns_aaaa_success_probe_plan,
    "dns-cname-chain": _dns_cname_chain_probe_plan,
    "dns-nxdomain": _dns_nxdomain_probe_plan,
    "dns-nodata": _dns_nodata_probe_plan,
    "dns-txt-answer": _dns_txt_answer_probe_plan,
    "ttl-expired": _ttl_expired_probe_plan,
    "arp-resolution": _arp_resolution_probe_plan,
}


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
