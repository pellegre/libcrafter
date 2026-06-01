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

from .cases import PROBE_CASE_BY_NAME, UDP_ECHO_LARGE_PAYLOAD_LENGTH
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


def _dns_mx_answer_probe_plan(
    *,
    case_name: str = "dns-mx-answer",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dns-mx-answer`` behavioral case.

    An MX (QTYPE 15) query against the controlled UDP DNS responder on port 53.
    The single answer carries structured MX RDATA: a 16-bit preference followed
    by the exchange ``<domain-name>`` (encoded uncompressed so the wire rdlength
    is ``2 + encoded-name length``). The case exercises composite RDATA decoding
    where a numeric field and a domain name share one record. The validation
    contract covers the transaction id, QR, rcode, question (name/type/class),
    and the MX answer (name/type 15/class, the decoded preference and exchange
    name, and the TTL) plus peer addresses and ports.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    destination_port = 53
    query_name = dns_query_name(profile=profile, seed=seed, sequence=sequence, digest=digest)
    exchange_name = dns_exchange_name(profile=profile, seed=seed, sequence=sequence, digest=digest)
    # The preference is a 16-bit field; keep it deterministic and non-zero so the
    # encoded/decoded value is unambiguous.
    mx_preference = 1 + int.from_bytes(digest[8:10], "big") % 0xFFFE
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
        "query_type": "MX",
        "query_type_value": 15,
        "query_class": "IN",
        "query_class_value": 1,
        "expected_answer_name": query_name,
        "expected_answer_type": "MX",
        "expected_answer_type_value": 15,
        "expected_answer_class": "IN",
        "expected_answer_class_value": 1,
        # The MX RDATA is a preference + exchange domain name. The endpoint
        # compares the decoded structured fields against these.
        "expected_mx_preference": mx_preference,
        "expected_mx_exchange": exchange_name,
        "expected_response_code": 0,
        "expected_response_flags": ["qr", "aa"],
        "answer_ttl": answer_ttl,
        "target_service": {
            "required": True,
            "kind": "udp-dns-responder",
            "port": destination_port,
            "query_name": query_name,
            "query_type": "MX",
            "mx_preference": mx_preference,
            "mx_exchange": exchange_name,
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
                "type": "MX",
                "type_value": 15,
                "class": "IN",
                "class_value": 1,
            },
            "answer": {
                "name": query_name,
                "type": "MX",
                "type_value": 15,
                "class": "IN",
                "class_value": 1,
                "preference": mx_preference,
                "exchange": exchange_name,
                "ttl": answer_ttl,
            },
        },
    }


def _dns_srv_answer_probe_plan(
    *,
    case_name: str = "dns-srv-answer",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dns-srv-answer`` behavioral case.

    An SRV (QTYPE 33) query against the controlled UDP DNS responder on port 53.
    SRV is a ``_service._proto.name`` query whose single answer carries composite
    RDATA: three 16-bit numeric fields (priority, weight, port) followed by the
    target ``<domain-name>`` (encoded uncompressed so the wire rdlength is
    ``6 + encoded-name length``). The case exercises a record that mixes several
    numeric fields with a domain name. The validation contract covers the
    transaction id, QR, rcode, question (name/type/class), and the SRV answer
    (name/type 33/class, the decoded priority, weight, service port, and target
    name, and the TTL) plus peer addresses and ports.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    destination_port = 53
    service_name = dns_service_name(profile=profile, seed=seed, sequence=sequence, digest=digest)
    target_name = dns_target_name(profile=profile, seed=seed, sequence=sequence, digest=digest)
    # Priority, weight, and service port are 16-bit fields; keep them deterministic
    # and non-zero so the encoded/decoded values are unambiguous.
    srv_priority = 1 + int.from_bytes(digest[8:10], "big") % 0xFFFE
    srv_weight = int.from_bytes(digest[10:12], "big")
    srv_port = 1 + int.from_bytes(digest[12:14], "big") % 0xFFFE
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
        "query_name": service_name,
        "query_type": "SRV",
        "query_type_value": 33,
        "query_class": "IN",
        "query_class_value": 1,
        "expected_answer_name": service_name,
        "expected_answer_type": "SRV",
        "expected_answer_type_value": 33,
        "expected_answer_class": "IN",
        "expected_answer_class_value": 1,
        # The SRV RDATA is priority + weight + port + target domain name. The
        # endpoint compares the decoded structured fields against these.
        "expected_srv_priority": srv_priority,
        "expected_srv_weight": srv_weight,
        "expected_srv_port": srv_port,
        "expected_srv_target": target_name,
        "expected_response_code": 0,
        "expected_response_flags": ["qr", "aa"],
        "answer_ttl": answer_ttl,
        "target_service": {
            "required": True,
            "kind": "udp-dns-responder",
            "port": destination_port,
            "query_name": service_name,
            "query_type": "SRV",
            "srv_priority": srv_priority,
            "srv_weight": srv_weight,
            "srv_port": srv_port,
            "srv_target": target_name,
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
                "name": service_name,
                "type": "SRV",
                "type_value": 33,
                "class": "IN",
                "class_value": 1,
            },
            "answer": {
                "name": service_name,
                "type": "SRV",
                "type_value": 33,
                "class": "IN",
                "class_value": 1,
                "priority": srv_priority,
                "weight": srv_weight,
                "port": srv_port,
                "target": target_name,
                "ttl": answer_ttl,
            },
        },
    }


def _dns_edns_opt_probe_plan(
    *,
    case_name: str = "dns-edns-opt",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dns-edns-opt`` behavioral case.

    An A (QTYPE 1) query that carries an EDNS(0) OPT pseudo-record (RFC 6891) in
    its additional section, advertising a planned requestor UDP payload size and
    one EDNS option (a deterministic NSID, RFC 5001). The controlled UDP DNS
    responder answers with a matching A record and synthesizes its own OPT
    pseudo-record in the response's additional section: the OPT owner name is
    root ``.``, TYPE is 41, the CLASS field carries the responder's UDP payload
    size, the TTL field packs the extended RCODE, EDNS version, and the DO flag,
    and the RDATA carries the responder's deterministic NSID option. The case
    exercises the additional section and the OPT pseudo-record's EDNS field
    layout (payload size in CLASS; extended rcode/version/flags packed into TTL;
    {code,length,data} options in RDATA). The validation contract covers the
    transaction id, QR, rcode, question (name/type/class), the A answer, the
    decoded additional-section OPT metadata (UDP payload size, extended rcode,
    version, DO flag, and the ordered option list), plus peer addresses/ports.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    destination_port = 53
    query_name = dns_query_name(profile=profile, seed=seed, sequence=sequence, digest=digest)
    answer_data = f"203.0.113.{1 + digest[4] % 250}"
    answer_ttl = 60 + digest[9] % 180
    # The stimulus advertises a deterministic requestor UDP payload size (a valid
    # EDNS(0) value) and one NSID option; the responder advertises its own size
    # and NSID. Keep both within the OPT CLASS u16 range.
    request_udp_payload_size = 1232
    response_udp_payload_size = 4096
    edns_version = 0
    edns_extended_rcode = 0
    edns_do = True
    request_nsid = dns_edns_nsid(profile=profile, seed=seed, sequence=sequence, digest=digest, role="client")
    response_nsid = dns_edns_nsid(profile=profile, seed=seed, sequence=sequence, digest=digest, role="server")
    # NSID (RFC 5001) option code is 3; the data is opaque identifier bytes.
    request_options = [{"code": 3, "data_hex": request_nsid}]
    response_options = [{"code": 3, "data_hex": response_nsid}]
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
        # The stimulus carries an EDNS(0) OPT record in its additional section.
        "edns_udp_payload_size": request_udp_payload_size,
        "edns_version": edns_version,
        "edns_do": edns_do,
        "edns_request_options": request_options,
        # The response's additional-section OPT metadata the endpoint decodes and
        # validates: UDP payload size (OPT CLASS), extended rcode/version/DO flag
        # (OPT TTL), and the ordered option list ({code, data} tuples).
        "expected_edns_udp_payload_size": response_udp_payload_size,
        "expected_edns_version": edns_version,
        "expected_edns_extended_rcode": edns_extended_rcode,
        "expected_edns_do": edns_do,
        "expected_edns_options": response_options,
        "target_service": {
            "required": True,
            "kind": "udp-dns-responder",
            "port": destination_port,
            "query_name": query_name,
            "query_type": "A",
            "answer_data": answer_data,
            "answer_ttl": answer_ttl,
            "edns": {
                "udp_payload_size": response_udp_payload_size,
                "version": edns_version,
                "extended_rcode": edns_extended_rcode,
                "do": edns_do,
                "options": response_options,
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
            "answer": {
                "name": query_name,
                "type": "A",
                "type_value": 1,
                "class": "IN",
                "class_value": 1,
                "data": answer_data,
                "ttl": answer_ttl,
            },
            "edns_opt": {
                "udp_payload_size": response_udp_payload_size,
                "version": edns_version,
                "extended_rcode": edns_extended_rcode,
                "do": edns_do,
                "options": response_options,
            },
        },
    }


def _dns_repeat_transaction_send(
    *,
    case_name: str,
    profile: str,
    seed: int,
    sequence: int,
    digest: bytes,
    index: int,
    source_ipv4: str,
    target_ipv4: str,
    query_id: int,
    source_port: int,
    destination_port: int,
    query_name: str,
) -> JSONObject:
    """Build one of the two sends for the ``dns-repeat-transaction`` case.

    Each send reuses the shared transaction id and query name but owns a distinct
    source port (the spec wants repeated ids over *separate* source ports) and a
    distinct deterministic A answer, plus a per-send capture filter and full
    validation contract so its response is matched back to it by id/source-port
    and never confused with the sibling send's same-name response.
    """

    answer_data = f"203.0.113.{1 + digest[10 + index] % 250}"
    answer_ttl = 60 + digest[12 + index] % 180
    return {
        "index": index,
        "source_ipv4": source_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": source_ipv4,
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
        "expected_answer_count": 1,
        "expected_response_code": 0,
        "expected_response_flags": ["qr", "aa"],
        "answer_ttl": answer_ttl,
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {source_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "target_service": {
            "required": True,
            "kind": "udp-dns-responder",
            "port": destination_port,
            "query_name": query_name,
            "query_type": "A",
            "answer_data": answer_data,
            "answer_ttl": answer_ttl,
        },
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": source_ipv4,
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


def _dns_repeat_transaction_probe_plan(
    *,
    case_name: str = "dns-repeat-transaction",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``dns-repeat-transaction`` behavioral case.

    Two A (QTYPE 1) queries against the controlled UDP DNS responder, reusing one
    transaction id and one query name across both sends but using two *distinct*
    deterministic source ports (RFC 5452 advises varying the source port; this
    case exercises the inverse — a reused id distinguished only by source port).
    Each send carries its own deterministic IPv4 answer, so the endpoint must
    receive two responses, decode each, and match every response back to *its*
    send by id and source port (and validate its own answer) without confusing
    the two same-name responses.

    The plan carries a ``sends`` array (one entry per send) plus the conventional
    single-send top-level fields (mirroring the first send) so the generic plan
    echo and any single-send consumer keep working unchanged; the DNS dispatch
    detects ``sends`` and drives both sends.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    # One shared transaction id reused across both sends (the case point), and one
    # shared query name; the two sends differ only in source port and answer.
    query_id = int.from_bytes(digest[0:2], "big") or 1
    destination_port = 53
    query_name = dns_query_name(profile=profile, seed=seed, sequence=sequence, digest=digest)
    first_source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    # Offset the second source port deterministically and keep it distinct from
    # the first (separate source ports is the whole point of the case).
    second_offset = 1 + int.from_bytes(digest[4:6], "big") % 5000
    second_source_port = 45000 + (first_source_port + second_offset) % 20000
    if second_source_port == first_source_port:
        second_source_port = first_source_port + 1
    source_ports = (first_source_port, second_source_port)

    sends = [
        _dns_repeat_transaction_send(
            case_name=case_name,
            profile=profile,
            seed=seed,
            sequence=sequence,
            digest=digest,
            index=index,
            source_ipv4=stimulus_ipv4,
            target_ipv4=target_ipv4,
            query_id=query_id,
            source_port=source_port,
            destination_port=destination_port,
            query_name=query_name,
        )
        for index, source_port in enumerate(source_ports)
    ]
    first = sends[0]

    plan: JSONObject = {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dns_query",
        "expected_response": "dns_response",
        # Conventional single-send top-level fields mirror the first send so the
        # generic plan echo / capture filter / single-send consumers keep working.
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": first["source_port"],
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
        "expected_answer_data": first["expected_answer_data"],
        "expected_answer_count": 1,
        "expected_response_code": 0,
        "expected_response_flags": ["qr", "aa"],
        "answer_ttl": first["answer_ttl"],
        # The repeat-transaction contract: two independent sends, each with its
        # own deterministic source port and answer, validated separately.
        "send_count": len(sends),
        "sends": sends,
        "target_service": {
            "required": True,
            "kind": "udp-dns-responder",
            "port": destination_port,
            "query_name": query_name,
            "query_type": "A",
            "answer_data": first["expected_answer_data"],
            "answer_ttl": first["answer_ttl"],
            "repeat_transaction": {
                "query_id": query_id,
                "query_name": query_name,
                "sends": [
                    {
                        "source_port": send["source_port"],
                        "answer_data": send["expected_answer_data"],
                        "answer_ttl": send["answer_ttl"],
                    }
                    for send in sends
                ],
            },
        },
        "capture_filter": first["capture_filter"],
        "validation": first["validation"],
    }
    return plan


def dns_edns_nsid(*, profile: str, seed: int, sequence: int, digest: bytes, role: str) -> str:
    """Return deterministic EDNS(0) NSID option data bytes as a hex string.

    NSID (RFC 5001) carries opaque identifier bytes. The client and server roles
    derive distinct, stable values per (case, profile, seed, sequence) so the
    stimulus and the response OPT records carry recognizably different option
    data. Returned as lowercase hex (no ``0x`` prefix) so the Rust endpoint can
    decode it back to bytes.
    """

    label = dns_label(profile)
    text = f"libcrafter-nsid-{role}={label}-{seed}-{sequence}-{digest.hex()[:8]}"
    return text.encode("ascii").hex()


def dns_service_name(*, profile: str, seed: int, sequence: int, digest: bytes) -> str:
    """Return the deterministic SRV service owner name (``_service._proto.name``).

    SRV owner names follow the RFC 2782 ``_Service._Proto.Name`` form. The name
    shares the controlled ``libcrafter.test.`` suffix as the other DNS cases but
    is prefixed with ``_sip._tcp`` so it is recognizably an SRV owner. Stable per
    (case, profile, seed, sequence).
    """

    label = dns_label(profile)
    suffix = digest.hex()[14:24]
    return f"_sip._tcp.srv-{seed}-{sequence}-{suffix}.{label}.libcrafter.test."


def dns_target_name(*, profile: str, seed: int, sequence: int, digest: bytes) -> str:
    """Return the deterministic SRV target (service host) domain name.

    The target shares the controlled ``libcrafter.test.`` suffix as the queried
    SRV owner but uses a distinct ``target-`` label so the SRV RDATA points at a
    separate host name. Stable per (case, profile, seed, sequence).
    """

    label = dns_label(profile)
    suffix = digest.hex()[16:26]
    return f"target-{seed}-{sequence}-{suffix}.{label}.libcrafter.test."


def dns_exchange_name(*, profile: str, seed: int, sequence: int, digest: bytes) -> str:
    """Return the deterministic MX exchange (mail server) domain name.

    The exchange shares the controlled ``libcrafter.test.`` suffix as the queried
    name but uses a distinct ``mail-`` label so the MX RDATA points at a separate
    owner name. Stable per (case, profile, seed, sequence).
    """

    label = dns_label(profile)
    suffix = digest.hex()[12:22]
    return f"mail-{seed}-{sequence}-{suffix}.{label}.libcrafter.test."


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


UDP_ECHO_LARGE_IPV4_HEADER_LENGTH = 20
UDP_ECHO_LARGE_UDP_HEADER_LENGTH = 8
UDP_ECHO_LARGE_IPV4_PACKET_SAFETY_LIMIT = 1400
UDP_ECHO_LARGE_MAX_PAYLOAD_LENGTH = (
    UDP_ECHO_LARGE_IPV4_PACKET_SAFETY_LIMIT
    - UDP_ECHO_LARGE_IPV4_HEADER_LENGTH
    - UDP_ECHO_LARGE_UDP_HEADER_LENGTH
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
    "dns-mx-answer": _dns_mx_answer_probe_plan,
    "dns-srv-answer": _dns_srv_answer_probe_plan,
    "dns-edns-opt": _dns_edns_opt_probe_plan,
    "dns-repeat-transaction": _dns_repeat_transaction_probe_plan,
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
    "udp-echo-empty": _udp_echo_empty_probe_plan,
    "udp-echo-short": _udp_echo_short_probe_plan,
    "udp-echo-binary": _udp_echo_binary_probe_plan,
    "udp-echo-large": _udp_echo_large_probe_plan,
    "udp-source-port-reflection": _udp_source_port_reflection_probe_plan,
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
