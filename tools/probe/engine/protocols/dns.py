"""Deterministic DNS probe cases and packet plans."""

from __future__ import annotations
from ..case_helpers import _behavior_case
from ..model import JSONObject, ProbeCase
from ..planning_helpers import (
    deterministic_bytes,
    deterministic_documentation_ipv6,
    deterministic_ipv4_pair,
    dns_label,
)
from .base import ProtocolPlugin, register

_DNS_CAPABILITIES = ["dns_service"]
BEHAVIOR_DNS_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="dns-a-success",
        description="Send an A query and validate a matching A answer.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
    _behavior_case(
        name="dns-aaaa-success",
        description="Send an AAAA query and validate a matching AAAA answer.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
    _behavior_case(
        name="dns-cname-chain",
        description="Query a CNAME that chains to an A record and validate the chain.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
    _behavior_case(
        name="dns-nxdomain",
        description="Query an absent name and validate the NXDOMAIN negative response.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
    _behavior_case(
        name="dns-nodata",
        description="Query a present name under an absent type and validate the NODATA (NOERROR, no answer) response.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
    _behavior_case(
        name="dns-txt-answer",
        description="Send a TXT query and validate the character-string answer.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
    _behavior_case(
        name="dns-mx-answer",
        description="Send an MX query and validate the preference + exchange answer.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
    _behavior_case(
        name="dns-srv-answer",
        description="Send an SRV query and validate the priority/weight/port/target answer.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
    _behavior_case(
        name="dns-edns-opt",
        description="Send an EDNS query with an OPT record and validate the OPT metadata.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
    _behavior_case(
        name="dns-repeat-transaction",
        description="Send two A queries reusing one transaction id over separate source ports and validate each response is matched to its own send.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
)
DNS_QUERY_CASE: ProbeCase = ProbeCase(
    name="dns-query",
    description="Send DNS query to controlled DNS service and validate matching reply.",
    stimulus="dns_query",
    expected_response="dns_response",
    required_capabilities=["dns_service"],
    endpoint_roles=["stimulus", "target"],
    metadata={"protocol": "dns", "service": "controlled_dns"},
)


def _dns_query_probe_plan(
    *, case_name: str = "dns-query", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes("dns-query", profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    query_type_value = 1 if sequence % 2 == 0 else 28
    query_type = "A" if query_type_value == 1 else "AAAA"
    query_name = dns_query_name(
        profile=profile, seed=seed, sequence=sequence, digest=digest
    )
    if query_type == "A":
        answer_data = f"203.0.113.{1 + digest[4] % 250}"
    else:
        answer_data = f"2001:db8:{int.from_bytes(digest[4:6], 'big'):x}:{int.from_bytes(digest[6:8], 'big'):x}::{1 + digest[8] % 65534:x}"
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
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "query_id": query_id,
            "qr": True,
            "response_code": 0,
            "question": {"name": query_name, "type": query_type, "class": "IN"},
            "answer": {
                "name": query_name,
                "type": query_type,
                "data": answer_data,
                "ttl": answer_ttl,
            },
        },
    }


def _dns_a_success_probe_plan(
    *, case_name: str = "dns-a-success", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    destination_port = 53
    query_name = dns_query_name(
        profile=profile, seed=seed, sequence=sequence, digest=digest
    )
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
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
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
    *, case_name: str = "dns-aaaa-success", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    destination_port = 53
    query_name = dns_query_name(
        profile=profile, seed=seed, sequence=sequence, digest=digest
    )
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
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
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
    *, case_name: str = "dns-cname-chain", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    destination_port = 53
    query_name = dns_query_name(
        profile=profile, seed=seed, sequence=sequence, digest=digest
    )
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
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
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
    *, case_name: str = "dns-nxdomain", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    destination_port = 53
    query_name = dns_query_name(
        profile=profile, seed=seed, sequence=sequence, digest=digest
    )
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
        "absent_name": query_name,
        "expected_answer_count": expected_answer_count,
        "expected_response_code": expected_response_code,
        "expected_response_flags": ["qr"],
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
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
    *, case_name: str = "dns-nodata", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    destination_port = 53
    query_name = dns_query_name(
        profile=profile, seed=seed, sequence=sequence, digest=digest
    )
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
        "present_name": query_name,
        "present_type": present_type,
        "present_type_value": present_type_value,
        "expected_answer_count": expected_answer_count,
        "expected_response_code": expected_response_code,
        "expected_response_flags": ["qr"],
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
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
    *, case_name: str = "dns-txt-answer", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    destination_port = 53
    query_name = dns_query_name(
        profile=profile, seed=seed, sequence=sequence, digest=digest
    )
    txt_strings = dns_txt_strings(
        profile=profile, seed=seed, sequence=sequence, digest=digest
    )
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
        "expected_txt_strings": txt_strings,
        "expected_response_code": 0,
        "expected_response_flags": ["qr", "aa"],
        "answer_ttl": answer_ttl,
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
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
    *, case_name: str = "dns-mx-answer", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    destination_port = 53
    query_name = dns_query_name(
        profile=profile, seed=seed, sequence=sequence, digest=digest
    )
    exchange_name = dns_exchange_name(
        profile=profile, seed=seed, sequence=sequence, digest=digest
    )
    mx_preference = 1 + int.from_bytes(digest[8:10], "big") % 65534
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
        "expected_mx_preference": mx_preference,
        "expected_mx_exchange": exchange_name,
        "expected_response_code": 0,
        "expected_response_flags": ["qr", "aa"],
        "answer_ttl": answer_ttl,
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
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
    *, case_name: str = "dns-srv-answer", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    destination_port = 53
    service_name = dns_service_name(
        profile=profile, seed=seed, sequence=sequence, digest=digest
    )
    target_name = dns_target_name(
        profile=profile, seed=seed, sequence=sequence, digest=digest
    )
    srv_priority = 1 + int.from_bytes(digest[8:10], "big") % 65534
    srv_weight = int.from_bytes(digest[10:12], "big")
    srv_port = 1 + int.from_bytes(digest[12:14], "big") % 65534
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
        "expected_srv_priority": srv_priority,
        "expected_srv_weight": srv_weight,
        "expected_srv_port": srv_port,
        "expected_srv_target": target_name,
        "expected_response_code": 0,
        "expected_response_flags": ["qr", "aa"],
        "answer_ttl": answer_ttl,
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
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
    *, case_name: str = "dns-edns-opt", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    destination_port = 53
    query_name = dns_query_name(
        profile=profile, seed=seed, sequence=sequence, digest=digest
    )
    answer_data = f"203.0.113.{1 + digest[4] % 250}"
    answer_ttl = 60 + digest[9] % 180
    request_udp_payload_size = 1232
    response_udp_payload_size = 4096
    edns_version = 0
    edns_extended_rcode = 0
    edns_do = True
    request_nsid = dns_edns_nsid(
        profile=profile, seed=seed, sequence=sequence, digest=digest, role="client"
    )
    response_nsid = dns_edns_nsid(
        profile=profile, seed=seed, sequence=sequence, digest=digest, role="server"
    )
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
        "edns_udp_payload_size": request_udp_payload_size,
        "edns_version": edns_version,
        "edns_do": edns_do,
        "edns_request_options": request_options,
        "expected_edns_udp_payload_size": response_udp_payload_size,
        "expected_edns_version": edns_version,
        "expected_edns_extended_rcode": edns_extended_rcode,
        "expected_edns_do": edns_do,
        "expected_edns_options": response_options,
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
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
        "capture_filter": f"udp and src host {target_ipv4} and dst host {source_ipv4} and src port {destination_port} and dst port {source_port}",
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
    *, case_name: str = "dns-repeat-transaction", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    destination_port = 53
    query_name = dns_query_name(
        profile=profile, seed=seed, sequence=sequence, digest=digest
    )
    first_source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
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
        "send_count": len(sends),
        "sends": sends,
        "capture_filter": first["capture_filter"],
        "validation": first["validation"],
    }
    return plan


def dns_edns_nsid(
    *, profile: str, seed: int, sequence: int, digest: bytes, role: str
) -> str:
    label = dns_label(profile)
    text = f"libcrafter-nsid-{role}={label}-{seed}-{sequence}-{digest.hex()[:8]}"
    return text.encode("ascii").hex()


def dns_service_name(*, profile: str, seed: int, sequence: int, digest: bytes) -> str:
    label = dns_label(profile)
    suffix = digest.hex()[14:24]
    return f"_sip._tcp.srv-{seed}-{sequence}-{suffix}.{label}.libcrafter.test."


def dns_target_name(*, profile: str, seed: int, sequence: int, digest: bytes) -> str:
    label = dns_label(profile)
    suffix = digest.hex()[16:26]
    return f"target-{seed}-{sequence}-{suffix}.{label}.libcrafter.test."


def dns_exchange_name(*, profile: str, seed: int, sequence: int, digest: bytes) -> str:
    label = dns_label(profile)
    suffix = digest.hex()[12:22]
    return f"mail-{seed}-{sequence}-{suffix}.{label}.libcrafter.test."


def dns_txt_strings(
    *, profile: str, seed: int, sequence: int, digest: bytes
) -> list[str]:
    label = dns_label(profile)
    return [
        f"libcrafter-probe-txt={label}-{seed}-{sequence}",
        f"v=libcrafter1 id={digest.hex()[:16]}",
    ]


def dns_canonical_name(*, profile: str, seed: int, sequence: int, digest: bytes) -> str:
    label = dns_label(profile)
    suffix = digest.hex()[10:20]
    return f"canonical-{seed}-{sequence}-{suffix}.{label}.libcrafter.test."


def dns_query_name(*, profile: str, seed: int, sequence: int, digest: bytes) -> str:
    label = dns_label(profile)
    suffix = digest.hex()[:10]
    return f"probe-{seed}-{sequence}-{suffix}.{label}.libcrafter.test."


_DNS_PLAN_BUILDERS: dict[str, object] = {
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
}
_DNS_STIMULUS_ENDPOINT_CASES: frozenset[str] = frozenset(
    {
        "dns-query",
        "dns-a-success",
        "dns-aaaa-success",
        "dns-cname-chain",
        "dns-nxdomain",
        "dns-nodata",
        "dns-txt-answer",
        "dns-mx-answer",
        "dns-srv-answer",
        "dns-edns-opt",
        "dns-repeat-transaction",
    }
)


def dns_failure_reasons(case_name: str) -> list[str] | None:
    return None


register(
    ProtocolPlugin(
        name="dns",
        cases=(DNS_QUERY_CASE, *BEHAVIOR_DNS_CASES),
        plan_builders=_DNS_PLAN_BUILDERS,
        planned_only_cases=frozenset(),
        profile_counts={},
        stimulus_endpoint_cases=_DNS_STIMULUS_ENDPOINT_CASES,
        failure_reasons=dns_failure_reasons,
    )
)
