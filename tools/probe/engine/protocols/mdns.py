"""mDNS probe protocol plugin: deterministic dry-run behavior plans."""

from __future__ import annotations

import json
import posixpath
import shlex
from collections.abc import Mapping, Sequence

from ..capability_derivation import capability, capability_default_true
from ..case_helpers import _behavior_case
from ..endpoint_addressing import (
    FAILURE_DECODE_FAILED,
    FAILURE_TARGET_SETUP_FAILED,
    FAILURE_TIMEOUT,
    FAILURE_WRONG_PAYLOAD,
    FAILURE_WRONG_PEER,
)
from ..model import JSONObject, JSONValue, ProbeCase
from ..planning_helpers import (
    deterministic_bytes,
    deterministic_documentation_ipv6,
    dns_label,
)
from ..target_service_helpers import (
    dedupe_ints,
    plans_by_destination_port,
    target_service_address_fields,
)
from .base import ProtocolPlugin, register


MDNS_SMOKE_PROFILE = "mdns-smoke"
MDNS_SERVICE_KIND = "mdns-controlled-responder"
MDNS_RUNTIME = "probe-mdns-reference"
MDNS_STIMULUS_DRIVER = "mdns_probe"
MDNS_ADAPTER_MODULE = "tools/probe/adapters/src/mdns.rs"
MDNS_PORT = 5353
MDNS_IPV4_MULTICAST = "224.0.0.251"
MDNS_IPV6_MULTICAST = "ff02::fb"
MDNS_DOCUMENTATION_IPV4_PREFIX = "192.0.2.0/24"
MDNS_RESPONDER_IPV4_PREFIX = "198.51.100.0/24"
MDNS_DOCUMENTATION_IPV6_PREFIX = "2001:db8::/32"
MDNS_SERVICE_NAME = "_ipp._tcp.local."
MDNS_SUBTYPE_NAME = "_printer._sub._ipp._tcp.local."
MDNS_SERVICE_ENUMERATION_NAME = "_services._dns-sd._udp.local."

_MDNS_IPV4_MULTICAST_CAPABILITIES = [
    "mdns_ipv4_multicast",
    "mdns_controlled_responder",
]
_MDNS_IPV6_MULTICAST_CAPABILITIES = [
    "mdns_ipv6_multicast",
    "mdns_ipv6_link_local_scope",
    "mdns_controlled_responder",
]
_MDNS_QU_CAPABILITIES = [
    "mdns_ipv4_multicast",
    "mdns_unicast_response",
    "mdns_controlled_responder",
]


MDNS_PROBE_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="mdns-ipv4-multicast-browse",
        description=(
            "Plan an IPv4 mDNS multicast PTR browse query and controlled "
            "DNS-SD response."
        ),
        stimulus="mdns_ipv4_ptr_browse",
        expected_response="mdns_dns_sd_response",
        required_capabilities=_MDNS_IPV4_MULTICAST_CAPABILITIES,
        protocol="mdns",
        metadata={
            "service": MDNS_SERVICE_KIND,
            "transport": "udp",
            "address_family": "ipv4",
            "message_kind": "query",
            "exchange": "browse",
            "planned_only": True,
            "live_capable": True,
            "multicast_group": MDNS_IPV4_MULTICAST,
            "udp_port": MDNS_PORT,
        },
    ),
    _behavior_case(
        name="mdns-ipv6-multicast-browse",
        description=(
            "Plan an IPv6 link-local mDNS multicast PTR browse query and "
            "controlled DNS-SD response."
        ),
        stimulus="mdns_ipv6_ptr_browse",
        expected_response="mdns_dns_sd_response",
        required_capabilities=_MDNS_IPV6_MULTICAST_CAPABILITIES,
        protocol="mdns",
        metadata={
            "service": MDNS_SERVICE_KIND,
            "transport": "udp",
            "address_family": "ipv6",
            "message_kind": "query",
            "exchange": "browse",
            "planned_only": True,
            "live_capable": True,
            "multicast_group": MDNS_IPV6_MULTICAST,
            "udp_port": MDNS_PORT,
        },
    ),
    _behavior_case(
        name="mdns-qu-unicast-response",
        description=(
            "Plan a multicast mDNS browse query with the QU bit set and a "
            "unicast response back to the stimulus port."
        ),
        stimulus="mdns_qu_query",
        expected_response="mdns_unicast_response",
        required_capabilities=_MDNS_QU_CAPABILITIES,
        protocol="mdns",
        metadata={
            "service": MDNS_SERVICE_KIND,
            "transport": "udp",
            "address_family": "ipv4",
            "message_kind": "query",
            "exchange": "qu_unicast_response",
            "planned_only": True,
            "live_capable": True,
            "multicast_group": MDNS_IPV4_MULTICAST,
            "udp_port": MDNS_PORT,
        },
    ),
    _behavior_case(
        name="mdns-service-resolve",
        description=(
            "Plan SRV/TXT resolution for one deterministic DNS-SD service "
            "instance."
        ),
        stimulus="mdns_service_resolve",
        expected_response="mdns_service_records",
        required_capabilities=_MDNS_IPV4_MULTICAST_CAPABILITIES,
        protocol="mdns",
        metadata={
            "service": MDNS_SERVICE_KIND,
            "transport": "udp",
            "address_family": "ipv4",
            "message_kind": "query",
            "exchange": "service_resolve",
            "planned_only": True,
            "live_capable": True,
            "multicast_group": MDNS_IPV4_MULTICAST,
            "udp_port": MDNS_PORT,
        },
    ),
    _behavior_case(
        name="mdns-announcement",
        description=(
            "Plan an unsolicited mDNS announcement from a controlled service."
        ),
        stimulus="mdns_announcement_emit",
        expected_response="mdns_announcement_observed",
        required_capabilities=_MDNS_IPV4_MULTICAST_CAPABILITIES,
        protocol="mdns",
        endpoint_roles=["target", "stimulus"],
        metadata={
            "service": MDNS_SERVICE_KIND,
            "transport": "udp",
            "address_family": "ipv4",
            "message_kind": "announcement",
            "exchange": "announcement",
            "planned_only": True,
            "live_capable": True,
            "multicast_group": MDNS_IPV4_MULTICAST,
            "udp_port": MDNS_PORT,
        },
    ),
    _behavior_case(
        name="mdns-goodbye",
        description="Plan an mDNS goodbye response with zero-TTL records.",
        stimulus="mdns_goodbye_emit",
        expected_response="mdns_goodbye_observed",
        required_capabilities=_MDNS_IPV4_MULTICAST_CAPABILITIES,
        protocol="mdns",
        endpoint_roles=["target", "stimulus"],
        metadata={
            "service": MDNS_SERVICE_KIND,
            "transport": "udp",
            "address_family": "ipv4",
            "message_kind": "goodbye",
            "exchange": "goodbye",
            "planned_only": True,
            "live_capable": True,
            "multicast_group": MDNS_IPV4_MULTICAST,
            "udp_port": MDNS_PORT,
        },
    ),
    _behavior_case(
        name="mdns-known-answer-suppression",
        description=(
            "Plan an mDNS browse query carrying a known answer that the "
            "controlled responder must suppress."
        ),
        stimulus="mdns_known_answer_query",
        expected_response="mdns_response_suppressed",
        required_capabilities=_MDNS_IPV4_MULTICAST_CAPABILITIES,
        protocol="mdns",
        metadata={
            "service": MDNS_SERVICE_KIND,
            "transport": "udp",
            "address_family": "ipv4",
            "message_kind": "query",
            "exchange": "known_answer_suppression",
            "planned_only": True,
            "live_capable": True,
            "multicast_group": MDNS_IPV4_MULTICAST,
            "udp_port": MDNS_PORT,
        },
    ),
    _behavior_case(
        name="mdns-cache-flush-response",
        description=(
            "Plan a unique-record mDNS response with the cache-flush bit set."
        ),
        stimulus="mdns_cache_flush_query",
        expected_response="mdns_cache_flush_response",
        required_capabilities=_MDNS_IPV4_MULTICAST_CAPABILITIES,
        protocol="mdns",
        metadata={
            "service": MDNS_SERVICE_KIND,
            "transport": "udp",
            "address_family": "ipv4",
            "message_kind": "response",
            "exchange": "cache_flush_response",
            "planned_only": True,
            "live_capable": True,
            "multicast_group": MDNS_IPV4_MULTICAST,
            "udp_port": MDNS_PORT,
        },
    ),
    _behavior_case(
        name="mdns-subtype-browse",
        description=(
            "Plan a DNS-SD subtype PTR browse query and controlled response."
        ),
        stimulus="mdns_subtype_browse",
        expected_response="mdns_subtype_response",
        required_capabilities=_MDNS_IPV4_MULTICAST_CAPABILITIES,
        protocol="mdns",
        metadata={
            "service": MDNS_SERVICE_KIND,
            "transport": "udp",
            "address_family": "ipv4",
            "message_kind": "query",
            "exchange": "subtype_browse",
            "planned_only": True,
            "live_capable": True,
            "multicast_group": MDNS_IPV4_MULTICAST,
            "udp_port": MDNS_PORT,
        },
    ),
    _behavior_case(
        name="mdns-bonjour-txt",
        description=(
            "Plan Bonjour-style TXT record behavior for a deterministic service "
            "instance."
        ),
        stimulus="mdns_bonjour_txt_query",
        expected_response="mdns_bonjour_txt_response",
        required_capabilities=_MDNS_IPV4_MULTICAST_CAPABILITIES,
        protocol="mdns",
        metadata={
            "service": MDNS_SERVICE_KIND,
            "transport": "udp",
            "address_family": "ipv4",
            "message_kind": "query",
            "exchange": "bonjour_txt",
            "planned_only": True,
            "live_capable": True,
            "multicast_group": MDNS_IPV4_MULTICAST,
            "udp_port": MDNS_PORT,
        },
    ),
)

_MDNS_CASE_BY_NAME: dict[str, ProbeCase] = {
    case.name: case for case in MDNS_PROBE_CASES
}
_MDNS_PLANNED_ONLY_CASES = frozenset(_MDNS_CASE_BY_NAME)


def _mdns_probe_plan(
    *,
    case_name: str,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    case = _MDNS_CASE_BY_NAME[case_name]
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    names = _mdns_names(digest, profile)

    if case_name == "mdns-ipv6-multicast-browse":
        return _mdns_ipv6_browse_plan(
            case=case,
            profile=profile,
            seed=seed,
            sequence=sequence,
            digest=digest,
            names=names,
        )
    return _mdns_ipv4_plan(
        case=case,
        profile=profile,
        seed=seed,
        sequence=sequence,
        digest=digest,
        names=names,
    )


def _mdns_ipv4_plan(
    *,
    case: ProbeCase,
    profile: str,
    seed: int,
    sequence: int,
    digest: bytes,
    names: JSONObject,
) -> JSONObject:
    source_ipv4, target_ipv4 = _documentation_ipv4_pair(digest)
    source_port = _mdns_source_port(case.name, digest)
    destination_ipv4 = MDNS_IPV4_MULTICAST
    response_destination_ipv4 = (
        source_ipv4
        if case.name == "mdns-qu-unicast-response"
        else MDNS_IPV4_MULTICAST
    )
    expected_packet_count = 0 if case.name == "mdns-known-answer-suppression" else 1
    source_is_target = case.name in {"mdns-announcement", "mdns-goodbye"}
    emitted_source_ipv4 = target_ipv4 if source_is_target else source_ipv4
    mdns_message, expected_mdns = _mdns_exchange_messages(
        case.name,
        names=names,
        target_ipv4=target_ipv4,
        target_ipv6=None,
        digest=digest,
    )

    plan = _base_plan(
        case=case,
        profile=profile,
        seed=seed,
        sequence=sequence,
        address_family="ipv4",
        source_port=source_port,
        destination_port=MDNS_PORT,
        source_address=emitted_source_ipv4,
        destination_address=destination_ipv4,
        target_address=target_ipv4,
        expected_reply_source=target_ipv4,
        expected_reply_destination=response_destination_ipv4,
        multicast_group=MDNS_IPV4_MULTICAST,
        mdns_message=mdns_message,
        expected_mdns=expected_mdns,
        target_service=_target_service(
            case=case,
            names=names,
            bind_address=target_ipv4,
            source_address=source_ipv4,
            address_family="ipv4",
            expected_mdns=expected_mdns,
        ),
        capture_filter=_ipv4_capture_filter(
            case_name=case.name,
            source_ipv4=source_ipv4,
            target_ipv4=target_ipv4,
            destination_ipv4=destination_ipv4,
            response_destination_ipv4=response_destination_ipv4,
            source_port=source_port,
        ),
        documentation_prefixes=[
            MDNS_DOCUMENTATION_IPV4_PREFIX,
            MDNS_RESPONDER_IPV4_PREFIX,
        ],
        expected_packet_count=expected_packet_count,
        response_destination="unicast"
        if case.name == "mdns-qu-unicast-response"
        else "multicast",
    )
    plan["source_ipv4"] = emitted_source_ipv4
    plan["destination_ipv4"] = destination_ipv4
    plan["target_ipv4"] = target_ipv4
    plan["expected_reply_source_ipv4"] = target_ipv4
    plan["expected_reply_destination_ipv4"] = response_destination_ipv4
    if source_is_target:
        plan["stimulus_source_role"] = "target"
    return plan


def _mdns_ipv6_browse_plan(
    *,
    case: ProbeCase,
    profile: str,
    seed: int,
    sequence: int,
    digest: bytes,
    names: JSONObject,
) -> JSONObject:
    target_digest = deterministic_bytes(f"{case.name}:target", profile, seed, sequence)
    source_ipv6 = deterministic_documentation_ipv6(digest)
    target_ipv6 = deterministic_documentation_ipv6(target_digest)
    source_port = _mdns_source_port(case.name, digest)
    mdns_message, expected_mdns = _mdns_exchange_messages(
        case.name,
        names=names,
        target_ipv4=None,
        target_ipv6=target_ipv6,
        digest=digest,
    )
    plan = _base_plan(
        case=case,
        profile=profile,
        seed=seed,
        sequence=sequence,
        address_family="ipv6",
        source_port=source_port,
        destination_port=MDNS_PORT,
        source_address=source_ipv6,
        destination_address=MDNS_IPV6_MULTICAST,
        target_address=target_ipv6,
        expected_reply_source=target_ipv6,
        expected_reply_destination=source_ipv6,
        multicast_group=MDNS_IPV6_MULTICAST,
        mdns_message=mdns_message,
        expected_mdns=expected_mdns,
        target_service=_target_service(
            case=case,
            names=names,
            bind_address=target_ipv6,
            source_address=source_ipv6,
            address_family="ipv6",
            expected_mdns=expected_mdns,
        ),
        capture_filter=(
            f"ip6 and udp and src host {target_ipv6} and dst host {source_ipv6} "
            f"and src port {MDNS_PORT} and dst port {source_port}"
        ),
        documentation_prefixes=[MDNS_DOCUMENTATION_IPV6_PREFIX],
        expected_packet_count=1,
        response_destination="multicast",
    )
    plan["source_ipv6"] = source_ipv6
    plan["destination_ipv6"] = MDNS_IPV6_MULTICAST
    plan["target_ipv6"] = target_ipv6
    plan["expected_reply_source_ipv6"] = target_ipv6
    plan["expected_reply_destination_ipv6"] = source_ipv6
    return plan


def _base_plan(
    *,
    case: ProbeCase,
    profile: str,
    seed: int,
    sequence: int,
    address_family: str,
    source_port: int,
    destination_port: int,
    source_address: str,
    destination_address: str,
    target_address: str,
    expected_reply_source: str,
    expected_reply_destination: str,
    multicast_group: str,
    mdns_message: JSONObject,
    expected_mdns: JSONObject,
    target_service: JSONObject,
    capture_filter: str,
    documentation_prefixes: list[str],
    expected_packet_count: int,
    response_destination: str,
) -> JSONObject:
    validation = _validation_contract(
        case=case,
        address_family=address_family,
        source_port=source_port,
        destination_port=destination_port,
        source_address=source_address,
        destination_address=destination_address,
        expected_reply_source=expected_reply_source,
        expected_reply_destination=expected_reply_destination,
        expected_mdns=expected_mdns,
        expected_packet_count=expected_packet_count,
        response_destination=response_destination,
    )
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
        "live_capable": True,
        "protocol": "mdns",
        "transport": "udp",
        "address_family": address_family,
        "source_port": source_port,
        "destination_port": destination_port,
        "service_port": MDNS_PORT,
        "multicast_group": multicast_group,
        "source_address": source_address,
        "destination_address": destination_address,
        "target_address": target_address,
        "expected_reply_source": expected_reply_source,
        "expected_reply_destination": expected_reply_destination,
        "mdns": mdns_message,
        "expected_mdns": expected_mdns,
        "target_service": target_service,
        "capture_filter": capture_filter,
        "validation": validation,
        "wire_requirements": {
            "requires_live_network": True,
            "requires_capture": True,
            "requires_multicast": "multicast" in case.required_capabilities[0],
            "requires_ipv6_link_local_scope": address_family == "ipv6",
            "requires_controlled_service": True,
            "expected_packet_count": expected_packet_count,
        },
        "provider_capabilities": list(case.required_capabilities),
        "required_capabilities": list(case.required_capabilities),
        "skip_reasons": {
            "capability": _capability_skip_reasons(case),
            "failure": mdns_failure_reasons(case.name) or [],
        },
        "stimulus_driver": {
            "name": MDNS_STIMULUS_DRIVER,
            "adapter_module": MDNS_ADAPTER_MODULE,
            "state": "planned-only",
            "planned_only": True,
        },
        "documentation_prefixes": documentation_prefixes,
    }


def _mdns_exchange_messages(
    case_name: str,
    *,
    names: JSONObject,
    target_ipv4: str | None,
    target_ipv6: str | None,
    digest: bytes,
) -> tuple[JSONObject, JSONObject]:
    query_id = int.from_bytes(digest[0:2], "big")
    instance_name = str(names["instance_name"])
    host_name = str(names["host_name"])
    txt_strings = list(names["txt_strings"])  # type: ignore[arg-type]
    service_records = _service_records(
        instance_name=instance_name,
        host_name=host_name,
        txt_strings=txt_strings,
        target_ipv4=target_ipv4,
        target_ipv6=target_ipv6,
        ttl=120,
    )

    if case_name in {
        "mdns-ipv4-multicast-browse",
        "mdns-ipv6-multicast-browse",
    }:
        question = _question(MDNS_SERVICE_NAME, "PTR")
        response_answers = [
            _ptr_answer(MDNS_SERVICE_NAME, instance_name),
            *_additional_service_records(service_records),
        ]
        return (
            _query_message(query_id=query_id, questions=[question]),
            _response_message(answers=response_answers, authoritative=True),
        )
    if case_name == "mdns-qu-unicast-response":
        question = _question(MDNS_SERVICE_NAME, "PTR", unicast_response=True)
        response_answers = [
            _ptr_answer(MDNS_SERVICE_NAME, instance_name),
            *_additional_service_records(service_records),
        ]
        return (
            _query_message(query_id=query_id, questions=[question]),
            _response_message(
                answers=response_answers,
                authoritative=True,
                response_delivery="unicast",
            ),
        )
    if case_name == "mdns-service-resolve":
        questions = [
            _question(instance_name, "SRV"),
            _question(instance_name, "TXT"),
        ]
        return (
            _query_message(query_id=query_id, questions=questions),
            _response_message(answers=service_records, authoritative=True),
        )
    if case_name == "mdns-announcement":
        answers = [
            _ptr_answer(MDNS_SERVICE_NAME, instance_name),
            *_additional_service_records(service_records),
        ]
        return (
            _response_message(answers=answers, authoritative=True, unsolicited=True),
            _response_message(answers=answers, authoritative=True, unsolicited=True),
        )
    if case_name == "mdns-goodbye":
        goodbye_records = [
            _ptr_answer(MDNS_SERVICE_NAME, instance_name, ttl=0),
            *_service_records(
                instance_name=instance_name,
                host_name=host_name,
                txt_strings=txt_strings,
                target_ipv4=target_ipv4,
                target_ipv6=target_ipv6,
                ttl=0,
            ),
        ]
        return (
            _response_message(
                answers=goodbye_records,
                authoritative=True,
                goodbye=True,
                unsolicited=True,
            ),
            _response_message(
                answers=goodbye_records,
                authoritative=True,
                goodbye=True,
                unsolicited=True,
            ),
        )
    if case_name == "mdns-known-answer-suppression":
        known_answer = _ptr_answer(MDNS_SERVICE_NAME, instance_name, ttl=120)
        return (
            _query_message(
                query_id=query_id,
                questions=[_question(MDNS_SERVICE_NAME, "PTR")],
                known_answers=[known_answer],
            ),
            {
                "transaction_id": 0,
                "message_kind": "suppressed",
                "expected_packet_count": 0,
                "suppressed_answer": known_answer,
                "reason": "known_answer_ttl_at_least_half_original",
            },
        )
    if case_name == "mdns-cache-flush-response":
        cache_flush_answer = _a_answer(host_name, target_ipv4 or "198.51.100.10")
        return (
            _query_message(
                query_id=query_id,
                questions=[_question(host_name, "A")],
            ),
            _response_message(
                answers=[cache_flush_answer],
                authoritative=True,
                cache_flush_required=True,
            ),
        )
    if case_name == "mdns-subtype-browse":
        question = _question(MDNS_SUBTYPE_NAME, "PTR")
        response_answers = [
            _ptr_answer(MDNS_SUBTYPE_NAME, instance_name),
            _ptr_answer(MDNS_SERVICE_ENUMERATION_NAME, MDNS_SERVICE_NAME),
            *_additional_service_records(service_records),
        ]
        return (
            _query_message(query_id=query_id, questions=[question]),
            _response_message(answers=response_answers, authoritative=True),
        )
    if case_name == "mdns-bonjour-txt":
        question = _question(instance_name, "TXT")
        txt_answer = _txt_answer(instance_name, txt_strings)
        return (
            _query_message(query_id=query_id, questions=[question]),
            _response_message(
                answers=[txt_answer],
                authoritative=True,
                bonjour_txt_keys=[item.split("=", 1)[0] for item in txt_strings],
            ),
        )
    raise ValueError(f"unsupported mDNS probe case {case_name!r}")


def _query_message(
    *,
    query_id: int,
    questions: Sequence[JSONObject],
    known_answers: Sequence[JSONObject] = (),
) -> JSONObject:
    return {
        "transaction_id": 0,
        "query_id_hint": query_id,
        "message_kind": "query",
        "opcode": "QUERY",
        "response": False,
        "questions": [dict(question) for question in questions],
        "answers": [dict(answer) for answer in known_answers],
        "authority": [],
        "additional": [],
        "transport": "udp/5353",
    }


def _response_message(
    *,
    answers: Sequence[JSONObject],
    authoritative: bool,
    response_delivery: str = "multicast",
    unsolicited: bool = False,
    goodbye: bool = False,
    cache_flush_required: bool = False,
    bonjour_txt_keys: Sequence[str] = (),
) -> JSONObject:
    message: JSONObject = {
        "transaction_id": 0,
        "message_kind": "response",
        "opcode": "QUERY",
        "response": True,
        "authoritative_answer": authoritative,
        "questions": [],
        "answers": [dict(answer) for answer in answers],
        "authority": [],
        "additional": [],
        "transport": "udp/5353",
        "response_delivery": response_delivery,
    }
    if unsolicited:
        message["unsolicited"] = True
    if goodbye:
        message["goodbye"] = True
    if cache_flush_required:
        message["cache_flush_required"] = True
    if bonjour_txt_keys:
        message["bonjour_txt_keys"] = list(bonjour_txt_keys)
    return message


def _question(
    name: str,
    record_type: str,
    *,
    unicast_response: bool = False,
) -> JSONObject:
    return {
        "name": name,
        "record_type": record_type,
        "class": "IN",
        "unicast_response": unicast_response,
    }


def _ptr_answer(name: str, target: str, *, ttl: int = 120) -> JSONObject:
    return {
        "name": name,
        "record_type": "PTR",
        "class": "IN",
        "ttl": ttl,
        "target": target,
        "cache_flush": False,
    }


def _srv_answer(name: str, target: str, *, port: int, ttl: int) -> JSONObject:
    return {
        "name": name,
        "record_type": "SRV",
        "class": "IN",
        "ttl": ttl,
        "priority": 0,
        "weight": 0,
        "port": port,
        "target": target,
        "cache_flush": True,
    }


def _txt_answer(name: str, strings: Sequence[str], *, ttl: int = 120) -> JSONObject:
    return {
        "name": name,
        "record_type": "TXT",
        "class": "IN",
        "ttl": ttl,
        "strings": list(strings),
        "cache_flush": True,
    }


def _a_answer(name: str, address: str, *, ttl: int = 120) -> JSONObject:
    return {
        "name": name,
        "record_type": "A",
        "class": "IN",
        "ttl": ttl,
        "address": address,
        "cache_flush": True,
    }


def _aaaa_answer(name: str, address: str, *, ttl: int = 120) -> JSONObject:
    return {
        "name": name,
        "record_type": "AAAA",
        "class": "IN",
        "ttl": ttl,
        "address": address,
        "cache_flush": True,
    }


def _service_records(
    *,
    instance_name: str,
    host_name: str,
    txt_strings: Sequence[str],
    target_ipv4: str | None,
    target_ipv6: str | None,
    ttl: int,
) -> list[JSONObject]:
    records = [
        _srv_answer(instance_name, host_name, port=631, ttl=ttl),
        _txt_answer(instance_name, txt_strings, ttl=ttl),
    ]
    if target_ipv4 is not None:
        records.append(_a_answer(host_name, target_ipv4, ttl=ttl))
    if target_ipv6 is not None:
        records.append(_aaaa_answer(host_name, target_ipv6, ttl=ttl))
    return records


def _additional_service_records(records: Sequence[JSONObject]) -> list[JSONObject]:
    return [dict(record) for record in records]


def _target_service(
    *,
    case: ProbeCase,
    names: JSONObject,
    bind_address: str,
    source_address: str,
    address_family: str,
    expected_mdns: JSONObject,
) -> JSONObject:
    service: JSONObject = {
        "required": True,
        "kind": MDNS_SERVICE_KIND,
        "protocol": "udp",
        "port": MDNS_PORT,
        "runtime": MDNS_RUNTIME,
        "planned_only": True,
        "deterministic": True,
        "behavior": str(case.metadata.get("exchange")),
        "service_name": MDNS_SERVICE_NAME,
        "subtype_name": MDNS_SUBTYPE_NAME,
        "instance_name": str(names["instance_name"]),
        "host_name": str(names["host_name"]),
        "txt_strings": list(names["txt_strings"]),  # type: ignore[arg-type]
        "records": list(expected_mdns.get("answers", []))
        if isinstance(expected_mdns.get("answers"), list)
        else [],
    }
    if address_family == "ipv6":
        service["bind_ipv6"] = bind_address
        service["source_ipv6"] = source_address
    else:
        service["bind_ipv4"] = bind_address
        service["source_ipv4"] = source_address
    return service


def _validation_contract(
    *,
    case: ProbeCase,
    address_family: str,
    source_port: int,
    destination_port: int,
    source_address: str,
    destination_address: str,
    expected_reply_source: str,
    expected_reply_destination: str,
    expected_mdns: JSONObject,
    expected_packet_count: int,
    response_destination: str,
) -> JSONObject:
    validation: JSONObject = {
        "expected_decode": "mdns",
        "transport": "udp",
        "source_port": source_port,
        "destination_port": destination_port,
        "udp_5353": True,
        "message_kind": str(case.metadata.get("message_kind")),
        "exchange": str(case.metadata.get("exchange")),
        "expected_packet_count": expected_packet_count,
        "response_destination": response_destination,
        "expected_records": _record_summaries(expected_mdns),
    }
    if address_family == "ipv6":
        validation["source_ipv6"] = expected_reply_source
        validation["destination_ipv6"] = expected_reply_destination
        validation["stimulus_source_ipv6"] = source_address
        validation["stimulus_destination_ipv6"] = destination_address
    else:
        validation["source_ipv4"] = expected_reply_source
        validation["destination_ipv4"] = expected_reply_destination
        validation["stimulus_source_ipv4"] = source_address
        validation["stimulus_destination_ipv4"] = destination_address
    if expected_mdns.get("message_kind") == "suppressed":
        validation["expected_decode"] = "no_mdns_response"
        validation["suppression_reason"] = str(expected_mdns.get("reason"))
    if expected_mdns.get("cache_flush_required") is True:
        validation["cache_flush_required"] = True
    if expected_mdns.get("goodbye") is True:
        validation["ttl"] = 0
    if isinstance(expected_mdns.get("bonjour_txt_keys"), list):
        validation["bonjour_txt_keys"] = list(
            expected_mdns["bonjour_txt_keys"]  # type: ignore[index]
        )
    return validation


def _record_summaries(message: JSONObject) -> list[JSONObject]:
    records = message.get("answers")
    if not isinstance(records, list):
        return []
    summaries: list[JSONObject] = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        summary: JSONObject = {
            "name": str(record.get("name", "")),
            "record_type": str(record.get("record_type", "")),
        }
        if "ttl" in record:
            summary["ttl"] = int(record["ttl"])  # type: ignore[arg-type]
        if "cache_flush" in record:
            summary["cache_flush"] = bool(record["cache_flush"])
        summaries.append(summary)
    return summaries


def _mdns_names(digest: bytes, profile: str) -> JSONObject:
    suffix = digest.hex()[:8]
    profile_label = dns_label(profile)
    instance_number = 1 + digest[2] % 99
    host_number = 1 + digest[3] % 99
    return {
        "service_name": MDNS_SERVICE_NAME,
        "subtype_name": MDNS_SUBTYPE_NAME,
        "instance_name": f"Crafter Printer {instance_number}._ipp._tcp.local.",
        "host_name": f"crafter-printer-{host_number}.local.",
        "txt_strings": [
            "txtvers=1",
            "qtotal=1",
            f"rp=printers/{profile_label}",
            "ty=Crafter Documentation Printer",
            f"UUID=00000000-0000-4000-8000-{suffix}0000",
        ],
    }


def _documentation_ipv4_pair(digest: bytes) -> tuple[str, str]:
    source_host = 1 + digest[4] % 250
    target_host = 1 + digest[5] % 250
    return f"192.0.2.{source_host}", f"198.51.100.{target_host}"


def _mdns_source_port(case_name: str, digest: bytes) -> int:
    if case_name in {
        "mdns-announcement",
        "mdns-goodbye",
        "mdns-cache-flush-response",
    }:
        return MDNS_PORT
    if case_name == "mdns-qu-unicast-response":
        return 49152 + int.from_bytes(digest[6:8], "big") % 12000
    return MDNS_PORT


def _ipv4_capture_filter(
    *,
    case_name: str,
    source_ipv4: str,
    target_ipv4: str,
    destination_ipv4: str,
    response_destination_ipv4: str,
    source_port: int,
) -> str:
    if case_name in {"mdns-announcement", "mdns-goodbye"}:
        return (
            f"udp and src host {target_ipv4} and dst host {destination_ipv4} "
            f"and src port {MDNS_PORT} and dst port {MDNS_PORT}"
        )
    if case_name == "mdns-known-answer-suppression":
        return f"udp and src host {target_ipv4} and port {MDNS_PORT}"
    return (
        f"udp and src host {target_ipv4} and dst host {response_destination_ipv4} "
        f"and src port {MDNS_PORT} and dst port {source_port}"
    )


def _capability_skip_reasons(case: ProbeCase) -> list[str]:
    reasons: list[str] = []
    for capability_name in case.required_capabilities:
        if capability_name in {"mdns_ipv4_multicast", "mdns_ipv6_multicast"}:
            reasons.append("requires_multicast")
        elif capability_name == "mdns_ipv6_link_local_scope":
            reasons.append("requires_ipv6_link_local_scope_metadata")
        elif capability_name in {"mdns_controlled_responder", "mdns_unicast_response"}:
            reasons.append("requires_controlled_service")
        else:
            reasons.append("provider_capability_unavailable")
    return list(dict.fromkeys(reasons))


def mdns_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    return [plan for plan in probe_plans if plan.get("case") in _MDNS_CASE_BY_NAME]


def mdns_target_service_contribution(
    probe_plans: Sequence[JSONObject],
    *,
    dry_run: bool,
) -> JSONObject:
    service_plans = [
        plan
        for plan in mdns_probe_plans(probe_plans)
        if isinstance(plan.get("target_service"), Mapping)
        and plan.get("target_service", {}).get("kind") == MDNS_SERVICE_KIND
    ]
    plans_by_port = plans_by_destination_port(service_plans)
    services = [
        {
            "name": MDNS_SERVICE_KIND,
            "protocol": "udp",
            "port": port,
            "purpose": "mdns-controlled-dns-sd-responder",
            "runtime": MDNS_RUNTIME,
            "deterministic": True,
            "planned_only": True,
            "query_count": sum(
                1
                for item in service_plans
                if int(item.get("destination_port", 0)) == port
            ),
            "cases": [
                str(item.get("case"))
                for item in service_plans
                if int(item.get("destination_port", 0)) == port
            ],
            "supports": {
                "bonjour_records": True,
                "qu_unicast_response": True,
                "known_answer_suppression": True,
                "goodbye": True,
                "a_records": True,
                "aaaa_records": True,
            },
            **target_service_address_fields(plan),
            **_mdns_target_service_ipv6_fields(service_plans),
            "log_paths": [
                f"live-artifacts/probe/target-services/mdns-{port}.stdout.txt",
                f"live-artifacts/probe/target-services/mdns-{port}.stderr.txt",
            ],
        }
        for port, plan in plans_by_port.items()
    ]
    return {
        "services": services,
        "starts_services": not dry_run and bool(services),
    }


def _mdns_target_service_ipv6_fields(probe_plans: Sequence[JSONObject]) -> JSONObject:
    for plan in probe_plans:
        service = plan.get("target_service")
        if not isinstance(service, Mapping):
            continue
        bind_ipv6 = service.get("bind_ipv6")
        source_ipv6 = service.get("source_ipv6")
        if isinstance(bind_ipv6, str) and bind_ipv6:
            fields: JSONObject = {"bind_ipv6": bind_ipv6}
            if isinstance(source_ipv6, str) and source_ipv6:
                fields["source_ipv6"] = source_ipv6
            return fields
    return {}


def mdns_port_check_lines(mdns_plans: Sequence[JSONObject]) -> list[str]:
    ports = dedupe_ints(
        int(plan["destination_port"])
        for plan in mdns_plans
        if isinstance(plan.get("destination_port"), int)
    )
    lines: list[str] = []
    for port in ports:
        lines.append(f"check_udp_port_free \"$mdns_bind_ipv4\" {port}")
        lines.append(
            f"if [ -n \"$mdns_bind_ipv6\" ]; then "
            f"check_udp6_port_free \"$mdns_bind_ipv6\" {port}; fi"
        )
    return lines


def mdns_responder_setup_lines(
    *,
    artifact_root: str,
    mdns_plans: Sequence[JSONObject],
) -> list[str]:
    ports = dedupe_ints(
        int(plan["destination_port"])
        for plan in mdns_plans
        if isinstance(plan.get("destination_port"), int)
    )
    if not ports:
        return []

    plan_path = posixpath.join(artifact_root, "mdns-plan.json")
    service_path = posixpath.join(artifact_root, "mdns-responder.py")
    lines = [
        f"cat > {shlex.quote(plan_path)} <<'JSON'",
        json.dumps(list(mdns_plans), sort_keys=True),
        "JSON",
        f"cat > {shlex.quote(service_path)} <<'PY'",
        *(_mdns_responder_python_lines()),
        "PY",
    ]
    for port in ports:
        stdout_path = posixpath.join(artifact_root, f"mdns-{port}.stdout.txt")
        stderr_path = posixpath.join(artifact_root, f"mdns-{port}.stderr.txt")
        pid_path = posixpath.join(artifact_root, f"mdns-{port}.pid")
        lines.extend(
            [
                (
                    f"python3 {shlex.quote(service_path)} "
                    f"\"$mdns_bind_ipv4\" \"$mdns_bind_ipv6\" "
                    f"\"$target_interface\" {port} {shlex.quote(plan_path)} "
                    f">{shlex.quote(stdout_path)} 2>{shlex.quote(stderr_path)} &"
                ),
                "pid=$!",
                f"echo \"$pid\" > {shlex.quote(pid_path)}",
                "printf '%s\\n' \"kill $pid 2>/dev/null || true\" >> \"$cleanup\"",
                f"printf '%s\\n' \"rm -f {shlex.quote(pid_path)}\" >> \"$cleanup\"",
                "sleep 0.5",
                "if ! kill -0 \"$pid\" 2>/dev/null; then",
                f"  cat {shlex.quote(stderr_path)} >&2 || true",
                f"  echo mdns_responder_{port}=failed >&2",
                "  exit 73",
                "fi",
                f"echo mdns_responder_{port}=running",
            ]
        )
    return lines


def _mdns_responder_python_lines() -> list[str]:
    return [
        "import json",
        "import select",
        "import signal",
        "import socket",
        "import struct",
        "import sys",
        "import time",
        "",
        "MDNS_IPV4_MULTICAST = '224.0.0.251'",
        "MDNS_IPV6_MULTICAST = 'ff02::fb'",
        "TYPE_CODES = {'A': 1, 'PTR': 12, 'TXT': 16, 'AAAA': 28, 'SRV': 33}",
        "stop = False",
        "",
        "def handle_stop(_signum, _frame):",
        "    global stop",
        "    stop = True",
        "",
        "signal.signal(signal.SIGTERM, handle_stop)",
        "signal.signal(signal.SIGINT, handle_stop)",
        "",
        "bind_ipv4, bind_ipv6, interface, port_text, plan_path = sys.argv[1:6]",
        "port = int(port_text)",
        "plans = json.load(open(plan_path, encoding='utf-8'))",
        "",
        "def log(event, **fields):",
        "    print(json.dumps({'event': event, **fields}, sort_keys=True), flush=True)",
        "",
        "def encode_name(name):",
        "    out = bytearray()",
        "    for label in str(name).rstrip('.').split('.'):",
        "        raw = label.encode('utf-8')",
        "        out.append(len(raw))",
        "        out.extend(raw)",
        "    out.append(0)",
        "    return bytes(out)",
        "",
        "def rr(record):",
        "    rtype = TYPE_CODES[str(record['record_type'])]",
        "    rclass = 1 | (0x8000 if record.get('cache_flush') else 0)",
        "    ttl = int(record.get('ttl', 120))",
        "    data = rdata(record, rtype)",
        "    return (",
        "        encode_name(record['name'])",
        "        + struct.pack('!HHIH', rtype, rclass, ttl, len(data))",
        "        + data",
        "    )",
        "",
        "def rdata(record, rtype):",
        "    if rtype == 1:",
        "        return socket.inet_aton(str(record['address']))",
        "    if rtype == 28:",
        "        return socket.inet_pton(socket.AF_INET6, str(record['address']))",
        "    if rtype == 12:",
        "        return encode_name(record['target'])",
        "    if rtype == 16:",
        "        chunks = []",
        "        for value in record.get('strings', []):",
        "            raw = str(value).encode('utf-8')",
        "            chunks.append(bytes([len(raw)]) + raw)",
        "        return b''.join(chunks)",
        "    if rtype == 33:",
        "        return struct.pack(",
        "            '!HHH',",
        "            int(record.get('priority', 0)),",
        "            int(record.get('weight', 0)),",
        "            int(record['port']),",
        "        ) + encode_name(record['target'])",
        "    return b''",
        "",
        "def response_bytes(plan):",
        "    message = plan.get('expected_mdns') or {}",
        "    answers = message.get('answers') or []",
        "    body = b''.join(rr(answer) for answer in answers)",
        "    return struct.pack('!HHHHHH', 0, 0x8400, 0, len(answers), 0, 0) + body",
        "",
        "def read_name(message, offset):",
        "    labels = []",
        "    while offset < len(message):",
        "        length = message[offset]",
        "        offset += 1",
        "        if length == 0:",
        "            break",
        "        if length & 0xC0:",
        "            offset += 1",
        "            break",
        "        labels.append(message[offset:offset + length].decode('utf-8', 'replace'))",
        "        offset += length",
        "    return '.'.join(labels) + '.', offset",
        "",
        "def query_shape(data):",
        "    if len(data) < 12:",
        "        return [], 0",
        "    qdcount = struct.unpack('!H', data[4:6])[0]",
        "    ancount = struct.unpack('!H', data[6:8])[0]",
        "    offset = 12",
        "    names = []",
        "    for _ in range(qdcount):",
        "        name, offset = read_name(data, offset)",
        "        names.append(name.lower())",
        "        offset += 4",
        "    return names, ancount",
        "",
        "def choose_plan(data):",
        "    names, ancount = query_shape(data)",
        "    if ancount:",
        "        for plan in plans:",
        "            if plan.get('case') == 'mdns-known-answer-suppression':",
        "                return plan",
        "    for plan in plans:",
        "        questions = ((plan.get('mdns') or {}).get('questions') or [])",
        "        wanted = {str(item.get('name', '')).lower() for item in questions}",
        "        if wanted and wanted.intersection(names):",
        "            return plan",
        "    for plan in plans:",
        "        if (plan.get('validation') or {}).get('expected_packet_count', 1):",
        "            return plan",
        "    return None",
        "",
        "def make_ipv4_socket():",
        "    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
        "    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)",
        "    sock.bind(('', port))",
        "    sock.settimeout(1.0)",
        "    try:",
        "        mreq = socket.inet_aton(MDNS_IPV4_MULTICAST) + socket.inet_aton(bind_ipv4)",
        "        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)",
        "    except OSError as exc:",
        "        log('multicast_join_failed', family='ipv4', error=str(exc))",
        "    return sock",
        "",
        "def make_ipv6_socket():",
        "    if not bind_ipv6:",
        "        return None",
        "    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)",
        "    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)",
        "    sock.bind(('::', port))",
        "    sock.settimeout(1.0)",
        "    try:",
        "        ifindex = socket.if_nametoindex(interface) if interface else 0",
        "        group = socket.inet_pton(socket.AF_INET6, MDNS_IPV6_MULTICAST)",
        (
            "        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, "
            "group + struct.pack('@I', ifindex))"
        ),
        "    except OSError as exc:",
        "        log('multicast_join_failed', family='ipv6', error=str(exc))",
        "    return sock",
        "",
        "sock4 = make_ipv4_socket()",
        "sock6 = make_ipv6_socket()",
        "sockets = [sock for sock in (sock4, sock6) if sock is not None]",
        (
            "log('listening', protocol='mdns', bonjour=True, port=port, "
            "bind_ipv4=bind_ipv4, bind_ipv6=bind_ipv6)"
        ),
        "for plan in plans:",
        "    if plan.get('case') in ('mdns-announcement', 'mdns-goodbye'):",
        "        payload = response_bytes(plan)",
        "        sock4.sendto(payload, (MDNS_IPV4_MULTICAST, port))",
        (
            "        log('emitted', case=plan.get('case'), bytes=len(payload), "
            "destination=MDNS_IPV4_MULTICAST)"
        ),
        "while not stop:",
        "    readable, _, _ = select.select(sockets, [], [], 1.0)",
        "    for sock in readable:",
        "        data, addr = sock.recvfrom(65535)",
        "        plan = choose_plan(data)",
        "        if not plan:",
        "            log('ignored', client=str(addr), bytes=len(data))",
        "            continue",
        "        if (plan.get('validation') or {}).get('expected_packet_count') == 0:",
        "            log('suppressed', case=plan.get('case'), client=str(addr))",
        "            continue",
        "        payload = response_bytes(plan)",
        (
            "        destination = addr if plan.get('case') == "
            "'mdns-qu-unicast-response' else (MDNS_IPV4_MULTICAST, port)"
        ),
        "        sock.sendto(payload, destination)",
        (
            "        log('responded', case=plan.get('case'), client=str(addr), "
            "bytes=len(payload), destination=str(destination))"
        ),
        "for sock in sockets:",
        "    sock.close()",
        "log('stopped', ts=time.time())",
    ]


def mdns_failure_reasons(case_name: str) -> list[str] | None:
    if case_name not in _MDNS_CASE_BY_NAME:
        return None
    return [
        FAILURE_TIMEOUT,
        FAILURE_WRONG_PEER,
        FAILURE_WRONG_PAYLOAD,
        FAILURE_DECODE_FAILED,
        FAILURE_TARGET_SETUP_FAILED,
    ]


def mdns_lab_capabilities(substrate: Mapping[str, JSONValue]) -> Mapping[str, object]:
    ipv4_unicast = capability(substrate, "ipv4_unicast", "ipv4")
    ipv6_unicast = capability(substrate, "ipv6_unicast", "ipv6")
    controlled_services = capability(
        substrate,
        "controlled_services",
        "controlled_service",
    )
    controlled_responder = controlled_services and capability_default_true(
        substrate,
        "mdns_controlled_responder",
        "mdns_responder",
        "controlled_udp_service",
    )
    link_layer_send = capability(substrate, "link_layer_send")
    link_layer_capture = capability(substrate, "link_layer_capture", "packet_capture")
    provider_mac = capability(substrate, "provider_mac_known", "provider_mac")
    interface_metadata = capability_default_true(
        substrate,
        "target_interface_known",
        "provider_interface_known",
    )
    ipv4_multicast = (
        ipv4_unicast
        and link_layer_send
        and link_layer_capture
        and capability_default_true(
            substrate,
            "mdns_ipv4_multicast",
            "ipv4_multicast",
            "multicast",
            "multicast_send",
        )
    )
    ipv6_multicast = (
        ipv6_unicast
        and link_layer_send
        and link_layer_capture
        and capability_default_true(
            substrate,
            "mdns_ipv6_multicast",
            "ipv6_multicast",
            "multicast",
            "multicast_send",
        )
    )
    return {
        "mdns_controlled_responder": controlled_responder,
        "mdns_unicast_response": (
            ipv4_unicast
            and controlled_responder
            and capability_default_true(substrate, "mdns_unicast_response")
        ),
        "mdns_ipv4_multicast": ipv4_multicast,
        "mdns_ipv6_multicast": ipv6_multicast,
        "mdns_ipv6_link_local_scope": (
            ipv6_multicast and provider_mac and interface_metadata
        ),
    }


_MDNS_PLAN_BUILDERS: dict[str, object] = {
    case.name: _mdns_probe_plan for case in MDNS_PROBE_CASES
}

_MDNS_PROFILE_COUNTS: dict[str, dict[str, int]] = {
    MDNS_SMOKE_PROFILE: {case.name: 1 for case in MDNS_PROBE_CASES}
}


register(
    ProtocolPlugin(
        name="mdns",
        cases=MDNS_PROBE_CASES,
        plan_builders=_MDNS_PLAN_BUILDERS,
        planned_only_cases=_MDNS_PLANNED_ONLY_CASES,
        profile_counts=_MDNS_PROFILE_COUNTS,
        stimulus_endpoint_cases=frozenset(),
        target_service=mdns_target_service_contribution,
        setup_script=None,
        rewrite_endpoint_addresses=None,
        failure_reasons=mdns_failure_reasons,
        lab_capabilities=mdns_lab_capabilities,
    )
)
