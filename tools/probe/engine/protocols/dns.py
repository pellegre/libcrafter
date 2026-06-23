"""DNS probe protocol plugin: cases, plan builders, and planning surface.

This is the DNS *planning half* migration (the second protocol onto the
:class:`ProtocolPlugin` contract, after the ARP vertical slice). It bundles
DNS's planning surface in one place:

* the ten DNS behavioral cases plus the inline ``dns-query`` smoke case and the
  DNS capability constant (the catalog contribution),
* the ``_dns_*_probe_plan`` plan builders, the multi-send
  ``_dns_repeat_transaction_send`` helper, and the DNS-only deterministic
  name/string helpers (the plan-builder contribution),
* and the DNS stimulus-endpoint routing set.

The plan builders and the deterministic helpers are moved verbatim from
:mod:`tools.probe.engine.planning`; :mod:`planning` re-imports the builders and
the ``dns_*`` name helpers so ``planning._<builder>`` /
``planning.PLAN_BUILDERS[name]`` (the DNS behavior tests' ``assertIs`` pins) and
``planning.dns_query_name`` (re-exported through ``cli`` for the
``cli._dns_query_name is planning.dns_query_name`` pin) keep identical object
identity. DNS carries no ``planned_only`` cases, and its ``profile_counts`` is
intentionally empty: DNS sits at the front of the ``behavior`` profile and the
``dns-query`` smoke case rides the ``smoke`` profile, both order-sensitive, so
the legacy ordered profile name tables in :mod:`tools.probe.engine.cases` keep
owning DNS's profile membership to preserve byte-identical selection order.

The DNS target-service / address-rewrite / failure-reason / lab-capability
hooks complete the migration here (step 20): the ``target_service`` hook
contributes the ``dns-responder`` service entries; the co-located setup-script
blocks (the per-port UDP free check and the responder heredoc + launch) are
called directly by ``target_services.target_service_setup_script`` because they
need the planned DNS plans the ``setup_script`` hook is not handed; the
``rewrite_endpoint_addresses`` hook reproduces the DNS live-path rewrite (and the
``dns-a-success`` fall-through to the shared IPv4 tail); the ``failure_reasons``
hook reproduces the DNS failure taxonomy; and the ``lab_capabilities`` hook
contributes the ``dns_service`` derived capability.

Imports are relative only so the module loads under both engine import roots
(``engine.protocols.dns`` for the CLI and ``tools.probe.engine.protocols.dns``
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
    FAILURE_WRONG_FLAGS,
    FAILURE_WRONG_PAYLOAD,
    FAILURE_WRONG_PEER,
    apply_shared_ipv4_rewrite_tail,
)
from ..model import JSONObject, JSONValue, ProbeCase, json_object
from ..planning_helpers import (
    deterministic_bytes,
    deterministic_documentation_ipv6,
    deterministic_ipv4_pair,
    dns_label,
)
from ..target_service_helpers import (
    TargetServiceDescriptor,
    dedupe_ints,
    plans_by_destination_port,
    target_service_address_fields,
)
from .base import ProtocolPlugin, register


# Capabilities required by each DNS behavioral case. DNS needs only IPv4 unicast
# plus a controlled DNS responder; the capability name matches the probe
# capability derivation in :mod:`tools.probe.engine.lab`, so the behavior-suite
# cases skip with stable reasons on providers that cannot support them.
_DNS_CAPABILITIES = ["dns_service"]


# Ten DNS behavioral cases (RFC-correct query/response shapes against a
# controlled DNS responder bound to the target address).
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
        description=(
            "Query a present name under an absent type and validate the NODATA "
            "(NOERROR, no answer) response."
        ),
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
        description=(
            "Send two A queries reusing one transaction id over separate source "
            "ports and validate each response is matched to its own send."
        ),
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
)


# The inline ``dns-query`` smoke case (the legacy per-protocol aggregation
# carried this directly rather than through the ``_behavior_case`` factory).
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


def dns_query_name(*, profile: str, seed: int, sequence: int, digest: bytes) -> str:
    label = dns_label(profile)
    suffix = digest.hex()[:10]
    return f"probe-{seed}-{sequence}-{suffix}.{label}.libcrafter.test."


# The DNS plan-builder dispatch contribution: each case name maps to the exact
# function object above. ``planning`` re-imports these so its module-level names
# and ``PLAN_BUILDERS`` entries are the same objects (identity-pinned by the DNS
# behavior tests).
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


# The DNS cases routed through the stimulus endpoint adapter. All eleven DNS
# cases (the inline ``dns-query`` smoke case plus the ten behavioral cases) have
# a stimulus-endpoint adapter arm, matching the legacy routing set exactly.
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


# --------------------------------------------------------------------------- #
# Target-service descriptor and case selector (moved from target_services.py)
# --------------------------------------------------------------------------- #
#
# Probe cases that drive the controlled UDP DNS responder. ``dns-query`` is the
# legacy smoke case; ``dns-a-success``, ``dns-aaaa-success``, and the later DNS
# behavioral cases reuse the same responder descriptor and target setup.
_DNS_RESPONDER_CASES: frozenset[str] = frozenset(
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


def dns_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return the DNS-query probe plans in order."""

    return [plan for plan in probe_plans if plan.get("case") in _DNS_RESPONDER_CASES]


def dns_responder_descriptor(
    *,
    bind_ipv4: str,
    source_ipv4: str,
    port: int,
    artifact_root: str,
) -> TargetServiceDescriptor:
    """Describe the controlled UDP DNS responder bound to the target address."""

    # Imported lazily so the plugin module loads during ``protocols`` package
    # auto-discovery without cycling through ``capabilities`` -> ``lab`` ->
    # ``protocols``. The constant is a plain skip-reason string.
    from ..capabilities import SKIP_REQUIRES_CONTROLLED_SERVICE

    return TargetServiceDescriptor(
        name="dns-responder",
        protocol="udp",
        purpose="dns-query",
        bind_ipv4=bind_ipv4,
        source_ipv4=source_ipv4,
        port=port,
        requires=["python3", SKIP_REQUIRES_CONTROLLED_SERVICE],
        setup_commands=[
            f"check udp port {bind_ipv4}:{port} is free",
            f"start dns-responder.py on {bind_ipv4}:{port}",
        ],
        cleanup_commands=[
            f"kill dns-responder on {bind_ipv4}:{port}",
        ],
        artifacts=[
            posixpath.join(artifact_root, f"dns-responder-{port}.stdout.txt"),
            posixpath.join(artifact_root, f"dns-responder-{port}.stderr.txt"),
            posixpath.join(artifact_root, f"dns-responder-{port}.pid"),
        ],
        metadata={"runtime": "python3", "deterministic": True},
    )


def dns_target_service_contribution(
    probe_plans: Sequence[JSONObject],
    *,
    dry_run: bool,
) -> JSONObject:
    """Return the DNS plugin's ``target_service_setup_plan`` contribution.

    Moved verbatim from the ``dns-responder`` ``services`` entries of the central
    ``target_service_setup_plan``: one controlled UDP DNS responder service per
    distinct destination port, plus the ``starts_services`` flip on a live run
    that has at least one DNS responder to stand up. The registry merge appends
    these services to the central plan's ``services`` list and OR-s
    ``starts_services``, byte-identical to the legacy per-protocol path.
    """

    dns_plans = dns_probe_plans(probe_plans)
    dns_plans_by_port = plans_by_destination_port(dns_plans)
    services = [
        {
            "name": "dns-responder",
            "protocol": "udp",
            "port": port,
            "purpose": "dns-query",
            "deterministic": True,
            "query_count": sum(
                1
                for plan in dns_plans
                if int(plan.get("destination_port", 0)) == port
            ),
            **target_service_address_fields(plan),
            "log_paths": [
                f"live-artifacts/probe/target-services/dns-responder-{port}.stdout.txt",
                f"live-artifacts/probe/target-services/dns-responder-{port}.stderr.txt",
            ],
        }
        for port, plan in dns_plans_by_port.items()
    ]
    return {
        "services": services,
        "starts_services": not dry_run and bool(dns_plans_by_port),
    }


# --------------------------------------------------------------------------- #
# Target setup-script blocks (moved from target_services.target_service_setup_script)
# --------------------------------------------------------------------------- #
#
# The DNS setup-script contribution is split into two blocks that the legacy
# ``target_service_setup_script`` emitted at two distinct positions: a per-port
# UDP port-free check (rendered before the closed/open-port handling) and the
# DNS responder heredoc + launch block (rendered after the TCP listeners). They
# are co-located here and called *directly* by ``target_service_setup_script``
# (the plugin ``setup_script`` hook receives no plan context), so the rendered
# bytes stay byte-identical to the legacy inline blocks.


def dns_port_check_lines(dns_plans: Sequence[JSONObject]) -> list[str]:
    """Render the DNS per-port UDP port-free check block.

    Moved verbatim from the ``for port in dns_ports:`` loop that ran before the
    DHCP/closed/open-port handling in ``target_service_setup_script``; binds
    ``$dns_bind_ipv4:port`` to confirm the port is free before the responder
    starts.
    """

    dns_ports = dedupe_ints(
        int(plan["destination_port"])
        for plan in dns_plans
        if isinstance(plan.get("destination_port"), int)
    )
    lines: list[str] = []
    for port in dns_ports:
        lines.extend(
            [
                "python3 - \"$dns_bind_ipv4\" \"$1\" <<'PY'".replace("$1", str(port)),
                "import socket",
                "import sys",
                "bind_ip = sys.argv[1]",
                "port = int(sys.argv[2])",
                "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
                "try:",
                "    sock.bind((bind_ip, port))",
                "except OSError as exc:",
                "    print(f'udp port {bind_ip}:{port} is not free: {exc}', file=sys.stderr)",
                "    sys.exit(1)",
                "finally:",
                "    sock.close()",
                "PY",
            ]
        )
    return lines


def dns_responder_setup_lines(
    *,
    artifact_root: str,
    dns_plans: Sequence[JSONObject],
) -> list[str]:
    """Render the DNS responder heredoc + launch block for the setup script.

    Moved verbatim from the ``if dns_ports:`` responder heredoc and the
    subsequent ``for port in dns_ports:`` launch loop of
    ``target_service_setup_script``; the orchestrator calls this with the planned
    DNS plans so the rendered script bytes stay byte-identical.
    """

    dns_plan_json = json.dumps(list(dns_plans), sort_keys=True)
    dns_ports = dedupe_ints(
        int(plan["destination_port"])
        for plan in dns_plans
        if isinstance(plan.get("destination_port"), int)
    )
    lines: list[str] = []
    if dns_ports:
        zone_path = posixpath.join(artifact_root, "dns-zone.json")
        service_path = posixpath.join(artifact_root, "dns-responder.py")
        lines.extend(
            [
                f"cat > {shlex.quote(zone_path)} <<'JSON'",
                dns_plan_json,
                "JSON",
                f"cat > {shlex.quote(service_path)} <<'PY'",
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
                "zone_path, bind_ip, port_text = sys.argv[1:4]",
                "port = int(port_text)",
                "plans = json.load(open(zone_path, encoding='utf-8'))",
                "records = {}",
                "present_names = set()",
                "# repeat_overrides maps a client source port to the A answer that",
                "# port's send expects. The dns-repeat-transaction case reuses one",
                "# transaction id and query name across two sends distinguished only",
                "# by source port, so the responder serves each send its own planned",
                "# answer keyed by the client source port — that is what lets the",
                "# stimulus match each response back to its send without confusing",
                "# the two same-name responses.",
                "repeat_overrides = {}",
                "for plan in plans:",
                "    name = str(plan['query_name']).lower().rstrip('.') + '.'",
                "    qtype = int(plan['query_type_value'])",
                "    service = plan.get('target_service') or {}",
                "    # NXDOMAIN cases register no record: the name is deliberately",
                "    # absent so the responder returns rcode 3 with an empty answer",
                "    # section and the original question echoed.",
                "    if isinstance(service, dict) and service.get('absent'):",
                "        records.pop((name, qtype), None)",
                "        continue",
                "    # NODATA cases: the name EXISTS in the zone, but only under a",
                "    # different type (present_type), so the queried type has no",
                "    # record. Mark the name present (so the responder returns",
                "    # rcode 0 NODATA, not rcode 3 NXDOMAIN) without registering an",
                "    # answer record for the queried type.",
                "    if isinstance(service, dict) and service.get('nodata'):",
                "        present_names.add(name)",
                "        records.pop((name, qtype), None)",
                "        continue",
                "    present_names.add(name)",
                "    # TXT answers carry a list of character-strings instead of a",
                "    # single address/name answer_data. Each string is encoded on",
                "    # the wire as one length-prefixed DNS character-string.",
                "    if qtype == 16:",
                "        strings = service.get('txt_strings') if isinstance(service, dict) else None",
                "        if not strings:",
                "            strings = plan.get('expected_txt_strings') or []",
                "        records[(name, qtype)] = {",
                "            'txt_strings': [str(value) for value in strings],",
                "            'ttl': int(plan.get('answer_ttl', 60)),",
                "        }",
                "        continue",
                "    # MX answers carry structured RDATA: a 16-bit preference",
                "    # followed by the exchange <domain-name>, encoded uncompressed",
                "    # so the wire rdlength is 2 + encoded-name length.",
                "    if qtype == 15:",
                "        preference = service.get('mx_preference') if isinstance(service, dict) else None",
                "        exchange = service.get('mx_exchange') if isinstance(service, dict) else None",
                "        if preference is None:",
                "            preference = plan.get('expected_mx_preference')",
                "        if exchange is None:",
                "            exchange = plan.get('expected_mx_exchange')",
                "        records[(name, qtype)] = {",
                "            'mx_preference': int(preference),",
                "            'mx_exchange': str(exchange).lower().rstrip('.') + '.',",
                "            'ttl': int(plan.get('answer_ttl', 60)),",
                "        }",
                "        continue",
                "    # SRV answers carry structured RDATA: three 16-bit fields",
                "    # (priority, weight, port) followed by the target",
                "    # <domain-name>, encoded uncompressed so the wire rdlength is",
                "    # 6 + encoded-name length.",
                "    if qtype == 33:",
                "        priority = service.get('srv_priority') if isinstance(service, dict) else None",
                "        weight = service.get('srv_weight') if isinstance(service, dict) else None",
                "        srv_port = service.get('srv_port') if isinstance(service, dict) else None",
                "        target = service.get('srv_target') if isinstance(service, dict) else None",
                "        if priority is None:",
                "            priority = plan.get('expected_srv_priority')",
                "        if weight is None:",
                "            weight = plan.get('expected_srv_weight')",
                "        if srv_port is None:",
                "            srv_port = plan.get('expected_srv_port')",
                "        if target is None:",
                "            target = plan.get('expected_srv_target')",
                "        records[(name, qtype)] = {",
                "            'srv_priority': int(priority),",
                "            'srv_weight': int(weight),",
                "            'srv_port': int(srv_port),",
                "            'srv_target': str(target).lower().rstrip('.') + '.',",
                "            'ttl': int(plan.get('answer_ttl', 60)),",
                "        }",
                "        continue",
                "    record = {",
                "        'answer_data': str(plan['expected_answer_data']),",
                "        'ttl': int(plan.get('answer_ttl', 60)),",
                "    }",
                "    # EDNS(0) cases attach an OPT pseudo-record (RFC 6891) to the",
                "    # response's additional section. The responder echoes a planned",
                "    # OPT: UDP payload size in CLASS, extended rcode/version/DO flag",
                "    # packed into TTL, and an ordered {code,length,data} option list",
                "    # in the RDATA.",
                "    edns = service.get('edns') if isinstance(service, dict) else None",
                "    if isinstance(edns, dict):",
                "        record['edns'] = {",
                "            'udp_payload_size': int(edns.get('udp_payload_size', 4096)),",
                "            'version': int(edns.get('version', 0)),",
                "            'extended_rcode': int(edns.get('extended_rcode', 0)),",
                "            'do': bool(edns.get('do', False)),",
                "            'options': [",
                "                {",
                "                    'code': int(option['code']),",
                "                    'data': bytes.fromhex(str(option.get('data_hex', ''))),",
                "                }",
                "                for option in edns.get('options', [])",
                "            ],",
                "        }",
                "    # dns-repeat-transaction: register the per-source-port answer",
                "    # overrides so each send (same name/id, distinct source port)",
                "    # gets its own A answer.",
                "    repeat = service.get('repeat_transaction') if isinstance(service, dict) else None",
                "    if isinstance(repeat, dict):",
                "        for send in repeat.get('sends', []):",
                "            repeat_overrides[(name, qtype, int(send['source_port']))] = {",
                "                'answer_data': str(send['answer_data']),",
                "                'ttl': int(send.get('answer_ttl', record['ttl'])),",
                "            }",
                "    chain = service.get('cname_chain') if isinstance(service, dict) else None",
                "    if isinstance(chain, dict):",
                "        canonical = str(chain['canonical_name']).lower().rstrip('.') + '.'",
                "        record['cname'] = {",
                "            'canonical_name': canonical,",
                "            'cname_ttl': int(chain.get('cname_ttl', record['ttl'])),",
                "            'address_ttl': int(chain.get('address_ttl', record['ttl'])),",
                "        }",
                "    records[(name, qtype)] = record",
                "",
                "def read_name(message, offset):",
                "    labels = []",
                "    jumped = False",
                "    consumed = 0",
                "    seen = set()",
                "    while True:",
                "        if offset >= len(message):",
                "            raise ValueError('name offset out of range')",
                "        length = message[offset]",
                "        if length & 0xc0 == 0xc0:",
                "            if offset + 1 >= len(message):",
                "                raise ValueError('truncated compression pointer')",
                "            pointer = ((length & 0x3f) << 8) | message[offset + 1]",
                "            if pointer in seen:",
                "                raise ValueError('compression pointer loop')",
                "            seen.add(pointer)",
                "            if not jumped:",
                "                consumed += 2",
                "            offset = pointer",
                "            jumped = True",
                "            continue",
                "        offset += 1",
                "        if not jumped:",
                "            consumed += 1",
                "        if length == 0:",
                "            return '.'.join(labels).lower() + '.', consumed",
                "        if length & 0xc0:",
                "            raise ValueError('unsupported dns label kind')",
                "        label = message[offset:offset + length]",
                "        if len(label) != length:",
                "            raise ValueError('truncated dns label')",
                "        labels.append(label.decode('ascii'))",
                "        offset += length",
                "        if not jumped:",
                "            consumed += length",
                "",
                "def encode_name(name):",
                "    out = bytearray()",
                "    for label in name.rstrip('.').split('.'):",
                "        raw = label.encode('ascii')",
                "        out.append(len(raw))",
                "        out.extend(raw)",
                "    out.append(0)",
                "    return bytes(out)",
                "",
                "def encode_opt(edns):",
                "    # EDNS(0) OPT pseudo-record (RFC 6891 Section 6.1): root owner",
                "    # name, TYPE 41, CLASS = requestor UDP payload size, TTL packs",
                "    # extended-rcode(8) | version(8) | DO flag (bit 0 of the low 16),",
                "    # and RDATA is the ordered {code(u16), length(u16), data} options.",
                "    do_flag = 0x8000 if edns['do'] else 0",
                "    ttl = (",
                "        ((edns['extended_rcode'] & 0xff) << 24)",
                "        | ((edns['version'] & 0xff) << 16)",
                "        | do_flag",
                "    )",
                "    rdata = b''",
                "    for option in edns['options']:",
                "        data = option['data']",
                "        rdata += struct.pack('!HH', option['code'] & 0xffff, len(data)) + data",
                "    return (",
                "        b'\\x00'",
                "        + struct.pack('!HHIH', 41, edns['udp_payload_size'] & 0xffff, ttl, len(rdata))",
                "        + rdata",
                "    )",
                "",
                "def response_for(query, client_port=None):",
                "    if len(query) < 12:",
                "        raise ValueError('query shorter than dns header')",
                "    txid, flags, qdcount, _ancount, _nscount, _arcount = struct.unpack('!HHHHHH', query[:12])",
                "    if qdcount < 1:",
                "        raise ValueError('query has no question')",
                "    name, consumed = read_name(query, 12)",
                "    question_end = 12 + consumed + 4",
                "    if question_end > len(query):",
                "        raise ValueError('truncated dns question')",
                "    qtype, qclass = struct.unpack('!HH', query[12 + consumed:question_end])",
                "    question = query[12:question_end]",
                "    record = records.get((name, qtype))",
                "    rd = flags & 0x0100",
                "    if record is None or qclass != 1:",
                "        # NODATA: the name exists (under a different type), so the",
                "        # response is NOERROR (rcode 0) with the question echoed and",
                "        # an empty answer section. NXDOMAIN (rcode 3) is reserved for",
                "        # names absent from the zone.",
                "        if qclass == 1 and name in present_names:",
                "            header = struct.pack('!HHHHHH', txid, 0x8000 | rd | 0x0080, 1, 0, 0, 0)",
                "            return header + question, {'name': name, 'qtype': qtype, 'rcode': 0}",
                "        header = struct.pack('!HHHHHH', txid, 0x8000 | rd | 3, 1, 0, 0, 0)",
                "        return header + question, {'name': name, 'qtype': qtype, 'rcode': 3}",
                "    chain = record.get('cname')",
                "    if chain is not None:",
                "        if qtype != 1:",
                "            raise ValueError(f'cname chain only supports qtype 1, got {qtype}')",
                "        canonical = chain['canonical_name']",
                "        canonical_wire = encode_name(canonical)",
                "        cname_answer = (",
                "            b'\\xc0\\x0c'",
                "            + struct.pack('!HHIH', 5, 1, chain['cname_ttl'], len(canonical_wire))",
                "            + canonical_wire",
                "        )",
                "        address = ipaddress.IPv4Address(record['answer_data']).packed",
                "        a_answer = (",
                "            canonical_wire",
                "            + struct.pack('!HHIH', 1, 1, chain['address_ttl'], len(address))",
                "            + address",
                "        )",
                "        header = struct.pack('!HHHHHH', txid, 0x8000 | rd | 0x0400 | 0x0080, 1, 2, 0, 0)",
                "        meta = {",
                "            'name': name,",
                "            'qtype': qtype,",
                "            'rcode': 0,",
                "            'answer_count': 2,",
                "            'canonical_name': canonical,",
                "        }",
                "        return header + question + cname_answer + a_answer, meta",
                "    answer_data = record.get('answer_data')",
                "    answer_ttl = record['ttl']",
                "    # Per-source-port answer override (dns-repeat-transaction): pick",
                "    # the A answer planned for this client source port so each send's",
                "    # response carries its own answer.",
                "    override = repeat_overrides.get((name, qtype, client_port))",
                "    if override is not None:",
                "        answer_data = override['answer_data']",
                "        answer_ttl = override['ttl']",
                "    if qtype == 1:",
                "        if answer_data is None:",
                "            raise ValueError('A answer missing answer_data')",
                "        rdata = ipaddress.IPv4Address(answer_data).packed",
                "    elif qtype == 28:",
                "        if answer_data is None:",
                "            raise ValueError('AAAA answer missing answer_data')",
                "        rdata = ipaddress.IPv6Address(answer_data).packed",
                "    elif qtype == 16:",
                "        # TXT RDATA: one or more DNS character-strings, each a",
                "        # single length octet followed by up to 255 content bytes.",
                "        rdata = b''",
                "        for value in record['txt_strings']:",
                "            raw = value.encode('utf-8')",
                "            if len(raw) > 255:",
                "                raise ValueError('txt character-string exceeds 255 bytes')",
                "            rdata += bytes([len(raw)]) + raw",
                "    elif qtype == 15:",
                "        # MX RDATA: 16-bit preference + exchange <domain-name>,",
                "        # encoded uncompressed so rdlength == 2 + name length.",
                "        rdata = struct.pack('!H', record['mx_preference'] & 0xffff)",
                "        rdata += encode_name(record['mx_exchange'])",
                "    elif qtype == 33:",
                "        # SRV RDATA: 16-bit priority + weight + port, then the",
                "        # target <domain-name>, encoded uncompressed so rdlength",
                "        # == 6 + name length.",
                "        rdata = struct.pack(",
                "            '!HHH',",
                "            record['srv_priority'] & 0xffff,",
                "            record['srv_weight'] & 0xffff,",
                "            record['srv_port'] & 0xffff,",
                "        )",
                "        rdata += encode_name(record['srv_target'])",
                "    else:",
                "        raise ValueError(f'unsupported qtype {qtype}')",
                "    answer = b'\\xc0\\x0c' + struct.pack('!HHIH', qtype, 1, answer_ttl, len(rdata)) + rdata",
                "    # EDNS(0) cases append an OPT pseudo-record to the additional",
                "    # section; arcount reflects it so the OPT decodes as an",
                "    # additional record rather than trailing bytes.",
                "    edns = record.get('edns')",
                "    additional = encode_opt(edns) if edns else b''",
                "    arcount = 1 if edns else 0",
                "    header = struct.pack(",
                "        '!HHHHHH', txid, 0x8000 | rd | 0x0400 | 0x0080, 1, 1, 0, arcount",
                "    )",
                "    meta = {'name': name, 'qtype': qtype, 'rcode': 0}",
                "    if edns:",
                "        meta['edns'] = True",
                "    return header + question + answer + additional, meta",
                "",
                "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
                "sock.bind((bind_ip, port))",
                "sock.settimeout(1.0)",
                "print(json.dumps({'event': 'listening', 'bind_ip': bind_ip, 'port': port}), flush=True)",
                "while not stop:",
                "    try:",
                "        data, addr = sock.recvfrom(4096)",
                "    except socket.timeout:",
                "        continue",
                "    try:",
                "        response, meta = response_for(data, addr[1])",
                "        sock.sendto(response, addr)",
                "        meta.update({'event': 'answered', 'client': addr[0], 'client_port': addr[1]})",
                "        print(json.dumps(meta, sort_keys=True), flush=True)",
                "    except Exception as exc:",
                "        print(json.dumps({'event': 'error', 'error': str(exc)}), file=sys.stderr, flush=True)",
                "sock.close()",
                "print(json.dumps({'event': 'stopped', 'ts': time.time()}), flush=True)",
                "PY",
            ]
        )
    for port in dns_ports:
        stdout_path = posixpath.join(artifact_root, f"dns-responder-{port}.stdout.txt")
        stderr_path = posixpath.join(artifact_root, f"dns-responder-{port}.stderr.txt")
        pid_path = posixpath.join(artifact_root, f"dns-responder-{port}.pid")
        lines.extend(
            [
                (
                    f"python3 {shlex.quote(posixpath.join(artifact_root, 'dns-responder.py'))} "
                    f"{shlex.quote(posixpath.join(artifact_root, 'dns-zone.json'))} "
                    f"\"$dns_bind_ipv4\" {port} "
                    f">{shlex.quote(stdout_path)} 2>{shlex.quote(stderr_path)} &"
                ),
                "pid=$!",
                f"echo \"$pid\" > {shlex.quote(pid_path)}",
                "printf '%s\\n' \"kill $pid 2>/dev/null || true\" >> \"$cleanup\"",
                f"printf '%s\\n' \"rm -f {shlex.quote(pid_path)}\" >> \"$cleanup\"",
                "sleep 0.5",
                "if ! kill -0 \"$pid\" 2>/dev/null; then",
                f"  cat {shlex.quote(stderr_path)} >&2 || true",
                f"  echo dns_responder_{port}=failed >&2",
                "  exit 73",
                "fi",
                f"echo dns_responder_{port}=running",
            ]
        )
    return lines


# --------------------------------------------------------------------------- #
# Live-path address rewrite (moved from cli._probe_plan_with_endpoint_addresses)
# --------------------------------------------------------------------------- #
#
# The legacy DNS rewrite branch (and failure branch) matched ten DNS cases but
# intentionally NOT ``dns-a-success``: that case carries no DNS-specific rewrite
# (its plan validation already pins the transport peers), so it fell through the
# per-protocol if/elif to the shared IPv4-layer tail, and its failure taxonomy
# defaulted to the empty list. The plugin reproduces that exactly: a case not in
# this set gets only the shared transport-IPv4 pre-sets plus the shared tail (the
# same bytes the legacy fall-through produced), and its failure hook returns
# ``None`` so the central dispatcher falls through to the default.
_DNS_REWRITE_CASES: frozenset[str] = frozenset(
    {
        "dns-query",
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


def dns_rewrite_endpoint_addresses(
    plan: JSONObject,
    *,
    source_ipv4: str,
    target_ipv4: str,
    source_mac: str | None = None,
    target_mac: str | None = None,
    target_interface: str | None = None,
    rewrite_source: str = "wire_endpoint_plan",
) -> JSONObject:
    """Rewrite a DNS probe plan onto the live lab-segment addresses.

    Moved verbatim from the DNS branch of
    ``cli._probe_plan_with_endpoint_addresses`` (including the shared
    transport-IPv4 pre-sets that ran before the per-protocol if/elif). DNS rides
    UDP over IPv4, so its rewrite is exhausted by the common transport-IPv4
    overwrite plus the per-send rewrite below; the branch then falls into the
    shared IPv4-layer validation/live-rewrite tail, applied here. ``dns-a-success``
    carries no DNS-specific rewrite (it is absent from the legacy DNS elif), so it
    skips the DNS-specific block and takes only the shared pre-sets + tail.
    """

    updated = dict(plan)
    updated["source_ipv4"] = source_ipv4
    updated["destination_ipv4"] = target_ipv4
    updated["expected_reply_source_ipv4"] = target_ipv4
    updated["expected_reply_destination_ipv4"] = source_ipv4
    case_name = str(updated.get("case", ""))
    if case_name in _DNS_REWRITE_CASES:
        source_port = int(updated.get("source_port", 0))
        destination_port = int(updated.get("destination_port", 53))
        updated["capture_filter"] = (
            f"udp and src host {target_ipv4} and dst host {source_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        )
        target_service = dict(
            json_object(updated.get("target_service", {}), "probe_plan.target_service")
        )
        target_service.update(
            {
                "bind_ipv4": target_ipv4,
                "port": destination_port,
                "source_ipv4": source_ipv4,
            }
        )
        updated["target_service"] = target_service
        # dns-repeat-transaction carries a per-send array; rewrite each send's
        # addresses, capture filter, and validation for the lab segment so every
        # send is matched against its own response (its own source port) and not
        # confused with the sibling send.
        sends = updated.get("sends")
        if isinstance(sends, list):
            rewritten_sends: list[JSONObject] = []
            for raw_send in sends:
                send = dict(json_object(raw_send, "probe_plan.send"))
                send_source_port = int(send.get("source_port", 0))
                send_destination_port = int(send.get("destination_port", 53))
                send["source_ipv4"] = source_ipv4
                send["destination_ipv4"] = target_ipv4
                send["expected_reply_source_ipv4"] = target_ipv4
                send["expected_reply_destination_ipv4"] = source_ipv4
                send["capture_filter"] = (
                    f"udp and src host {target_ipv4} and dst host {source_ipv4} "
                    f"and src port {send_destination_port} and dst port {send_source_port}"
                )
                send_validation = dict(
                    json_object(send.get("validation", {}), "probe_plan.send.validation")
                )
                send_validation["source_ipv4"] = target_ipv4
                send_validation["destination_ipv4"] = source_ipv4
                send["validation"] = send_validation
                rewritten_sends.append(send)
            updated["sends"] = rewritten_sends
    return apply_shared_ipv4_rewrite_tail(
        updated,
        case_name=case_name,
        source_ipv4=source_ipv4,
        target_ipv4=target_ipv4,
        rewrite_source=rewrite_source,
    )


# --------------------------------------------------------------------------- #
# Failure-reason taxonomy (moved from cli._failure_reasons_for_case)
# --------------------------------------------------------------------------- #


def dns_failure_reasons(case_name: str) -> list[str] | None:
    """Return the ordered DNS failure-reason taxonomy for ``case_name``.

    Moved verbatim from the DNS branch of ``cli._failure_reasons_for_case`` (the
    ten DNS cases excluding ``dns-a-success``, which the legacy code left to the
    empty default). Returns ``None`` for a non-matching case so the central
    dispatcher falls through to the next branch (and, for ``dns-a-success``, to
    the empty default).
    """

    if case_name in _DNS_REWRITE_CASES:
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_WRONG_FLAGS,
            FAILURE_DECODE_FAILED,
            FAILURE_TARGET_SETUP_FAILED,
        ]
    return None


# --------------------------------------------------------------------------- #
# Lab-capability derivation (moved from lab.probe_capabilities_from_lab_capabilities)
# --------------------------------------------------------------------------- #


def dns_lab_capabilities(substrate: Mapping[str, JSONValue]) -> Mapping[str, object]:
    """Return the DNS plugin's derived probe-capability contribution.

    Moved verbatim from the ``dns_service`` boolean derivation in
    ``lab.probe_capabilities_from_lab_capabilities``: the controlled DNS
    responder needs an IPv4-unicast substrate that can host a controlled
    service. The shared ``capability_names`` / ``capability_sources`` tables
    stay in ``lab``; this hook contributes only the derived ``dns_service``
    boolean, merged byte-identically over the legacy value.
    """

    ipv4_unicast = capability(substrate, "ipv4_unicast", "ipv4")
    controlled_services = capability(
        substrate,
        "controlled_services",
        "controlled_service",
    )
    return {
        "dns_service": ipv4_unicast and controlled_services,
    }


register(
    ProtocolPlugin(
        name="dns",
        # The inline ``dns-query`` smoke case is declared first to match its
        # legacy position in the per-protocol aggregation, followed by the ten
        # behavioral cases in declaration order.
        cases=(DNS_QUERY_CASE, *BEHAVIOR_DNS_CASES),
        plan_builders=_DNS_PLAN_BUILDERS,
        # DNS carries no planned-only cases (every builder materializes a plan).
        planned_only_cases=frozenset(),
        # DNS's profile membership stays in the legacy ordered profile tables in
        # ``cases.py`` to preserve byte-identical selection order (the registry-
        # first profile merge would otherwise move DNS to the front of the smoke
        # and behavior profiles). Contribute nothing here.
        profile_counts={},
        stimulus_endpoint_cases=_DNS_STIMULUS_ENDPOINT_CASES,
        # DNS target-service / address-rewrite / failure-reason / lab-capability
        # hooks (step 20, completing DNS). ``target_service`` contributes the
        # ``dns-responder`` services entries (and diverts the DNS cases off the
        # legacy target path). ``setup_script`` stays ``None``: DNS's setup-script
        # blocks (the per-port UDP free check and the responder heredoc + launch)
        # need the planned DNS plans, which the plugin ``setup_script`` hook does
        # not receive, so ``target_services.target_service_setup_script`` renders
        # them by calling :func:`dns_port_check_lines` /
        # :func:`dns_responder_setup_lines` directly (byte-identically to the
        # legacy inline blocks).
        target_service=dns_target_service_contribution,
        setup_script=None,
        rewrite_endpoint_addresses=dns_rewrite_endpoint_addresses,
        failure_reasons=dns_failure_reasons,
        lab_capabilities=dns_lab_capabilities,
    )
)
