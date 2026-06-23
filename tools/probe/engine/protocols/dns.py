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
hooks are deferred to the second half of the slice (step 20); they are ``None``
here, so DNS keeps riding the legacy target-service / CLI paths until then.

Imports are relative only so the module loads under both engine import roots
(``engine.protocols.dns`` for the CLI and ``tools.probe.engine.protocols.dns``
for the tests).
"""

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
        # hooks land in step 20. Until then DNS keeps riding the legacy target-
        # service / CLI paths, so these stay ``None``.
        target_service=None,
        setup_script=None,
        rewrite_endpoint_addresses=None,
        failure_reasons=None,
        lab_capabilities=None,
    )
)
