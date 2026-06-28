"""SSDP probe protocol plugin: dry-run discovery packet plans.

The SSDP probe surface plans source-backed UDP discovery exchanges without
turning probe into a scanner or discovery daemon. All cases are planned-only
until the Rust stimulus adapter and target-service assets land; the plans still
record packet bytes, role intent, capability gates, failure taxonomy, and the
profile contribution in the auto-discovered plugin.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..capability_derivation import capability
from ..case_helpers import _behavior_case
from ..endpoint_addressing import (
    FAILURE_DECODE_FAILED,
    FAILURE_TARGET_SETUP_FAILED,
    FAILURE_TIMEOUT,
    FAILURE_WRONG_PAYLOAD,
    FAILURE_WRONG_PEER,
)
from ..model import JSONObject, JSONValue, ProbeCase
from ..planning_helpers import deterministic_bytes, deterministic_documentation_ipv6
from ..target_service_helpers import (
    plans_by_destination_port,
    target_service_address_fields,
)
from .base import ProtocolPlugin, register


SSDP_SMOKE_PROFILE = "ssdp-smoke"
SSDP_SERVICE_KIND = "ssdp-controlled-responder"
SSDP_RUNTIME = "probe-ssdp-reference"
SSDP_STIMULUS_DRIVER = "ssdp_probe"
SSDP_ADAPTER_MODULE = "tools/probe/adapters/src/ssdp.rs"
SSDP_UDP_PORT = 1900
SSDP_IPV4_MULTICAST = "239.255.255.250"
SSDP_IPV4_HOST = "239.255.255.250:1900"
SSDP_IPV6_LINK_LOCAL_MULTICAST = "ff02::c"
SSDP_IPV6_LINK_LOCAL_HOST = "[ff02::c]:1900"
SSDP_DOCUMENTATION_IPV4_PREFIX = "198.51.100.0/24"
SSDP_DOCUMENTATION_IPV6_PREFIX = "2001:db8::/32"
SSDP_LOCATION_PREFIX = "192.0.2.0/24"
SSDP_MAN_DISCOVER = '"ssdp:discover"'
SSDP_ST_ALL = "ssdp:all"
SSDP_TARGET_ROOTDEVICE = "upnp:rootdevice"
SSDP_SERVER = "example-os/1.0 UPnP/2.0 example-product/1.0"

_SSDP_IPV4_SEARCH_CAPABILITIES = [
    "ssdp_ipv4_multicast",
    "ssdp_controlled_responder",
]
_SSDP_IPV6_SEARCH_CAPABILITIES = [
    "ssdp_ipv6_multicast",
    "ssdp_controlled_responder",
]
_SSDP_NOTIFY_CAPABILITIES = [
    "ssdp_ipv4_multicast",
    "ssdp_controlled_responder",
]
_SSDP_OFFLINE_CAPABILITIES = ["ssdp_offline_plan"]


SSDP_PROBE_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="ssdp-ipv4-search-exchange",
        description=(
            "Plan an IPv4 M-SEARCH multicast stimulus and deterministic "
            "controlled SSDP response."
        ),
        stimulus="ssdp_m_search",
        expected_response="ssdp_search_response",
        required_capabilities=_SSDP_IPV4_SEARCH_CAPABILITIES,
        protocol="ssdp",
        metadata={
            "service": SSDP_SERVICE_KIND,
            "transport": "udp",
            "address_family": "ipv4",
            "message_kind": "m_search",
            "planned_only": True,
            "live_capable": True,
            "multicast_group": SSDP_IPV4_MULTICAST,
            "udp_port": SSDP_UDP_PORT,
        },
    ),
    _behavior_case(
        name="ssdp-ipv6-search-exchange",
        description=(
            "Plan an IPv6 M-SEARCH multicast stimulus and deterministic "
            "controlled SSDP response."
        ),
        stimulus="ssdp_m_search_ipv6",
        expected_response="ssdp_search_response",
        required_capabilities=_SSDP_IPV6_SEARCH_CAPABILITIES,
        protocol="ssdp",
        metadata={
            "service": SSDP_SERVICE_KIND,
            "transport": "udp",
            "address_family": "ipv6",
            "message_kind": "m_search",
            "planned_only": True,
            "live_capable": True,
            "multicast_group": SSDP_IPV6_LINK_LOCAL_MULTICAST,
            "udp_port": SSDP_UDP_PORT,
        },
    ),
    _behavior_case(
        name="ssdp-notify-capture",
        description=(
            "Plan a bounded NOTIFY advertisement from a controlled target and "
            "capture-side decode validation."
        ),
        stimulus="ssdp_notify",
        expected_response="ssdp_notify_observed",
        required_capabilities=_SSDP_NOTIFY_CAPABILITIES,
        protocol="ssdp",
        endpoint_roles=["target", "stimulus"],
        metadata={
            "service": SSDP_SERVICE_KIND,
            "transport": "udp",
            "address_family": "ipv4",
            "message_kind": "notify",
            "planned_only": True,
            "live_capable": True,
            "multicast_group": SSDP_IPV4_MULTICAST,
            "udp_port": SSDP_UDP_PORT,
        },
    ),
    _behavior_case(
        name="ssdp-raw-fallback",
        description=(
            "Plan unrelated UDP/1900 payload handling that must remain Raw "
            "outside the SSDP shape gate."
        ),
        stimulus="ssdp_unrelated_udp_payload",
        expected_response="raw_payload_preserved",
        required_capabilities=_SSDP_OFFLINE_CAPABILITIES,
        protocol="ssdp",
        metadata={
            "service": SSDP_SERVICE_KIND,
            "transport": "udp",
            "message_kind": "raw_fallback",
            "planned_only": True,
            "offline_only": True,
            "udp_port": SSDP_UDP_PORT,
        },
    ),
    _behavior_case(
        name="ssdp-malformed-observation",
        description=(
            "Plan malformed SSDP-like payload reporting as a structured parse "
            "error without live transmission."
        ),
        stimulus="ssdp_malformed_payload",
        expected_response="structured_parse_error",
        required_capabilities=_SSDP_OFFLINE_CAPABILITIES,
        protocol="ssdp",
        metadata={
            "service": SSDP_SERVICE_KIND,
            "transport": "udp",
            "message_kind": "malformed",
            "planned_only": True,
            "offline_only": True,
            "udp_port": SSDP_UDP_PORT,
        },
    ),
)

_SSDP_CASE_BY_NAME: dict[str, ProbeCase] = {
    case.name: case for case in SSDP_PROBE_CASES
}
_SSDP_PLANNED_ONLY_CASES = frozenset(_SSDP_CASE_BY_NAME)
_SSDP_LIVE_CAPABLE_CASES = frozenset(
    case.name
    for case in SSDP_PROBE_CASES
    if case.metadata.get("live_capable") is True
)


def _ssdp_probe_plan(
    *,
    case_name: str,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    case = _SSDP_CASE_BY_NAME[case_name]
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    if case_name == "ssdp-ipv6-search-exchange":
        return _ssdp_ipv6_search_plan(
            case=case,
            profile=profile,
            seed=seed,
            sequence=sequence,
            digest=digest,
        )
    if case_name == "ssdp-notify-capture":
        return _ssdp_notify_plan(
            case=case,
            profile=profile,
            seed=seed,
            sequence=sequence,
            digest=digest,
        )
    if case_name == "ssdp-raw-fallback":
        return _ssdp_raw_fallback_plan(
            case=case,
            profile=profile,
            seed=seed,
            sequence=sequence,
            digest=digest,
        )
    if case_name == "ssdp-malformed-observation":
        return _ssdp_malformed_plan(
            case=case,
            profile=profile,
            seed=seed,
            sequence=sequence,
            digest=digest,
        )
    return _ssdp_ipv4_search_plan(
        case=case,
        profile=profile,
        seed=seed,
        sequence=sequence,
        digest=digest,
    )


def _ssdp_ipv4_search_plan(
    *,
    case: ProbeCase,
    profile: str,
    seed: int,
    sequence: int,
    digest: bytes,
) -> JSONObject:
    source_ipv4, target_ipv4 = _documentation_ipv4_pair(digest)
    source_port = _ephemeral_port(digest)
    mx = 1 + digest[2] % 5
    usn = _device_usn(digest)
    location = _location_url(digest)
    request_payload = _search_payload(host=SSDP_IPV4_HOST, mx=mx)
    response_payload = _response_payload(
        location=location,
        st=SSDP_TARGET_ROOTDEVICE,
        usn=usn,
    )
    return _base_plan(
        case=case,
        profile=profile,
        seed=seed,
        sequence=sequence,
        source_port=source_port,
        destination_port=SSDP_UDP_PORT,
        payload=request_payload,
        expected_payload=response_payload,
        source_ipv4=source_ipv4,
        destination_ipv4=SSDP_IPV4_MULTICAST,
        target_ipv4=target_ipv4,
        expected_reply_source_ipv4=target_ipv4,
        expected_reply_destination_ipv4=source_ipv4,
        documentation_prefixes=[
            SSDP_DOCUMENTATION_IPV4_PREFIX,
            SSDP_LOCATION_PREFIX,
        ],
        ssdp={
            "message_kind": "m_search",
            "method": "M-SEARCH",
            "request_target": "*",
            "version": "HTTP/1.1",
            "headers": _search_headers(host=SSDP_IPV4_HOST, mx=mx),
        },
        expected_ssdp={
            "message_kind": "response",
            "start_line": "HTTP/1.1 200 OK",
            "status_code": 200,
            "reason_phrase": "OK",
            "headers": _response_headers(
                location=location,
                st=SSDP_TARGET_ROOTDEVICE,
                usn=usn,
            ),
        },
        capture_filter=(
            f"udp and src host {target_ipv4} and dst host {source_ipv4} "
            f"and src port {SSDP_UDP_PORT} and dst port {source_port}"
        ),
        validation={
            "expected_decode": "ssdp",
            "source_ipv4": target_ipv4,
            "destination_ipv4": source_ipv4,
            "source_port": SSDP_UDP_PORT,
            "destination_port": source_port,
            "status_code": 200,
            "st": SSDP_TARGET_ROOTDEVICE,
            "usn": usn,
            "planned_only": True,
        },
        target_service={
            "required": True,
            "kind": SSDP_SERVICE_KIND,
            "protocol": "udp",
            "port": SSDP_UDP_PORT,
            "bind_ipv4": target_ipv4,
            "source_ipv4": source_ipv4,
            "runtime": SSDP_RUNTIME,
            "behavior": "search_response",
            "response_payload_hex": response_payload.hex(),
            "deterministic": True,
            "planned_only": True,
        },
        wire_requirements={
            "requires_ipv4_multicast": True,
            "requires_controlled_service": True,
            "requires_ssdp_controlled_responder": True,
            "dry_run_only_until_adapter": True,
        },
        digest=digest,
    )


def _ssdp_ipv6_search_plan(
    *,
    case: ProbeCase,
    profile: str,
    seed: int,
    sequence: int,
    digest: bytes,
) -> JSONObject:
    source_ipv6 = deterministic_documentation_ipv6(digest)
    target_ipv6 = deterministic_documentation_ipv6(digest[::-1])
    source_port = _ephemeral_port(digest)
    mx = 1 + digest[2] % 5
    usn = _device_usn(digest)
    location = _location_url(digest)
    request_payload = _search_payload(host=SSDP_IPV6_LINK_LOCAL_HOST, mx=mx)
    response_payload = _response_payload(
        location=location,
        st=SSDP_TARGET_ROOTDEVICE,
        usn=usn,
    )
    return _base_plan(
        case=case,
        profile=profile,
        seed=seed,
        sequence=sequence,
        source_port=source_port,
        destination_port=SSDP_UDP_PORT,
        payload=request_payload,
        expected_payload=response_payload,
        source_ipv6=source_ipv6,
        destination_ipv6=SSDP_IPV6_LINK_LOCAL_MULTICAST,
        target_ipv6=target_ipv6,
        expected_reply_source_ipv6=target_ipv6,
        expected_reply_destination_ipv6=source_ipv6,
        documentation_prefixes=[
            SSDP_DOCUMENTATION_IPV6_PREFIX,
            SSDP_LOCATION_PREFIX,
        ],
        ssdp={
            "message_kind": "m_search",
            "method": "M-SEARCH",
            "request_target": "*",
            "version": "HTTP/1.1",
            "headers": _search_headers(host=SSDP_IPV6_LINK_LOCAL_HOST, mx=mx),
        },
        expected_ssdp={
            "message_kind": "response",
            "start_line": "HTTP/1.1 200 OK",
            "status_code": 200,
            "reason_phrase": "OK",
            "headers": _response_headers(
                location=location,
                st=SSDP_TARGET_ROOTDEVICE,
                usn=usn,
            ),
        },
        capture_filter=(
            f"ip6 and udp and src host {target_ipv6} and dst host {source_ipv6} "
            f"and src port {SSDP_UDP_PORT} and dst port {source_port}"
        ),
        validation={
            "expected_decode": "ssdp",
            "source_ipv6": target_ipv6,
            "destination_ipv6": source_ipv6,
            "source_port": SSDP_UDP_PORT,
            "destination_port": source_port,
            "status_code": 200,
            "st": SSDP_TARGET_ROOTDEVICE,
            "usn": usn,
            "planned_only": True,
        },
        target_service={
            "required": True,
            "kind": SSDP_SERVICE_KIND,
            "protocol": "udp",
            "port": SSDP_UDP_PORT,
            "bind_ipv6": target_ipv6,
            "source_ipv6": source_ipv6,
            "runtime": SSDP_RUNTIME,
            "behavior": "search_response_ipv6",
            "response_payload_hex": response_payload.hex(),
            "deterministic": True,
            "planned_only": True,
        },
        wire_requirements={
            "requires_ipv6_multicast": True,
            "requires_controlled_service": True,
            "requires_ssdp_controlled_responder": True,
            "dry_run_only_until_adapter": True,
        },
        digest=digest,
    )


def _ssdp_notify_plan(
    *,
    case: ProbeCase,
    profile: str,
    seed: int,
    sequence: int,
    digest: bytes,
) -> JSONObject:
    source_ipv4, target_ipv4 = _documentation_ipv4_pair(digest)
    source_port = SSDP_UDP_PORT
    usn = _device_usn(digest)
    location = _location_url(digest)
    payload = _notify_payload(location=location, usn=usn)
    return _base_plan(
        case=case,
        profile=profile,
        seed=seed,
        sequence=sequence,
        source_port=source_port,
        destination_port=SSDP_UDP_PORT,
        payload=payload,
        expected_payload=payload,
        source_ipv4=target_ipv4,
        destination_ipv4=SSDP_IPV4_MULTICAST,
        target_ipv4=target_ipv4,
        expected_reply_source_ipv4=target_ipv4,
        expected_reply_destination_ipv4=source_ipv4,
        documentation_prefixes=[
            SSDP_DOCUMENTATION_IPV4_PREFIX,
            SSDP_LOCATION_PREFIX,
        ],
        ssdp={
            "message_kind": "notify",
            "method": "NOTIFY",
            "request_target": "*",
            "version": "HTTP/1.1",
            "headers": _notify_headers(location=location, usn=usn),
        },
        expected_ssdp={
            "message_kind": "notify",
            "method": "NOTIFY",
            "headers": _notify_headers(location=location, usn=usn),
        },
        capture_filter=(
            f"udp and src host {target_ipv4} and dst host {SSDP_IPV4_MULTICAST} "
            f"and src port {SSDP_UDP_PORT} and dst port {SSDP_UDP_PORT}"
        ),
        validation={
            "expected_decode": "ssdp",
            "source_ipv4": target_ipv4,
            "destination_ipv4": SSDP_IPV4_MULTICAST,
            "source_port": SSDP_UDP_PORT,
            "destination_port": SSDP_UDP_PORT,
            "method": "NOTIFY",
            "nt": SSDP_TARGET_ROOTDEVICE,
            "nts": "ssdp:alive",
            "usn": usn,
            "planned_only": True,
        },
        target_service={
            "required": True,
            "kind": SSDP_SERVICE_KIND,
            "protocol": "udp",
            "port": SSDP_UDP_PORT,
            "bind_ipv4": target_ipv4,
            "source_ipv4": source_ipv4,
            "runtime": SSDP_RUNTIME,
            "behavior": "notify_emit",
            "notify_payload_hex": payload.hex(),
            "deterministic": True,
            "planned_only": True,
        },
        wire_requirements={
            "requires_ipv4_multicast": True,
            "requires_controlled_service": True,
            "requires_capture": True,
            "dry_run_only_until_adapter": True,
        },
        digest=digest,
    )


def _ssdp_raw_fallback_plan(
    *,
    case: ProbeCase,
    profile: str,
    seed: int,
    sequence: int,
    digest: bytes,
) -> JSONObject:
    source_ipv4, target_ipv4 = _documentation_ipv4_pair(digest)
    source_port = _ephemeral_port(digest)
    payload = b"not-ssdp\r\nbinary:\x00\xff\r\n"
    return _base_plan(
        case=case,
        profile=profile,
        seed=seed,
        sequence=sequence,
        source_port=source_port,
        destination_port=SSDP_UDP_PORT,
        payload=payload,
        expected_payload=payload,
        source_ipv4=source_ipv4,
        destination_ipv4=target_ipv4,
        expected_reply_source_ipv4=target_ipv4,
        expected_reply_destination_ipv4=source_ipv4,
        documentation_prefixes=[SSDP_DOCUMENTATION_IPV4_PREFIX],
        ssdp={
            "message_kind": "raw_fallback",
            "shape_gate": "reject",
            "payload_hex": payload.hex(),
        },
        expected_ssdp={
            "message_kind": "raw_preserved",
            "raw_hex": payload.hex(),
        },
        capture_filter=(
            f"udp and host {target_ipv4} and port {SSDP_UDP_PORT}"
        ),
        validation={
            "expected_decode": "raw",
            "source_ipv4": target_ipv4,
            "destination_ipv4": source_ipv4,
            "source_port": SSDP_UDP_PORT,
            "destination_port": source_port,
            "raw_hex": payload.hex(),
            "planned_only": True,
        },
        target_service={
            "required": False,
            "kind": "none",
            "behavior": "offline_raw_fallback",
        },
        wire_requirements={
            "offline_only": True,
            "requires_live_network": False,
        },
        digest=digest,
    )


def _ssdp_malformed_plan(
    *,
    case: ProbeCase,
    profile: str,
    seed: int,
    sequence: int,
    digest: bytes,
) -> JSONObject:
    source_ipv4, target_ipv4 = _documentation_ipv4_pair(digest)
    source_port = _ephemeral_port(digest)
    payload = b"M-SEARCH * HTTP/1.1\r\nHOST 239.255.255.250:1900\r\n\r\n"
    return _base_plan(
        case=case,
        profile=profile,
        seed=seed,
        sequence=sequence,
        source_port=source_port,
        destination_port=SSDP_UDP_PORT,
        payload=payload,
        expected_payload=payload,
        source_ipv4=source_ipv4,
        destination_ipv4=target_ipv4,
        expected_reply_source_ipv4=target_ipv4,
        expected_reply_destination_ipv4=source_ipv4,
        documentation_prefixes=[SSDP_DOCUMENTATION_IPV4_PREFIX],
        ssdp={
            "message_kind": "malformed",
            "payload_hex": payload.hex(),
            "malformed_reason": "header_missing_colon",
        },
        expected_ssdp={
            "message_kind": "structured_error",
            "context": "ssdp.header",
            "required": "header-name ':' header-value",
            "available": len(payload),
        },
        capture_filter=(
            f"udp and host {target_ipv4} and port {SSDP_UDP_PORT}"
        ),
        validation={
            "expected_decode": "structured_error",
            "error_context": "ssdp.header",
            "source_ipv4": target_ipv4,
            "destination_ipv4": source_ipv4,
            "source_port": SSDP_UDP_PORT,
            "destination_port": source_port,
            "planned_only": True,
        },
        target_service={
            "required": False,
            "kind": "none",
            "behavior": "offline_malformed_observation",
        },
        wire_requirements={
            "offline_only": True,
            "requires_live_network": False,
        },
        digest=digest,
    )


def _base_plan(
    *,
    case: ProbeCase,
    profile: str,
    seed: int,
    sequence: int,
    source_port: int,
    destination_port: int,
    payload: bytes,
    expected_payload: bytes,
    documentation_prefixes: list[str],
    ssdp: JSONObject,
    expected_ssdp: JSONObject,
    capture_filter: str,
    validation: JSONObject,
    target_service: JSONObject,
    wire_requirements: JSONObject,
    digest: bytes,
    source_ipv4: str | None = None,
    destination_ipv4: str | None = None,
    target_ipv4: str | None = None,
    expected_reply_source_ipv4: str | None = None,
    expected_reply_destination_ipv4: str | None = None,
    source_ipv6: str | None = None,
    destination_ipv6: str | None = None,
    target_ipv6: str | None = None,
    expected_reply_source_ipv6: str | None = None,
    expected_reply_destination_ipv6: str | None = None,
) -> JSONObject:
    payload_hex = payload.hex()
    expected_payload_hex = expected_payload.hex()
    plan: JSONObject = {
        "schema_version": 1,
        "case": case.name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": case.stimulus,
        "expected_response": case.expected_response,
        "planned_only": True,
        "live_capable": bool(case.metadata.get("live_capable", False)),
        "protocol": "ssdp",
        "transport": "udp",
        "source_port": source_port,
        "destination_port": destination_port,
        "udp_port": SSDP_UDP_PORT,
        "multicast_group": str(case.metadata.get("multicast_group", "")),
        "payload_hex": payload_hex,
        "payload_length": len(payload),
        "udp_payload_hex": payload_hex,
        "udp_payload_length": len(payload),
        "expected_payload_hex": expected_payload_hex,
        "expected_payload_length": len(expected_payload),
        "ssdp": ssdp,
        "expected_ssdp": expected_ssdp,
        "stimulus_driver": {
            "name": SSDP_STIMULUS_DRIVER,
            "adapter_module": SSDP_ADAPTER_MODULE,
            "state": "planned-only",
            "planned_only": True,
        },
        "target_service": target_service,
        "capture_filter": capture_filter,
        "validation": validation,
        "wire_requirements": wire_requirements,
        "skip_reasons": {
            "capability": _capability_skip_reasons(case),
            "failure": ssdp_failure_reasons(case.name) or [],
        },
        "documentation_prefixes": documentation_prefixes,
        "digest_hex": digest.hex()[:16],
    }
    for key, value in (
        ("source_ipv4", source_ipv4),
        ("destination_ipv4", destination_ipv4),
        ("target_ipv4", target_ipv4),
        ("expected_reply_source_ipv4", expected_reply_source_ipv4),
        ("expected_reply_destination_ipv4", expected_reply_destination_ipv4),
        ("source_ipv6", source_ipv6),
        ("destination_ipv6", destination_ipv6),
        ("target_ipv6", target_ipv6),
        ("expected_reply_source_ipv6", expected_reply_source_ipv6),
        ("expected_reply_destination_ipv6", expected_reply_destination_ipv6),
    ):
        if value:
            plan[key] = value
    return plan


def _search_headers(*, host: str, mx: int) -> list[JSONObject]:
    return [
        _header("HOST", host),
        _header("MAN", SSDP_MAN_DISCOVER),
        _header("MX", str(mx)),
        _header("ST", SSDP_ST_ALL),
        _header("USER-AGENT", "libcrafter-probe/0.1 UPnP/2.0 ssdp-probe/0.1"),
    ]


def _response_headers(*, location: str, st: str, usn: str) -> list[JSONObject]:
    return [
        _header("CACHE-CONTROL", "max-age=1800"),
        _header("EXT", ""),
        _header("LOCATION", location),
        _header("SERVER", SSDP_SERVER),
        _header("ST", st),
        _header("USN", usn),
        _header("BOOTID.UPNP.ORG", "1"),
        _header("CONFIGID.UPNP.ORG", "1"),
    ]


def _notify_headers(*, location: str, usn: str) -> list[JSONObject]:
    return [
        _header("HOST", SSDP_IPV4_HOST),
        _header("CACHE-CONTROL", "max-age=1800"),
        _header("LOCATION", location),
        _header("NT", SSDP_TARGET_ROOTDEVICE),
        _header("NTS", "ssdp:alive"),
        _header("SERVER", SSDP_SERVER),
        _header("USN", usn),
        _header("BOOTID.UPNP.ORG", "1"),
        _header("CONFIGID.UPNP.ORG", "1"),
    ]


def _search_payload(*, host: str, mx: int) -> bytes:
    return _message_bytes(
        "M-SEARCH * HTTP/1.1",
        _search_headers(host=host, mx=mx),
    )


def _response_payload(*, location: str, st: str, usn: str) -> bytes:
    return _message_bytes(
        "HTTP/1.1 200 OK",
        _response_headers(location=location, st=st, usn=usn),
    )


def _notify_payload(*, location: str, usn: str) -> bytes:
    return _message_bytes(
        "NOTIFY * HTTP/1.1",
        _notify_headers(location=location, usn=usn),
    )


def _message_bytes(start_line: str, headers: Sequence[JSONObject]) -> bytes:
    lines = [start_line]
    for header in headers:
        name = str(header["name"])
        value = str(header["value"])
        lines.append(f"{name}: {value}" if value else f"{name}:")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def _header(name: str, value: str) -> JSONObject:
    return {"name": name, "value": value}


def _documentation_ipv4_pair(digest: bytes) -> tuple[str, str]:
    source_host = 1 + digest[0] % 120
    target_host = 121 + digest[1] % 120
    return f"198.51.100.{source_host}", f"198.51.100.{target_host}"


def _ephemeral_port(digest: bytes) -> int:
    return 49152 + int.from_bytes(digest[4:6], "big") % 12000


def _device_usn(digest: bytes) -> str:
    suffix = digest.hex()[:12]
    return f"uuid:device-{suffix}::{SSDP_TARGET_ROOTDEVICE}"


def _location_url(digest: bytes) -> str:
    host = 1 + digest[3] % 250
    return f"http://192.0.2.{host}:8000/root.xml"


def _capability_skip_reasons(case: ProbeCase) -> list[str]:
    reasons: list[str] = []
    for capability_name in case.required_capabilities:
        if capability_name in {
            "ssdp_ipv4_multicast",
            "ssdp_ipv6_multicast",
        }:
            reasons.append("requires_multicast")
        elif capability_name == "ssdp_controlled_responder":
            reasons.append("requires_controlled_service")
        elif capability_name == "ssdp_offline_plan":
            reasons.append("offline_plan_unavailable")
        else:
            reasons.append("provider_capability_unavailable")
    return list(dict.fromkeys(reasons))


def ssdp_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    return [plan for plan in probe_plans if plan.get("case") in _SSDP_CASE_BY_NAME]


def ssdp_target_service_contribution(
    probe_plans: Sequence[JSONObject],
    *,
    dry_run: bool,
) -> JSONObject:
    service_plans = [
        plan
        for plan in ssdp_probe_plans(probe_plans)
        if isinstance(plan.get("target_service"), Mapping)
        and plan.get("target_service", {}).get("kind") == SSDP_SERVICE_KIND
    ]
    plans_by_port = plans_by_destination_port(service_plans)
    services = [
        {
            "name": SSDP_SERVICE_KIND,
            "protocol": "udp",
            "port": port,
            "purpose": "ssdp-controlled-discovery-response",
            "runtime": SSDP_RUNTIME,
            "deterministic": True,
            "planned_only": True,
            "query_count": sum(
                1
                for item in service_plans
                if int(item.get("destination_port", 0)) == port
            ),
            **target_service_address_fields(plan),
            "log_paths": [
                f"live-artifacts/probe/target-services/ssdp-{port}.stdout.txt",
                f"live-artifacts/probe/target-services/ssdp-{port}.stderr.txt",
            ],
        }
        for port, plan in plans_by_port.items()
    ]
    return {
        "services": services,
        "starts_services": not dry_run and bool(services),
    }


def ssdp_failure_reasons(case_name: str) -> list[str] | None:
    if case_name in _SSDP_LIVE_CAPABLE_CASES:
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_DECODE_FAILED,
            FAILURE_TARGET_SETUP_FAILED,
        ]
    if case_name == "ssdp-raw-fallback":
        return [FAILURE_WRONG_PAYLOAD, FAILURE_DECODE_FAILED]
    if case_name == "ssdp-malformed-observation":
        return [FAILURE_DECODE_FAILED, FAILURE_WRONG_PAYLOAD]
    return None


def ssdp_lab_capabilities(substrate: Mapping[str, JSONValue]) -> Mapping[str, object]:
    dry_run = substrate.get("dry_run") is True
    ipv4_unicast = capability(substrate, "ipv4_unicast", "ipv4")
    ipv6_unicast = capability(substrate, "ipv6_unicast", "ipv6")
    controlled_services = capability(
        substrate,
        "controlled_services",
        "controlled_service",
    )
    ipv4_multicast = capability(substrate, "ipv4_multicast")
    ipv6_multicast = capability(substrate, "ipv6_multicast", "multicast")
    link_layer_capture = capability(substrate, "link_layer_capture", "packet_capture")
    return {
        "ssdp_offline_plan": True,
        "ssdp_controlled_responder": dry_run or controlled_services,
        "ssdp_ipv4_multicast": dry_run
        or (ipv4_unicast and ipv4_multicast and link_layer_capture),
        "ssdp_ipv6_multicast": dry_run
        or (ipv6_unicast and ipv6_multicast and link_layer_capture),
    }


_SSDP_PLAN_BUILDERS: dict[str, object] = {
    case.name: _ssdp_probe_plan for case in SSDP_PROBE_CASES
}

_SSDP_PROFILE_COUNTS: dict[str, dict[str, int]] = {
    SSDP_SMOKE_PROFILE: {case.name: 1 for case in SSDP_PROBE_CASES}
}


register(
    ProtocolPlugin(
        name="ssdp",
        cases=SSDP_PROBE_CASES,
        plan_builders=_SSDP_PLAN_BUILDERS,
        planned_only_cases=_SSDP_PLANNED_ONLY_CASES,
        profile_counts=_SSDP_PROFILE_COUNTS,
        stimulus_endpoint_cases=frozenset(),
        target_service=ssdp_target_service_contribution,
        setup_script=None,
        rewrite_endpoint_addresses=None,
        failure_reasons=ssdp_failure_reasons,
        lab_capabilities=ssdp_lab_capabilities,
    )
)
