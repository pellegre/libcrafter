"""NTP probe protocol plugin: deterministic dry-run peer exchange plans."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..capability_derivation import capability, capability_default_true
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
from ..planning_helpers import deterministic_bytes
from ..target_service_helpers import (
    plans_by_destination_port,
    target_service_address_fields,
)
from .base import ProtocolPlugin, register


NTP_SMOKE_PROFILE = "ntp-smoke"
NTP_SERVICE_KIND = "ntp-controlled-responder"
NTP_RUNTIME = "probe-ntp-reference"
NTP_STIMULUS_DRIVER = "ntp_probe"
NTP_ADAPTER_MODULE = "tools/probe/adapters/src/ntp.rs"
NTP_PORT = 123
NTP_FIXED_HEADER_LEN = 48
NTP_DOCUMENTATION_IPV4_PREFIX = "198.51.100.0/24"
_NTP_CAPABILITIES = ["ntp_controlled_responder", "privileged_udp_port"]
_NTP_OFFLINE_CAPABILITIES = ["ntp_offline_plan"]


NTP_PROBE_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="ntp-client-server-exchange",
        description=(
            "Plan an NTP client-mode request and deterministic server-mode "
            "response from a controlled responder."
        ),
        stimulus="ntp_client_request",
        expected_response="ntp_server_response",
        required_capabilities=_NTP_CAPABILITIES,
        protocol="ntp",
        metadata={
            "service": NTP_SERVICE_KIND,
            "transport": "udp",
            "udp_port": NTP_PORT,
            "planned_only": True,
            "live_capable": True,
            "message_kind": "client_server",
        },
    ),
    _behavior_case(
        name="ntp-kod-response",
        description=(
            "Plan a controlled NTP Kiss-o'-Death response and decode-only "
            "observation."
        ),
        stimulus="ntp_client_request",
        expected_response="ntp_kiss_o_death_response",
        required_capabilities=_NTP_CAPABILITIES,
        protocol="ntp",
        metadata={
            "service": NTP_SERVICE_KIND,
            "transport": "udp",
            "udp_port": NTP_PORT,
            "planned_only": True,
            "live_capable": True,
            "message_kind": "kiss_o_death",
        },
    ),
    _behavior_case(
        name="ntp-extension-preservation",
        description=(
            "Plan an NTP packet carrying a raw-preserved extension field and "
            "controlled responder observation."
        ),
        stimulus="ntp_extension_request",
        expected_response="ntp_extension_response",
        required_capabilities=_NTP_CAPABILITIES,
        protocol="ntp",
        metadata={
            "service": NTP_SERVICE_KIND,
            "transport": "udp",
            "udp_port": NTP_PORT,
            "planned_only": True,
            "live_capable": True,
            "message_kind": "extension_preservation",
        },
    ),
    _behavior_case(
        name="ntp-nts-extension-plan",
        description=(
            "Plan raw-preserving NTS packet-extension fields without NTS-KE or "
            "cryptographic processing."
        ),
        stimulus="ntp_nts_extension_request",
        expected_response="ntp_nts_extension_observed",
        required_capabilities=_NTP_CAPABILITIES,
        protocol="ntp",
        metadata={
            "service": NTP_SERVICE_KIND,
            "transport": "udp",
            "udp_port": NTP_PORT,
            "planned_only": True,
            "live_capable": True,
            "message_kind": "nts_extension",
        },
    ),
    _behavior_case(
        name="ntp-malformed-observation",
        description=(
            "Plan malformed NTP-like UDP/123 payload handling as offline "
            "structured-error or raw-fallback evidence."
        ),
        stimulus="ntp_malformed_payload",
        expected_response="ntp_structured_error_or_raw_fallback",
        required_capabilities=_NTP_OFFLINE_CAPABILITIES,
        protocol="ntp",
        metadata={
            "service": NTP_SERVICE_KIND,
            "transport": "udp",
            "udp_port": NTP_PORT,
            "planned_only": True,
            "offline_only": True,
            "message_kind": "malformed",
        },
    ),
)

_NTP_CASE_BY_NAME: dict[str, ProbeCase] = {
    case.name: case for case in NTP_PROBE_CASES
}
_NTP_PLANNED_ONLY_CASES = frozenset(_NTP_CASE_BY_NAME)
_NTP_LIVE_CAPABLE_CASES = frozenset(
    case.name
    for case in NTP_PROBE_CASES
    if case.metadata.get("live_capable") is True
)
_NTP_STIMULUS_ENDPOINT_CASES = _NTP_LIVE_CAPABLE_CASES


def _ntp_probe_plan(
    *,
    case_name: str,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    case = _NTP_CASE_BY_NAME[case_name]
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    source_ipv4, target_ipv4 = _documentation_ipv4_pair(digest)
    source_port = _ephemeral_port(digest)
    request_transmit = _timestamp(digest[4:12])

    if case_name == "ntp-malformed-observation":
        return _ntp_malformed_plan(
            case=case,
            profile=profile,
            seed=seed,
            sequence=sequence,
            digest=digest,
            source_ipv4=source_ipv4,
            target_ipv4=target_ipv4,
            source_port=source_port,
        )

    request_extension_fields: list[JSONObject] = []
    response_extension_fields: list[JSONObject] = []
    request_tail = b""
    response_tail = b""
    behavior = "server_response"
    expected_mode = "server"
    expected_stratum = 2
    expected_reference_id = "GPS\\0"
    expected_decode = "ntp"

    if case_name == "ntp-kod-response":
        behavior = "kiss_o_death"
        expected_stratum = 0
        expected_reference_id = "RATE"
    elif case_name == "ntp-extension-preservation":
        behavior = "preserve_extension_field"
        request_tail = _extension_field(0x2222, digest[12:28])
        response_tail = request_tail
        request_extension_fields = [
            _extension_metadata(0x2222, "extension-field-0x2222", request_tail)
        ]
        response_extension_fields = [
            _extension_metadata(0x2222, "extension-field-0x2222", response_tail)
        ]
    elif case_name == "ntp-nts-extension-plan":
        behavior = "preserve_nts_packet_extensions"
        unique_id = _extension_field(0x0104, digest[12:28])
        cookie = _extension_field(0x0204, digest[8:32])
        authenticator_body = (
            (4).to_bytes(2, "big")
            + (8).to_bytes(2, "big")
            + digest[0:4]
            + digest[4:12]
        )
        authenticator = _extension_field(0x0404, authenticator_body)
        request_tail = unique_id + cookie + authenticator
        response_tail = request_tail
        request_extension_fields = [
            _extension_metadata(0x0104, "unique-identifier", unique_id),
            _extension_metadata(0x0204, "nts-cookie", cookie),
            _extension_metadata(
                0x0404,
                "nts-authenticator-and-encrypted-extension-fields",
                authenticator,
            ),
        ]
        response_extension_fields = [dict(field) for field in request_extension_fields]

    request_payload = _fixed_header(
        mode=3,
        stratum=0,
        reference_id=b"\0\0\0\0",
        transmit_timestamp=request_transmit,
    ) + request_tail
    response_payload = _fixed_header(
        mode=4,
        stratum=expected_stratum,
        reference_id=_reference_id_bytes(expected_reference_id),
        reference_timestamp=_timestamp(digest[12:20]),
        origin_timestamp=request_transmit,
        receive_timestamp=_timestamp(digest[20:28]),
        transmit_timestamp=_timestamp(digest[24:32]),
    ) + response_tail

    return _base_plan(
        case=case,
        profile=profile,
        seed=seed,
        sequence=sequence,
        digest=digest,
        source_ipv4=source_ipv4,
        target_ipv4=target_ipv4,
        source_port=source_port,
        request_payload=request_payload,
        response_payload=response_payload,
        ntp={
            "version": 4,
            "mode": "client",
            "first_octet": 0x23,
            "stratum": 0,
            "transmit_timestamp": request_transmit,
            "extension_fields": request_extension_fields,
        },
        expected_ntp={
            "version": 4,
            "mode": expected_mode,
            "first_octet": 0x24,
            "stratum": expected_stratum,
            "reference_id": expected_reference_id,
            "origin_timestamp": request_transmit,
            "extension_fields": response_extension_fields,
        },
        behavior=behavior,
        expected_decode=expected_decode,
        live_capable=True,
        target_service_required=True,
    )


def _ntp_malformed_plan(
    *,
    case: ProbeCase,
    profile: str,
    seed: int,
    sequence: int,
    digest: bytes,
    source_ipv4: str,
    target_ipv4: str,
    source_port: int,
) -> JSONObject:
    payload = b"\x23\x00\x06\xec" + digest[:8]
    return _base_plan(
        case=case,
        profile=profile,
        seed=seed,
        sequence=sequence,
        digest=digest,
        source_ipv4=source_ipv4,
        target_ipv4=target_ipv4,
        source_port=source_port,
        request_payload=payload,
        response_payload=payload,
        ntp={
            "message_kind": "malformed",
            "payload_hex": payload.hex(),
            "malformed_reason": "shorter_than_fixed_header",
            "fixed_header_required": NTP_FIXED_HEADER_LEN,
        },
        expected_ntp={
            "message_kind": "structured_error",
            "context": "ntp.fixed_header",
            "required": NTP_FIXED_HEADER_LEN,
            "available": len(payload),
        },
        behavior="offline_malformed_observation",
        expected_decode="structured_error",
        live_capable=False,
        target_service_required=False,
    )


def _base_plan(
    *,
    case: ProbeCase,
    profile: str,
    seed: int,
    sequence: int,
    digest: bytes,
    source_ipv4: str,
    target_ipv4: str,
    source_port: int,
    request_payload: bytes,
    response_payload: bytes,
    ntp: JSONObject,
    expected_ntp: JSONObject,
    behavior: str,
    expected_decode: str,
    live_capable: bool,
    target_service_required: bool,
) -> JSONObject:
    validation: JSONObject = {
        "expected_decode": expected_decode,
        "source_ipv4": target_ipv4,
        "destination_ipv4": source_ipv4,
        "source_port": NTP_PORT,
        "destination_port": source_port,
        "mode": str(expected_ntp.get("mode", "")),
        "behavior": behavior,
        "planned_only": True,
    }
    if expected_decode == "structured_error":
        validation["error_context"] = "ntp.fixed_header"
        validation["required"] = NTP_FIXED_HEADER_LEN
        validation["available"] = len(request_payload)

    target_service: JSONObject
    if target_service_required:
        target_service = {
            "required": True,
            "kind": NTP_SERVICE_KIND,
            "protocol": "udp",
            "port": NTP_PORT,
            "bind_ipv4": target_ipv4,
            "source_ipv4": source_ipv4,
            "runtime": NTP_RUNTIME,
            "behavior": behavior,
            "response_payload_hex": response_payload.hex(),
            "deterministic": True,
            "planned_only": True,
            "live_requires_provider": True,
            "controlled_responder": True,
        }
    else:
        target_service = {
            "required": False,
            "kind": "none",
            "behavior": behavior,
        }

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
        "live_capable": live_capable,
        "protocol": "ntp",
        "transport": "udp",
        "source_ipv4": source_ipv4,
        "destination_ipv4": target_ipv4,
        "target_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": source_ipv4,
        "source_port": source_port,
        "destination_port": NTP_PORT,
        "service_port": NTP_PORT,
        "payload_hex": request_payload.hex(),
        "payload_length": len(request_payload),
        "request_payload_hex": request_payload.hex(),
        "response_payload_hex": response_payload.hex(),
        "response_payload_length": len(response_payload),
        "udp_payload_hex": request_payload.hex(),
        "udp_payload_length": len(request_payload),
        "expected_payload_hex": response_payload.hex(),
        "expected_payload_length": len(response_payload),
        "packet": {
            "stack": ["ipv4", "udp", "ntp"],
            "root": "l3:ipv4",
            "ipv4": {
                "src": source_ipv4,
                "dst": target_ipv4,
                "protocol": "udp",
                "ttl": 64,
            },
            "udp": {
                "src_port": source_port,
                "dst_port": NTP_PORT,
            },
            "ntp": ntp,
        },
        "expected_response_packet": {
            "stack": ["ipv4", "udp", "ntp"],
            "root": "l3:ipv4",
            "ipv4": {
                "src": target_ipv4,
                "dst": source_ipv4,
                "protocol": "udp",
                "ttl": 64,
            },
            "udp": {
                "src_port": NTP_PORT,
                "dst_port": source_port,
            },
            "ntp": expected_ntp,
        },
        "ntp": ntp,
        "expected_ntp": expected_ntp,
        "target_service": target_service,
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {source_ipv4} "
            f"and src port {NTP_PORT} and dst port {source_port}"
        ),
        "validation": validation,
        "wire_requirements": {
            "requires_ipv4_unicast": live_capable,
            "requires_controlled_service": live_capable,
            "requires_ntp_controlled_responder": live_capable,
            "requires_privileged_udp_port": live_capable,
            "offline_only": not live_capable,
            "requires_live_network": live_capable,
            "live_requires_provider": live_capable,
            "live_requires_confirm_live_run": live_capable,
            "dry_run_only_until_adapter": True,
        },
        "stimulus_driver": {
            "name": NTP_STIMULUS_DRIVER,
            "adapter_module": NTP_ADAPTER_MODULE,
            "state": "planned-only",
            "planned_only": True,
        },
        "provider_capabilities": list(case.required_capabilities),
        "required_capabilities": list(case.required_capabilities),
        "skip_reasons": {
            "capability": _capability_skip_reasons(case),
            "failure": ntp_failure_reasons(case.name) or [],
        },
        "documentation_prefixes": [NTP_DOCUMENTATION_IPV4_PREFIX],
        "digest_hex": digest.hex()[:16],
    }


def _fixed_header(
    *,
    mode: int,
    stratum: int,
    reference_id: bytes,
    transmit_timestamp: int,
    reference_timestamp: int = 0,
    origin_timestamp: int = 0,
    receive_timestamp: int = 0,
) -> bytes:
    first_octet = (4 << 3) | (mode & 0x07)
    return b"".join(
        (
            bytes([first_octet, stratum & 0xFF, 6, 0xEC]),
            (0).to_bytes(4, "big"),
            (0).to_bytes(4, "big"),
            reference_id[:4].ljust(4, b"\0"),
            reference_timestamp.to_bytes(8, "big"),
            origin_timestamp.to_bytes(8, "big"),
            receive_timestamp.to_bytes(8, "big"),
            transmit_timestamp.to_bytes(8, "big"),
        )
    )


def _extension_field(field_type: int, body: bytes) -> bytes:
    padded_body = bytes(body)
    minimum_body_len = 24
    if len(padded_body) < minimum_body_len:
        padded_body = padded_body + bytes(minimum_body_len - len(padded_body))
    remainder = (len(padded_body) + 4) % 4
    if remainder:
        padded_body = padded_body + bytes(4 - remainder)
    length = len(padded_body) + 4
    return field_type.to_bytes(2, "big") + length.to_bytes(2, "big") + padded_body


def _extension_metadata(field_type: int, label: str, encoded: bytes) -> JSONObject:
    return {
        "field_type": field_type,
        "field_type_hex": f"0x{field_type:04x}",
        "label": label,
        "declared_length": len(encoded),
        "body_length": len(encoded) - 4,
        "raw_hex": encoded.hex(),
        "preserve_raw": True,
    }


def _reference_id_bytes(label: str) -> bytes:
    return label.replace("\\0", "\0").encode("ascii")[:4].ljust(4, b"\0")


def _timestamp(material: bytes) -> int:
    return int.from_bytes(material[:8].ljust(8, b"\0"), "big")


def _documentation_ipv4_pair(digest: bytes) -> tuple[str, str]:
    source_host = 1 + digest[0] % 120
    target_host = 121 + digest[1] % 120
    return f"198.51.100.{source_host}", f"198.51.100.{target_host}"


def _ephemeral_port(digest: bytes) -> int:
    return 49152 + int.from_bytes(digest[2:4], "big") % 12000


def _capability_skip_reasons(case: ProbeCase) -> list[str]:
    reasons: list[str] = []
    for capability_name in case.required_capabilities:
        if capability_name == "ntp_controlled_responder":
            reasons.append("requires_controlled_ntp_responder")
        elif capability_name == "privileged_udp_port":
            reasons.append("requires_privileged_port")
        elif capability_name == "ntp_offline_plan":
            reasons.append("offline_plan_unavailable")
        else:
            reasons.append("provider_capability_unavailable")
    return list(dict.fromkeys(reasons))


def ntp_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    return [plan for plan in probe_plans if plan.get("case") in _NTP_CASE_BY_NAME]


def ntp_target_service_contribution(
    probe_plans: Sequence[JSONObject],
    *,
    dry_run: bool,
) -> JSONObject:
    service_plans = [
        plan
        for plan in ntp_probe_plans(probe_plans)
        if isinstance(plan.get("target_service"), Mapping)
        and plan.get("target_service", {}).get("kind") == NTP_SERVICE_KIND
    ]
    plans_by_port = plans_by_destination_port(service_plans)
    services = [
        {
            "name": NTP_SERVICE_KIND,
            "protocol": "udp",
            "port": port,
            "purpose": "ntp-controlled-responder",
            "runtime": NTP_RUNTIME,
            "deterministic": True,
            "planned_only": True,
            "live_requires_provider": True,
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
                "client_server_exchange": True,
                "kiss_o_death_response": True,
                "extension_preservation": True,
                "nts_packet_extensions": True,
                "time_synchronization": False,
                "nts_key_exchange": False,
            },
            **target_service_address_fields(plan),
            "log_paths": [
                f"live-artifacts/probe/target-services/ntp-{port}.stdout.txt",
                f"live-artifacts/probe/target-services/ntp-{port}.stderr.txt",
            ],
        }
        for port, plan in plans_by_port.items()
    ]
    return {
        "services": services,
        "starts_services": not dry_run and bool(services),
    }


def ntp_failure_reasons(case_name: str) -> list[str] | None:
    if case_name in _NTP_LIVE_CAPABLE_CASES:
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_WRONG_FLAGS,
            FAILURE_DECODE_FAILED,
            FAILURE_TARGET_SETUP_FAILED,
        ]
    if case_name == "ntp-malformed-observation":
        return [FAILURE_DECODE_FAILED, FAILURE_WRONG_PAYLOAD]
    return None


def ntp_lab_capabilities(substrate: Mapping[str, JSONValue]) -> Mapping[str, object]:
    dry_run = substrate.get("dry_run") is True
    ipv4_unicast = capability(substrate, "ipv4_unicast", "ipv4")
    controlled_services = capability(
        substrate,
        "controlled_services",
        "controlled_service",
    )
    controlled_responder = controlled_services and capability_default_true(
        substrate,
        "ntp_controlled_responder",
        "ntp_responder",
        "controlled_udp_service",
    )
    return {
        "ntp_offline_plan": dry_run or capability_default_true(
            substrate,
            "ntp_offline_plan",
        ),
        "ntp_controlled_responder": ipv4_unicast and controlled_responder,
    }


def ntp_rewrite_endpoint_addresses(
    plan: JSONObject,
    *,
    source_ipv4: str,
    target_ipv4: str,
    source_mac: str | None = None,
    target_mac: str | None = None,
    target_interface: str | None = None,
    rewrite_source: str = "wire_endpoint_plan",
) -> JSONObject:
    """Rewrite an NTP dry-run plan onto the live stimulus/target IPv4 pair."""

    del source_mac, target_mac, target_interface

    updated = dict(plan)
    case_name = str(updated.get("case", ""))
    if case_name not in _NTP_LIVE_CAPABLE_CASES:
        return _mark_ntp_address_rewrite_skipped(
            updated,
            source_ipv4=source_ipv4,
            target_ipv4=target_ipv4,
            rewrite_source=rewrite_source,
            reason="offline_only",
        )

    source_port = int(updated.get("source_port", 0))
    updated["source_ipv4"] = source_ipv4
    updated["destination_ipv4"] = target_ipv4
    updated["target_ipv4"] = target_ipv4
    updated["expected_reply_source_ipv4"] = target_ipv4
    updated["expected_reply_destination_ipv4"] = source_ipv4
    updated["capture_filter"] = (
        f"udp and src host {target_ipv4} and dst host {source_ipv4} "
        f"and src port {NTP_PORT} and dst port {source_port}"
    )
    _rewrite_packet_addresses(updated, source_ipv4=source_ipv4, target_ipv4=target_ipv4)
    _rewrite_ntp_target_service(updated, bind_ipv4=target_ipv4, source_ipv4=source_ipv4)
    return apply_shared_ipv4_rewrite_tail(
        updated,
        case_name=case_name,
        source_ipv4=source_ipv4,
        target_ipv4=target_ipv4,
        rewrite_source=rewrite_source,
    )


def _rewrite_packet_addresses(
    updated: JSONObject,
    *,
    source_ipv4: str,
    target_ipv4: str,
) -> None:
    packet = dict(json_object(updated.get("packet", {}), "probe_plan.packet"))
    ipv4 = dict(json_object(packet.get("ipv4", {}), "probe_plan.packet.ipv4"))
    ipv4["src"] = source_ipv4
    ipv4["dst"] = target_ipv4
    packet["ipv4"] = ipv4
    updated["packet"] = packet

    response = dict(
        json_object(
            updated.get("expected_response_packet", {}),
            "probe_plan.expected_response_packet",
        )
    )
    response_ipv4 = dict(
        json_object(
            response.get("ipv4", {}),
            "probe_plan.expected_response_packet.ipv4",
        )
    )
    response_ipv4["src"] = target_ipv4
    response_ipv4["dst"] = source_ipv4
    response["ipv4"] = response_ipv4
    updated["expected_response_packet"] = response


def _rewrite_ntp_target_service(
    updated: JSONObject,
    *,
    bind_ipv4: str,
    source_ipv4: str,
) -> None:
    target_service = dict(
        json_object(updated.get("target_service", {}), "probe_plan.target_service")
    )
    if not target_service:
        return
    target_service["bind_ipv4"] = bind_ipv4
    target_service["source_ipv4"] = source_ipv4
    updated["target_service"] = target_service


def _mark_ntp_address_rewrite_skipped(
    updated: JSONObject,
    *,
    source_ipv4: str,
    target_ipv4: str,
    rewrite_source: str,
    reason: str,
) -> JSONObject:
    skip_reasons = dict(
        updated.get("skip_reasons", {})
        if isinstance(updated.get("skip_reasons"), Mapping)
        else {}
    )
    address_rewrite = list(
        skip_reasons.get("address_rewrite", [])
        if isinstance(skip_reasons.get("address_rewrite"), list)
        else []
    )
    address_rewrite.append(reason)
    skip_reasons["address_rewrite"] = list(
        dict.fromkeys(str(item) for item in address_rewrite)
    )
    updated["skip_reasons"] = skip_reasons
    updated["live_address_rewrite"] = {
        "source": rewrite_source,
        "status": "skipped",
        "reason": reason,
        "stimulus_ipv4": source_ipv4,
        "target_ipv4": target_ipv4,
    }
    return updated


_NTP_PLAN_BUILDERS: dict[str, object] = {
    case.name: _ntp_probe_plan for case in NTP_PROBE_CASES
}

register(
    ProtocolPlugin(
        name="ntp",
        cases=NTP_PROBE_CASES,
        plan_builders=_NTP_PLAN_BUILDERS,
        planned_only_cases=_NTP_PLANNED_ONLY_CASES,
        profile_counts={},
        stimulus_endpoint_cases=_NTP_STIMULUS_ENDPOINT_CASES,
        target_service=ntp_target_service_contribution,
        setup_script=None,
        rewrite_endpoint_addresses=ntp_rewrite_endpoint_addresses,
        failure_reasons=ntp_failure_reasons,
        lab_capabilities=ntp_lab_capabilities,
    )
)
