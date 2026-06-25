"""Generator-stage sampler plugin for the SNMP layer.

SNMP oracle execution is still staged behind backend adapters, but the planner
needs a protocol sampler so SNMP stacks produce deterministic, source-backed
message shapes. The sampler keeps values synthetic and documentation-safe:
communities, engine IDs, users, authentication parameters, privacy parameters,
and encrypted scoped data are placeholder bytes only.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import _SamplingContext, _integer_domain_value
from .base import ProtocolSampler, register


_SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"
_SYS_OBJECT_ID_OID = "1.3.6.1.2.1.1.2.0"
_SYS_UPTIME_OID = "1.3.6.1.2.1.1.3.0"
_SNMP_TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
_COLD_START_OID = "1.3.6.1.6.3.1.1.5.1"
_USM_STATS_UNSUPPORTED_SEC_LEVELS = "1.3.6.1.6.3.15.1.1.1.0"

_SUPPORTED_FIELDS = frozenset(
    {
        "version",
        "community",
        "pdu_tag",
        "request_id",
        "error_status",
        "error_index",
        "non_repeaters",
        "max_repetitions",
        "enterprise_oid",
        "agent_address",
        "generic_trap",
        "specific_trap",
        "timestamp",
        "varbinds",
        "msg_id",
        "msg_max_size",
        "msg_flags",
        "msg_security_model",
        "msg_security_parameters",
        "scoped_data_kind",
        "context_engine_id",
        "context_name",
        "encrypted_scoped_pdu",
    }
)

_PDU_FOR_CASE = {
    "get-request": "get_request",
    "get-next-request": "get_next_request",
    "response": "response",
    "set-request": "set_request",
    "v1-trap": "trap_v1",
    "get-bulk-request": "get_bulk_request",
    "inform-request": "inform_request",
    "snmpv2-trap": "snmpv2_trap",
    "v2-trap": "snmpv2_trap",
    "report": "report",
}


def _sample_snmp_field(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
) -> object:
    if field_name == "version":
        if domain == "unknown_preserved":
            return {"raw": 99}
        return domain
    if field_name == "community":
        return _community_for_domain(domain)
    if field_name == "pdu_tag":
        if domain == "unknown_preserved":
            return {"raw": 0xA9}
        return domain
    if field_name == "request_id":
        return _integer_domain_value(ctx, domain, field_name, bits=31)
    if field_name == "error_status":
        return _error_status_for_domain(domain)
    if field_name == "error_index":
        return 0 if domain == "zero" else _integer_domain_value(ctx, domain, field_name, bits=31)
    if field_name == "non_repeaters":
        return 0 if domain == "zero" else _integer_domain_value(ctx, domain, field_name, bits=31)
    if field_name == "max_repetitions":
        return 0 if domain == "zero" else _integer_domain_value(ctx, domain, field_name, bits=31)
    if field_name == "enterprise_oid":
        return _SYS_OBJECT_ID_OID if domain == "source_backed" else "1.3.6.1.4.1.8072.9999"
    if field_name == "agent_address":
        return "192.0.2.10"
    if field_name == "generic_trap":
        return _generic_trap_for_domain(domain)
    if field_name == "specific_trap":
        return 0 if domain == "zero" else _integer_domain_value(ctx, domain, field_name, bits=31)
    if field_name == "timestamp":
        return 0 if domain == "zero" else _integer_domain_value(ctx, domain, field_name, bits=32)
    if field_name == "varbinds":
        return _varbinds_for_domain(domain)
    if field_name == "msg_id":
        return _integer_domain_value(ctx, domain, field_name, bits=31)
    if field_name == "msg_max_size":
        if domain == "default":
            return 65507
        return _integer_domain_value(ctx, domain, field_name, bits=31)
    if field_name == "msg_flags":
        return _msg_flags_for_domain(domain)
    if field_name == "msg_security_model":
        return _security_model_for_domain(domain)
    if field_name == "msg_security_parameters":
        return _security_parameters_for_domain(domain)
    if field_name == "scoped_data_kind":
        return domain
    if field_name == "context_engine_id":
        return _context_bytes_for_domain(domain, synthetic_hex="80000000646f632d656e67696e65")
    if field_name == "context_name":
        return _context_bytes_for_domain(domain, synthetic_hex="646f632d636f6e74657874")
    if field_name == "encrypted_scoped_pdu":
        if domain == "empty":
            return {"hex": ""}
        return {"hex": "308180040b646f632d636970686572"}
    raise ValueError(f"spec error: unsupported snmp field sampler: {field_name}")


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter: SNMP uses the sampled domain and case context."""

    return _sample_snmp_field(ctx, field_name, domain)


def _community_for_domain(domain: object) -> object:
    if domain == "empty":
        return ""
    if domain == "non_utf8":
        return {"hex": "646f6300ff"}
    return "doc-community"


def _context_bytes_for_domain(domain: object, *, synthetic_hex: str) -> object:
    if domain == "empty":
        return {"hex": ""}
    if domain == "non_utf8":
        return {"hex": "646f6300ff"}
    return {"hex": synthetic_hex}


def _error_status_for_domain(domain: object) -> object:
    if domain in {"no_error", "v1_assigned", "v2_assigned"}:
        return "no_error"
    return {"raw": 18}


def _generic_trap_for_domain(domain: object) -> object:
    if domain == "cold_start":
        return "cold_start"
    if domain == "warm_start":
        return "warm_start"
    if domain == "link_down":
        return "link_down"
    if domain == "link_up":
        return "link_up"
    if domain == "authentication_failure":
        return "authentication_failure"
    if domain == "egp_neighbor_loss":
        return "egp_neighbor_loss"
    if domain == "enterprise_specific":
        return "enterprise_specific"
    return {"raw": 99}


def _msg_flags_for_domain(domain: object) -> object:
    if domain == "none":
        return []
    if domain == "auth":
        return ["auth"]
    if domain == "privacy":
        return ["auth", "privacy"]
    if domain == "reportable":
        return ["reportable"]
    if domain == "reserved_privacy_without_auth":
        return ["privacy"]
    return {"raw": 0xF8}


def _security_model_for_domain(domain: object) -> object:
    if domain == "snmpv1":
        return "snmpv1"
    if domain == "snmpv2c":
        return "snmpv2c"
    if domain == "usm":
        return "usm"
    if domain == "tsm":
        return "tsm"
    if domain in {"unassigned_preserved", "unknown_preserved"}:
        return {"raw": 255}
    return "usm"


def _security_parameters_for_domain(domain: object) -> object:
    if domain == "empty":
        return {"hex": ""}
    if domain == "raw_preserved":
        return {"hex": "040b646f632d736563706172"}
    if domain == "malformed_usm_accessor_error":
        return {"kind": "malformed_usm", "hex": "300704058000000064"}
    return _usm_parameters()


def _usm_parameters() -> JSONObject:
    return {
        "kind": "usm",
        "engine_id": {"hex": "80000000646f632d656e67696e65"},
        "engine_boots": 1,
        "engine_time": 2,
        "user_name": "doc-user",
        "authentication_parameters": {"hex": "000000000000000000000000"},
        "privacy_parameters": {"hex": "0000000000000000"},
    }


def _varbinds_for_domain(domain: object) -> list[JSONObject]:
    if domain == "empty":
        return []
    if domain == "integer":
        return [_varbind(_SYS_DESCR_OID, {"type": "integer", "value": 7})]
    if domain == "octet_string":
        return [_varbind(_SYS_DESCR_OID, {"type": "octet_string", "hex": "646f632d76616c7565"})]
    if domain == "object_identifier":
        return [_varbind(_SYS_OBJECT_ID_OID, {"type": "object_identifier", "value": _SYS_OBJECT_ID_OID})]
    if domain == "ip_address":
        return [_varbind("1.3.6.1.2.1.4.20.1.1.192.0.2.10", {"type": "ip_address", "value": "192.0.2.10"})]
    if domain == "counter32":
        return [_varbind(_SYS_DESCR_OID, {"type": "counter32", "value": 42})]
    if domain == "gauge32":
        return [_varbind(_SYS_DESCR_OID, {"type": "gauge32", "value": 128})]
    if domain == "time_ticks":
        return [_varbind(_SYS_UPTIME_OID, {"type": "time_ticks", "value": 12345})]
    if domain == "opaque":
        return [_varbind(_SYS_DESCR_OID, {"type": "opaque", "hex": "0403646f63"})]
    if domain == "counter64":
        return [_varbind(_SYS_DESCR_OID, {"type": "counter64", "value": 123456789})]
    if domain == "exception":
        return [_varbind(_SYS_DESCR_OID, {"type": "no_such_object"})]
    if domain == "raw_value_preserved":
        return [_varbind(_SYS_DESCR_OID, {"type": "raw", "tlv_hex": "9f1f03010203"})]
    return [_varbind(_SYS_DESCR_OID, {"type": "null"})]


def _varbind(name: str, value: JSONObject) -> JSONObject:
    return {"name": name, "value": value}


def _request_varbinds() -> list[JSONObject]:
    return [_varbind(_SYS_DESCR_OID, {"type": "null"})]


def _response_varbinds() -> list[JSONObject]:
    return [_varbind(_SYS_UPTIME_OID, {"type": "time_ticks", "value": 12345})]


def _notification_varbinds() -> list[JSONObject]:
    return [
        _varbind(_SYS_UPTIME_OID, {"type": "time_ticks", "value": 12345}),
        _varbind(_SNMP_TRAP_OID, {"type": "object_identifier", "value": _COLD_START_OID}),
    ]


def _report_varbinds() -> list[JSONObject]:
    return [_varbind(_USM_STATS_UNSUPPORTED_SEC_LEVELS, {"type": "counter32", "value": 1})]


def _all_value_varbinds() -> list[JSONObject]:
    return [
        *_varbinds_for_domain("integer"),
        *_varbinds_for_domain("octet_string"),
        _varbind("1.3.6.1.2.1.1.5.0", {"type": "null"}),
        *_varbinds_for_domain("object_identifier"),
        *_varbinds_for_domain("ip_address"),
        *_varbinds_for_domain("counter32"),
        *_varbinds_for_domain("gauge32"),
        *_varbinds_for_domain("time_ticks"),
        *_varbinds_for_domain("opaque"),
        *_varbinds_for_domain("counter64"),
        _varbind("1.3.6.1.2.1.1.99.1", {"type": "unsigned32", "value": 99}),
        _varbind("1.3.6.1.2.1.1.99.2", {"type": "no_such_object"}),
        _varbind("1.3.6.1.2.1.1.99.3", {"type": "no_such_instance"}),
        _varbind("1.3.6.1.2.1.1.99.4", {"type": "end_of_mib_view"}),
    ]


def _apply_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None = None,
) -> None:
    """Apply one SNMP feature behavior to the sampled SNMP plan fields."""

    del grammar
    if "snmp" not in fields:
        return
    snmp = fields["snmp"]
    snmp.clear()
    snmp["message_length"] = "derived"

    normalized_feature = feature.replace("-", "_")
    normalized_case = case.replace("_", "-")
    normalized_behavior = behavior.replace("_", "-")

    if normalized_feature == "snmp_v3":
        _apply_v3_behavior(snmp, case=normalized_case, behavior=normalized_behavior)
    elif normalized_feature == "snmp_pdu_matrix":
        _apply_pdu_matrix_behavior(snmp, case=normalized_case, behavior=normalized_behavior)
    else:
        _apply_basic_behavior(snmp, case=normalized_case, behavior=normalized_behavior)

    _pin_udp_ports(fields, snmp)
    if "payload" in fields:
        fields["payload"] = {"hex": "", "length": 0}


def _apply_basic_behavior(snmp: JSONObject, *, case: str, behavior: str) -> None:
    if "truncated-message" in case:
        snmp.update({"version": "v2c", "message_length": {"malformed": "truncated"}})
        return
    if "ber-length" in case:
        snmp.update(_community_pdu("v2c", "response", request_id=100))
        snmp["varbinds"] = [_varbind(_SYS_DESCR_OID, {"type": "malformed_length", "hex": "0404ff"})]
        return
    if behavior == "v1-get-request" or "v1-get-request" in case:
        snmp.update(_community_pdu("v1", "get_request", request_id=100))
        return
    if behavior == "v2c-response" or "v2c-response" in case:
        snmp.update(_community_pdu("v2c", "response", request_id=101))
        snmp["varbinds"] = _response_varbinds()
        return
    if behavior == "ber-values" or "ber-values" in case:
        snmp.update(_community_pdu("v2c", "response", request_id=102))
        snmp["varbinds"] = _all_value_varbinds()
        return
    if behavior == "unknown-value-preservation" or "unknown-value-preservation" in case:
        snmp.update(_community_pdu("v2c", {"raw": 0xA9}, request_id=103))
        snmp["error_status"] = {"raw": 18}
        snmp["raw_pdu"] = {"hex": "a9070201670201120201003000"}
        return
    snmp.update(_community_pdu("v2c", "get_request", request_id=100))


def _apply_pdu_matrix_behavior(snmp: JSONObject, *, case: str, behavior: str) -> None:
    if "malformed-pdu-length" in case:
        snmp.update(_community_pdu("v2c", "get_request", request_id=110))
        snmp["pdu_length"] = {"malformed": "truncated"}
        return
    if "malformed-v1-trap-body" in case:
        _apply_v1_trap(snmp)
        snmp["varbinds"] = [{"malformed": "truncated"}]
        return
    if "unknown" in case or behavior == "unknown-pdu":
        snmp.update(_community_pdu("v2c", {"raw": 0xA9}, request_id=111))
        snmp["raw_pdu"] = {"hex": "a90702016f0201000201003000"}
        return
    if "v1-trap" in case or behavior == "v1-trap":
        _apply_v1_trap(snmp)
        return

    pdu_tag = _pdu_tag_for_case_or_behavior(case, behavior)
    if pdu_tag is None:
        pdu_tag = "get_request"

    version = "v1" if pdu_tag == "trap_v1" else "v2c"
    snmp.update(_community_pdu(version, pdu_tag, request_id=120))
    if pdu_tag == "get_bulk_request":
        snmp["non_repeaters"] = 0
        snmp["max_repetitions"] = 10
        snmp.pop("error_status", None)
        snmp.pop("error_index", None)
    elif pdu_tag in {"inform_request", "snmpv2_trap"}:
        snmp["varbinds"] = _notification_varbinds()
    elif pdu_tag == "report":
        snmp["varbinds"] = _report_varbinds()
    elif pdu_tag == "response":
        snmp["varbinds"] = _response_varbinds()
    elif pdu_tag == "set_request":
        snmp["varbinds"] = [_varbind(_SYS_DESCR_OID, {"type": "octet_string", "hex": "646f63"})]


def _apply_v3_behavior(snmp: JSONObject, *, case: str, behavior: str) -> None:
    snmp.update(_v3_base())
    if "malformed-v3-header" in case:
        snmp["msg_id"] = {"malformed": "truncated"}
        return
    if "malformed-v3-usm" in case:
        snmp["msg_security_parameters"] = {"kind": "malformed_usm", "hex": "300704058000000064"}
        return
    if "malformed-v3-scoped" in case:
        snmp["scoped_data_kind"] = {"malformed": "bad_tlv"}
        return
    if behavior == "flags-and-security-models" or "flags-security-models" in case:
        snmp["msg_flags"] = {"raw": 0xF8}
        snmp["msg_security_model"] = {"raw": 255}
    elif behavior == "raw-security-parameters" or "raw-security-parameters" in case:
        snmp["msg_security_parameters"] = {"hex": "040b646f632d736563706172"}
    elif behavior == "usm-security-parameters" or "usm-security-parameters" in case:
        snmp["msg_security_parameters"] = _usm_parameters()
    elif behavior == "encrypted-scoped-data" or "encrypted-scoped-data" in case:
        snmp["msg_flags"] = ["auth", "privacy"]
        snmp["msg_security_parameters"] = _usm_parameters()
        snmp["scoped_data_kind"] = "encrypted_opaque"
        snmp["encrypted_scoped_pdu"] = {"hex": "308180040b646f632d636970686572"}
        snmp.pop("context_engine_id", None)
        snmp.pop("context_name", None)
        snmp.pop("pdu_tag", None)
        snmp.pop("request_id", None)
        snmp.pop("error_status", None)
        snmp.pop("error_index", None)
        snmp.pop("varbinds", None)
    elif behavior == "report-pdu" or "report-pdu" in case:
        snmp["pdu_tag"] = "report"
        snmp["varbinds"] = _report_varbinds()


def _community_pdu(version: object, pdu_tag: object, *, request_id: int) -> JSONObject:
    return {
        "version": version,
        "community": "doc-community",
        "pdu_tag": pdu_tag,
        "request_id": request_id,
        "error_status": "no_error",
        "error_index": 0,
        "varbinds": _request_varbinds(),
    }


def _pdu_tag_for_case_or_behavior(case: str, behavior: str) -> str | None:
    for marker, candidate in _PDU_FOR_CASE.items():
        if marker in case:
            return candidate
    return _PDU_FOR_CASE.get(behavior)


def _apply_v1_trap(snmp: JSONObject) -> None:
    snmp.update(
        {
            "version": "v1",
            "community": "doc-trap",
            "pdu_tag": "trap_v1",
            "enterprise_oid": _SYS_OBJECT_ID_OID,
            "agent_address": "192.0.2.10",
            "generic_trap": "cold_start",
            "specific_trap": 0,
            "timestamp": 12345,
            "varbinds": _response_varbinds(),
        }
    )


def _v3_base() -> JSONObject:
    return {
        "version": "v3",
        "msg_id": 1000,
        "msg_max_size": 65507,
        "msg_flags": ["reportable"],
        "msg_security_model": "usm",
        "msg_security_parameters": _usm_parameters(),
        "scoped_data_kind": "plaintext",
        "context_engine_id": {"hex": "80000000646f632d656e67696e65"},
        "context_name": {"hex": "646f632d636f6e74657874"},
        "pdu_tag": "report",
        "request_id": 1000,
        "error_status": "no_error",
        "error_index": 0,
        "varbinds": _report_varbinds(),
    }


def _pin_udp_ports(fields: dict[str, JSONObject], snmp: Mapping[str, object]) -> None:
    if "udp" not in fields:
        return
    udp = fields["udp"]
    pdu_tag = snmp.get("pdu_tag")
    trap_port = isinstance(pdu_tag, str) and pdu_tag in {"trap_v1", "snmpv2_trap"}
    udp["src_port"] = 49152
    udp["dst_port"] = 162 if trap_port else 161


def _handles_feature(feature: str) -> bool:
    return feature.startswith("snmp_")


register(
    ProtocolSampler(
        layer="snmp",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_behavior,
        handles_feature=_handles_feature,
    )
)
