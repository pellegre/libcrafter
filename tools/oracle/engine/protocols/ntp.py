"""Generator-stage sampler plugin for the NTP layer.

NTP oracle coverage stays at the packet primitive boundary: deterministic
fixed-header fields, opaque extension-field bytes, NTS packet extension bytes,
legacy MAC tail bytes, and conservative UDP/123 raw-fallback intent. Clock
synchronization, peer state, NTS-KE, Autokey verification, retries, scanning,
and live target selection are out of scope.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject, JSONValue
from ..sampling import _SKIP_FIELD, _SamplingContext, weighted_choice
from .base import ProtocolSampler, register


_NTP_PORT = 123
_NTP_CLIENT_PORT = 49152
_IPV4_CLIENT = "192.0.2.10"
_IPV4_SERVER = "198.51.100.123"
_IPV6_CLIENT = "2001:db8::10"
_IPV6_SERVER = "2001:db8::123"

_RAW_FALLBACK_PAYLOAD_HEX = (
    "230000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000010203"
)
_MINIMAL_FIXED_HEADER_HEX = "23" + "00" * 47

_SUPPORTED_FIELDS = frozenset(
    {
        "leap_indicator",
        "version",
        "mode",
        "stratum",
        "poll",
        "precision",
        "root_delay",
        "root_dispersion",
        "reference_id",
        "reference_timestamp",
        "origin_timestamp",
        "receive_timestamp",
        "transmit_timestamp",
        "extension_fields",
        "legacy_mac",
    }
)

_CASE_BEHAVIOR = {
    "ntp-header-client-request": "client-request",
    "ntp-header-server-response": "server-response",
    "ntp-header-kiss-o-death": "kiss-o-death-response",
    "ntp-header-ntpv3-sntp": "ntpv3-sntp-compatible",
    "ntp-header-raw-timestamps": "raw-timestamp-values",
    "ntp-header-override-friendly-fields": "override-friendly-fixed-fields",
    "ntp-extension-unknown-field": "unknown-extension-field",
    "ntp-extension-checksum-complement": "checksum-complement-extension",
    "ntp-extension-with-legacy-mac": "extension-with-legacy-mac",
    "ntp-extension-standalone-legacy-mac": "standalone-legacy-mac-tail",
    "ntp-extension-ambiguous-tail": "ambiguous-tail-handling",
    "ntp-extension-raw-fallback-boundary": "raw-fallback-boundary",
    "malformed-ntp-short-extension-header": "malformed-short-extension-header",
    "malformed-ntp-invalid-extension-length": "malformed-invalid-extension-length",
    "malformed-ntp-truncated-mac-after-extension": "malformed-truncated-mac-after-extension",
    "ntp-nts-unique-identifier": "unique-identifier",
    "ntp-nts-cookie": "cookie",
    "ntp-nts-cookie-placeholder": "cookie-placeholder",
    "ntp-nts-authenticator-opaque": "authenticator-opaque",
    "ntp-nts-authenticator-parts": "authenticator-parts",
    "ntp-nts-stack": "nts-stack",
}


def _sample_ntp_field(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
) -> object:
    if field_name == "leap_indicator":
        return _leap_indicator_for_domain(domain)
    if field_name == "version":
        return _version_for_domain(domain)
    if field_name == "mode":
        return _mode_for_domain(domain)
    if field_name == "stratum":
        return _stratum_for_domain(domain)
    if field_name == "poll":
        return _signed_octet_for_domain(ctx, domain, default=6, deterministic=4)
    if field_name == "precision":
        return _signed_octet_for_domain(ctx, domain, default=-20, deterministic=-18)
    if field_name == "root_delay":
        return _root_delay_for_domain(ctx, domain)
    if field_name == "root_dispersion":
        return _root_dispersion_for_domain(ctx, domain)
    if field_name == "reference_id":
        return {"hex": _reference_id_hex_for_domain(domain)}
    if field_name == "reference_timestamp":
        return _timestamp_for_domain(ctx, domain, deterministic=0x0102030405060708)
    if field_name == "origin_timestamp":
        return _timestamp_for_domain(ctx, domain, deterministic=0x1112131415161718)
    if field_name == "receive_timestamp":
        return _timestamp_for_domain(ctx, domain, deterministic=0x2122232425262728)
    if field_name == "transmit_timestamp":
        return _timestamp_for_domain(ctx, domain, deterministic=0x3132333435363738)
    if field_name == "extension_fields":
        return _extension_fields_for_domain(domain)
    if field_name == "legacy_mac":
        return _legacy_mac_for_domain(domain)
    raise ValueError(f"spec error: unsupported ntp field sampler: {field_name}")


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    del field_spec, current_fields
    return _sample_ntp_field(ctx, field_name, domain)


def _leap_indicator_for_domain(domain: object) -> object:
    if domain in {
        "no_warning",
        "last_minute_61_seconds",
        "last_minute_59_seconds",
        "alarm_unsynchronized",
    }:
        return domain
    return "no_warning"


def _version_for_domain(domain: object) -> object:
    if domain == "old_version_preserved":
        return {"raw": 2}
    if domain == "future_preserved":
        return {"raw": 7}
    if domain in {"ntp_v4", "ntp_v3_sntp"}:
        return domain
    return "ntp_v4"


def _mode_for_domain(domain: object) -> object:
    if domain in {
        "client",
        "server",
        "symmetric_active",
        "symmetric_passive",
        "broadcast",
        "control",
        "private_use",
    }:
        return domain
    return "client"


def _stratum_for_domain(domain: object) -> object:
    if domain == "reserved_preserved":
        return {"raw": 250}
    if domain in {"unspecified_or_kod", "primary", "secondary", "unsynchronized"}:
        return domain
    return "unspecified_or_kod"


def _signed_octet_for_domain(
    ctx: _SamplingContext,
    domain: object,
    *,
    default: int,
    deterministic: int,
) -> int:
    if isinstance(domain, int):
        return max(-128, min(127, domain))
    if domain == "boundary":
        return weighted_choice(ctx.rng, ((-128, 1), (127, 1)))
    if domain == "deterministic":
        return deterministic
    return default


def _root_delay_for_domain(ctx: _SamplingContext, domain: object) -> int:
    if domain == "zero":
        return 0
    if domain == "negative_raw_preserved":
        return 0xFFFF0001
    if domain == "boundary":
        return weighted_choice(ctx.rng, ((0, 1), (0xFFFFFFFF, 1)))
    return 0x00010000


def _root_dispersion_for_domain(ctx: _SamplingContext, domain: object) -> int:
    if domain == "zero":
        return 0
    if domain == "boundary":
        return weighted_choice(ctx.rng, ((0, 1), (0xFFFFFFFF, 1)))
    return 0x00020000


def _reference_id_hex_for_domain(domain: object) -> str:
    if domain == "zero":
        return "00000000"
    if domain == "primary_ascii":
        return "47505300"
    if domain == "secondary_ipv4":
        return "c000027b"
    if domain == "kiss_o_death":
        return "52415445"
    if domain == "opaque_preserved":
        return "deadbeef"
    return "4c4f434c"


def _timestamp_for_domain(
    ctx: _SamplingContext,
    domain: object,
    *,
    deterministic: int,
) -> int:
    if isinstance(domain, int):
        return max(0, min((1 << 64) - 1, domain))
    if domain == "zero":
        return 0
    if domain == "boundary":
        return weighted_choice(ctx.rng, ((0, 1), ((1 << 64) - 1, 1)))
    return deterministic


def _extension_fields_for_domain(domain: object) -> object:
    if domain == "empty":
        return []
    if domain == "single":
        return [_extension_field(0x2222, "deadbeef01020304", declared_length=28)]
    if domain == "multiple":
        return [
            _extension_field(0x2222, "deadbeef01020304", declared_length=28),
            _extension_field(0x2005, "aabb"),
        ]
    if domain == "unknown_preserved":
        return [_extension_field(0x2222, "deadbeef01020304", declared_length=28)]
    return _SKIP_FIELD


def _legacy_mac_for_domain(domain: object) -> object:
    if domain == "crypto_nak_4_octet":
        return _legacy_mac(0x01020304, "")
    if domain == "legacy_20_octet":
        return _legacy_mac(0x01020304, "ab" * 16)
    if domain == "legacy_24_octet":
        return _legacy_mac(0x01020304, "cd" * 20)
    return _SKIP_FIELD


def _extension_field(
    field_type: int,
    body_hex: str,
    *,
    declared_length: int | None = None,
) -> JSONObject:
    field: JSONObject = {
        "field_type": field_type,
        "body_hex": body_hex,
    }
    if declared_length is not None:
        field["declared_length"] = declared_length
    return field


def _legacy_mac(key_id: int, digest_hex: str) -> JSONObject:
    return {"key_id": key_id, "digest_hex": digest_hex}


def _apply_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None = None,
) -> None:
    if "ntp" not in fields and "ntp" in stack:
        fields["ntp"] = {}
    if "ntp" not in fields:
        return

    selected = _selected_behavior(feature=feature, case=case, behavior=behavior, grammar=grammar)
    ntp = fields["ntp"]
    ntp.clear()

    if selected is None:
        _apply_default_header(ntp)
        _pin_udp_ports(fields, ntp)
        _pin_ip_context(fields)
        return

    if _selected_is_raw_fallback(selected, case):
        _apply_raw_fallback(fields, selected)
        _pin_udp_from_behavior(fields, selected, ntp)
        _pin_ip_context(fields)
        return

    if _selected_is_malformed(selected, case):
        _apply_malformed_behavior(ntp, case=case, selected=selected)
        _pin_udp_from_behavior(fields, selected, ntp)
        _pin_ip_context(fields)
        return

    _apply_default_header(ntp)
    raw_ntp = selected.get("ntp")
    if isinstance(raw_ntp, Mapping):
        _apply_ntp_mapping(ntp, raw_ntp)
    _pin_udp_from_behavior(fields, selected, ntp)
    _pin_ip_context(fields)
    if "payload" in fields:
        fields["payload"] = {"hex": "", "length": 0}


def _post_sample(fields: dict[str, JSONObject], *, stack: Sequence[str], case: str) -> None:
    del stack, case
    ntp = fields.get("ntp")
    if ntp is None:
        return
    _pin_udp_ports(fields, ntp)
    _pin_ip_context(fields)


def _apply_default_header(ntp: JSONObject) -> None:
    ntp.setdefault("leap_indicator", "no_warning")
    ntp.setdefault("version", "ntp_v4")
    ntp.setdefault("mode", "client")
    ntp.setdefault("stratum", "unspecified_or_kod")
    ntp.setdefault("poll", 6)
    ntp.setdefault("precision", -20)
    ntp.setdefault("root_delay", 0)
    ntp.setdefault("root_dispersion", 0)
    ntp.setdefault("reference_id", {"hex": "00000000"})
    ntp.setdefault("reference_timestamp", 0)
    ntp.setdefault("origin_timestamp", 0)
    ntp.setdefault("receive_timestamp", 0)
    ntp.setdefault("transmit_timestamp", 0)


def _apply_ntp_mapping(ntp: JSONObject, raw_ntp: Mapping[str, object]) -> None:
    for key, value in raw_ntp.items():
        if key == "reference_id" and isinstance(value, str):
            ntp["reference_id"] = {"hex": value}
        elif key == "extension_fields":
            ntp["extension_fields"] = _extension_fields_from_behavior(value)
        elif key == "legacy_mac" and isinstance(value, Mapping):
            ntp["legacy_mac"] = _legacy_mac_from_behavior(value)
        elif key == "tail_hex" and isinstance(value, str):
            ntp["tail_hex"] = value
        else:
            ntp[key] = _json_value(value)


def _extension_fields_from_behavior(value: object) -> list[JSONObject]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    fields: list[JSONObject] = []
    for raw_field in value:
        if isinstance(raw_field, Mapping):
            fields.append(_extension_from_behavior(raw_field))
    return fields


def _extension_from_behavior(raw_field: Mapping[str, object]) -> JSONObject:
    field: JSONObject = {}
    field_type = raw_field.get("field_type")
    if isinstance(field_type, int):
        field["field_type"] = field_type
    for source_key, target_key in (
        ("length", "declared_length"),
        ("declared_length", "declared_length"),
        ("body_hex", "body_hex"),
        ("nonce_hex", "nonce_hex"),
        ("ciphertext_hex", "ciphertext_hex"),
        ("tag_hex", "tag_hex"),
        ("additional_padding_hex", "additional_padding_hex"),
    ):
        value = raw_field.get(source_key)
        if isinstance(value, (str, int)):
            field[target_key] = value
    return field


def _legacy_mac_from_behavior(value: Mapping[str, object]) -> JSONObject:
    key_id = value.get("key_id")
    digest_hex = value.get("digest_hex")
    mac: JSONObject = {}
    if isinstance(key_id, int):
        mac["key_id"] = key_id
    if isinstance(digest_hex, str):
        mac["digest_hex"] = digest_hex
    return mac


def _apply_raw_fallback(fields: dict[str, JSONObject], selected: Mapping[str, object]) -> None:
    ntp = fields["ntp"]
    payload_hex = _payload_hex_from_behavior(selected) or _RAW_FALLBACK_PAYLOAD_HEX
    ntp["raw_fallback"] = {"hex": payload_hex, "length": len(payload_hex) // 2}
    ntp["payload_hex"] = payload_hex
    ntp["expected_layers"] = ["udp", "raw"]
    fields["payload"] = {"hex": payload_hex, "length": len(payload_hex) // 2}


def _payload_hex_from_behavior(selected: Mapping[str, object]) -> str | None:
    payload = selected.get("payload")
    if not isinstance(payload, Mapping):
        return None
    if payload.get("encoding") == "hex" and isinstance(payload.get("value"), str):
        return str(payload["value"])
    raw_hex = payload.get("raw_hex")
    if isinstance(raw_hex, str):
        return raw_hex
    return None


def _apply_malformed_behavior(
    ntp: JSONObject,
    *,
    case: str,
    selected: Mapping[str, object],
) -> None:
    ntp["malformed"] = True
    expected_error = selected.get("expected_error")
    if isinstance(expected_error, Mapping):
        ntp["expected_error"] = _json_object(expected_error)

    case_id = _identifier_part(case)
    if "short-extension-header" in case_id:
        ntp["payload_hex"] = _RAW_FALLBACK_PAYLOAD_HEX
    elif "invalid-extension-length" in case_id:
        ntp["payload_hex"] = _MINIMAL_FIXED_HEADER_HEX + "2222000c"
        ntp["extension_header_hex"] = "2222000c"
    elif "truncated-mac-after-extension" in case_id:
        ntp["extension_fields"] = [_extension_field(0x2222, "aabb", declared_length=16)]
        ntp["trailing_mac_hex"] = "010203"


def _selected_is_raw_fallback(selected: Mapping[str, object], case: str) -> bool:
    name = selected.get("name")
    if isinstance(name, str) and "raw-fallback" in _identifier_part(name):
        return True
    return "raw-fallback" in _identifier_part(case)


def _selected_is_malformed(selected: Mapping[str, object], case: str) -> bool:
    if selected.get("malformed") is True:
        return True
    name = selected.get("name")
    if isinstance(name, str) and "malformed" in _identifier_part(name):
        return True
    return "malformed" in _identifier_part(case)


def _pin_udp_from_behavior(
    fields: dict[str, JSONObject],
    behavior: Mapping[str, object],
    ntp: Mapping[str, object],
) -> None:
    udp = behavior.get("udp")
    udp_fields = fields.setdefault("udp", {})
    if isinstance(udp, Mapping):
        source_port = udp.get("source_port", udp.get("sport"))
        destination_port = udp.get("destination_port", udp.get("dport"))
        if isinstance(source_port, int):
            udp_fields["src_port"] = source_port
        if isinstance(destination_port, int):
            udp_fields["dst_port"] = destination_port
        return
    _pin_udp_ports(fields, ntp)


def _pin_udp_ports(fields: dict[str, JSONObject], ntp: Mapping[str, object]) -> None:
    if "udp" not in fields:
        return
    udp = fields["udp"]
    if _is_server_response(ntp):
        udp["src_port"] = _NTP_PORT
        udp["dst_port"] = _NTP_CLIENT_PORT
    else:
        udp["src_port"] = _NTP_CLIENT_PORT
        udp["dst_port"] = _NTP_PORT


def _pin_ip_context(fields: dict[str, JSONObject]) -> None:
    server_is_source = _udp_server_is_source(fields.get("udp", {}))
    if "ipv4" in fields:
        ipv4 = fields["ipv4"]
        ipv4["src"] = _IPV4_SERVER if server_is_source else _IPV4_CLIENT
        ipv4["dst"] = _IPV4_CLIENT if server_is_source else _IPV4_SERVER
        ipv4["protocol"] = "udp"
    if "ipv6" in fields:
        ipv6 = fields["ipv6"]
        ipv6["src"] = _IPV6_SERVER if server_is_source else _IPV6_CLIENT
        ipv6["dst"] = _IPV6_CLIENT if server_is_source else _IPV6_SERVER
        ipv6["next_header"] = "udp"


def _is_server_response(ntp: Mapping[str, object]) -> bool:
    mode = ntp.get("mode")
    return mode == "server"


def _udp_server_is_source(udp: Mapping[str, object]) -> bool:
    return udp.get("src_port") == _NTP_PORT


def _selected_behavior(
    *,
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None,
) -> Mapping[str, object] | None:
    behaviors = _feature_behaviors(grammar, feature)
    if not behaviors:
        return None

    by_name = {
        str(candidate.get("name")): candidate
        for candidate in behaviors
        if isinstance(candidate.get("name"), str)
    }
    mapped = _CASE_BEHAVIOR.get(_identifier_part(case))
    if mapped in by_name:
        return by_name[mapped]
    if behavior in by_name:
        return by_name[behavior]

    case_id = _identifier_part(case)
    for name, candidate in by_name.items():
        if _identifier_part(name) in case_id:
            return candidate
    return None


def _feature_behaviors(grammar: JSONObject | None, feature: str) -> list[Mapping[str, object]]:
    if grammar is None:
        return []
    features = grammar.get("features")
    if not isinstance(features, Mapping):
        return []
    feature_spec = features.get(feature)
    if not isinstance(feature_spec, Mapping):
        return []
    behaviors = feature_spec.get("behaviors", [])
    if not isinstance(behaviors, Sequence) or isinstance(behaviors, (str, bytes)):
        return []
    return [item for item in behaviors if isinstance(item, Mapping)]


def _handles_feature(feature: str) -> bool:
    return feature.startswith("ntp_")


def _identifier_part(value: str) -> str:
    return value.replace("_", "-").lower()


def _json_object(mapping: Mapping[str, object]) -> JSONObject:
    return {str(key): _json_value(value) for key, value in mapping.items()}


def _json_value(value: object) -> JSONValue:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, Mapping):
        return _json_object(value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [_json_value(item) for item in value]
    return str(value)


register(
    ProtocolSampler(
        layer="ntp",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_behavior,
        handles_feature=_handles_feature,
        post_sample=_post_sample,
    )
)
