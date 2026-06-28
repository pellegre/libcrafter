"""Generator-stage sampler plugin for the SSDP layer.

SSDP oracle coverage is data-driven from the layer and feature specs added by
the preceding plan steps. The sampler seeds source-backed HTTP-like datagram
fields, while the feature hook replaces those seeds with the exact behavior
matrix entry selected by the generator. Backend materialization stays in the
backend-specific steps; this module only registers the generator-stage
``ProtocolSampler``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject, JSONValue
from ..sampling import _SKIP_FIELD, _SamplingContext
from .base import ProtocolSampler, register


_SSDP_PORT = 1900
_IPV4_HOST = "239.255.255.250:1900"
_IPV6_SITE_HOST = "[ff05::c]:1900"
_IPV6_LINK_HOST = "[ff02::c]:1900"
_DISCOVER_MAN = '"ssdp:discover"'
_ROOT_DEVICE = "upnp:rootdevice"
_DEVICE_USN = "uuid:device-001::upnp:rootdevice"
_LOCATION = "http://192.0.2.10:8000/root.xml"
_SERVER = "example-os/1.0 UPnP/2.0 example-product/1.0"

_SUPPORTED_FIELDS = frozenset(
    {
        "message_kind",
        "method",
        "request_target",
        "version",
        "status_code",
        "reason_phrase",
        "headers",
        "body",
    }
)


def _sample_ssdp_field(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    current_fields: Mapping[str, object],
) -> object:
    message_kind = str(current_fields.get("message_kind") or _message_kind_for_case(ctx, domain))
    if field_name == "message_kind":
        return message_kind
    if field_name == "method":
        return _method_for_domain(message_kind, domain)
    if field_name == "request_target":
        return _request_target_for_domain(message_kind, domain)
    if field_name == "version":
        if domain == "explicit_preserved":
            return "HTTP/1.0"
        return "HTTP/1.1"
    if field_name == "status_code":
        return _status_code_for_domain(message_kind, domain)
    if field_name == "reason_phrase":
        return _reason_phrase_for_domain(message_kind, domain)
    if field_name == "headers":
        return _headers_for_domain(domain)
    if field_name == "body":
        return _body_for_domain(message_kind, domain)
    raise ValueError(f"spec error: unsupported ssdp field sampler: {field_name}")


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    del field_spec
    return _sample_ssdp_field(ctx, field_name, domain, current_fields)


def _message_kind_for_case(ctx: _SamplingContext, domain: object) -> str:
    case = ctx.case.replace("_", "-")
    if "raw-fallback" in case:
        return "raw_preserved"
    if "unknown" in case:
        return "unknown_request_preserved"
    if "response" in case or "body" in case or "boundary" in case:
        return "response"
    if "notify" in case or "duplicate" in case or "extension" in case:
        return "notify"
    if isinstance(domain, str):
        return domain
    return "m_search"


def _method_for_domain(message_kind: str, domain: object) -> object:
    if message_kind in {"response", "unknown_response_preserved"}:
        return _SKIP_FIELD
    if domain == "unknown_preserved" or message_kind == "unknown_request_preserved":
        return "M-SEARCH-EXAMPLE"
    if domain == "excluded_search":
        return "SEARCH"
    if message_kind == "notify":
        return "NOTIFY"
    return "M-SEARCH"


def _request_target_for_domain(message_kind: str, domain: object) -> object:
    if message_kind in {"response", "unknown_response_preserved"}:
        return _SKIP_FIELD
    if domain == "unknown_preserved":
        return "/example-preserved"
    return "*"


def _status_code_for_domain(message_kind: str, domain: object) -> object:
    if message_kind not in {"response", "unknown_response_preserved"}:
        return _SKIP_FIELD
    if domain == "unknown_preserved" or message_kind == "unknown_response_preserved":
        return 299
    if domain == "excluded_http_error":
        return 404
    return 200


def _reason_phrase_for_domain(message_kind: str, domain: object) -> object:
    if message_kind not in {"response", "unknown_response_preserved"}:
        return _SKIP_FIELD
    if domain == "empty":
        return ""
    if domain == "unknown_preserved" or message_kind == "unknown_response_preserved":
        return "Example Preserved"
    return "OK"


def _headers_for_domain(domain: object) -> list[JSONObject]:
    if domain == "notify_alive":
        return _notify_headers("ssdp:alive", full=True)
    if domain == "notify_byebye":
        return _notify_headers("ssdp:byebye", full=False)
    if domain == "notify_update":
        return [
            *_notify_headers("ssdp:update", full=False),
            _header("NEXTBOOTID.UPNP.ORG", "2"),
        ]
    if domain == "response_ok_ext":
        return _response_headers()
    if domain == "duplicate_preserved":
        return [
            _header("HOST", _IPV4_HOST),
            _header("NT", _ROOT_DEVICE),
            _header("NT", "uuid:device-001"),
            _header("USN", _DEVICE_USN),
            _header("USN", "uuid:device-001"),
            _header("CACHE-CONTROL", "max-age=1800"),
            _header("CACHE-CONTROL", "max-age=60"),
        ]
    if domain == "extension_nls":
        return [
            _header("HOST", _IPV6_SITE_HOST),
            _header("BOOTID.UPNP.ORG", "1"),
            _header("CONFIGID.UPNP.ORG", "16777215"),
            _header("NEXTBOOTID.UPNP.ORG", "2"),
            _header("SEARCHPORT.UPNP.ORG", "49152"),
            _header("TCPPORT.UPNP.ORG", "65535"),
            _header("CPFN.UPNP.ORG", "Example Control Point"),
            _header("CPUUID.UPNP.ORG", "uuid:control-point-001"),
            _header("SECURELOCATION.UPNP.ORG", "https://192.0.2.10:8443/root.xml"),
            _header("OPT", '"http://schemas.upnp.org/upnp/1/0/"; ns=01'),
            _header("01-NLS", "1"),
        ]
    if domain == "unknown_preserved":
        return [
            _header("host", _IPV4_HOST),
            _header("X-EXAMPLE.ORG", "one"),
            _header("X-EXAMPLE.ORG", "two"),
            _header("01-NLS", "1"),
        ]
    if domain == "excluded_eventing_preserved":
        return [
            _header("HOST", _IPV4_HOST),
            _header("NT", "upnp:event"),
            _header("CALLBACK", "<http://192.0.2.10:8000/events>"),
        ]
    return _search_headers(_IPV4_HOST)


def _body_for_domain(message_kind: str, domain: object) -> object:
    if domain == "empty":
        return {"hex": ""}
    if domain == "opaque_preserved":
        return {"hex": "626f64792d6279746573"}
    if domain == "binary":
        return {"hex": "000d0a626f64793a6279746573ff"}
    if message_kind in {"m_search", "notify", "unknown_request_preserved"}:
        return _SKIP_FIELD
    return {"hex": ""}


def _apply_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None = None,
) -> None:
    if "ssdp" not in fields:
        return

    if feature == "ssdp_malformed":
        _apply_malformed_behavior(fields, feature=feature, case=case, behavior=behavior, grammar=grammar)
        return

    selected = _selected_behavior(feature=feature, case=case, behavior=behavior, grammar=grammar)
    if selected is None:
        return

    ssdp = fields["ssdp"]
    ssdp.clear()
    _apply_behavior_mapping(ssdp, selected)
    _pin_udp_from_behavior(fields, selected)
    _pin_ip_from_behavior(fields, selected)
    if "payload" in fields:
        fields["payload"] = {"hex": "", "length": 0}


def _post_sample(fields: dict[str, JSONObject], *, stack: Sequence[str], case: str) -> None:
    del stack, case
    if "ssdp" in fields:
        _pin_udp_ports(fields)


def _apply_behavior_mapping(ssdp: JSONObject, behavior: Mapping[str, object]) -> None:
    message_kind = behavior.get("message_kind")
    if isinstance(message_kind, str):
        ssdp["message_kind"] = message_kind

    start_line = behavior.get("start_line")
    if isinstance(start_line, str):
        ssdp["start_line"] = start_line
        _apply_start_line_fields(ssdp, start_line)

    headers = _headers_from_behavior(behavior)
    if headers:
        ssdp["headers"] = headers

    body = _bytes_mapping(behavior.get("body"))
    if body is not None:
        ssdp["body"] = body

    payload = _bytes_mapping(behavior.get("payload"))
    if payload is not None:
        ssdp["payload"] = payload
        if message_kind == "raw_preserved":
            ssdp.pop("method", None)
            ssdp.pop("request_target", None)
            ssdp.pop("version", None)
            ssdp.pop("status_code", None)
            ssdp.pop("reason_phrase", None)
            ssdp.pop("headers", None)
            ssdp.pop("body", None)


def _apply_start_line_fields(ssdp: JSONObject, start_line: str) -> None:
    parts = start_line.split(" ", 2)
    if start_line.startswith("HTTP/"):
        ssdp["version"] = parts[0]
        if len(parts) > 1 and parts[1].isdigit():
            ssdp["status_code"] = int(parts[1])
        if len(parts) > 2:
            ssdp["reason_phrase"] = parts[2]
        ssdp.pop("method", None)
        ssdp.pop("request_target", None)
        return

    if len(parts) >= 1:
        ssdp["method"] = parts[0]
    if len(parts) >= 2:
        ssdp["request_target"] = parts[1]
    if len(parts) >= 3:
        ssdp["version"] = parts[2]
    ssdp.pop("status_code", None)
    ssdp.pop("reason_phrase", None)


def _headers_from_behavior(behavior: Mapping[str, object]) -> list[JSONObject]:
    raw_headers = behavior.get("headers")
    if not isinstance(raw_headers, Sequence) or isinstance(raw_headers, (str, bytes)):
        return []
    headers: list[JSONObject] = []
    for raw_header in raw_headers:
        if not isinstance(raw_header, Mapping):
            continue
        name = raw_header.get("name")
        if not isinstance(name, str):
            continue
        value = raw_header.get("value", "")
        wire_value = raw_header.get("wire_value")
        header = _header(name, "" if value is None else str(value))
        if isinstance(wire_value, str):
            header["wire_value"] = wire_value
        headers.append(header)
    return headers


def _bytes_mapping(value: object) -> JSONObject | None:
    if not isinstance(value, Mapping):
        return None
    encoding = value.get("encoding")
    raw_value = value.get("value")
    if not isinstance(raw_value, str):
        return None
    if encoding == "hex":
        return {"hex": raw_value}
    if encoding == "utf8":
        return {"utf8": raw_value}
    return None


def _pin_udp_from_behavior(fields: dict[str, JSONObject], behavior: Mapping[str, object]) -> None:
    udp = behavior.get("udp")
    if not isinstance(udp, Mapping):
        _pin_udp_ports(fields)
        return
    udp_fields = fields.setdefault("udp", {})
    source_port = udp.get("source_port")
    destination_port = udp.get("destination_port")
    if isinstance(source_port, int):
        udp_fields["src_port"] = source_port
    if isinstance(destination_port, int):
        udp_fields["dst_port"] = destination_port


def _pin_udp_ports(fields: dict[str, JSONObject]) -> None:
    if "udp" not in fields:
        return
    udp = fields["udp"]
    udp["src_port"] = _SSDP_PORT
    udp["dst_port"] = _SSDP_PORT


def _pin_ip_from_behavior(fields: dict[str, JSONObject], behavior: Mapping[str, object]) -> None:
    ip = behavior.get("ip")
    if not isinstance(ip, Mapping):
        return
    version = ip.get("version")
    if version == 4 and "ipv4" in fields:
        ipv4 = fields["ipv4"]
        _copy_str(ip, ipv4, "source", "src")
        _copy_str(ip, ipv4, "destination", "dst")
        _copy_int(ip, ipv4, "ttl", "ttl")
        if ip.get("protocol") == "udp":
            ipv4["protocol"] = "udp"
    elif version == 6 and "ipv6" in fields:
        ipv6 = fields["ipv6"]
        _copy_str(ip, ipv6, "source", "src")
        _copy_str(ip, ipv6, "destination", "dst")
        _copy_int(ip, ipv6, "hop_limit", "hop_limit")
        if ip.get("next_header") == "udp":
            ipv6["next_header"] = "udp"


def _copy_str(src: Mapping[str, object], dst: JSONObject, src_key: str, dst_key: str) -> None:
    value = src.get(src_key)
    if isinstance(value, str):
        dst[dst_key] = value


def _copy_int(src: Mapping[str, object], dst: JSONObject, src_key: str, dst_key: str) -> None:
    value = src.get(src_key)
    if isinstance(value, int):
        dst[dst_key] = value


def _apply_malformed_behavior(
    fields: dict[str, JSONObject],
    *,
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None,
) -> None:
    selected = _selected_behavior(feature=feature, case=case, behavior=behavior, grammar=grammar)
    if selected is None:
        return
    ssdp = fields["ssdp"]
    ssdp.clear()
    ssdp["message_kind"] = "malformed"
    fixture = selected.get("fixture")
    if isinstance(fixture, str):
        ssdp["fixture"] = fixture
    expected_error = selected.get("expected_error")
    if isinstance(expected_error, Mapping):
        ssdp["expected_error"] = _json_object(expected_error)
    _pin_udp_from_behavior(fields, selected)
    if "payload" in fields:
        fields["payload"] = {"hex": "", "length": 0}


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
    if feature == "ssdp_multicast":
        selected = _multicast_behavior_for_case(case, behavior, by_name)
        if selected is not None:
            return selected

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
    raw_behaviors = feature_spec.get("behaviors", [])
    if not isinstance(raw_behaviors, Sequence) or isinstance(raw_behaviors, (str, bytes)):
        return []
    return [item for item in raw_behaviors if isinstance(item, Mapping)]


def _multicast_behavior_for_case(
    case: str,
    behavior: str,
    by_name: Mapping[str, Mapping[str, object]],
) -> Mapping[str, object] | None:
    case_id = _identifier_part(case)
    if "ipv4" in case_id:
        return by_name.get("ipv4-m-search-multicast")
    if "ipv6" in case_id:
        if "link" in _identifier_part(behavior):
            return by_name.get("ipv6-link-scope-m-search-multicast-override")
        return by_name.get("ipv6-site-scope-m-search-multicast")
    return None


def _handles_feature(feature: str) -> bool:
    return feature.startswith("ssdp_")


def _search_headers(host: str) -> list[JSONObject]:
    return [
        _header("HOST", host),
        _header("MAN", _DISCOVER_MAN),
        _header("MX", "1"),
        _header("ST", "ssdp:all"),
    ]


def _notify_headers(subtype: str, *, full: bool) -> list[JSONObject]:
    headers = [
        _header("HOST", _IPV4_HOST),
        _header("NT", _ROOT_DEVICE),
        _header("NTS", subtype),
        _header("USN", _DEVICE_USN),
        _header("BOOTID.UPNP.ORG", "1"),
        _header("CONFIGID.UPNP.ORG", "1"),
    ]
    if full:
        headers[1:1] = [
            _header("CACHE-CONTROL", "max-age=1800"),
            _header("LOCATION", _LOCATION),
        ]
        headers.insert(-2, _header("SERVER", _SERVER))
    return headers


def _response_headers() -> list[JSONObject]:
    return [
        _header("CACHE-CONTROL", "max-age=1800"),
        _header("DATE", "Fri, 01 Jan 2027 00:00:00 GMT"),
        _header("EXT", ""),
        _header("LOCATION", _LOCATION),
        _header("SERVER", _SERVER),
        _header("ST", _ROOT_DEVICE),
        _header("USN", _DEVICE_USN),
        _header("BOOTID.UPNP.ORG", "1"),
        _header("CONFIGID.UPNP.ORG", "1"),
    ]


def _header(name: str, value: str) -> JSONObject:
    return {"name": name, "value": value}


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


def _identifier_part(value: str) -> str:
    return value.replace("_", "-").lower()


register(
    ProtocolSampler(
        layer="ssdp",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_behavior,
        handles_feature=_handles_feature,
        post_sample=_post_sample,
    )
)
