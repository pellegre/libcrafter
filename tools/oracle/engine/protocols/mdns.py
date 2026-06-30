"""Generator-stage sampler plugin for the mDNS layer.

mDNS oracle specs model DNS wire messages over UDP/5353. This sampler keeps the
generator plan at that packet-message boundary: it emits deterministic DNS-like
message fields, pins UDP/5353 context, and records fixture/error intent for
compressed or malformed cases that later backend steps materialize.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject, JSONValue
from ..sampling import _SamplingContext
from .base import ProtocolSampler, register


_MDNS_PORT = 5353
_MDNS_IPV4_MULTICAST = "224.0.0.251"
_MDNS_IPV6_MULTICAST = "ff02::fb"
_MDNS_ETHERNET_IPV4 = "01:00:5e:00:00:fb"
_MDNS_ETHERNET_IPV6 = "33:33:00:00:00:fb"
_DEFAULT_HOST = "printer.local."
_SERVICE = "_ipp._tcp.local."
_INSTANCE = "Office\\032Printer._ipp._tcp.local."
_TARGET = "office-printer.local."

_SUPPORTED_FIELDS = frozenset(
    {
        "transport",
        "message_kind",
        "transaction_id",
        "is_response",
        "questions",
        "answers",
        "authority",
        "additional",
        "class_bits",
        "name_encoding",
    }
)

_RESPONSE_KINDS = frozenset({"multicast_response", "announcement", "goodbye"})


def _sample_mdns_field(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    current_fields: Mapping[str, object],
) -> object:
    message_kind = str(current_fields.get("message_kind") or _message_kind_for_domain(ctx, domain))
    if field_name == "transport":
        return _transport(unicast_reply=domain == "unicast_reply_override")
    if field_name == "message_kind":
        return _message_kind_for_domain(ctx, domain)
    if field_name == "transaction_id":
        return 0x1A2B if domain == "explicit_override" else 0
    if field_name == "is_response":
        return domain == "true" or message_kind in _RESPONSE_KINDS
    if field_name == "questions":
        return _questions_for_domain(domain)
    if field_name == "answers":
        return _answers_for_domain(domain)
    if field_name == "authority":
        return [_a_record(_DEFAULT_HOST)]
    if field_name == "additional":
        return _additionals_for_domain(domain)
    if field_name == "class_bits":
        return _class_bits_for_domain(domain)
    if field_name == "name_encoding":
        return str(domain)
    raise ValueError(f"spec error: unsupported mdns field sampler: {field_name}")


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    del field_spec
    return _sample_mdns_field(ctx, field_name, domain, current_fields)


def _apply_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None = None,
) -> None:
    if "mdns" not in fields and "mdns" in stack:
        fields["mdns"] = {}
    if "mdns" not in fields:
        return

    selected = _selected_behavior(feature=feature, case=case, behavior=behavior, grammar=grammar)
    if selected is None:
        _pin_udp_ports(fields)
        return

    if feature == "mdns_malformed":
        _apply_malformed_behavior(fields, selected)
        return

    mdns = fields["mdns"]
    mdns.clear()
    mdns["transport"] = _transport_from_behavior(selected)
    mdns["transaction_id"] = 0
    mdns["opcode"] = "query"
    mdns["response_code"] = "no_error"
    mdns["name_encoding"] = "uncompressed"
    _apply_behavior_mapping(mdns, selected, case=case)
    _finalize_message_defaults(mdns)
    _pin_udp_from_behavior(fields, selected)
    _pin_ip_from_behavior(fields, selected)
    _pin_ethernet_for_case(fields, case=case, selected=selected)
    if "payload" in fields:
        fields["payload"] = {"hex": "", "length": 0}


def _post_sample(fields: dict[str, JSONObject], *, stack: Sequence[str], case: str) -> None:
    del stack
    if "mdns" not in fields:
        return
    _pin_udp_ports(fields)
    _pin_multicast_defaults_for_case(fields, case)


def _apply_behavior_mapping(mdns: JSONObject, behavior: Mapping[str, object], *, case: str) -> None:
    message_kind = behavior.get("message_kind")
    if isinstance(message_kind, str):
        mdns["message_kind"] = message_kind
    else:
        mdns["message_kind"] = _message_kind_for_case(case)

    dns = behavior.get("dns")
    if isinstance(dns, Mapping):
        _apply_dns_mapping(mdns, dns)

    question = behavior.get("question")
    if isinstance(question, Mapping):
        mdns["questions"] = [_question_from_behavior(question)]

    raw_questions = behavior.get("questions")
    if _is_mapping_sequence(raw_questions):
        mdns["questions"] = [_question_from_behavior(item) for item in raw_questions]

    answer = behavior.get("answer")
    if isinstance(answer, Mapping):
        mdns["answers"] = [_record_from_behavior(answer)]

    for source_key, target_key in (
        ("answers", "answers"),
        ("authority", "authority"),
        ("additional", "additional"),
    ):
        raw_records = behavior.get(source_key)
        if _is_mapping_sequence(raw_records):
            mdns[target_key] = [_record_from_behavior(item) for item in raw_records]

    if behavior.get("raw_dns") is True:
        mdns["raw_dns"] = True
        mdns["name_encoding"] = "compressed_normalized"

    for key in ("fixture", "file_format", "root", "link_type", "helper"):
        value = behavior.get(key)
        if isinstance(value, str):
            mdns[key] = value

    expected_stack = behavior.get("expected_stack")
    if isinstance(expected_stack, Sequence) and not isinstance(expected_stack, (str, bytes)):
        mdns["expected_stack"] = [str(item) for item in expected_stack]

    comparison = behavior.get("comparison")
    if isinstance(comparison, Sequence) and not isinstance(comparison, (str, bytes)):
        mdns["comparison"] = [str(item) for item in comparison]


def _apply_dns_mapping(mdns: JSONObject, dns: Mapping[str, object]) -> None:
    _copy_int(dns, mdns, "transaction_id", "transaction_id")
    _copy_bool(dns, mdns, "is_response", "is_response")
    _copy_str(dns, mdns, "opcode", "opcode")
    _copy_str(dns, mdns, "response_code", "response_code")
    authoritative = dns.get("authoritative")
    if isinstance(authoritative, bool):
        mdns["authoritative"] = authoritative
        if authoritative:
            _add_flag(mdns, "authoritative")

    raw_questions = dns.get("questions")
    if _is_mapping_sequence(raw_questions):
        mdns["questions"] = [_question_from_behavior(item) for item in raw_questions]

    raw_answers = dns.get("answers")
    if _is_mapping_sequence(raw_answers):
        mdns["answers"] = [_record_from_behavior(item) for item in raw_answers]

    raw_authority = dns.get("authority")
    if _is_mapping_sequence(raw_authority):
        mdns["authority"] = [_record_from_behavior(item) for item in raw_authority]

    raw_additional = dns.get("additional")
    if _is_mapping_sequence(raw_additional):
        mdns["additional"] = [_record_from_behavior(item) for item in raw_additional]


def _apply_malformed_behavior(fields: dict[str, JSONObject], behavior: Mapping[str, object]) -> None:
    mdns = fields["mdns"]
    mdns.clear()
    mdns["message_kind"] = "malformed"
    mdns["transport"] = _transport()
    fixture = behavior.get("fixture")
    if isinstance(fixture, str):
        mdns["fixture"] = fixture
    expected_error = behavior.get("expected_error")
    if isinstance(expected_error, Mapping):
        mdns["expected_error"] = _json_object(expected_error)
    _pin_udp_from_behavior(fields, behavior)
    if "payload" in fields:
        fields["payload"] = {"hex": "", "length": 0}


def _finalize_message_defaults(mdns: JSONObject) -> None:
    message_kind = str(mdns.get("message_kind") or "multicast_query")
    if "is_response" not in mdns:
        mdns["is_response"] = message_kind in _RESPONSE_KINDS
    if "questions" not in mdns and not bool(mdns.get("is_response")):
        mdns["questions"] = [_question(_DEFAULT_HOST, "A")]
    if bool(mdns.get("is_response")) and "flags" not in mdns:
        mdns["flags"] = ["authoritative"]
        mdns["authoritative"] = True


def _selected_behavior(
    *,
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None,
) -> Mapping[str, object] | None:
    by_name = {
        str(candidate.get("name")): candidate
        for candidate in _feature_behaviors(grammar, feature)
        if isinstance(candidate.get("name"), str)
    }
    if behavior in by_name:
        return by_name[behavior]

    case_id = _identifier_part(case)
    for name, candidate in by_name.items():
        if _identifier_part(name) in case_id:
            return candidate
    for candidate in by_name.values():
        coverage_case = candidate.get("coverage_case")
        if isinstance(coverage_case, str) and _identifier_part(coverage_case) == case_id:
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


def _message_kind_for_domain(ctx: _SamplingContext, domain: object) -> str:
    if isinstance(domain, str):
        return domain
    return _message_kind_for_case(ctx.case)


def _message_kind_for_case(case: str) -> str:
    case_id = _identifier_part(case)
    if "known-answer" in case_id:
        return "known_answer_query"
    if "probe" in case_id:
        return "probe"
    if "announcement" in case_id:
        return "announcement"
    if "goodbye" in case_id:
        return "goodbye"
    if "resolve" in case_id:
        return "dns_sd_resolve"
    if "dns-sd" in case_id or "bonjour" in case_id:
        return "dns_sd_browse"
    if "response" in case_id or "cache-flush" in case_id or "unknown-record" in case_id:
        return "multicast_response"
    return "multicast_query"


def _questions_for_domain(domain: object) -> list[JSONObject]:
    if domain == "ptr_local":
        return [_question(_SERVICE, "PTR")]
    if domain == "a_local":
        return [_question(_DEFAULT_HOST, "A")]
    if domain == "aaaa_local":
        return [_question(_DEFAULT_HOST, "AAAA")]
    if domain == "any_probe":
        return [_question(_DEFAULT_HOST, "ANY", raw_class=0x8001)]
    if domain == "qu_question":
        return [_question(_DEFAULT_HOST, "A", raw_class=0x8001)]
    if domain == "dns_sd_browse":
        return [_question(_SERVICE, "PTR")]
    if domain == "dns_sd_resolve":
        return [_question(_INSTANCE, "SRV"), _question(_INSTANCE, "TXT")]
    if domain == "dns_sd_subtype":
        return [_question("_printer._sub._ipp._tcp.local.", "PTR")]
    return [_question(_DEFAULT_HOST, "A")]


def _answers_for_domain(domain: object) -> list[JSONObject]:
    if domain == "known_answer":
        return [_a_record(_DEFAULT_HOST)]
    if domain == "ptr":
        return [_ptr_record(_SERVICE, _INSTANCE)]
    if domain == "srv":
        return [_srv_record(_INSTANCE)]
    if domain == "txt":
        return [_txt_record(_INSTANCE)]
    if domain == "a":
        return [_a_record(_TARGET)]
    if domain == "aaaa":
        return [_aaaa_record(_TARGET)]
    if domain == "cache_flush":
        return [_a_record(_DEFAULT_HOST, cache_flush=True)]
    if domain == "goodbye_zero_ttl":
        return [_a_record(_DEFAULT_HOST, ttl=0, cache_flush=True)]
    if domain == "raw_unknown":
        return [_raw_unknown_record("opaque.local.")]
    if domain == "compressed_owner":
        record = _a_record(_DEFAULT_HOST)
        record["name_encoding"] = "compressed_normalized"
        return [record]
    return [_a_record(_DEFAULT_HOST)]


def _additionals_for_domain(domain: object) -> list[JSONObject]:
    if domain == "raw_unknown":
        return [_raw_unknown_record("opaque.local.")]
    if domain in {"dns_sd_additionals", "address_records"}:
        return [_a_record(_TARGET, cache_flush=True), _aaaa_record(_TARGET, cache_flush=True)]
    return [_a_record(_TARGET)]


def _class_bits_for_domain(domain: object) -> list[str]:
    if domain == "qu":
        return ["qu"]
    if domain == "cache_flush":
        return ["cache_flush"]
    if domain == "explicit_high_bit_preserved":
        return ["explicit_high_bit_preserved"]
    return ["base_class"]


def _question_from_behavior(value: Mapping[str, object]) -> JSONObject:
    question = _json_object(value)
    qtype = question.pop("qtype", None)
    if qtype is not None and "type" not in question:
        question["type"] = qtype
    qname = question.pop("qname", None)
    if qname is not None and "name" not in question:
        question["name"] = qname
    raw_class = question.get("raw_class")
    if isinstance(raw_class, int) and raw_class & 0x8000:
        question.setdefault("base_class", "IN")
        question.setdefault("unicast_response_preferred", True)
    return question


def _record_from_behavior(value: Mapping[str, object]) -> JSONObject:
    record = _json_object(value)
    if record.get("cache_flush") is True:
        record.setdefault("raw_class", 0x8001)
        record.setdefault("base_class", "IN")
    raw_class = record.get("raw_class")
    if isinstance(raw_class, int) and raw_class & 0x8000:
        record.setdefault("base_class", "IN")
        record.setdefault("cache_flush", True)
    rdata = value.get("rdata")
    if isinstance(rdata, Mapping):
        bytes_value = _bytes_mapping(rdata)
        if bytes_value is not None:
            record["rdata"] = bytes_value
    return record


def _question(name: str, qtype: str, *, raw_class: int | None = None) -> JSONObject:
    question: JSONObject = {"name": name, "type": qtype, "class": "IN"}
    if raw_class is not None:
        question["raw_class"] = raw_class
        question["base_class"] = "IN"
        question["unicast_response_preferred"] = bool(raw_class & 0x8000)
    return question


def _a_record(name: str, *, ttl: int = 120, cache_flush: bool = False) -> JSONObject:
    record: JSONObject = {
        "name": name,
        "type": "A",
        "class": "IN",
        "ttl": ttl,
        "address": "192.0.2.55",
    }
    if cache_flush:
        record["cache_flush"] = True
        record["raw_class"] = 0x8001
        record["base_class"] = "IN"
    return record


def _aaaa_record(name: str, *, ttl: int = 120, cache_flush: bool = False) -> JSONObject:
    record: JSONObject = {
        "name": name,
        "type": "AAAA",
        "class": "IN",
        "ttl": ttl,
        "address": "2001:db8::55",
    }
    if cache_flush:
        record["cache_flush"] = True
        record["raw_class"] = 0x8001
        record["base_class"] = "IN"
    return record


def _ptr_record(name: str, target: str, *, ttl: int = 4500) -> JSONObject:
    return {"name": name, "type": "PTR", "class": "IN", "ttl": ttl, "target": target}


def _srv_record(name: str, *, ttl: int = 120, cache_flush: bool = True) -> JSONObject:
    record: JSONObject = {
        "name": name,
        "type": "SRV",
        "class": "IN",
        "ttl": ttl,
        "priority": 0,
        "weight": 0,
        "port": 631,
        "target": _TARGET,
    }
    if cache_flush:
        record["cache_flush"] = True
        record["raw_class"] = 0x8001
        record["base_class"] = "IN"
    return record


def _txt_record(name: str, *, ttl: int = 120, cache_flush: bool = True) -> JSONObject:
    record: JSONObject = {
        "name": name,
        "type": "TXT",
        "class": "IN",
        "ttl": ttl,
        "strings": ["txtvers=1", "qtotal=1", "rp=printers/office"],
    }
    if cache_flush:
        record["cache_flush"] = True
        record["raw_class"] = 0x8001
        record["base_class"] = "IN"
    return record


def _raw_unknown_record(name: str) -> JSONObject:
    return {
        "name": name,
        "type": 65280,
        "class": "IN",
        "ttl": 120,
        "rdata": {"hex": "00010203ff"},
    }


def _transport(*, unicast_reply: bool = False) -> JSONObject:
    return {
        "udp_source_port": _MDNS_PORT,
        "udp_destination_port": _MDNS_PORT,
        "service_port": _MDNS_PORT,
        "unicast_reply": unicast_reply,
    }


def _transport_from_behavior(behavior: Mapping[str, object]) -> JSONObject:
    udp = behavior.get("udp")
    if not isinstance(udp, Mapping):
        return _transport()
    source_port = udp.get("source_port")
    destination_port = udp.get("destination_port")
    return {
        "udp_source_port": source_port if isinstance(source_port, int) else _MDNS_PORT,
        "udp_destination_port": (
            destination_port if isinstance(destination_port, int) else _MDNS_PORT
        ),
        "service_port": _MDNS_PORT,
        "unicast_reply": False,
    }


def _pin_udp_from_behavior(fields: dict[str, JSONObject], behavior: Mapping[str, object]) -> None:
    udp_fields = fields.setdefault("udp", {})
    udp = behavior.get("udp")
    if isinstance(udp, Mapping):
        source_port = udp.get("source_port")
        destination_port = udp.get("destination_port")
        udp_fields["src_port"] = source_port if isinstance(source_port, int) else _MDNS_PORT
        udp_fields["dst_port"] = (
            destination_port if isinstance(destination_port, int) else _MDNS_PORT
        )
        return
    _pin_udp_ports(fields)


def _pin_udp_ports(fields: dict[str, JSONObject]) -> None:
    if "udp" not in fields:
        return
    fields["udp"]["src_port"] = _MDNS_PORT
    fields["udp"]["dst_port"] = _MDNS_PORT


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


def _pin_ethernet_for_case(
    fields: dict[str, JSONObject],
    *,
    case: str,
    selected: Mapping[str, object],
) -> None:
    if "ethernet" not in fields:
        return
    case_id = _identifier_part(case)
    ip = selected.get("ip")
    destination = ip.get("destination") if isinstance(ip, Mapping) else None
    if "ipv4" in case_id or destination == _MDNS_IPV4_MULTICAST:
        fields["ethernet"]["dst"] = _MDNS_ETHERNET_IPV4
    elif "ipv6" in case_id or destination == _MDNS_IPV6_MULTICAST:
        fields["ethernet"]["dst"] = _MDNS_ETHERNET_IPV6


def _pin_multicast_defaults_for_case(fields: dict[str, JSONObject], case: str) -> None:
    case_id = _identifier_part(case)
    if "mdns-ipv4-multicast" in case_id:
        if "ipv4" in fields:
            fields["ipv4"]["dst"] = _MDNS_IPV4_MULTICAST
            fields["ipv4"]["ttl"] = 255
            fields["ipv4"]["protocol"] = "udp"
        if "ethernet" in fields:
            fields["ethernet"]["dst"] = _MDNS_ETHERNET_IPV4
    elif "mdns-ipv6-multicast" in case_id:
        if "ipv6" in fields:
            fields["ipv6"]["dst"] = _MDNS_IPV6_MULTICAST
            fields["ipv6"]["hop_limit"] = 255
            fields["ipv6"]["next_header"] = "udp"
        if "ethernet" in fields:
            fields["ethernet"]["dst"] = _MDNS_ETHERNET_IPV6


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


def _add_flag(mdns: JSONObject, flag: str) -> None:
    flags = mdns.setdefault("flags", [])
    if isinstance(flags, list) and flag not in flags:
        flags.append(flag)


def _copy_str(src: Mapping[str, object], dst: JSONObject, src_key: str, dst_key: str) -> None:
    value = src.get(src_key)
    if isinstance(value, str):
        dst[dst_key] = value


def _copy_int(src: Mapping[str, object], dst: JSONObject, src_key: str, dst_key: str) -> None:
    value = src.get(src_key)
    if isinstance(value, int):
        dst[dst_key] = value


def _copy_bool(src: Mapping[str, object], dst: JSONObject, src_key: str, dst_key: str) -> None:
    value = src.get(src_key)
    if isinstance(value, bool):
        dst[dst_key] = value


def _is_mapping_sequence(value: object) -> bool:
    return (
        isinstance(value, Sequence)
        and not isinstance(value, (str, bytes))
        and all(isinstance(item, Mapping) for item in value)
    )


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


def _handles_feature(feature: str) -> bool:
    return feature.startswith("mdns_")


register(
    ProtocolSampler(
        layer="mdns",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_behavior,
        handles_feature=_handles_feature,
        post_sample=_post_sample,
    )
)
