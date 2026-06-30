"""Wireshark-stage parser-only normalization for mDNS over UDP/5353.

Wireshark may expose multicast DNS as either an ``mdns`` protocol or ordinary
``dns`` fields on UDP/5353, depending on version and dissection path. This
plugin keeps ordinary DNS out of the comparable surface, but promotes UDP/5353
DNS-shaped parser output to the backend-neutral ``mdns`` layer used by the
oracle pcap checks.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ....model import JSONObject
from ..decode_helpers import (
    _field_list,
    _fields_from_aliases,
    _layer,
    _layer_any,
    _parse_int,
    _parse_int_fields,
)
from .base import WiresharkProtocol, register


MDNS_PORT = 5353

_MDNS_TSHARK_ALIASES: JSONObject = {
    "transaction_id": ("mdns.id", "dns.id"),
    "is_response": ("mdns.flags.response", "dns.flags.response"),
    "opcode": ("mdns.flags.opcode", "dns.flags.opcode"),
    "authoritative": ("mdns.flags.authoritative", "dns.flags.authoritative"),
    "response_code": ("mdns.flags.rcode", "dns.flags.rcode"),
    "question_count": ("mdns.count.queries", "dns.count.queries"),
    "answer_count": ("mdns.count.answers", "dns.count.answers"),
    "authority_count": ("mdns.count.auth_rr", "dns.count.auth_rr"),
    "additional_count": ("mdns.count.add_rr", "dns.count.add_rr"),
}

_TYPE_CODES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "PTR": 12,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "ANY": 255,
}


def _normalize(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    udp = _udp_fields(layers)
    if not _is_mdns_udp(udp):
        return {}

    dns_layer = _dns_layer(layers)
    output = _fields_from_aliases(dns_layer, dict(_MDNS_TSHARK_ALIASES))
    _parse_int_fields(
        output,
        "transaction_id",
        "opcode",
        "response_code",
        "question_count",
        "answer_count",
        "authority_count",
        "additional_count",
    )
    _parse_bool_fields(output, "is_response", "authoritative")
    output["transport"] = _transport_fields(udp)
    output["udp_5353"] = True
    output["questions"] = _questions(dns_layer)
    output["answers"] = _records(dns_layer)
    output["dns_sd"] = _dns_sd_fields(output["questions"], output["answers"])
    output["message_kind"] = _message_kind(output)
    return output


def canonicalize_mdns_payload(
    layers: list[str],
    fields: dict[str, JSONObject],
    layers_object: JSONObject,
    *,
    source_hex: str | None = None,
) -> None:
    """Promote UDP/5353 DNS parser output to the neutral ``mdns`` layer."""

    mdns = _normalize(layers_object, source_hex=source_hex)
    if not mdns:
        return

    existing = _first_layer_index(layers, "mdns")
    if existing is not None:
        fields[_layer_key_at(layers, existing)] = mdns
        return

    dns_index = _first_layer_index(layers, "dns")
    if dns_index is not None:
        key = _layer_key_at(layers, dns_index)
        fields.pop(key, None)
        layers[dns_index] = "mdns"
        fields[_layer_key_at(layers, dns_index)] = mdns
        return

    insert_at = _insert_index_after_udp(layers)
    layers.insert(insert_at, "mdns")
    fields[_layer_key_at(layers, insert_at)] = mdns


def _udp_fields(layers: JSONObject) -> JSONObject:
    layer = _layer(layers, "udp")
    output = _fields_from_aliases(
        layer,
        {
            "src_port": ("udp.srcport",),
            "dst_port": ("udp.dstport",),
        },
    )
    _parse_int_fields(output, "src_port", "dst_port")
    return output


def _is_mdns_udp(udp: Mapping[str, object]) -> bool:
    return udp.get("src_port") == MDNS_PORT or udp.get("dst_port") == MDNS_PORT


def _transport_fields(udp: Mapping[str, object]) -> JSONObject:
    src = _int_value(udp.get("src_port"))
    dst = _int_value(udp.get("dst_port"))
    return {
        "udp_source_port": src,
        "udp_destination_port": dst,
        "service_port": MDNS_PORT,
        "unicast_reply": src != MDNS_PORT or dst != MDNS_PORT,
    }


def _dns_layer(layers: JSONObject) -> JSONObject:
    return _layer_any(layers, "mdns", "dns")


def _questions(layer: JSONObject) -> list[JSONObject]:
    names = _field_values(layer, "mdns.qry.name", "dns.qry.name")
    types = _field_values(layer, "mdns.qry.type", "dns.qry.type")
    classes = _field_values(layer, "mdns.qry.class", "dns.qry.class")
    questions: list[JSONObject] = []
    for index, name in enumerate(names):
        raw_class = _class_value(_nth(classes, index, 1))
        questions.append(
            {
                "name": str(name),
                "record_type": _type_value(_nth(types, index, "A")),
                "raw_question_class": raw_class,
                "base_question_class": raw_class & 0x7FFF,
                "unicast_response_preferred": bool(raw_class & 0x8000),
            }
        )
    return questions


def _records(layer: JSONObject) -> list[JSONObject]:
    names = _field_values(layer, "mdns.resp.name", "dns.resp.name")
    types = _field_values(layer, "mdns.resp.type", "dns.resp.type")
    classes = _field_values(layer, "mdns.resp.class", "dns.resp.class")
    ttls = _field_values(layer, "mdns.resp.ttl", "dns.resp.ttl")
    data = _record_data_values(layer)
    records: list[JSONObject] = []
    for index, name in enumerate(names):
        raw_class = _class_value(_nth(classes, index, 1))
        record: JSONObject = {
            "name": str(name),
            "record_type": _type_value(_nth(types, index, "A")),
            "raw_class": raw_class,
            "base_class": raw_class & 0x7FFF,
            "cache_flush": bool(raw_class & 0x8000),
        }
        ttl = _parse_int(_nth(ttls, index, None))
        if ttl is not None:
            record["ttl"] = ttl
        rdata = _nth(data, index, None)
        if rdata is not None:
            record["rdata"] = str(rdata)
        records.append(record)
    return records


def _record_data_values(layer: JSONObject) -> list[object]:
    values: list[object] = []
    for name in (
        "mdns.a",
        "dns.a",
        "mdns.aaaa",
        "dns.aaaa",
        "mdns.ptr.domain_name",
        "dns.ptr.domain_name",
        "mdns.srv.target",
        "dns.srv.target",
        "mdns.txt",
        "dns.txt",
    ):
        values.extend(_field_list(layer, name))
    return values


def _dns_sd_fields(questions: object, records: object) -> JSONObject:
    names = [
        str(item.get("name"))
        for section in (questions, records)
        if isinstance(section, list)
        for item in section
        if isinstance(item, Mapping) and isinstance(item.get("name"), str)
    ]
    return {
        "service_names": [name for name in names if _is_service_name(name)],
        "instance_names": [name for name in names if _is_instance_name(name)],
        "subtype_names": [name for name in names if "._sub." in name],
        "browse_names": [
            name
            for name in names
            if _is_service_name(name) or "._sub." in name
        ],
        "txt_strings": [
            str(item.get("rdata"))
            for item in records
            if isinstance(item, Mapping)
            and item.get("record_type") == _TYPE_CODES["TXT"]
            and item.get("rdata") is not None
        ]
        if isinstance(records, list)
        else [],
    }


def _message_kind(fields: Mapping[str, object]) -> str:
    if not bool(fields.get("is_response")):
        if fields.get("answers"):
            return "known_answer_query"
        return "dns_sd_browse" if _has_dns_sd(fields.get("questions")) else "multicast_query"
    answers = fields.get("answers")
    if isinstance(answers, list):
        if any(isinstance(item, Mapping) and item.get("ttl") == 0 for item in answers):
            return "goodbye"
        if answers:
            return "multicast_response"
    return "announcement"


def _has_dns_sd(questions: object) -> bool:
    return isinstance(questions, list) and any(
        isinstance(item, Mapping)
        and isinstance(item.get("name"), str)
        and _is_service_name(str(item["name"]))
        for item in questions
    )


def _is_service_name(name: str) -> bool:
    labels = name.rstrip(".").split(".")
    return len(labels) >= 3 and labels[0].startswith("_") and labels[1].startswith("_")


def _is_instance_name(name: str) -> bool:
    labels = name.rstrip(".").split(".")
    return len(labels) >= 4 and not labels[0].startswith("_") and labels[1].startswith("_")


def _field_values(layer: JSONObject, *names: str) -> list[object]:
    for name in names:
        values = _field_list(layer, name)
        if values:
            return values
    return []


def _nth(values: Sequence[object], index: int, default: object) -> object:
    return values[index] if index < len(values) else default


def _type_value(value: object) -> int | str:
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed
    text = str(value).strip()
    token = text.split(" ", 1)[0].upper()
    return _TYPE_CODES.get(token, token)


def _class_value(value: object) -> int:
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed & 0xFFFF
    text = str(value).strip()
    token = text.split(" ", 1)[0].upper()
    if token in {"IN", "CLASS_IN"}:
        return 1
    return 0


def _parse_bool_fields(output: JSONObject, *names: str) -> None:
    for name in names:
        if name in output:
            output[name] = _truthy(output[name])


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower().split(" ", 1)[0] not in {"", "0", "0x0", "false"}
    return bool(value)


def _first_layer_index(layers: Sequence[str], layer: str) -> int | None:
    for index, item in enumerate(layers):
        if item == layer:
            return index
    return None


def _insert_index_after_udp(layers: Sequence[str]) -> int:
    for index, item in enumerate(layers):
        if item == "udp":
            return index + 1
    return len(layers)


def _layer_key_at(layers: Sequence[str], index: int) -> str:
    layer = layers[index]
    occurrence = sum(1 for position in range(index + 1) if layers[position] == layer)
    return layer if occurrence == 1 else f"{layer}#{occurrence}"


def _int_value(value: object) -> int:
    parsed = _parse_int(value)
    return parsed if parsed is not None else 0


register(
    WiresharkProtocol(
        layer="mdns",
        normalize=_normalize,
        tshark_aliases=dict(_MDNS_TSHARK_ALIASES),
    )
)
