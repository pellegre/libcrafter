"""Scapy-stage encode and decode support for mDNS over UDP/5353.

The oracle models mDNS as DNS message bytes carried on UDP/5353, with mDNS-only
class-bit interpretation layered on top: QU in question QCLASS and cache-flush in
record CLASS. Scapy has DNS primitives but no separate mDNS layer, so this plugin
adapts the backend-neutral ``mdns`` fields into the existing DNS materializer and
normalizes UDP/5353 DNS payloads back to the ``mdns`` layer.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ....model import JSONObject
from .. import dns_raw
from ..encode_helpers import _bool_int, _int, _layer_fields, _text
from .base import ScapyProtocol, register
from .dns import (
    _dns_flags,
    _dns_opcode,
    _dns_questions,
    _dns_records,
    _dns_response_code,
)


MDNS_PORT = 5353

_CLASS_CODES = dict(dns_raw._CLASS_CODES)
_RESPONSE_KINDS = frozenset({"multicast_response", "announcement", "goodbye"})

_SUPPORTED_FIELDS = frozenset(
    {
        "additional",
        "answers",
        "authority",
        "authoritative",
        "class_bits",
        "comparison",
        "expected_error",
        "expected_stack",
        "file_format",
        "fixture",
        "flags",
        "helper",
        "is_response",
        "link_type",
        "message_kind",
        "name_encoding",
        "opcode",
        "questions",
        "raw_dns",
        "response_code",
        "root",
        "transaction_id",
        "transport",
    }
)


def _build(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    del stack, index
    mdns_fields = _layer_fields(fields, "mdns")
    payload = _raw_fixture_payload(mdns_fields, case=getattr(plan, "case", None))
    if payload is not None:
        return scapy_all.Raw(load=payload)

    raw_dns = mdns_fields.get("raw_dns")
    if isinstance(raw_dns, Mapping):
        return scapy_all.Raw(load=dns_raw.build_raw_dns_bytes(raw_dns))

    return _mdns_dns(mdns_fields, scapy_all)


def _mdns_dns(mdns_fields: Mapping[str, object], scapy_all: Any) -> Any:
    dns_fields = _dns_fields(mdns_fields)
    questions = _dns_questions(dns_fields, scapy_all)
    answers = _dns_records(dns_fields.get("answers"), scapy_all)
    authority = _dns_records(dns_fields.get("authority"), scapy_all)
    additional = _dns_records(dns_fields.get("additional"), scapy_all)
    flags = _dns_flags(dns_fields.get("flags", []))
    return scapy_all.DNS(
        id=_int(dns_fields.get("transaction_id"), 0),
        qr=_bool_int(dns_fields.get("is_response"), 0),
        opcode=_dns_opcode(dns_fields.get("opcode")),
        qdcount=_section_count(dns_fields.get("questions")),
        ancount=_section_count(dns_fields.get("answers")),
        nscount=_section_count(dns_fields.get("authority")),
        arcount=_section_count(dns_fields.get("additional")),
        aa=flags["aa"],
        tc=flags["tc"],
        rd=flags["rd"],
        ra=flags["ra"],
        ad=flags["ad"],
        cd=flags["cd"],
        z=flags["z"],
        rcode=_dns_response_code(dns_fields.get("response_code")),
        qd=questions,
        an=answers,
        ns=authority,
        ar=additional,
    )


def _dns_fields(mdns_fields: Mapping[str, object]) -> JSONObject:
    message_kind = _text(mdns_fields.get("message_kind"), "multicast_query")
    is_response = mdns_fields.get("is_response")
    response = _bool_int(is_response, 1 if message_kind in _RESPONSE_KINDS else 0)

    dns_fields: JSONObject = {
        "transaction_id": _int(mdns_fields.get("transaction_id"), 0),
        "is_response": bool(response),
        "opcode": mdns_fields.get("opcode", "query"),  # type: ignore[assignment]
        "response_code": mdns_fields.get("response_code", "no_error"),  # type: ignore[assignment]
        "questions": _questions(mdns_fields.get("questions")),
        "answers": _records(mdns_fields.get("answers")),
        "authority": _records(mdns_fields.get("authority")),
        "additional": _records(mdns_fields.get("additional")),
    }

    flags = mdns_fields.get("flags")
    if flags is not None:
        dns_fields["flags"] = flags  # type: ignore[assignment]
    elif response or mdns_fields.get("authoritative") is True:
        dns_fields["flags"] = ["authoritative"]
    return dns_fields


def _section_count(value: object) -> int:
    if isinstance(value, list):
        return len(value)
    return 0


def _questions(value: object) -> list[JSONObject]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    output: list[JSONObject] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        qtype = item.get("qtype", item.get("type", "A"))
        raw_class = _raw_question_class(item)
        output.append(
            {
                "qname": item.get("qname", item.get("name", ".")),
                "qtype": qtype,
                "qclass": raw_class,
            }
        )
    return output


def _records(value: object) -> list[JSONObject]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    output: list[JSONObject] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        record: JSONObject = {str(key): _json_value(val) for key, val in item.items()}
        record["record_class"] = _raw_record_class(item)
        if "rrname" not in record and "name" in item:
            record["name"] = _json_value(item["name"])
        if "record_type" not in record and "type" in item:
            record["type"] = _json_value(item["type"])
        output.append(record)
    return output


def _raw_question_class(question: Mapping[str, object]) -> int:
    raw = question.get("raw_class", question.get("raw_question_class"))
    if raw is not None:
        return _class_code(raw)
    base = _class_code(
        question.get(
            "base_class",
            question.get("class", question.get("qclass", question.get("record_class", "IN"))),
        )
    )
    if question.get("unicast_response_preferred") is True:
        base |= 0x8000
    return base


def _raw_record_class(record: Mapping[str, object]) -> int:
    raw = record.get("raw_class")
    if raw is not None:
        return _class_code(raw)
    base = _class_code(
        record.get(
            "base_class",
            record.get("class", record.get("rclass", record.get("record_class", "IN"))),
        )
    )
    if record.get("cache_flush") is True:
        base |= 0x8000
    return base


def _class_code(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value & 0xFFFF
    text = _text(value, "IN").strip()
    if text.isdigit():
        return int(text) & 0xFFFF
    code = _CLASS_CODES.get(text.upper())
    if code is not None:
        return code
    return int(text, 0) & 0xFFFF


def _raw_fixture_payload(mdns_fields: Mapping[str, object], *, case: object) -> bytes | None:
    fixture = mdns_fields.get("fixture")
    if not isinstance(fixture, str):
        return None
    raw = _fixture_packet_bytes(fixture, _text(case, ""))
    return _udp_payload_from_packet_bytes(raw)


def _fixture_packet_bytes(path_text: str, case_name: str) -> bytes:
    path = Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("mDNS fixture path must be project-relative")
    if not path.exists():
        raise ValueError(f"mDNS fixture does not exist: {path_text}")

    if path.suffix == ".bin":
        return path.read_bytes()

    lines = path.read_text(encoding="utf-8").splitlines()
    if _is_corpus(lines):
        wanted = case_name.replace("malformed-", "", 1)
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split("|")
            if len(parts) >= 5 and parts[0] in {case_name, wanted}:
                return bytes.fromhex(parts[-1])
        raise ValueError(f"mDNS fixture corpus {path_text} has no case {case_name!r}")

    hex_text = "".join(
        line.split("#", 1)[0].strip() for line in lines if line.split("#", 1)[0].strip()
    )
    return bytes.fromhex(hex_text)


def _is_corpus(lines: Sequence[str]) -> bool:
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        return "|" in stripped
    return False


def _udp_payload_from_packet_bytes(raw: bytes) -> bytes:
    payload = _udp_payload_from_ipv4(raw)
    if payload is not None:
        return payload
    payload = _udp_payload_from_ipv6(raw)
    if payload is not None:
        return payload
    payload = _udp_payload_from_ethernet(raw)
    if payload is not None:
        return payload
    return raw


def _udp_payload_from_ethernet(raw: bytes) -> bytes | None:
    if len(raw) < 14:
        return None
    ethertype = int.from_bytes(raw[12:14], "big")
    if ethertype == 0x0800:
        return _udp_payload_from_ipv4(raw[14:])
    if ethertype == 0x86DD:
        return _udp_payload_from_ipv6(raw[14:])
    return None


def _udp_payload_from_ipv4(raw: bytes) -> bytes | None:
    if len(raw) < 28 or raw[0] >> 4 != 4:
        return None
    ihl = (raw[0] & 0x0F) * 4
    if ihl < 20 or len(raw) < ihl + 8 or raw[9] != 17:
        return None
    total_len = int.from_bytes(raw[2:4], "big")
    packet_end = min(total_len, len(raw)) if total_len >= ihl + 8 else len(raw)
    udp_len = int.from_bytes(raw[ihl + 4 : ihl + 6], "big")
    payload_end = min(ihl + udp_len, packet_end) if udp_len >= 8 else packet_end
    return raw[ihl + 8 : payload_end]


def _udp_payload_from_ipv6(raw: bytes) -> bytes | None:
    if len(raw) < 48 or raw[0] >> 4 != 6 or raw[6] != 17:
        return None
    payload_len = int.from_bytes(raw[4:6], "big")
    packet_end = min(40 + payload_len, len(raw)) if payload_len >= 8 else len(raw)
    udp_len = int.from_bytes(raw[44:46], "big")
    payload_end = min(40 + udp_len, packet_end) if udp_len >= 8 else packet_end
    return raw[48:payload_end]


def canonicalize_mdns_payload(
    packet: Any,
    layers: list[str],
    fields: dict[str, JSONObject],
) -> None:
    """Promote UDP/5353 DNS or Raw payloads to the neutral ``mdns`` layer."""

    udp = _scapy_layer(packet, "UDP")
    if udp is None or not _is_mdns_udp(udp):
        return

    dns = mdns_dns_packet(packet)
    mdns_fields = _mdns_fields_from_dns(dns, udp) if dns is not None else _mdns_fallback_fields(udp)

    dns_index = _payload_index_after_udp(layers, names={"dns"})
    if dns_index is not None:
        dns_key = _layer_key_at(layers, dns_index)
        fields.pop(dns_key, None)
        layers[dns_index] = "mdns"
        fields[_layer_key_at(layers, dns_index)] = mdns_fields
        return

    payload_index = _payload_index_after_udp(layers, names={"payload", "raw"})
    if payload_index is None:
        layers.append("mdns")
        fields[_layer_key_at(layers, len(layers) - 1)] = mdns_fields
        return

    payload_key = _layer_key_at(layers, payload_index)
    fields.pop(payload_key, None)
    layers[payload_index] = "mdns"
    fields[_layer_key_at(layers, payload_index)] = mdns_fields


def mdns_dns_packet(packet: Any) -> Any | None:
    udp = _scapy_layer(packet, "UDP")
    if udp is None or not _is_mdns_udp(udp):
        return None
    dns = _scapy_layer(packet, "DNS")
    if dns is not None:
        return dns
    payload = getattr(udp, "payload", None)
    if payload is None or payload.__class__.__name__ == "NoPayload":
        return None
    try:
        raw_payload = bytes(payload)
    except Exception:  # pragma: no cover - Scapy exception types vary.
        return None
    if len(raw_payload) < dns_raw.DNS_HEADER_LENGTH:
        return None
    try:
        from scapy.layers.dns import DNS  # type: ignore[import-untyped]

        return DNS(raw_payload)
    except Exception:  # pragma: no cover - Scapy exception types vary.
        return None


def mdns_metadata(message: JSONObject, packet: Any) -> JSONObject:
    udp = _scapy_layer(packet, "UDP")
    output: JSONObject = {
        "udp_5353": udp is not None and _is_mdns_udp(udp),
        "message_kind": _message_kind(message),
    }
    if udp is not None:
        output["transport"] = _transport_fields(udp)
    output["questions"] = [_mdns_question_metadata(item) for item in _section(message, "questions")]
    output["answers"] = [_mdns_record_metadata(item) for item in _section(message, "answers")]
    output["authorities"] = [_mdns_record_metadata(item) for item in _section(message, "authorities")]
    output["additionals"] = [_mdns_record_metadata(item) for item in _section(message, "additionals")]
    return output


def _mdns_fields_from_dns(dns: Any, udp: Any) -> JSONObject:
    header = _dns_header_fields(dns)
    header["transport"] = _transport_fields(udp)
    header["udp_5353"] = True
    header["message_kind"] = _message_kind_from_dns(dns)
    return header


def _mdns_fallback_fields(udp: Any) -> JSONObject:
    return {
        "transport": _transport_fields(udp),
        "udp_5353": True,
        "message_kind": "malformed",
    }


def _dns_header_fields(dns: Any) -> JSONObject:
    flags = _dns_flags(_dns_flags_word(dns))
    return {
        "transaction_id": _dns_int(getattr(dns, "id", 0)),
        "is_response": bool(_dns_int(getattr(dns, "qr", 0))),
        "opcode": _dns_int(getattr(dns, "opcode", 0)),
        "authoritative": bool(flags["aa"]),
        "truncated": bool(flags["tc"]),
        "recursion_desired": bool(flags["rd"]),
        "recursion_available": bool(flags["ra"]),
        "authenticated_data": bool(flags["ad"]),
        "checking_disabled": bool(flags["cd"]),
        "z": flags["z"],
        "response_code": _dns_int(getattr(dns, "rcode", 0)),
        "question_count": _dns_int(getattr(dns, "qdcount", 0)),
        "answer_count": _dns_int(getattr(dns, "ancount", 0)),
        "authority_count": _dns_int(getattr(dns, "nscount", 0)),
        "additional_count": _dns_int(getattr(dns, "arcount", 0)),
    }


def _dns_flags_word(dns: Any) -> int:
    word = _dns_int(getattr(dns, "qr", 0)) << 15
    word |= (_dns_int(getattr(dns, "opcode", 0)) & 0x0F) << 11
    word |= _dns_int(getattr(dns, "aa", 0)) << 10
    word |= _dns_int(getattr(dns, "tc", 0)) << 9
    word |= _dns_int(getattr(dns, "rd", 0)) << 8
    word |= _dns_int(getattr(dns, "ra", 0)) << 7
    word |= _dns_int(getattr(dns, "z", 0)) << 6
    word |= _dns_int(getattr(dns, "ad", 0)) << 5
    word |= _dns_int(getattr(dns, "cd", 0)) << 4
    word |= _dns_int(getattr(dns, "rcode", 0)) & 0x0F
    return word & 0xFFFF


def _transport_fields(udp: Any) -> JSONObject:
    sport = _dns_int(getattr(udp, "sport", 0))
    dport = _dns_int(getattr(udp, "dport", 0))
    return {
        "udp_source_port": sport,
        "udp_destination_port": dport,
        "service_port": MDNS_PORT,
        "unicast_reply": sport != MDNS_PORT or dport != MDNS_PORT,
    }


def _message_kind(message: JSONObject) -> str:
    header = message.get("header")
    if not isinstance(header, Mapping):
        return "malformed"
    if not bool(header.get("is_response")):
        if _section(message, "answers"):
            return "known_answer_query"
        if _section(message, "authorities"):
            return "probe"
        return "multicast_query"
    answers = _section(message, "answers")
    if any(_dns_int(record.get("ttl")) == 0 for record in answers):
        return "goodbye"
    if answers:
        return "multicast_response"
    return "announcement"


def _message_kind_from_dns(dns: Any) -> str:
    if not bool(_dns_int(getattr(dns, "qr", 0))):
        if _dns_section_records(dns, "an"):
            return "known_answer_query"
        if _dns_section_records(dns, "ns"):
            return "probe"
        return "multicast_query"
    if any(_dns_int(getattr(record, "ttl", 0)) == 0 for record in _dns_section_records(dns, "an")):
        return "goodbye"
    return "multicast_response"


def _mdns_question_metadata(question: JSONObject) -> JSONObject:
    raw_class = _dns_int(question.get("record_class"))
    return {
        "name": question.get("name"),
        "record_type": question.get("record_type"),
        "raw_question_class": raw_class,
        "base_question_class": raw_class & 0x7FFF,
        "unicast_response_preferred": bool(raw_class & 0x8000),
    }


def _mdns_record_metadata(record: JSONObject) -> JSONObject:
    raw_class = _dns_int(record.get("record_class"))
    return {
        "name": record.get("name"),
        "record_type": record.get("record_type"),
        "raw_class": raw_class,
        "base_class": raw_class & 0x7FFF,
        "cache_flush": bool(raw_class & 0x8000),
        "ttl": record.get("ttl"),
        "rdata": record.get("rdata"),
    }


def _section(message: JSONObject, name: str) -> list[JSONObject]:
    value = message.get(name)
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _dns_section_records(dns: Any, attr: str) -> list[Any]:
    records = getattr(dns, attr, None)
    if records is None:
        return []
    if isinstance(records, (list, tuple)):
        return [record for record in records if record is not None]
    return [records]


def _payload_index_after_udp(layers: Sequence[str], *, names: set[str]) -> int | None:
    try:
        udp_index = list(layers).index("udp")
    except ValueError:
        return None
    for index in range(udp_index + 1, len(layers)):
        if layers[index] in names:
            return index
    return None


def _scapy_layer(packet: Any, class_name: str) -> Any:
    current = packet
    while current is not None and current.__class__.__name__ != "NoPayload":
        if current.__class__.__name__ == class_name:
            return current
        current = current.payload
    return None


def _layer_key_at(layers: Sequence[str], index: int) -> str:
    layer_name = layers[index]
    count = sum(1 for item in layers[: index + 1] if item == layer_name)
    return layer_name if count == 1 else f"{layer_name}#{count}"


def _is_mdns_udp(udp: Any) -> bool:
    sport = _dns_int(getattr(udp, "sport", 0))
    dport = _dns_int(getattr(udp, "dport", 0))
    return sport == MDNS_PORT or dport == MDNS_PORT


def _dns_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _json_value(value: object) -> object:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_value(val) for key, val in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    return str(value)


register(
    ScapyProtocol(
        layer="mdns",
        scapy_class="DNS",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
    )
)
