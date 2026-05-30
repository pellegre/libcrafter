"""Scapy-owned raw DNS byte construction for low-level oracle cases.

Some DNS wire shapes cannot be produced reliably through Scapy's high-level
``DNS``/``DNSRR`` fields: an explicit compression pointer, byte-preserving
non-text labels, a malformed pointer, or a deliberately overrun RDLENGTH.
Scapy re-derives those bytes on its own, so the helpers in this module build the
exact DNS message octets from a backend-neutral ``dns_raw`` spec and hand them
back as a Scapy layer.

Every builder is small and named after the wire structure it emits (header
word, name labels, compression pointer, question, resource record, RDATA) so a
reader can audit each octet. The bytes stay Scapy-owned: the public entrypoint
wraps them in ``scapy.Raw`` so the rest of the backend treats the DNS payload
exactly like any other materialized layer while preserving the bytes verbatim.

Addresses default to documentation ranges (192.0.2.0/24, 2001:db8::/32) so raw
cases never leave documentation address space.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Any

# DNS header is a fixed 12-octet prefix: id, flags word, then the four section
# counts. The flag word packs QR, opcode, AA, TC, RD, RA, the Z reserved bit,
# AD, CD, and the 4-bit RCODE. We build it explicitly so a malformed or
# user-pinned flag word survives untouched.
DNS_HEADER_LENGTH = 12
_COMPRESSION_POINTER_MARKER = 0xC0
_MAX_LABEL_LENGTH = 63

_OPCODE_ALIASES: dict[str, int] = {
    "query": 0,
    "iquery": 1,
    "inverse-query": 1,
    "status": 2,
    "notify": 4,
    "update": 5,
}
_RCODE_ALIASES: dict[str, int] = {
    "no-error": 0,
    "format-error": 1,
    "server-failure": 2,
    "name-error": 3,
    "nxdomain": 3,
    "not-implemented": 4,
    "refused": 5,
}
# Minimal record-type name -> numeric type code table. The raw helpers only need
# the codepoints that the raw cases reference; everything else may be given as a
# numeric type in the spec.
_TYPE_CODES: dict[str, int] = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "OPT": 41,
    "DS": 43,
    "RRSIG": 46,
    "NSEC": 47,
    "DNSKEY": 48,
    "NSEC3": 50,
    "SVCB": 64,
    "HTTPS": 65,
}
_CLASS_CODES: dict[str, int] = {
    "IN": 1,
    "CH": 3,
    "HS": 4,
    "NONE": 254,
    "ANY": 255,
}


def is_raw_dns_spec(value: object) -> bool:
    """Return True when a DNS layer carries a raw-byte spec."""

    return isinstance(value, Mapping)


def materialize_raw_dns(spec: Mapping[str, object], scapy_all: Any) -> Any:
    """Build a raw DNS message and return it as a byte-exact Scapy layer.

    The bytes are wrapped in ``scapy.Raw`` so the surrounding UDP/IP materializer
    keeps them verbatim; Scapy still dissects the DNS payload on decode because
    the root decoder re-parses the whole packet.
    """

    raw_bytes = build_raw_dns_bytes(spec)
    return scapy_all.Raw(load=raw_bytes)


def build_raw_dns_bytes(spec: Mapping[str, object]) -> bytes:
    """Assemble complete DNS message octets from a backend-neutral raw spec.

    Spec shape (all keys optional unless noted):
      transaction_id: int
      flags: header flag spec (see ``dns_flags_word``)
      response_code / rcode: name or int merged into the flag word
      opcode: name or int merged into the flag word
      questions: list of {name, type, class}
      answers / authority / additional: list of record specs
      counts: optional explicit override {qd, an, ns, ar} for malformed counts
      trailing_bytes: hex string appended after the last record
    """

    questions = _as_list(spec.get("questions"))
    answers = _as_list(spec.get("answers"))
    authority = _as_list(spec.get("authority"))
    additional = _as_list(spec.get("additional"))

    # The name buffer offsets compression pointers against the live wire image,
    # so records are encoded against the bytes emitted so far.
    body = bytearray()
    for question in questions:
        body += dns_question_bytes(question, base_offset=DNS_HEADER_LENGTH + len(body))
    for record in [*answers, *authority, *additional]:
        body += dns_record_bytes(record, base_offset=DNS_HEADER_LENGTH + len(body))

    counts = _section_counts(spec, questions, answers, authority, additional)
    header = dns_header_bytes(
        transaction_id=_int(spec.get("transaction_id", spec.get("id")), 0),
        flags_word=dns_flags_word(spec),
        counts=counts,
    )

    message = bytes(header) + bytes(body)
    trailing = spec.get("trailing_bytes")
    if trailing is not None:
        message += _blob(trailing)
    return message


def dns_header_bytes(
    *,
    transaction_id: int,
    flags_word: int,
    counts: tuple[int, int, int, int],
) -> bytes:
    """Pack the fixed 12-octet DNS header."""

    qdcount, ancount, nscount, arcount = counts
    return b"".join(
        _uint16(value)
        for value in (transaction_id, flags_word, qdcount, ancount, nscount, arcount)
    )


def dns_flags_word(spec: Mapping[str, object]) -> int:
    """Build the 16-bit DNS flag word from a normalized spec.

    Accepts an explicit ``flags`` integer (used verbatim, even if malformed) or
    a flag-name list/mapping plus ``opcode`` and ``response_code`` overrides.
    """

    flags = spec.get("flags")
    if isinstance(flags, int) and not isinstance(flags, bool):
        return flags & 0xFFFF

    qr = 1 if _bool(spec.get("is_response")) else 0
    opcode = _opcode_value(spec.get("opcode")) & 0xF
    rcode = _rcode_value(spec.get("response_code", spec.get("rcode"))) & 0xF
    names = _flag_name_set(flags)

    word = qr << 15
    word |= opcode << 11
    word |= (1 if "authoritative" in names else 0) << 10
    word |= (1 if "truncated" in names else 0) << 9
    word |= (1 if "recursion_desired" in names else 0) << 8
    word |= (1 if "recursion_available" in names else 0) << 7
    word |= (1 if "reserved_z" in names else 0) << 6
    word |= (1 if "authentic_data" in names else 0) << 5
    word |= (1 if "checking_disabled" in names else 0) << 4
    word |= rcode
    return word & 0xFFFF


def dns_name_bytes(name: object) -> bytes:
    """Encode a presentation name as uncompressed wire labels ending in root.

    Supports ``\\DDD`` decimal escapes and ``\\.`` so non-text and embedded-dot
    labels are byte-preserving.
    """

    labels = _split_presentation_labels(_name_text(name))
    output = bytearray()
    for label in labels:
        if len(label) > _MAX_LABEL_LENGTH:
            raise ValueError(f"raw dns label exceeds 63 octets: {label!r}")
        output.append(len(label))
        output += label
    output.append(0)
    return bytes(output)


def dns_compression_pointer_bytes(offset: int) -> bytes:
    """Encode a 14-bit compression pointer (0xC000 | offset)."""

    if offset < 0 or offset > 0x3FFF:
        raise ValueError(f"compression pointer offset out of range: {offset}")
    return _uint16((_COMPRESSION_POINTER_MARKER << 8) | offset)


def dns_partial_name_with_pointer(prefix: object, pointer_offset: int) -> bytes:
    """Encode leading labels followed by a compression pointer.

    This is the byte shape libcrafter must decode to reconstruct the full name.
    """

    output = bytearray()
    if prefix not in (None, "", "."):
        for label in _split_presentation_labels(_name_text(prefix)):
            if len(label) > _MAX_LABEL_LENGTH:
                raise ValueError(f"raw dns label exceeds 63 octets: {label!r}")
            output.append(len(label))
            output += label
    output += dns_compression_pointer_bytes(pointer_offset)
    return bytes(output)


def dns_question_bytes(question: Mapping[str, object], *, base_offset: int) -> bytes:
    """Encode one question entry: name + QTYPE + QCLASS."""

    name = _question_name_bytes(question, base_offset=base_offset)
    qtype = _type_code(question.get("type", question.get("qtype")))
    qclass = _class_code(question.get("class", question.get("qclass")))
    return name + _uint16(qtype) + _uint16(qclass)


def dns_record_bytes(record: Mapping[str, object], *, base_offset: int) -> bytes:
    """Encode one resource record: name + TYPE + CLASS + TTL + RDLENGTH + RDATA.

    RDATA is taken verbatim from ``rdata``/``data``. ``rdlength_override`` pins a
    declared length that disagrees with the real RDATA so malformed-overrun cases
    can be produced.
    """

    name = _record_name_bytes(record, base_offset=base_offset)
    rtype = _type_code(record.get("type", record.get("record_type")))
    rclass = _class_code(record.get("class", record.get("record_class")))
    ttl = _int(record.get("ttl"), 60)
    rdata = dns_rdata_bytes(record, base_offset=base_offset + len(name) + 10)
    rdlength = record.get("rdlength_override")
    declared = _int(rdlength, len(rdata)) if rdlength is not None else len(rdata)
    return (
        name
        + _uint16(rtype)
        + _uint16(rclass)
        + _uint32(ttl)
        + _uint16(declared)
        + rdata
    )


def dns_rdata_bytes(record: Mapping[str, object], *, base_offset: int) -> bytes:
    """Build RDATA octets from the record spec.

    The raw helpers default to opaque ``rdata``/``data`` blobs. A small number of
    convenience encoders cover the common low-level cases (A address, a
    name target with an embedded compression pointer) so the spec stays readable.
    """

    if "rdata" in record or "data" in record:
        return _blob(record.get("rdata", record.get("data")))
    address = record.get("address")
    if address is not None:
        return _address_bytes(address)
    target = record.get("target_with_pointer")
    if isinstance(target, Mapping):
        return dns_partial_name_with_pointer(
            target.get("prefix"),
            _int(target.get("pointer_offset"), DNS_HEADER_LENGTH),
        )
    target_name = record.get("target", record.get("name_target"))
    if target_name is not None:
        return dns_name_bytes(target_name)
    return b""


# --- internal helpers -------------------------------------------------------


def _question_name_bytes(question: Mapping[str, object], *, base_offset: int) -> bytes:
    pointer = question.get("name_with_pointer")
    if isinstance(pointer, Mapping):
        return dns_partial_name_with_pointer(
            pointer.get("prefix"),
            _int(pointer.get("pointer_offset"), DNS_HEADER_LENGTH),
        )
    raw_name = question.get("raw_name")
    if raw_name is not None:
        return _blob(raw_name)
    return dns_name_bytes(question.get("name", question.get("qname", ".")))


def _record_name_bytes(record: Mapping[str, object], *, base_offset: int) -> bytes:
    pointer = record.get("name_with_pointer")
    if isinstance(pointer, Mapping):
        return dns_partial_name_with_pointer(
            pointer.get("prefix"),
            _int(pointer.get("pointer_offset"), DNS_HEADER_LENGTH),
        )
    raw_name = record.get("raw_name")
    if raw_name is not None:
        return _blob(raw_name)
    return dns_name_bytes(record.get("name", record.get("rrname", ".")))


def _section_counts(
    spec: Mapping[str, object],
    questions: list[object],
    answers: list[object],
    authority: list[object],
    additional: list[object],
) -> tuple[int, int, int, int]:
    counts = spec.get("counts")
    if isinstance(counts, Mapping):
        return (
            _int(counts.get("qd", counts.get("qdcount")), len(questions)),
            _int(counts.get("an", counts.get("ancount")), len(answers)),
            _int(counts.get("ns", counts.get("nscount")), len(authority)),
            _int(counts.get("ar", counts.get("arcount")), len(additional)),
        )
    return (len(questions), len(answers), len(authority), len(additional))


def _flag_name_set(flags: object) -> set[str]:
    names: set[str] = set()
    aliases = {
        "aa": "authoritative",
        "authoritative": "authoritative",
        "tc": "truncated",
        "truncated": "truncated",
        "rd": "recursion_desired",
        "recursion_desired": "recursion_desired",
        "ra": "recursion_available",
        "recursion_available": "recursion_available",
        "ad": "authentic_data",
        "authentic_data": "authentic_data",
        "cd": "checking_disabled",
        "checking_disabled": "checking_disabled",
        "z": "reserved_z",
        "reserved_z": "reserved_z",
    }
    if isinstance(flags, Mapping):
        for key, value in flags.items():
            slot = aliases.get(str(key).lower().replace("-", "_"))
            if slot is not None and _bool(value):
                names.add(slot)
        return names
    values = flags if isinstance(flags, list) else ([flags] if flags is not None else [])
    for item in values:
        if not isinstance(item, str):
            continue
        slot = aliases.get(item.lower().replace("-", "_"))
        if slot is not None:
            names.add(slot)
    return names


def _opcode_value(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        if lowered in _OPCODE_ALIASES:
            return _OPCODE_ALIASES[lowered]
        if lowered == "unknown":
            return 14
        return int(lowered, 0)
    return 0


def _rcode_value(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        if lowered in _RCODE_ALIASES:
            return _RCODE_ALIASES[lowered]
        if lowered == "unknown":
            return 11
        return int(lowered, 0)
    return 0


def _type_code(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError(f"dns type must not be boolean: {value!r}")
    if isinstance(value, int):
        return value
    if value is None:
        return _TYPE_CODES["A"]
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    code = _TYPE_CODES.get(text.upper())
    if code is None:
        raise ValueError(f"unsupported raw dns type: {value!r}")
    return code


def _class_code(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError(f"dns class must not be boolean: {value!r}")
    if isinstance(value, int):
        return value
    if value is None:
        return _CLASS_CODES["IN"]
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    code = _CLASS_CODES.get(text.upper())
    if code is None:
        raise ValueError(f"unsupported raw dns class: {value!r}")
    return code


def _split_presentation_labels(name: str) -> list[bytes]:
    if name in ("", "."):
        return []
    trimmed = name[:-1] if name.endswith(".") else name
    labels: list[bytes] = []
    current = bytearray()
    index = 0
    length = len(trimmed)
    while index < length:
        char = trimmed[index]
        if char == "\\":
            index += 1
            if index >= length:
                raise ValueError(f"dangling escape in dns name: {name!r}")
            nxt = trimmed[index]
            if nxt.isdigit():
                digits = trimmed[index : index + 3]
                if len(digits) != 3 or not digits.isdigit():
                    raise ValueError(f"invalid decimal escape in dns name: {name!r}")
                current.append(int(digits))
                index += 3
                continue
            current.append(ord(nxt))
            index += 1
            continue
        if char == ".":
            labels.append(bytes(current))
            current = bytearray()
            index += 1
            continue
        current.append(ord(char))
        index += 1
    labels.append(bytes(current))
    return labels


def _name_text(value: object) -> str:
    if value is None:
        return "."
    if isinstance(value, str):
        return value
    return str(value)


def _address_bytes(value: object) -> bytes:
    text = str(value).strip()
    try:
        return ipaddress.ip_address(text).packed
    except ValueError as exc:
        raise ValueError(f"unsupported raw dns address: {value!r}") from exc


def _blob(value: object) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, Mapping):
        hex_value = value.get("hex")
        if isinstance(hex_value, str):
            return bytes.fromhex(hex_value)
        raise ValueError(f"raw dns blob object requires hex, got {value!r}")
    if isinstance(value, list):
        return bytes(int(item) & 0xFF for item in value)
    if isinstance(value, str):
        return bytes.fromhex(value)
    raise ValueError(f"expected blob-compatible raw dns value, got {value!r}")


def _as_list(value: object) -> list[object]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.lower() in {"true", "yes", "1", "response"}
    return False


def _int(value: object, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"expected integer-compatible raw dns value, got {value!r}")


def _uint16(value: int) -> bytes:
    return int(value & 0xFFFF).to_bytes(2, "big")


def _uint32(value: int) -> bytes:
    return int(value & 0xFFFFFFFF).to_bytes(4, "big")
