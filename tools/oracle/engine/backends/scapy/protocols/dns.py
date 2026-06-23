"""Scapy-stage encode plugin for the DNS layer.

Moves the ``_dns`` (DNS) builder and its full cluster of section/record helpers
(``_dns_questions``, ``_dns_records``, ``_dns_record_a`` / ``_aaaa`` / ``_mx`` /
``_soa`` / ``_srv`` / ``_ds`` / ``_dnskey`` / ``_rrsig`` / ``_nsec`` / ``_nsec3`` /
``_svcb`` / ``_opt`` and the rest), the flag/opcode/rcode/qtype/qclass coercions,
the SvcParam/EDNS option encoders, and the DNS codepoint maps (``_QTYPE_CODES``,
``_QCLASS_CODES``, ``_SVCB_PARAM_KEY_CODES``, ``_DNS_FLAG_NAMES``,
``_DNS_RECORD_BUILDERS``) verbatim out of :mod:`..packets` and registers the
``dns`` layer through the :class:`~.base.ScapyProtocol` contract; only the dispatch
moves out of the legacy ``_build_layer`` if/elif. Behavior must stay byte-identical.

The raw-DNS path (``dns_raw.is_raw_dns_spec`` / ``dns_raw.materialize_raw_dns``) is
unchanged; this module keeps importing :mod:`..dns_raw` for it, exactly as
``packets`` did. ``_dns`` and ``_dns_record_entry`` are re-imported back into
:mod:`..packets` so the existing ``test_dns_backend.py`` references
(``packets._dns`` / ``packets._dns_record_entry``) keep resolving.

DNS decode is the whole-packet ``_normalize_dns_*`` cluster in :mod:`..normalize`;
this plugin therefore carries no ``normalize`` callback (``normalize=None``) and DNS
decode continues through the legacy Scapy normalize path until step 31 co-locates it.

Shared primitives come from the helper modules so this plugin does not depend on the
``packets`` orchestrator (which would create a circular import). Relative imports
only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ....model import JSONObject
from .. import dns_raw
from ..encode_helpers import (
    _bool_int,
    _int,
    _layer_fields,
    _optional_field,
    _text,
)
from .base import ScapyProtocol, register


# Encode-side field allowlist for ``_validate_layer_fields`` — the canonical field
# names plus every Scapy/oracle alias the DNS builder accepts. Mirrors the former
# ``packets._SUPPORTED_FIELDS_BY_LAYER["dns"]`` entry exactly.
_SUPPORTED_FIELDS = frozenset(
    {
        "additional",
        "answers",
        "authority",
        "dns_raw",
        "flags",
        "id",
        "is_response",
        "opcode",
        "qname",
        "qtype",
        "questions",
        "query",
        "response_code",
        "transaction_id",
    }
)


# ---------------------------------------------------------------------------
# Encode
# ---------------------------------------------------------------------------


def _build(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    return _dns(fields, scapy_all)


def _dns(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    dns_fields = _layer_fields(fields, "dns")
    raw_spec = dns_fields.get("dns_raw")
    if dns_raw.is_raw_dns_spec(raw_spec):
        return dns_raw.materialize_raw_dns(raw_spec, scapy_all)
    questions_value = dns_fields.get("questions")
    flags = _dns_flags(_optional_field(dns_fields, "flags"))
    questions = _dns_questions(dns_fields, scapy_all)
    if questions is None:
        questions = _dns_default_question(dns_fields, scapy_all)
    answers = _dns_records(dns_fields.get("answers"), scapy_all)
    authority = _dns_records(dns_fields.get("authority"), scapy_all)
    additional = _dns_records(dns_fields.get("additional"), scapy_all)
    return scapy_all.DNS(
        id=_int(_optional_field(dns_fields, "transaction_id", "id"), 0),
        qr=_bool_int(_optional_field(dns_fields, "is_response"), 0),
        opcode=_dns_opcode(_optional_field(dns_fields, "opcode")),
        qdcount=_dns_count(questions_value, 1),
        ancount=_dns_count(dns_fields.get("answers"), 0),
        nscount=_dns_count(dns_fields.get("authority"), 0),
        arcount=_dns_count(dns_fields.get("additional"), 0),
        aa=flags["aa"],
        tc=flags["tc"],
        rd=flags["rd"],
        ra=flags["ra"],
        ad=flags["ad"],
        cd=flags["cd"],
        z=flags["z"],
        rcode=_dns_response_code(_optional_field(dns_fields, "response_code")),
        qd=questions,
        an=answers,
        ns=authority,
        ar=additional,
    )


def _dns_default_question(dns_fields: Mapping[str, object], scapy_all: Any) -> Any:
    question = _first_question(dns_fields)
    qname = _dns_normalized_name(_text(question.get("qname"), "example.com."))
    return scapy_all.DNSQR(
        qname=qname,
        qtype=_dns_qtype(question.get("qtype", dns_fields.get("qtype"))),
    )


def _dns_opcode(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        aliases = {
            "query": 0,
            "iquery": 1,
            "inverse-query": 1,
            "status": 2,
            "notify": 4,
            "update": 5,
        }
        if lowered in aliases:
            return aliases[lowered]
        if lowered == "unknown":
            return 14
        return int(lowered, 0)
    return _int(value, 0)


def _dns_response_code(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        aliases = {
            "no-error": 0,
            "format-error": 1,
            "server-failure": 2,
            "name-error": 3,
            "nxdomain": 3,
            "not-implemented": 4,
            "refused": 5,
        }
        if lowered in aliases:
            return aliases[lowered]
        if lowered == "unknown":
            return 11
        return int(lowered, 0)
    return _int(value, 0)


def _dns_flags(value: object) -> dict[str, int]:
    flags = {"aa": 0, "tc": 0, "rd": 1, "ra": 0, "ad": 0, "cd": 0, "z": 0}
    if value is None:
        return flags
    if isinstance(value, Mapping):
        return _dns_flags_mapping(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return _dns_flags_word(value)
    values = value if isinstance(value, list) else [value]
    flags = {"aa": 0, "tc": 0, "rd": 0, "ra": 0, "ad": 0, "cd": 0, "z": 0}
    for item in values:
        if isinstance(item, int) and not isinstance(item, bool):
            return _dns_flags_word(item)
        if not isinstance(item, str):
            continue
        lowered = item.lower().replace("-", "_")
        if lowered in {"raw", "reserved_z", "z"}:
            flags["z"] = 1
        elif lowered in _DNS_FLAG_NAMES:
            flags[_DNS_FLAG_NAMES[lowered]] = 1
    return flags


def _dns_flags_mapping(value: Mapping[str, object]) -> dict[str, int]:
    flags = {"aa": 0, "tc": 0, "rd": 0, "ra": 0, "ad": 0, "cd": 0, "z": 0}
    for name, slot in {
        "authoritative": "aa",
        "aa": "aa",
        "truncated": "tc",
        "tc": "tc",
        "recursion_desired": "rd",
        "rd": "rd",
        "recursion_available": "ra",
        "ra": "ra",
        "authentic_data": "ad",
        "ad": "ad",
        "checking_disabled": "cd",
        "cd": "cd",
        "reserved_z": "z",
        "z": "z",
    }.items():
        if name in value:
            flags[slot] = _bool_int(value[name], 0)
    return flags


def _dns_flags_word(value: int) -> dict[str, int]:
    return {
        "aa": (value >> 10) & 0x1,
        "tc": (value >> 9) & 0x1,
        "rd": (value >> 8) & 0x1,
        "ra": (value >> 7) & 0x1,
        "z": (value >> 6) & 0x1,
        "ad": (value >> 5) & 0x1,
        "cd": (value >> 4) & 0x1,
    }


_DNS_FLAG_NAMES: dict[str, str] = {
    "authoritative": "aa",
    "truncated": "tc",
    "recursion_desired": "rd",
    "recursion_available": "ra",
    "authentic_data": "ad",
    "checking_disabled": "cd",
}


def _dns_normalized_name(value: object) -> str:
    name = _text(value, "")
    if name in {"", "."}:
        return "."
    if not name.endswith("."):
        return f"{name}."
    return name


# QTYPE/QCLASS codepoint maps used to feed Scapy unambiguous numeric values.
#
# Scapy's DNSQR qtype/qclass enums use their own spellings (for example CHAOS
# rather than CH) and omit several IANA names (such as QCLASS NONE), so passing
# a canonical IANA name string can raise a KeyError. Resolving the canonical
# name to its numeric codepoint here keeps Scapy as the reference encoder while
# accepting the same symbolic names libcrafter uses. The maps reuse the raw
# helper's code tables; QTYPE ANY (the query-only meta-type) shares codepoint
# 255 with QCLASS ANY and is added explicitly.
_QTYPE_CODES: dict[str, int] = {**dns_raw._TYPE_CODES, "ANY": 255}
_QCLASS_CODES: dict[str, int] = dict(dns_raw._CLASS_CODES)


def _dns_qtype(value: object) -> object:
    if value is None:
        return "A"
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
        return _QTYPE_CODES.get(text.upper(), text.upper())
    return _text(value, "A")


def _dns_qclass(value: object) -> object:
    if value is None:
        return "IN"
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
        return _QCLASS_CODES.get(text.upper(), text.upper())
    return "IN"


def _first_question(dns_fields: Mapping[str, object]) -> JSONObject:
    questions = dns_fields.get("questions")
    if isinstance(questions, list) and questions:
        first = questions[0]
        if isinstance(first, Mapping):
            return dict(first)  # type: ignore[arg-type, return-value]
        if isinstance(first, str):
            return {"qname": first}
    return {}


def _dns_questions(dns_fields: Mapping[str, object], scapy_all: Any) -> object | None:
    questions = dns_fields.get("questions")
    if not isinstance(questions, list) or not questions:
        return None
    chain = None
    for question in questions:
        if isinstance(question, Mapping):
            qname = _dns_normalized_name(question.get("qname", question.get("name")))
            qtype = _dns_qtype(question.get("qtype", question.get("type")))
            qclass = _dns_qclass(question.get("qclass", question.get("record_class")))
        else:
            qname = _dns_normalized_name(question)
            qtype = "A"
            qclass = "IN"
        entry = scapy_all.DNSQR(qname=qname, qtype=qtype, qclass=qclass)
        chain = entry if chain is None else chain / entry
    return chain


def _dns_records(value: object, scapy_all: Any) -> object | None:
    if not isinstance(value, list) or not value:
        return None
    chain = None
    for record in value:
        if not isinstance(record, Mapping):
            continue
        entry = _dns_record_entry(record, scapy_all)
        chain = entry if chain is None else chain / entry
    return chain


def _dns_record_entry(record: Mapping[str, object], scapy_all: Any) -> Any:
    rr_type = _dns_record_type_token(record)
    name = _dns_normalized_name(record.get("name", record.get("rrname")))
    ttl = _int(record.get("ttl"), 60)
    builder = _DNS_RECORD_BUILDERS.get(rr_type)
    if builder is not None:
        return builder(record, scapy_all, name=name, ttl=ttl)
    if rr_type == "OPT":
        return _dns_record_opt(record, scapy_all, name=name, ttl=ttl)
    return _dns_record_raw(record, scapy_all, name=name, ttl=ttl, rr_type=rr_type)


def _dns_record_type_token(record: Mapping[str, object]) -> str:
    raw = record.get("type", record.get("record_type"))
    if isinstance(raw, int) and not isinstance(raw, bool):
        return str(raw)
    text = _text(raw, "A").strip()
    if text.isdigit():
        return text
    return text.upper()


def _dns_record_class(value: object) -> object:
    if value is None:
        return "IN"
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    text = _text(value, "IN").strip()
    if text.isdigit():
        return int(text)
    return text.upper()


def _dns_rr_common(record: Mapping[str, object], *, name: str, ttl: int) -> dict[str, Any]:
    return {
        "rrname": name,
        "ttl": ttl,
        "rclass": _dns_record_class(record.get("record_class", record.get("rclass"))),
    }


def _dns_record_a(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    address = _text(record.get("address", record.get("rdata")), "192.0.2.53")
    return scapy_all.DNSRR(type="A", rdata=address, **_dns_rr_common(record, name=name, ttl=ttl))


def _dns_record_aaaa(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    address = _text(record.get("address", record.get("rdata")), "2001:db8::53")
    return scapy_all.DNSRR(type="AAAA", rdata=address, **_dns_rr_common(record, name=name, ttl=ttl))


def _dns_record_name_target(
    rr_type: str,
    default: str,
) -> Any:
    def builder(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
        target = _dns_normalized_name(
            record.get("target", record.get("rdata", default)),
        )
        return scapy_all.DNSRR(
            type=rr_type,
            rdata=target,
            **_dns_rr_common(record, name=name, ttl=ttl),
        )

    return builder


def _dns_record_mx(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    return scapy_all.DNSRRMX(
        preference=_int(record.get("preference"), 10),
        exchange=_dns_normalized_name(record.get("exchange", record.get("target"))),
        **_dns_rr_common(record, name=name, ttl=ttl),
    )


def _dns_record_txt(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    strings = record.get("strings", record.get("rdata"))
    if isinstance(strings, list):
        rdata = [_dns_text_string(item) for item in strings]
    elif strings is None:
        rdata = [b""]
    else:
        rdata = [_dns_text_string(strings)]
    return scapy_all.DNSRR(type="TXT", rdata=rdata, **_dns_rr_common(record, name=name, ttl=ttl))


def _dns_record_soa(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    return scapy_all.DNSRRSOA(
        mname=_dns_normalized_name(record.get("primary_name", record.get("mname"))),
        rname=_dns_normalized_name(record.get("responsible_name", record.get("rname"))),
        serial=_int(record.get("serial"), 0),
        refresh=_int(record.get("refresh"), 0),
        retry=_int(record.get("retry"), 0),
        expire=_int(record.get("expire"), 0),
        minimum=_int(record.get("minimum"), 0),
        **_dns_rr_common(record, name=name, ttl=ttl),
    )


def _dns_record_srv(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    return scapy_all.DNSRRSRV(
        priority=_int(record.get("priority"), 0),
        weight=_int(record.get("weight"), 0),
        port=_int(record.get("port"), 0),
        target=_dns_normalized_name(record.get("target")),
        **_dns_rr_common(record, name=name, ttl=ttl),
    )


def _dns_record_ds(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    return scapy_all.DNSRRDS(
        keytag=_int(record.get("key_tag", record.get("keytag")), 0),
        algorithm=_int(record.get("algorithm"), 0),
        digesttype=_int(record.get("digest_type", record.get("digesttype")), 0),
        digest=_dns_blob(record.get("digest")),
        **_dns_rr_common(record, name=name, ttl=ttl),
    )


def _dns_record_dnskey(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    return scapy_all.DNSRRDNSKEY(
        flags=_int(record.get("flags"), 0),
        protocol=_int(record.get("protocol"), 3),
        algorithm=_int(record.get("algorithm"), 0),
        publickey=_dns_blob(record.get("public_key", record.get("publickey"))),
        **_dns_rr_common(record, name=name, ttl=ttl),
    )


def _dns_record_rrsig(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    return scapy_all.DNSRRRSIG(
        typecovered=_dns_qtype(record.get("type_covered", record.get("typecovered"))),
        algorithm=_int(record.get("algorithm"), 0),
        labels=_int(record.get("labels"), 0),
        originalttl=_int(record.get("original_ttl", record.get("originalttl")), 0),
        expiration=_int(record.get("signature_expiration", record.get("expiration")), 0),
        inception=_int(record.get("signature_inception", record.get("inception")), 0),
        keytag=_int(record.get("key_tag", record.get("keytag")), 0),
        signersname=_dns_normalized_name(record.get("signer_name", record.get("signersname"))),
        signature=_dns_blob(record.get("signature")),
        **_dns_rr_common(record, name=name, ttl=ttl),
    )


def _dns_record_nsec(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    return scapy_all.DNSRRNSEC(
        nextname=_dns_normalized_name(record.get("next_name", record.get("nextname"))),
        typebitmaps=_dns_type_bitmaps(
            record.get("type_bitmaps", record.get("typebitmaps")), scapy_all
        ),
        **_dns_rr_common(record, name=name, ttl=ttl),
    )


def _dns_record_nsec3(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    # Scapy 2.7's DNSRRNSEC3 FieldLenField does not reliably auto-compute the
    # Salt Length / Hash Length octets from a raw bytes salt or next hashed
    # owner name, so the length prefixes are passed explicitly. Both fields stay
    # raw bytes (RFC 5155 Section 3.2), never reinterpreted as text.
    salt = _dns_blob(record.get("salt"))
    next_hashed_owner = _dns_blob(
        record.get("next_hashed_owner", record.get("nexthashedownername"))
    )
    return scapy_all.DNSRRNSEC3(
        hashalg=_int(record.get("hash_algorithm", record.get("hashalg")), 1),
        flags=_int(record.get("flags"), 0),
        iterations=_int(record.get("iterations"), 0),
        saltlength=len(salt),
        salt=salt,
        hashlength=len(next_hashed_owner),
        nexthashedownername=next_hashed_owner,
        typebitmaps=_dns_type_bitmaps(
            record.get("type_bitmaps", record.get("typebitmaps")), scapy_all
        ),
        **_dns_rr_common(record, name=name, ttl=ttl),
    )


def _dns_record_svcb(rr_type: str) -> Any:
    def builder(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
        # Scapy's high-level DNSRRSVCB/DNSRRHTTPS SvcParam field re-interprets and
        # re-encodes the per-key SvcParamValue (for example it length-prefixes the
        # alpn id list and rejects raw port/ipvNhint bytes), so it cannot carry the
        # SvcParamValue verbatim the way libcrafter and the wire format require.
        # The oracle contract compares SvcParam values as opaque bytes, so this
        # builder owns the exact RDATA octets and hands them to Scapy as a generic
        # DNSRR (TYPE 64/65) whose rdata is preserved verbatim. Scapy still
        # re-dissects the bytes as SVCB/HTTPS on decode; the byte image is the
        # reference boundary either way.
        rdata = _dns_svcb_rdata_bytes(record)
        return scapy_all.DNSRR(
            type=_dns_record_type_int(rr_type),
            rdata=rdata,
            **_dns_rr_common(record, name=name, ttl=ttl),
        )

    return builder


def _dns_svcb_rdata_bytes(record: Mapping[str, object]) -> bytes:
    """Build SVCB/HTTPS RDATA verbatim: SvcPriority, uncompressed TargetName, then
    SvcParams in strictly increasing SvcParamKey order with opaque values.

    The TargetName is uncompressed (RFC 9460 Section 2.2) and may be the root
    name ``.``. Each SvcParam is a {SvcParamKey, length, value} tuple whose value
    bytes are carried exactly as given so the encoding matches libcrafter's
    byte-for-byte. Params are sorted by ascending key to mirror the libcrafter
    SvcParams ordering rule.
    """

    priority = _int(record.get("priority", record.get("svc_priority")), 0)
    target = dns_raw.dns_name_bytes(record.get("target", record.get("target_name")))
    params = _dns_svcb_param_tuples(record.get("params", record.get("svc_params")))
    params.sort(key=lambda pair: pair[0])
    body = bytearray()
    body += int(priority & 0xFFFF).to_bytes(2, "big")
    body += target
    for key, value in params:
        body += int(key & 0xFFFF).to_bytes(2, "big")
        body += int(len(value) & 0xFFFF).to_bytes(2, "big")
        body += value
    return bytes(body)


def _dns_svcb_param_tuples(value: object) -> list[tuple[int, bytes]]:
    if not isinstance(value, list):
        return []
    params: list[tuple[int, bytes]] = []
    for param in value:
        if not isinstance(param, Mapping):
            continue
        key = _dns_svc_param_key_code(param.get("key"))
        param_value = _dns_blob(param.get("value"))
        params.append((key, param_value))
    return params


def _dns_svc_param_key_code(value: object) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    text = _text(value, "0").strip()
    if text.isdigit():
        return int(text)
    lowered = text.lower().replace("_", "-")
    code = _SVCB_PARAM_KEY_CODES.get(lowered)
    if code is not None:
        return code
    return int(text, 0)


# SvcParamKey mnemonic -> numeric codepoint (IANA DNS SVCB SvcParamKeys, RFC
# 9460 / RFC 9461). Mirrors the libcrafter dns_svc_param_key mapping so a case
# may give either a named or a numeric key.
_SVCB_PARAM_KEY_CODES: dict[str, int] = {
    "mandatory": 0,
    "alpn": 1,
    "no-default-alpn": 2,
    "port": 3,
    "ipv4hint": 4,
    "ech": 5,
    "ipv6hint": 6,
    "dohpath": 7,
}


def _dns_record_opt(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    rclass = _int(record.get("udp_payload_size", record.get("rclass")), 4096)
    extrcode = _int(record.get("extended_rcode", record.get("extrcode")), 0)
    version = _int(record.get("version"), 0)
    z = 0x8000 if _bool_int(record.get("dnssec_ok"), 0) else 0
    z |= _int(record.get("z_bits", record.get("z")), 0) & 0x7FFF
    return scapy_all.DNSRROPT(
        rrname=_dns_normalized_name(record.get("name", record.get("rrname", "."))),
        rclass=rclass,
        extrcode=extrcode,
        version=version,
        z=z,
        rdata=_dns_edns_options(record.get("options"), scapy_all),
    )


def _dns_record_raw(
    record: Mapping[str, object],
    scapy_all: Any,
    *,
    name: str,
    ttl: int,
    rr_type: str,
) -> Any:
    rdata = _dns_blob(record.get("data", record.get("rdata")))
    return scapy_all.DNSRR(
        type=_dns_record_type_int(rr_type),
        rdata=rdata,
        **_dns_rr_common(record, name=name, ttl=ttl),
    )


def _dns_record_type_int(rr_type: str) -> object:
    if rr_type.isdigit():
        return int(rr_type)
    return rr_type


def _dns_text_string(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, Mapping):
        hex_value = value.get("hex")
        if isinstance(hex_value, str):
            return bytes.fromhex(hex_value)
    return _text(value, "").encode("utf-8")


def _dns_blob(value: object) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, Mapping):
        hex_value = value.get("hex")
        if isinstance(hex_value, str):
            return bytes.fromhex(hex_value)
        raise ValueError(f"dns blob object requires hex, got {value!r}")
    if isinstance(value, str):
        return bytes.fromhex(value)
    raise ValueError(f"expected blob-compatible dns value, got {value!r}")


def _dns_type_bitmaps(value: object, scapy_all: Any) -> list[int]:
    if value is None:
        return []
    record_types = value
    if isinstance(value, Mapping):
        record_types = value.get("record_types", [])
    if not isinstance(record_types, list):
        return []
    return [_dns_type_code(item, scapy_all) for item in record_types]


def _dns_type_code(value: object, scapy_all: Any) -> int:
    if isinstance(value, bool):
        raise ValueError(f"dns type bitmap entry must not be a boolean: {value!r}")
    if isinstance(value, int):
        return value
    text = _text(value, "").strip()
    if text.isdigit():
        return int(text)
    reverse = _dns_type_name_to_code(scapy_all)
    code = reverse.get(text.upper())
    if code is None:
        raise ValueError(f"unsupported dns type bitmap entry: {value!r}")
    return code


def _dns_type_name_to_code(scapy_all: Any) -> dict[str, int]:
    from scapy.layers import dns as scapy_dns  # type: ignore[import-untyped]

    return {name: code for code, name in scapy_dns.dnstypes.items()}


def _dns_edns_options(value: object, scapy_all: Any) -> list[object]:
    if not isinstance(value, list):
        return []
    options: list[object] = []
    for option in value:
        if not isinstance(option, Mapping):
            continue
        optcode = _int(option.get("option_code", option.get("optcode")), 0)
        optdata = _dns_blob(option.get("option_data", option.get("optdata")))
        options.append(scapy_all.EDNS0TLV(optcode=optcode, optdata=optdata))
    return options


def _dns_svc_params(value: object, scapy_all: Any) -> list[object]:
    if not isinstance(value, list):
        return []
    params: list[object] = []
    for param in value:
        if not isinstance(param, Mapping):
            continue
        key = _dns_svc_param_key(param.get("key"))
        param_value = _dns_blob(param.get("value"))
        params.append(scapy_all.SvcParam(key=key, value=param_value))
    return params


def _dns_svc_param_key(value: object) -> object:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    text = _text(value, "0").strip()
    if text.isdigit():
        return int(text)
    return text


_DNS_RECORD_BUILDERS: dict[str, Any] = {
    "A": _dns_record_a,
    "AAAA": _dns_record_aaaa,
    "NS": _dns_record_name_target("NS", "ns.example.com."),
    "CNAME": _dns_record_name_target("CNAME", "alias.example.com."),
    "PTR": _dns_record_name_target("PTR", "host.example.com."),
    "MX": _dns_record_mx,
    "TXT": _dns_record_txt,
    "SOA": _dns_record_soa,
    "SRV": _dns_record_srv,
    "DS": _dns_record_ds,
    "DNSKEY": _dns_record_dnskey,
    "RRSIG": _dns_record_rrsig,
    "NSEC": _dns_record_nsec,
    "NSEC3": _dns_record_nsec3,
    "SVCB": _dns_record_svcb("SVCB"),
    "HTTPS": _dns_record_svcb("HTTPS"),
}


def _dns_count(value: object, default: int) -> int:
    if isinstance(value, list):
        return len(value)
    return default


register(
    ScapyProtocol(
        layer="dns",
        scapy_class="DNS",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
        normalize=None,
    )
)
