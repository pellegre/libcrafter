"""Generator-stage sampler plugin for the SCTP layer."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import _SKIP_FIELD, _SamplingContext, _integer_domain_value
from .base import ProtocolSampler, register


_SUPPORTED_FIELDS = frozenset(
    {
        "checksum",
        "chunk_flags",
        "chunks",
        "dst_port",
        "payload_protocol_identifier",
        "src_port",
        "stream_id",
        "stream_sequence",
        "tsn",
        "user_data",
        "verification_tag",
    }
)


def _sample_sctp_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "src_port":
        if domain == "zero_explicit_preserved":
            return 0
        if domain == "boundary":
            return 65535
        return ctx.src_port
    if field_name == "dst_port":
        if domain == "zero_explicit_preserved":
            return 0
        if domain == "boundary":
            return 65535
        return ctx.dst_port
    if field_name == "verification_tag":
        if domain == "zero_init":
            return 0
        if domain == "boundary":
            return 0xFFFFFFFF
        return 0x11223344
    if field_name == "checksum":
        if domain in {"derived_crc32c", "explicit_valid"}:
            return _SKIP_FIELD
        if domain == "explicit_invalid":
            return 0x01020304
        if domain == "explicit_zero":
            return 0
        if domain == "boundary":
            return 0xFFFFFFFF
        return _SKIP_FIELD
    if field_name == "chunks":
        return ["data"]
    if field_name == "chunk_flags":
        if domain == "zero":
            return 0
        if domain == "boundary":
            return 0xFF
        return 0x03
    if field_name == "tsn":
        return 0x01020304
    if field_name == "stream_id":
        return 1
    if field_name == "stream_sequence":
        return 2
    if field_name == "payload_protocol_identifier":
        if domain == "reserved":
            return 0
        if domain == "webrtc_binary":
            return 53
        if domain == "user_defined":
            return 0x80000000
        return 51
    if field_name == "user_data":
        if domain == "empty":
            return {"hex": ""}
        if domain == "binary":
            return {"hex": "00010203"}
        if domain == "padding_boundary":
            return {"hex": "6869"}
        return {"hex": ctx.payload.hex() or "637261667465722d736374702d66697874757265"}
    if field_name in {"tsn", "stream_id", "stream_sequence"}:
        return _integer_domain_value(ctx, domain, field_name, bits=32)
    return _SKIP_FIELD


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    del field_spec, current_fields
    return _sample_sctp_field(ctx, field_name, domain)


def _apply_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None = None,
) -> None:
    del feature, behavior, grammar
    sctp = fields.setdefault("sctp", {})
    sctp.setdefault("chunks", ["data"])
    sctp.setdefault("chunk_flags", 0x03)
    sctp.setdefault("tsn", 0x01020304)
    sctp.setdefault("stream_id", 1)
    sctp.setdefault("stream_sequence", 2)
    sctp.setdefault("payload_protocol_identifier", 51)
    sctp.setdefault("user_data", {"hex": "637261667465722d736374702d66697874757265"})

    if case == "sctp-native-ipv6-data":
        sctp["src_port"] = 49152
        sctp["dst_port"] = 5001
        sctp["verification_tag"] = 0x55667788
        return
    if case == "sctp-udp-encap-data":
        fields.setdefault("udp", {})["src_port"] = 9899
        fields.setdefault("udp", {})["dst_port"] = 9899
        sctp["src_port"] = 5000
        sctp["dst_port"] = 5001
        sctp["verification_tag"] = 0x0A0B0C0D
        return
    sctp["src_port"] = 49152
    sctp["dst_port"] = 5000
    sctp["verification_tag"] = 0x11223344


def _handles_feature(feature: str) -> bool:
    return feature == "sctp_core"


register(
    ProtocolSampler(
        layer="sctp",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_behavior,
        handles_feature=_handles_feature,
    )
)
