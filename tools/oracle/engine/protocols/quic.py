"""Generator-stage sampler plugin for the QUIC UDP payload layer.

QUIC support in the oracle deliberately mirrors the crate boundary: generate
exact UDP payload bytes for source-backed packet-header cases, bind them to
UDP/4433 in documentation address space, and leave protected payloads opaque.
TLS transcript construction, endpoint state, HTTP/3, and QPACK stay out of the
oracle primitive layer and are represented by contract-only fixture cases.

Relative imports only so the module works under both the ``engine.*`` CLI import
root and the ``tools.oracle.engine.*`` test import root.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import _SamplingContext
from .base import ProtocolSampler, register


QUIC_TEST_PORT = 4433
_SUPPORTED_FIELDS = frozenset({"raw_hex"})

_CID = "8394c8f0"
_SCID = "aa"

# Small, deterministic, source-backed QUIC datagrams. Long-header packet length
# fields include the packet number byte and the opaque protected payload.
_V1_INITIAL = f"c00000000104{_CID}01{_SCID}000301beef"
_V2_INITIAL = f"d06b3343cf04{_CID}01{_SCID}000301beef"
_VERSION_NEGOTIATION = f"c00000000004{_CID}01{_SCID}000000016b3343cf"
_RETRY = f"f00000000104{_CID}01{_SCID}010203000102030405060708090a0b0c0d0e0f"
_HANDSHAKE = f"e00000000104{_CID}01{_SCID}0302cafe"
_ZERO_RTT = f"d00000000104{_CID}01{_SCID}0303cafe"
_DATAGRAM_PAYLOAD = f"c00000000104{_CID}01{_SCID}0006300401020304"
_PROTECTED_RAW = f"c00000000104{_CID}01{_SCID}000501aabbccdd"
_GREASED_FIXED_BIT = f"800000000104{_CID}01{_SCID}000301beef"

_CASE_HEX = {
    "quic-v1-initial": _V1_INITIAL,
    "quic-v2-initial": _V2_INITIAL,
    "quic-version-negotiation": _VERSION_NEGOTIATION,
    "quic-retry": _RETRY,
    "quic-handshake": _HANDSHAKE,
    "quic-zero-rtt": _ZERO_RTT,
    "quic-coalesced-initial-handshake": _V1_INITIAL + _HANDSHAKE,
    "quic-datagram-frame": _DATAGRAM_PAYLOAD,
    "quic-grease-bit": _GREASED_FIXED_BIT,
    "quic-protected-raw": _PROTECTED_RAW,
    "quic-pcap-udp-4433": _V1_INITIAL,
}


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    del domain, field_spec, current_fields
    if field_name == "raw_hex":
        return _raw_hex_for_case(ctx.case)
    raise ValueError(f"spec error: unsupported quic field sampler: {field_name}")


def _raw_hex_for_case(case: str) -> str:
    normalized = case.replace("_", "-")
    return _CASE_HEX.get(normalized, _V1_INITIAL)


def _handles_feature(feature: str) -> bool:
    return feature == "quic_behavior"


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
    if "quic" not in fields:
        fields["quic"] = {}
    fields["quic"]["raw_hex"] = _raw_hex_for_case(case)

    udp = fields.get("udp")
    if isinstance(udp, dict):
        udp.setdefault("src_port", 49152)
        udp["dst_port"] = QUIC_TEST_PORT

    if "ipv4" in fields:
        fields["ipv4"]["src"] = "192.0.2.10"
        fields["ipv4"]["dst"] = "198.51.100.20"
        fields["ipv4"]["protocol"] = "udp"
    if "ipv6" in fields:
        fields["ipv6"]["src"] = "2001:db8::10"
        fields["ipv6"]["dst"] = "2001:db8::20"
        fields["ipv6"]["next_header"] = "udp"
    if "ethernet" in fields:
        fields["ethernet"].setdefault("src", "00:00:5e:00:53:10")
        fields["ethernet"].setdefault("dst", "00:00:5e:00:53:20")


register(
    ProtocolSampler(
        layer="quic",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_behavior,
        handles_feature=_handles_feature,
    )
)
