"""Generator-stage sampler plugins for the simple framing/wrapper layers.

Covers ``payload``, ``null_loopback``, ``linux_cooked`` and ``llc_snap``. These
are small, low-risk wrapper layers. ``payload`` was sampled in-line inside
``generator._sample_field_value`` while the other three had ``_sample_<l>_field``
free functions; this module moves that logic verbatim into one
:class:`~.base.ProtocolSampler` per layer (behavior must stay byte-identical) and
self-registers on import. Only the dispatch moves out of the generator's legacy
if/elif.

The dot11-aware payload helper (``_payload_for_context``) is moved here with the
``payload`` sampler; the ``_dot11_is_management`` predicate it needs stays a shared
sampling primitive (the unmigrated dot11 sampler still uses it) and is imported
from :mod:`..sampling`. ``llc_snap`` also participates in the Wi-Fi stack; only its
generic framing sampling is migrated here, Wi-Fi composition stays with the Wi-Fi
steps.

The EtherType-from-stack routing helper (``_declared_ethertype_for_stack``) is
shared cross-layer stack grammar, so it lives in :mod:`..sampling` and is imported
here rather than duplicated. Relative imports only so the package resolves under
both the ``engine.*`` (CLI) and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping

from ..sampling import (
    _SamplingContext,
    _declared_ethertype_for_stack,
    _dot11_is_management,
)
from .base import ProtocolSampler, register


# Fields each framing layer samples, mirroring the former
# ``generator._SUPPORTED_FIELDS[...]`` entries exactly.
_PAYLOAD_SUPPORTED_FIELDS = frozenset({"hex", "length"})
_NULL_LOOPBACK_SUPPORTED_FIELDS = frozenset({"type"})
_LINUX_COOKED_SUPPORTED_FIELDS = frozenset(
    {"packet_type", "address_type", "address_length", "source_address", "protocol"}
)
_LLC_SNAP_SUPPORTED_FIELDS = frozenset(
    {"control", "dsap", "ethertype", "oui", "payload_length", "ssap"}
)


def _payload_for_context(ctx: _SamplingContext) -> bytes:
    dot11 = ctx.sampled_layers.get("dot11")
    if isinstance(dot11, Mapping):
        frame_control = dot11.get("frame_control")
        if isinstance(frame_control, int) and _dot11_is_management(frame_control):
            return b""
    return ctx.payload


def _sample_payload(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    payload = _payload_for_context(ctx)
    return payload.hex() if field_name == "hex" else len(payload)


def _sample_null_loopback_field(ctx: _SamplingContext, field_name: str) -> object:
    if field_name == "type":
        return "ipv4" if "ipv4" in ctx.stack else "ipv6"
    raise ValueError(f"spec error: unsupported null_loopback field sampler: {field_name}")


def _sample_null_loopback(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    return _sample_null_loopback_field(ctx, field_name)


def _sample_linux_cooked_field(
    ctx: _SamplingContext, field_name: str, domain: object
) -> object:
    if field_name == "packet_type":
        return domain
    if field_name == "address_type":
        return "ethernet"
    if field_name == "address_length":
        return 6
    if field_name == "source_address":
        return {"hex": f"{ctx.src_mac.replace(':', '')}0000"}
    if field_name == "protocol":
        return _declared_ethertype_for_stack(ctx.stack, "linux_cooked")
    raise ValueError(f"spec error: unsupported linux_cooked field sampler: {field_name}")


def _sample_linux_cooked(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    return _sample_linux_cooked_field(ctx, field_name, domain)


def _sample_llc_snap_field(ctx: _SamplingContext, field_name: str) -> object:
    if field_name == "dsap":
        return 0xAA
    if field_name == "ssap":
        return 0xAA
    if field_name == "control":
        return 0x03
    if field_name == "oui":
        return {"hex": "000000"}
    if field_name == "ethertype":
        return _declared_ethertype_for_stack(ctx.stack, "llc_snap")
    if field_name == "payload_length":
        return 0
    raise ValueError(f"spec error: unsupported llc_snap field sampler: {field_name}")


def _sample_llc_snap(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    return _sample_llc_snap_field(ctx, field_name)


register(
    ProtocolSampler(
        layer="payload",
        supported_fields=_PAYLOAD_SUPPORTED_FIELDS,
        sample=_sample_payload,
    )
)

register(
    ProtocolSampler(
        layer="null_loopback",
        supported_fields=_NULL_LOOPBACK_SUPPORTED_FIELDS,
        sample=_sample_null_loopback,
    )
)

register(
    ProtocolSampler(
        layer="linux_cooked",
        supported_fields=_LINUX_COOKED_SUPPORTED_FIELDS,
        sample=_sample_linux_cooked,
    )
)

register(
    ProtocolSampler(
        layer="llc_snap",
        supported_fields=_LLC_SNAP_SUPPORTED_FIELDS,
        sample=_sample_llc_snap,
    )
)
