"""Generator-stage sampler plugins for the IEEE 802.15.4 / Zigbee layers.

Owns the four spec layers of the 802.15.4 family — ``dot15d4`` (MAC frame),
``dot15d4_radio`` (the IEEE 802.15.4 TAP / DLT 283 pseudo-header), ``zigbee_nwk``
(Zigbee NWK), and ``zigbee_aps`` (Zigbee APS) — mirroring how the crate groups the
Zigbee sublayers under ``protocols/link/dot15d4``. Each layer registers a
:class:`~.base.ProtocolSampler` whose ``supported_fields`` mirrors the former
``generator._SUPPORTED_FIELDS`` entry and whose ``sample`` reproduces the legacy
per-field sampler verbatim.

The MAC is sampled as an addressed (short-16, PAN-ID compressed) data frame so
scapy's Dot15d4FCS dissector dispatches the MAC payload into ZigbeeNWK ->
ZigbeeAppDataPayload (``conf.dot15d4_protocol="zigbee"``), producing the same layer
structure libcrafter decodes. The values mirror the
``zigbee-mac-nwk-aps-data-stack`` spec case so the materialized frame is a real,
decodable Zigbee data stack rather than a degenerate default frame.

``dot15d4_radio`` samples no fields: the IEEE 802.15.4 TAP pseudo-header carries no
strict-byte descriptor fields through the scapy reference path (libcrafter owns the
TAP decode), so its ``supported_fields`` is empty and its ``sample`` is unreachable
— the same behavior-driven shape as the BLE / IGMP samplers. None of these layers
carries a Python feature ``apply_behavior`` (their feature values, where any, flow
through the generic feature-fields mechanism), so the plugins register no
``apply_behavior`` / ``handles_feature``.

Relative imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping

from ..sampling import _SamplingContext
from .base import ProtocolSampler, register


# Per-layer field allowlists, mirroring the former ``generator._SUPPORTED_FIELDS``
# entries. Each is a subset of the layer's declared spec fields; the remaining spec
# fields are generator-auto-filled (fcs), header-only, or behavior-driven and are
# not sampled directly.
_DOT15D4_SUPPORTED_FIELDS = frozenset(
    {
        "frame_type",
        "pan_id_compression",
        "dest_addr_mode",
        "src_addr_mode",
        "seq",
        "dest_pan",
        "dest_addr",
        "src_addr",
    }
)
# The IEEE 802.15.4 TAP (DLT 283) pseudo-header carries no strict-byte descriptor
# fields through the scapy reference path; libcrafter owns the TAP decode, so no
# fields are sampled (an empty allowlist, like the behavior-driven BLE/IGMP layers).
_DOT15D4_RADIO_SUPPORTED_FIELDS: frozenset[str] = frozenset()
_ZIGBEE_NWK_SUPPORTED_FIELDS = frozenset(
    {
        "frame_type",
        "protocol_version",
        "dest",
        "src",
        "radius",
        "seq",
    }
)
_ZIGBEE_APS_SUPPORTED_FIELDS = frozenset(
    {
        "frame_type",
        "delivery_mode",
        "dest_endpoint",
        "cluster",
        "profile",
        "src_endpoint",
        "counter",
    }
)


def _sample_dot15d4(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    if field_name == "frame_type":
        return "data"
    if field_name == "pan_id_compression":
        return True
    if field_name == "dest_addr_mode":
        return "short_16"
    if field_name == "src_addr_mode":
        return "short_16"
    if field_name == "seq":
        return 0x07
    if field_name == "dest_pan":
        return 0x1234
    if field_name == "dest_addr":
        return 0x0000
    if field_name == "src_addr":
        return 0xABCD
    raise ValueError(f"spec error: unsupported dot15d4 field sampler: {field_name}")


def _sample_dot15d4_radio(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Unreachable dot15d4_radio field sampler.

    ``dot15d4_radio`` declares an empty ``supported_fields`` set, so
    ``_sample_layer_fields`` skips every TAP field and never calls this adapter. It
    exists only to satisfy the :class:`ProtocolSampler` contract (``sample`` is
    required).
    """

    raise ValueError(
        f"spec error: unsupported dot15d4_radio field sampler: {field_name}"
    )


def _sample_zigbee_nwk(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    if field_name == "frame_type":
        return "data"
    if field_name == "protocol_version":
        return 2
    if field_name == "dest":
        return 0x0000
    if field_name == "src":
        return 0xABCD
    if field_name == "radius":
        return 30
    if field_name == "seq":
        return 0x42
    raise ValueError(f"spec error: unsupported zigbee_nwk field sampler: {field_name}")


def _sample_zigbee_aps(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    if field_name == "frame_type":
        return "data"
    if field_name == "delivery_mode":
        return "unicast"
    if field_name == "dest_endpoint":
        return 0x01
    if field_name == "cluster":
        return 0x0006
    if field_name == "profile":
        return 0x0104
    if field_name == "src_endpoint":
        return 0x01
    if field_name == "counter":
        return 0x09
    raise ValueError(f"spec error: unsupported zigbee_aps field sampler: {field_name}")


register(
    ProtocolSampler(
        layer="dot15d4",
        supported_fields=_DOT15D4_SUPPORTED_FIELDS,
        sample=_sample_dot15d4,
    )
)
register(
    ProtocolSampler(
        layer="dot15d4_radio",
        supported_fields=_DOT15D4_RADIO_SUPPORTED_FIELDS,
        sample=_sample_dot15d4_radio,
    )
)
register(
    ProtocolSampler(
        layer="zigbee_nwk",
        supported_fields=_ZIGBEE_NWK_SUPPORTED_FIELDS,
        sample=_sample_zigbee_nwk,
    )
)
register(
    ProtocolSampler(
        layer="zigbee_aps",
        supported_fields=_ZIGBEE_APS_SUPPORTED_FIELDS,
        sample=_sample_zigbee_aps,
    )
)
