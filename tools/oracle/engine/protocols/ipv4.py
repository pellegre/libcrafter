"""Generator-stage sampler plugin for the IPv4 layer.

Moves the ``_sample_ipv4_field`` sampler, its address/protocol/options helpers,
and the ``ipv4_options`` feature behavior out of :mod:`generator` and registers
them through the uniform :class:`~.base.ProtocolSampler` contract. The sampling
and behavior logic is moved verbatim (behavior must stay byte-identical); only the
dispatch moves from the generator's legacy if/elif into this self-contained
module, which self-registers on import.

IPv4 is the first migrated layer with a feature behavior: ``apply_behavior``
reproduces the legacy ``ipv4_options`` branch of ``_apply_feature_behavior`` and
``handles_feature`` claims ownership of the ``"ipv4_options"`` feature name, so the
generator's registry-first feature loop runs it exactly once.

Shared primitives (``_is_ipv4_root_dhcp_stack``, ``_next_layer_after``) live in
:mod:`..sampling` because they are cross-layer stack grammar still used by other
(unmigrated) layers; they are imported here rather than duplicated. Relative
imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import (
    _SamplingContext,
    _integer_domain_value,
    _is_ipv4_root_dhcp_stack,
    _next_layer_after,
)
from .base import ProtocolSampler, register


# IPv4 fields the generator samples, mirroring the former
# ``generator._SUPPORTED_FIELDS["ipv4"]`` entry.
_SUPPORTED_FIELDS = frozenset(
    {
        "ds_field",
        "src",
        "dst",
        "ttl",
        "protocol",
        "identification",
        "flags",
        "fragment_offset",
        "options",
    }
)


def _ipv4_for_domain(
    ctx: _SamplingContext, domain: object, default: str, *, dst: bool
) -> str:
    if domain == "zero":
        return "0.0.0.0"
    if domain == "broadcast" and dst:
        if _is_ipv4_root_dhcp_stack(ctx.stack):
            return default
        return "255.255.255.255"
    return default


def _ipv4_protocol_for_stack(stack: Sequence[str]) -> str:
    next_layer = _next_layer_after(stack, "ipv4")
    if next_layer in {"icmp", "tcp", "udp"}:
        return next_layer
    return "unknown"


def _ipv4_options_hex(case: str, behavior: str) -> str:
    key = f"{case} {behavior}".replace("_", "-")
    if "source-route" in key:
        return "830704c0000201"
    if "record-route" in key:
        return "07070400000000"
    if "timestamp" in key or "traceroute" in key or "generic" in key:
        return "440c05000000000000000000120c00010000ffffc0000201"
    if "nop" in key:
        return "01010101"
    return "00000000"


def _sample_ipv4_field(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    current_fields: Mapping[str, object],
) -> object:
    if field_name == "src":
        return _ipv4_for_domain(ctx, domain, ctx.src_ipv4, dst=False)
    if field_name == "dst":
        return _ipv4_for_domain(ctx, domain, ctx.dst_ipv4, dst=True)
    if field_name == "ds_field":
        if "boundary-fields" in ctx.case:
            return 0xFF
        if domain == "dscp_ef_ecn_not_ect":
            return 0b10111000
        if domain == "dscp_cs5_ecn_ect0":
            return 0b10100010
        return _integer_domain_value(ctx, domain, field_name, bits=8)
    if field_name == "ttl":
        if "ttl-255" in ctx.case:
            return 255
        return _integer_domain_value(ctx, domain, field_name, bits=8)
    if field_name == "protocol":
        return _ipv4_protocol_for_stack(ctx.stack)
    if field_name == "identification":
        return _integer_domain_value(ctx, domain, field_name, bits=16)
    if field_name == "flags":
        if "fragment-mf-offset" in ctx.case:
            return "mf"
        if any(layer in ctx.stack for layer in ("tcp", "udp", "icmp", "dns", "dhcp")):
            return "none"
        # ESP/AH/IKEv2 datagrams are never carried as IP fragments in the oracle
        # corpus: libcrafter (correctly) leaves a non-first fragment body opaque
        # and does not dispatch the inner protocol on a fragment, while Scapy
        # binds the IP protocol number regardless of fragmentation. Pin the outer
        # (and inner tunnel) IP to non-fragmented so both backends dissect the
        # ESP/AH/IKEv2 layer and the decoded models agree.
        if any(layer in ctx.stack for layer in ("esp", "ah", "ikev2")):
            return "none"
        if ctx.profile == "smoke":
            return "none"
        return str(domain)
    if field_name == "fragment_offset":
        if "fragment-mf-offset" in ctx.case:
            return 1
        if any(layer in ctx.stack for layer in ("tcp", "udp", "icmp", "dns", "dhcp")):
            return 0
        if any(layer in ctx.stack for layer in ("esp", "ah", "ikev2")):
            return 0
        if domain == "non_initial":
            return 1
        if current_fields.get("flags") == "mf":
            return _integer_domain_value(ctx, domain, field_name, bits=13)
        return 0
    if field_name == "options":
        return {"hex": _ipv4_options_hex(ctx.case, str(domain))}
    raise ValueError(f"spec error: unsupported ipv4 field sampler: {field_name}")


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter: IPv4 reads ``current_fields`` (flags -> offset)."""

    return _sample_ipv4_field(ctx, field_name, domain, current_fields)


def _apply_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None = None,
) -> None:
    """Apply the ``ipv4_options`` feature behavior to the sampled IPv4 fields.

    Byte-identical to the legacy ``ipv4_options`` branch of
    ``generator._apply_feature_behavior``: it pins the IPv4 options hex for the
    selected case/behavior and forces non-fragmented IPv4 so the options carry on
    the first (and only) fragment. ``grammar`` is part of the uniform
    ``apply_behavior`` call path (the TCP ``tcp_header`` behavior reads it); IPv4
    does not consult it.
    """

    if "ipv4" in fields:
        fields["ipv4"]["options"] = {"hex": _ipv4_options_hex(case, behavior)}
        fields["ipv4"]["flags"] = "none"
        fields["ipv4"]["fragment_offset"] = 0


def _handles_feature(feature: str) -> bool:
    return feature == "ipv4_options"


register(
    ProtocolSampler(
        layer="ipv4",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_behavior,
        handles_feature=_handles_feature,
    )
)
