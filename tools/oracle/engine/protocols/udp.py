"""Generator-stage sampler plugin for the UDP layer.

Moves the ``_sample_udp_field`` sampler and the ``udp_options`` feature behavior
(``_apply_udp_options_behavior``) out of :mod:`generator` and registers them
through the uniform :class:`~.base.ProtocolSampler` contract. The sampling and
behavior logic is moved verbatim (behavior must stay byte-identical); only the
dispatch moves from the generator's legacy if/elif into this self-contained
module, which self-registers on import.

UDP carries a feature behavior like IPv4: ``apply_behavior`` reproduces the legacy
``udp_options`` branch of ``_apply_feature_behavior`` and ``handles_feature``
claims ownership of the ``"udp_options"`` feature name, so the generator's
registry-first feature loop runs it exactly once.

The UDP source/destination port defaults are stack-aware (DHCP 68/67, DNS
ephemeral/53, RIP 520, RIPng 521); that resolution is preserved exactly. The
RIP/RIPng *cross-layer* UDP writes live in those protocols' own behavior plugins
(later steps), so this module does not special-case them beyond the port
defaulting the sampler already did.

Shared primitives (``_SamplingContext``, ``_integer_domain_value``,
``ephemeral_port``, ``_SKIP_FIELD``) and the UDP surplus-options intent helpers
(``_udp_options_field``, ``_payload_hex_from_fields``) live in :mod:`..sampling`
because they are also consumed by the still-in-``generator`` ``udp_options``
metadata/feature-tag emitters; they are imported here rather than duplicated.
Relative imports only so the package resolves under both the ``engine.*`` (CLI)
and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import (
    _SKIP_FIELD,
    _SamplingContext,
    _integer_domain_value,
    _payload_hex_from_fields,
    _udp_options_field,
    ephemeral_port,
)
from .base import ProtocolSampler, register


# UDP fields the generator samples, mirroring the former
# ``generator._SUPPORTED_FIELDS["udp"]`` entry.
_SUPPORTED_FIELDS = frozenset({"src_port", "dst_port", "checksum", "options"})


def _sample_udp_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "src_port":
        if "dhcp" in ctx.stack:
            return 68
        if "dns" in ctx.stack:
            return ephemeral_port(ctx.rng)
        # RIP (UDP/520, RFC 1058 §3.4) and RIPng (UDP/521, RFC 2080 §2) are
        # exchanged from the well-known port, not an ephemeral one.
        if "rip" in ctx.stack:
            return 520
        if "ripng" in ctx.stack:
            return 521
        if domain in {"bootpc", "dns_client", "dynamic"}:
            return _integer_domain_value(ctx, domain, field_name, bits=16)
        return ctx.src_port
    if field_name == "dst_port":
        if "dhcp" in ctx.stack:
            return 67
        if "dns" in ctx.stack:
            return 53
        if "rip" in ctx.stack:
            return 520
        if "ripng" in ctx.stack:
            return 521
        if domain in {"bootps", "dns_server"}:
            return ctx.dst_port
        if domain == "dynamic":
            return _integer_domain_value(ctx, domain, field_name, bits=16)
        return ctx.dst_port
    if field_name == "checksum" and domain == "zero_ipv4" and "ipv4" in ctx.stack:
        return 0
    if field_name == "options":
        payload_hex = ctx.payload.hex() if "payload" in ctx.stack else None
        return _udp_options_field(
            f"{ctx.case} {domain}".replace("_", "-"),
            payload_hex=payload_hex,
        ) or _SKIP_FIELD
    return _SKIP_FIELD


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter: UDP uses only ``ctx``/``field_name``/``domain``."""

    return _sample_udp_field(ctx, field_name, domain)


def _apply_udp_options_behavior(
    fields: dict[str, JSONObject],
    *,
    case: str,
    behavior: str,
) -> None:
    key = f"{case} {behavior}".replace("_", "-")
    udp_fields = fields.setdefault("udp", {})
    if "ipv4-zero-checksum" in key or "ipv6-zero-checksum" in key:
        udp_fields["checksum"] = 0
    payload_hex = _payload_hex_from_fields(fields.get("payload", {})) if "payload" in fields else None
    options = _udp_options_field(key, payload_hex=payload_hex)
    if options is None:
        udp_fields.pop("options", None)
    else:
        udp_fields["options"] = options


def _apply_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
) -> None:
    """Apply the ``udp_options`` feature behavior to the sampled UDP fields.

    Byte-identical to the legacy ``udp_options`` branch of
    ``generator._apply_feature_behavior``: it pins the UDP surplus options for the
    selected case/behavior, zeroes the UDP checksum for the IPv4/IPv6 zero-checksum
    cases, and drops the options field when the case carries no surplus area.
    """

    _apply_udp_options_behavior(fields, case=case, behavior=behavior)


def _handles_feature(feature: str) -> bool:
    return feature == "udp_options"


register(
    ProtocolSampler(
        layer="udp",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_behavior,
        handles_feature=_handles_feature,
    )
)
