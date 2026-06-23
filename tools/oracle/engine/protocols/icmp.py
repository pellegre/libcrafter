"""Generator-stage sampler plugin for the ICMPv4 and ICMPv6 layers.

Moves the shared ``_sample_icmp_field`` sampler, the ``_icmp_error_type_for_case``
helper, and both ICMP error behaviors out of :mod:`generator` and registers them
through the uniform :class:`~.base.ProtocolSampler` contract. The sampling and
behavior logic is moved verbatim (behavior must stay byte-identical); only the
dispatch moves out of the generator's legacy if/elif into this self-contained
module, which self-registers on import.

``icmp`` and ``icmpv6`` share one field sampler: the legacy ``_sample_field_value``
had two ``if layer ==`` branches that both called ``_sample_icmp_field``, so both
registered :class:`ProtocolSampler` instances delegate to the same moved function.

Each layer owns one error feature behavior. The ``icmp`` plugin owns
``icmpv4_errors`` (the structured ICMPv4 error free function converted in the
preceding step, which reads ``self.grammar`` for the per-behavior spec); the
``icmpv6`` plugin owns ``icmpv6_errors`` (the inline branch that sets the ICMPv6
type via ``_icmp_error_type_for_case(... ipv6=True)`` and ``code=0``). The
generator's registry-first feature loop threads ``self.grammar`` into the
``apply_behavior`` call, so each plugin accepts it as the ``grammar`` keyword.

Shared primitives (``_SamplingContext``, ``bounded_int``, ``_object``,
``_object_list``, ``_json_object``, ``_string_or_none``) and the deterministic ICMP
error blobs (``_ICMP_QUOTED_IPV4_DATAGRAM``, ``_ICMP_MPLS_EXTENSION_BYTES``,
``_ICMP_EXTENSION_BYTES``) live in :mod:`..sampling`; they are imported here rather
than duplicated. Relative imports only so the package resolves under both the
``engine.*`` (CLI) and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import (
    _ICMP_EXTENSION_BYTES,
    _ICMP_MPLS_EXTENSION_BYTES,
    _ICMP_QUOTED_IPV4_DATAGRAM,
    _SKIP_FIELD,
    _SamplingContext,
    _json_object,
    _object,
    _object_list,
    _string_or_none,
    bounded_int,
)
from .base import ProtocolSampler, register


# ICMPv4 fields the generator samples, mirroring the former
# ``generator._SUPPORTED_FIELDS["icmp"]`` entry.
_ICMP_SUPPORTED_FIELDS = frozenset(
    {
        "type",
        "code",
        "checksum",
        "identifier",
        "sequence",
        "rest_of_header",
        "gateway",
        "pointer",
        "next_hop_mtu",
        "originate_timestamp",
        "receive_timestamp",
        "transmit_timestamp",
        "address_mask",
        "router_addresses",
        "router_address_entry_size",
        "router_lifetime",
        "extension_bytes",
        "embedded_header",
    }
)
# ICMPv6 fields the generator samples, mirroring the former
# ``generator._SUPPORTED_FIELDS["icmpv6"]`` entry.
_ICMPV6_SUPPORTED_FIELDS = frozenset({"type", "code", "identifier", "sequence"})

# ICMP rest-of-header / body fields the base echo sampler intentionally skips so a
# plain echo case stays an echo query; the live-matrix and error behaviors attach
# them per ICMP behavior. Mirrors the former ``generator._ICMP_BODY_FIELDS``.
_ICMP_BODY_FIELDS = {
    "checksum",
    "rest_of_header",
    "gateway",
    "pointer",
    "next_hop_mtu",
    "originate_timestamp",
    "receive_timestamp",
    "transmit_timestamp",
    "address_mask",
    "router_addresses",
    "router_address_entry_size",
    "router_lifetime",
    "extension_bytes",
    "embedded_header",
}


def _sample_icmp_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "type":
        return str(domain).replace("_", "-") if domain in {"echo_reply", "echo_request"} else domain
    if field_name == "code":
        return 0
    if field_name in {"identifier", "sequence"}:
        return bounded_int(ctx.rng, 0, 65535)
    # Rest-of-header, gateway, pointer, MTU, timestamp, address-mask, router
    # discovery, and extension-byte fields are populated per ICMP behavior by the
    # live-matrix sampler so the base path stays an echo query. Emitting them
    # unconditionally here would attach body bytes to plain echo cases.
    if field_name in _ICMP_BODY_FIELDS:
        return _SKIP_FIELD
    raise ValueError(f"spec error: unsupported icmp field sampler: {field_name}")


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter shared by ICMPv4 and ICMPv6.

    Both layers use only ``ctx``/``field_name``/``domain`` (the legacy
    ``_sample_field_value`` had two ``if layer ==`` branches that both called
    ``_sample_icmp_field``).
    """

    return _sample_icmp_field(ctx, field_name, domain)


def _icmp_error_type_for_case(case: str, behavior: str, *, ipv6: bool) -> str:
    key = f"{case} {behavior}".replace("_", "-")
    if "packet-too-big" in key:
        return "packet_too_big" if ipv6 else "destination_unreachable"
    if "time-exceeded" in key:
        return "time_exceeded"
    if "parameter-problem" in key:
        return "parameter_problem"
    if "redirect" in key and not ipv6:
        return "redirect"
    return "destination_unreachable"


def _icmp_behavior_embeds(spec: JSONObject | None) -> set[str]:
    """Return the set of layer names a behavior's ``embeds`` declaration lists."""

    if spec is None:
        return set()
    embeds = spec.get("embeds")
    if not isinstance(embeds, Sequence) or isinstance(embeds, (str, bytes)):
        return set()
    return {value for value in embeds if isinstance(value, str)}


def _icmpv4_error_behavior_spec(
    grammar: JSONObject, feature: str, behavior: str
) -> JSONObject | None:
    features = _object(grammar.get("features"), "features")
    if feature not in features:
        raise ValueError(f"unsupported feature: {feature}")
    feature_spec = _object(features[feature], f"features.{feature}")
    behaviors = _object_list(
        feature_spec.get("behaviors", []), f"features.{feature}.behaviors"
    )
    for raw_behavior in behaviors:
        if not isinstance(raw_behavior, Mapping):
            continue
        entry = _json_object(raw_behavior)
        if entry.get("name") == behavior:
            return entry
    return None


def _apply_icmpv4_error_behavior(
    fields: dict[str, JSONObject],
    *,
    grammar: JSONObject,
    feature: str,
    case: str,
    behavior: str,
) -> None:
    """Populate one structured ICMPv4 error behavior.

    Structured error behaviors (destination unreachable, time exceeded,
    parameter problem, redirect, fragmentation-needed) carry an outer IPv4
    header, the ICMP error header, and a quoted (embedded) IPv4 datagram
    prefix with deterministic payload bytes. The quoted datagram is emitted
    as the ``embedded_header`` field so both backends materialize the same
    bytes after the ICMP rest-of-header.

    Extension-framing behaviors marked raw-compatible (RFC 4884/4950 MPLS,
    RFC 5837 interface information) still include the quoted datagram before
    their deterministic ``extension_bytes`` body. The reference model keeps
    this as a flat trailing payload for backend-neutral comparison.

    ``grammar`` is threaded in from ``self.grammar`` for the per-behavior
    feature-spec lookup.
    """

    icmp = fields["icmp"]
    spec = _icmpv4_error_behavior_spec(grammar, feature, behavior)
    icmp_type = _string_or_none(spec.get("icmp_type")) if spec is not None else None
    if icmp_type is None:
        icmp_type = _icmp_error_type_for_case(case, behavior, ipv6=False)
    icmp["type"] = icmp_type
    icmp["code"] = 0

    embeds = _icmp_behavior_embeds(spec)

    # Extension error behaviors keep backend-neutral flat payload bytes, but
    # the ICMP error body still starts with a quoted datagram.
    if "icmp_extension_mpls" in embeds:
        icmp["embedded_header"] = {"hex": _ICMP_QUOTED_IPV4_DATAGRAM}
        icmp["extension_bytes"] = {"hex": _ICMP_MPLS_EXTENSION_BYTES}
        return
    if embeds.intersection({"icmp_extension_header", "icmp_extension_object"}):
        icmp["extension_bytes"] = {"hex": _ICMP_EXTENSION_BYTES}
        if "quoted_ipv4" in embeds or "ipv4" in embeds:
            icmp["embedded_header"] = {"hex": _ICMP_QUOTED_IPV4_DATAGRAM}
        return

    # Structured quoted-datagram error behaviors: outer IPv4 header, ICMP
    # error header, quoted IPv4 prefix, and deterministic quoted payload.
    if "ipv4" in embeds or "payload_prefix" in embeds:
        icmp["embedded_header"] = {"hex": _ICMP_QUOTED_IPV4_DATAGRAM}
        if behavior == "redirect" or icmp_type == "redirect":
            icmp["gateway"] = "192.0.2.1"
        elif behavior == "parameter_problem" or icmp_type == "parameter_problem":
            icmp["pointer"] = 20
        elif behavior == "frag_needed_next_hop_mtu":
            icmp["next_hop_mtu"] = 1280


def _apply_icmp_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None = None,
) -> None:
    """Apply the ``icmpv4_errors`` feature behavior to the sampled ICMPv4 fields.

    Byte-identical to the legacy ``icmpv4_errors`` branch of
    ``generator._apply_feature_behavior``, which gated on ``"icmp" in fields``. The
    registry-first feature loop admits a plugin when its layer is in ``fields`` *or*
    in ``stack``, so the ``"icmp" not in fields`` early return preserves the exact
    legacy condition. ``grammar`` is threaded in from ``self.grammar`` for the
    per-behavior spec lookup.
    """

    if "icmp" not in fields:
        return
    if grammar is None:
        raise ValueError("icmpv4_errors behavior requires the loaded grammar")
    _apply_icmpv4_error_behavior(
        fields,
        grammar=grammar,
        feature=feature,
        case=case,
        behavior=behavior,
    )


def _handles_icmp_feature(feature: str) -> bool:
    return feature == "icmpv4_errors"


def _apply_icmpv6_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None = None,
) -> None:
    """Apply the ``icmpv6_errors`` feature behavior to the sampled ICMPv6 fields.

    Byte-identical to the legacy ``icmpv6_errors`` branch of
    ``generator._apply_feature_behavior``, which gated on ``"icmpv6" in fields`` and
    set the ICMPv6 type from ``_icmp_error_type_for_case(... ipv6=True)`` plus
    ``code=0``. ``grammar`` is part of the uniform ``apply_behavior`` call path; the
    ICMPv6 error branch does not consult it.
    """

    if "icmpv6" not in fields:
        return
    fields["icmpv6"]["type"] = _icmp_error_type_for_case(case, behavior, ipv6=True)
    fields["icmpv6"]["code"] = 0


def _handles_icmpv6_feature(feature: str) -> bool:
    return feature == "icmpv6_errors"


register(
    ProtocolSampler(
        layer="icmp",
        supported_fields=_ICMP_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_icmp_behavior,
        handles_feature=_handles_icmp_feature,
    )
)

register(
    ProtocolSampler(
        layer="icmpv6",
        supported_fields=_ICMPV6_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_icmpv6_behavior,
        handles_feature=_handles_icmpv6_feature,
    )
)
