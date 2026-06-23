"""Generator-stage sampler plugin for the TCP layer.

Moves the ``_sample_tcp_field`` sampler, its option-region helpers, and the
``tcp_options``/``tcp_header`` feature behaviors (converted to free functions in
the preceding step) out of :mod:`generator` and registers them through the uniform
:class:`~.base.ProtocolSampler` contract. The sampling and behavior logic is moved
verbatim (behavior must stay byte-identical); only the dispatch moves from the
generator's legacy if/elif into this self-contained module, which self-registers on
import.

TCP owns two feature behaviors. ``apply_behavior`` reproduces the legacy
``tcp_options`` and ``tcp_header`` branches of ``_apply_feature_behavior`` and
``handles_feature`` claims ownership of both feature names, so the generator's
registry-first feature loop runs the right behavior exactly once. The
``tcp_header`` behavior reads the loaded spec grammar to resolve a behavior's
declared control-bit ``flags`` list; the generator threads ``self.grammar`` into the
registry-loop ``apply_behavior`` call (the established step-08 plugin call path), so
the plugin receives it as the ``grammar`` keyword rather than reaching back into
generator state.

Shared primitives (``_SamplingContext``, ``_integer_domain_value``, ``_field_bits``,
``_identifier_part``) and the generic spec-validation helpers (``_object``,
``_object_list``, ``_string_list``) live in :mod:`..sampling`; they are imported here
rather than duplicated. Relative imports only so the package resolves under both the
``engine.*`` (CLI) and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import (
    _SamplingContext,
    _field_bits,
    _identifier_part,
    _integer_domain_value,
    _object,
    _object_list,
    _string_list,
)
from .base import ProtocolSampler, register


# TCP fields the generator samples, mirroring the former
# ``generator._SUPPORTED_FIELDS["tcp"]`` entry.
_SUPPORTED_FIELDS = frozenset(
    {
        "src_port",
        "dst_port",
        "sequence",
        "acknowledgement",
        "reserved",
        "flags",
        "window",
        "urgent_pointer",
        "options",
    }
)


def _tcp_options_hex(case: str, behavior: str) -> str:
    key = f"{case} {behavior}".replace("_", "-")
    if "sack" in key:
        return "0402050a0000000100000002"
    if any(token in key for token in ("mptcp", "fast-open", "edo", "generic", "advanced")):
        return "1e04000122040102fd040000fe040102"
    if "header-boundary" in key or "all-flags" in key:
        return "01010101"
    return "020405b4010303070402080a0102030405060708"


# Per-behavior option region for the focused single-option tcp_options cases.
# Each entry carries exactly one TCP option whose declared length byte matches
# its data so the Scapy reference backend emits it verbatim (comparable cases)
# or so libcrafter preserves the documented wire form (preserved-only cases).
# Sources: RFC 9293 (base options/EOL/NOP), RFC 793/879 (MSS kind 2),
# RFC 7323 (Window Scale kind 3, Timestamps kind 8), RFC 2018 (SACK Permitted
# kind 4, SACK kind 5), RFC 7413 (Fast Open kind 34), RFC 8684 (MPTCP kind 30),
# RFC 5482 (User Timeout kind 28), RFC 5925 (TCP-AO kind 29), RFC 8547
# (TCP-ENO kind 69), RFC 9768 (Accurate ECN kinds 172/174), and RFC 6994
# (experimental ExID kinds 253/254). See docs/guide/tcp.md.
_TCP_OPTION_CASE_HEX: dict[str, str] = {
    # Comparable kinds: Scapy builds these byte-identically to libcrafter.
    "mss": "020405b4",  # kind 2, len 4: MSS 1460
    "window-scale": "030307",  # kind 3, len 3: shift 7
    "sack-permitted": "0402",  # kind 4, len 2
    "sack": "050a0000000100000002",  # kind 5, len 10: one SACK block
    "timestamp": "080a0102030405060708",  # kind 8, len 10: TSval/TSecr
    "fast-open": "2202",  # kind 34, len 2: Fast Open cookie request
    "mptcp-generic": "1e040001",  # kind 30, len 4: MPTCP generic subtype
    "unknown-generic": "c804aabb",  # kind 200, len 4: unknown valid generic
    # Preserved-only kinds: declared coverage, byte_policy structured_error.
    # Scapy has no faithful native build/compare path; libcrafter preserves
    # these bytes verbatim (asserted by the crate suites).
    "user-timeout": "1c0480e8",  # kind 28, len 4: G=1, value 0x00e8 (RFC 5482)
    "tcp-ao": "1d0c01020304050607080910",  # kind 29, len 12: KeyID/RNext/MAC
    "tcp-eno": "4504aabb",  # kind 69, len 4: ENO suboptions (RFC 8547)
    "accurate-ecn": "ac0601020304",  # kind 172, len 6: AccECN order-0 counters
    "experimental": "fd06f0010203",  # kind 253, len 6: ExID 0xf001 + data
    # Malformed: a length byte below the two-octet minimum (kind 2, len 1).
    # No offline malformed comparison pathway; the crate suites assert the error.
    "malformed-length": "0201",
}


def _tcp_option_case_hex(behavior: str) -> str:
    """Return the option region hex for one focused tcp_options behavior."""

    key = _identifier_part(behavior)
    if key not in _TCP_OPTION_CASE_HEX:
        raise ValueError(f"spec error: no tcp option hex for behavior {behavior!r}")
    return _TCP_OPTION_CASE_HEX[key]


def _sample_tcp_field(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    field_spec: JSONObject,
) -> object:
    if field_name == "src_port":
        return _integer_domain_value(ctx, domain, field_name, bits=16)
    if field_name == "dst_port":
        return _integer_domain_value(ctx, domain, field_name, bits=16)
    if field_name in {"sequence", "acknowledgement", "urgent_pointer"}:
        return _integer_domain_value(ctx, domain, field_name, bits=_field_bits(field_spec))
    if field_name == "reserved":
        return _integer_domain_value(ctx, domain, field_name, bits=3)
    if field_name == "flags":
        return domain
    if field_name == "window":
        return _integer_domain_value(ctx, domain, field_name, bits=16)
    if field_name == "options":
        return {"hex": _tcp_options_hex(ctx.case, str(domain))}
    raise ValueError(f"spec error: unsupported tcp field sampler: {field_name}")


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter: TCP reads ``field_spec`` (integer bit widths)."""

    return _sample_tcp_field(ctx, field_name, domain, dict(field_spec))


def _apply_tcp_options_behavior(
    fields: dict[str, JSONObject],
    *,
    case: str,
    behavior: str,
) -> None:
    """Populate one TCP option behavior for the tcp_options feature.

    Broad option-list cases (tcp-options*, tcp-all-flags-reserved-offset)
    keep their existing combined option region via ``_tcp_options_hex``. The
    focused single-option cases (tcp-option-*) materialize exactly one option
    kind via ``_tcp_option_case_hex``: the comparable kinds (MSS, Window
    Scale, SACK Permitted, SACK, Timestamp, Fast Open, MPTCP generic, and an
    unknown valid generic) emit a self-consistent option both backends build
    byte-identically. The preserved-only kinds (User Timeout, TCP-AO,
    TCP-ENO, Accurate ECN, experimental ExID) and the malformed-length case
    carry byte_policy: structured_error and are excluded from offline
    sampling (see _case_supported_in_direction), so they never reach this
    materialization in an offline run; the option bytes are still defined
    here so the spec's declared coverage stays reproducible and so the
    libcrafter_to_reference and dry-plan paths can render them determinist
    ically. Every value uses fixed, seed-independent bytes.
    """

    tcp = fields["tcp"]
    case_id = _identifier_part(case)
    if case_id.startswith("tcp-option-"):
        tcp["options"] = {"hex": _tcp_option_case_hex(behavior)}
        return
    tcp["options"] = {"hex": _tcp_options_hex(case, behavior)}
    if case == "tcp-all-flags-reserved-offset":
        tcp["flags"] = "all"
        tcp["reserved"] = 7


def _tcp_header_behavior_flags(
    grammar: JSONObject, feature: str, behavior: str
) -> list[str]:
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
        if raw_behavior.get("name") != behavior:
            continue
        return _string_list(
            raw_behavior.get("flags", []),
            f"features.{feature}.behaviors.{behavior}.flags",
        )
    return []


def _apply_tcp_header_behavior(
    fields: dict[str, JSONObject],
    *,
    grammar: JSONObject,
    feature: str,
    case: str,
    behavior: str,
) -> None:
    """Populate one TCP header behavior for the tcp_header feature.

    The control-bit set comes from the behavior's declared ``flags`` list so
    SYN, SYN-ACK, RST-ACK, and payload/raw ACK cases set exactly the bits the
    spec names. Per-case overrides fill the remaining header behaviors: an
    explicit checksum override that compile() must honor, a deliberately
    out-of-range data offset that decode preserves rather than rewriting, and
    a deterministic application payload for the raw-payload-preservation
    cases. Every value uses documentation-safe, seed-independent bytes so the
    comparison stays deterministic.
    """

    tcp = fields["tcp"]
    flags = _tcp_header_behavior_flags(grammar, feature, behavior)
    if flags:
        tcp["flags"] = list(flags)

    key = case.replace("_", "-")
    if "explicit-checksum" in key:
        # Honored override: fix the TCP checksum to a constant so both
        # backends emit it verbatim instead of deriving from the pseudo
        # header. Exercises the protocol-correct-defaults / honored-override
        # contract for an intentionally non-derived value.
        tcp["checksum"] = 0xBEEF
    if "invalid-data-offset" in key:
        # Deliberately malformed: a data offset of 15 (60 bytes) with no
        # option space. compile() preserves the explicit value rather than
        # rewriting it; compared non-strict (see supported_cases byte_policy).
        tcp["data_offset"] = 15
    if "payload-ack" in key or "raw-payload" in key:
        # Raw payload preservation: a fixed application payload that must
        # round-trip as a trailing Raw layer after the TCP header.
        payload_hex = "7261772d7463702d7061796c6f6164"  # b"raw-tcp-payload"
        fields["payload"] = {
            "hex": payload_hex,
            "length": len(payload_hex) // 2,
        }


def _apply_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject,
) -> None:
    """Apply a TCP feature behavior to the sampled TCP fields.

    Byte-identical to the legacy ``tcp_options``/``tcp_header`` branches of
    ``generator._apply_feature_behavior``, which both gated on ``"tcp" in
    fields``. The registry-first feature loop admits a plugin when its layer is
    in ``fields`` *or* in ``stack``, so the ``"tcp" not in fields`` early return
    preserves the exact legacy condition. ``grammar`` is threaded in from
    ``self.grammar`` for the ``tcp_header`` flag lookup.
    """

    if "tcp" not in fields:
        return
    if feature == "tcp_options":
        _apply_tcp_options_behavior(fields, case=case, behavior=behavior)
    elif feature == "tcp_header":
        _apply_tcp_header_behavior(
            fields,
            grammar=grammar,
            feature=feature,
            case=case,
            behavior=behavior,
        )


def _handles_feature(feature: str) -> bool:
    return feature in {"tcp_options", "tcp_header"}


register(
    ProtocolSampler(
        layer="tcp",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_behavior,
        handles_feature=_handles_feature,
    )
)
