"""Generator-stage sampler plugins for the Wi-Fi (802.11) stack.

The 802.11 stack spans ``radiotap``, ``dot11``, ``eapol``, and ``rsn`` (the
``llc_snap`` framing layer migrated separately). This module is the home for all
of them; ``radiotap``, ``eapol``, and ``rsn`` are migrated here and ``dot11`` is
added next.

Moves the ``_sample_radiotap_field`` / ``_sample_eapol_field`` /
``_sample_rsn_field`` samplers out of :mod:`generator` verbatim and registers them
through the uniform :class:`~.base.ProtocolSampler` contract; only the dispatch
moves out of the generator's legacy if/elif. None of these layers carry feature
behavior, so each plugin registers ``sample`` alone. Behavior must stay
byte-identical.

The ``_rsn_information_value_hex`` helper is co-located here (the ``eapol`` and
``rsn`` samplers use it) and re-imported by :mod:`generator`, which still owns the
``dot11`` management-tag sampler that also consumes it until ``dot11`` migrates.

Shared sampling primitives (``_SamplingContext``, ``_SKIP_FIELD``,
``_integer_domain_value``) live in :mod:`..sampling`; they are imported here rather
than duplicated. Relative imports only so the package resolves under both the
``engine.*`` (CLI) and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping

from ..sampling import _SamplingContext, _SKIP_FIELD, _integer_domain_value
from .base import ProtocolSampler, register


# Radiotap fields the generator samples, mirroring the former
# ``generator._SUPPORTED_FIELDS["radiotap"]`` entry.
_RADIOTAP_SUPPORTED_FIELDS = frozenset(
    {
        "antenna",
        "channel_flags",
        "channel_frequency",
        "dbm_antenna_signal",
        "fcs_status",
        "flags",
        "length",
        "pad",
        "present_words",
        "rate",
        "rx_flags",
        "tx_flags",
        "unknown_fields",
        "version",
    }
)


def _sample_radiotap_field(
    ctx: _SamplingContext, field_name: str, domain: object
) -> object:
    if field_name == "version":
        return 0 if domain != "explicit_nonzero" else 1
    if field_name == "pad":
        return 0
    if field_name == "length":
        return 0
    if field_name == "present_words":
        return [0]
    if field_name == "flags":
        if domain == "absent":
            return _SKIP_FIELD
        if domain in {"fcs_present", "fcs_present_failed"}:
            return "fcs_present"
        if domain == "failed_fcs":
            return "failed_fcs"
        return "none"
    if field_name == "rate":
        return _SKIP_FIELD if domain == "absent" else (2 if domain == "2" else _integer_domain_value(ctx, domain, field_name, bits=8))
    if field_name == "channel_frequency":
        return _SKIP_FIELD if domain == "absent" else _integer_domain_value(ctx, domain, field_name, bits=16)
    if field_name == "channel_flags":
        if domain == "absent":
            return _SKIP_FIELD
        return domain
    if field_name == "dbm_antenna_signal":
        if domain == "absent":
            return _SKIP_FIELD
        if domain == "boundary":
            return -128
        return -42 if domain == "synthetic_signal" else _integer_domain_value(ctx, domain, field_name, bits=8)
    if field_name == "antenna":
        return _SKIP_FIELD if domain == "absent" else _integer_domain_value(ctx, domain, field_name, bits=8)
    if field_name == "rx_flags":
        if domain == "absent":
            return _SKIP_FIELD
        return 0x0001 if domain == "failed_fcs" else 0
    if field_name == "tx_flags":
        if domain == "absent":
            return _SKIP_FIELD
        return 0x0008 if domain == "no_ack" else 0
    if field_name == "unknown_fields":
        return _SKIP_FIELD if domain == "absent" else {"hex": "aabbccdd"}
    if field_name == "fcs_status":
        return _SKIP_FIELD if domain == "absent" else domain
    raise ValueError(f"spec error: unsupported radiotap field sampler: {field_name}")


def _sample_radiotap(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter: radiotap reads only ctx/field_name/domain."""

    return _sample_radiotap_field(ctx, field_name, domain)


register(
    ProtocolSampler(
        layer="radiotap",
        supported_fields=_RADIOTAP_SUPPORTED_FIELDS,
        sample=_sample_radiotap,
    )
)


# EAPOL fields the generator samples, mirroring the former
# ``generator._SUPPORTED_FIELDS["eapol"]`` entry.
_EAPOL_SUPPORTED_FIELDS = frozenset(
    {
        "body_length",
        "descriptor_type",
        "key_data",
        "key_data_length",
        "key_id",
        "key_information",
        "key_iv",
        "key_length",
        "key_mic",
        "key_nonce",
        "key_rsc",
        "packet_type",
        "replay_counter",
        "version",
    }
)

# RSN fields the generator samples, mirroring the former
# ``generator._SUPPORTED_FIELDS["rsn"]`` entry.
_RSN_SUPPORTED_FIELDS = frozenset(
    {
        "akm_suites",
        "capabilities",
        "element_id",
        "group_cipher_suite",
        "group_management_cipher_suite",
        "length",
        "pairwise_cipher_suites",
        "pmkid_list",
        "trailing_bytes",
        "version",
    }
)


def _rsn_information_value_hex() -> str:
    return "0100000fac040100000fac040100000fac020000"


def _sample_eapol_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    is_key = "key" in ctx.case.replace("_", "-")
    if field_name == "version":
        return 2 if domain in {1, 2, 3, "explicit"} else 2
    if field_name == "packet_type":
        case = ctx.case.replace("_", "-")
        if "logoff" in case:
            return "logoff"
        if is_key:
            return "key"
        if "eap-packet" in case:
            return "eap_packet"
        return "start"
    if field_name == "body_length":
        return 0
    if not is_key:
        return _SKIP_FIELD
    if field_name == "descriptor_type":
        return "rsn_key"
    if field_name == "key_information":
        return 0x008A if "key-data" not in ctx.case else 0x010A
    if field_name == "key_length":
        return 16
    if field_name == "replay_counter":
        return 1
    if field_name == "key_nonce":
        return {"hex": "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f"}
    if field_name == "key_iv":
        return {"hex": "00000000000000000000000000000000"}
    if field_name == "key_rsc":
        return {"hex": "0000000000000000"}
    if field_name == "key_id":
        return {"hex": "0000000000000000"}
    if field_name == "key_mic":
        return {"hex": "00000000000000000000000000000000"}
    if field_name == "key_data_length":
        return 0
    if field_name == "key_data":
        return {"hex": _rsn_information_value_hex()} if "key-data" in ctx.case else _SKIP_FIELD
    raise ValueError(f"spec error: unsupported eapol field sampler: {field_name}")


def _sample_rsn_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "element_id":
        return 48
    if field_name == "length":
        return 0
    if field_name == "version":
        return 1
    if field_name == "group_cipher_suite":
        return "ccmp_128"
    if field_name == "pairwise_cipher_suites":
        return ["ccmp_128"]
    if field_name == "akm_suites":
        return ["sae"] if "sae" in ctx.case else ["psk"]
    if field_name == "capabilities":
        return 0x00C0 if "management-protection" in ctx.case else 0
    if field_name == "pmkid_list":
        return _SKIP_FIELD
    if field_name == "group_management_cipher_suite":
        return "bip_cmac_128" if "management-protection" in ctx.case else _SKIP_FIELD
    if field_name == "trailing_bytes":
        if domain in {"absent", "empty"} or "unknown-suite-raw" not in ctx.case:
            return _SKIP_FIELD
        return {"hex": "aabb"}
    raise ValueError(f"spec error: unsupported rsn field sampler: {field_name}")


def _sample_eapol(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter: eapol reads only ctx/field_name/domain."""

    return _sample_eapol_field(ctx, field_name, domain)


def _sample_rsn(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter: rsn reads only ctx/field_name/domain."""

    return _sample_rsn_field(ctx, field_name, domain)


register(
    ProtocolSampler(
        layer="eapol",
        supported_fields=_EAPOL_SUPPORTED_FIELDS,
        sample=_sample_eapol,
    )
)


register(
    ProtocolSampler(
        layer="rsn",
        supported_fields=_RSN_SUPPORTED_FIELDS,
        sample=_sample_rsn,
    )
)
