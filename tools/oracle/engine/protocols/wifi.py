"""Generator-stage sampler plugins for the Wi-Fi (802.11) stack.

The 802.11 stack spans ``radiotap``, ``dot11``, ``eapol``, and ``rsn`` (the
``llc_snap`` framing layer migrated separately). This module is the home for all
of them; ``radiotap``, ``dot11``, ``eapol``, and ``rsn`` are all migrated here.

Moves the ``_sample_radiotap_field`` / ``_sample_dot11_field`` /
``_sample_eapol_field`` / ``_sample_rsn_field`` samplers out of :mod:`generator`
verbatim and registers them through the uniform :class:`~.base.ProtocolSampler`
contract; only the dispatch moves out of the generator's legacy if/elif. None of
these layers carry feature behavior, so each plugin registers ``sample`` alone.
Behavior must stay byte-identical.

The ``_rsn_information_value_hex`` helper is co-located here (the ``eapol`` and
``rsn`` samplers and the ``dot11`` management-tag sampler all use it).

Shared sampling primitives (``_SamplingContext``, ``_SKIP_FIELD``,
``_integer_domain_value``, ``_mac_for_domain``, ``_dot11_is_management``) live in
:mod:`..sampling`; they are imported here rather than duplicated. Relative imports
only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import (
    _SamplingContext,
    _SKIP_FIELD,
    _dot11_is_management,
    _integer_domain_value,
    _mac_for_domain,
)
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


# Dot11 fields the generator samples, mirroring the former
# ``generator._SUPPORTED_FIELDS["dot11"]`` entry.
_DOT11_SUPPORTED_FIELDS = frozenset(
    {
        "addr1",
        "addr2",
        "addr3",
        "addr4",
        "duration_id",
        "frame_control",
        "frame_type",
        "from_ds",
        "ht_control",
        "management_fixed_fields",
        "more_data",
        "more_fragments",
        "order",
        "payload",
        "power_management",
        "protected",
        "protocol_version",
        "qos_control",
        "retry",
        "sequence_control",
        "subtype",
        "tagged_parameters",
        "to_ds",
    }
)


def _sample_dot11_field(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    current_fields: Mapping[str, object],
) -> object:
    frame_control = _dot11_frame_control_for_case(ctx.case, ctx.stack)
    if field_name == "frame_control":
        return frame_control
    if field_name == "protocol_version":
        return frame_control & 0x3
    if field_name == "frame_type":
        return (frame_control >> 2) & 0x3
    if field_name == "subtype":
        return (frame_control >> 4) & 0xF
    if field_name == "to_ds":
        return 1 if frame_control & 0x0100 else 0
    if field_name == "from_ds":
        return 1 if frame_control & 0x0200 else 0
    if field_name == "more_fragments":
        return 0
    if field_name == "retry":
        return 0
    if field_name == "power_management":
        return 0
    if field_name == "more_data":
        return 0
    if field_name == "protected":
        return 1 if frame_control & 0x4000 else 0
    if field_name == "order":
        return 0
    if field_name == "duration_id":
        if domain == "nav":
            return 314
        if domain == "association_id":
            return 0xC001
        if domain == "boundary":
            return 0xFFFF
        return 0
    if field_name == "addr1":
        return _mac_for_domain(ctx, domain, ctx.dst_mac)
    if field_name == "addr2":
        if domain == "absent" and _dot11_control_address_count(frame_control) < 2:
            return _SKIP_FIELD
        return _mac_for_domain(ctx, domain, ctx.src_mac)
    if field_name == "addr3":
        if domain == "absent" and _dot11_header_has_three_addresses(frame_control):
            return ctx.dst_mac
        if domain == "absent":
            return _SKIP_FIELD
        return _mac_for_domain(ctx, domain, "00:00:5e:00:53:03")
    if field_name == "addr4":
        if not _dot11_has_addr4(current_fields):
            return _SKIP_FIELD
        return _mac_for_domain(ctx, domain, "00:00:5e:00:53:04")
    if field_name == "sequence_control":
        if not _dot11_header_has_sequence_control(frame_control):
            return _SKIP_FIELD
        if _dot11_is_data(frame_control) and "llc_snap" in ctx.stack:
            if domain == "sequence":
                return 0x1230
            if domain == "boundary":
                return 0xFFF0
            return 0x1000
        if domain == "absent":
            return 0x1000
        if domain == "fragment_zero":
            return 0x1000
        if domain == "sequence":
            return 0x1230
        if domain == "boundary":
            return 0xFFFF
        return 0x1000
    if field_name == "qos_control":
        if not _dot11_has_qos_control(frame_control):
            return _SKIP_FIELD
        if domain == "ack_policy":
            return 0x0020
        if domain == "boundary":
            return 0xFFFF
        return 0
    if field_name == "ht_control":
        return _SKIP_FIELD
    if field_name == "management_fixed_fields":
        if not _dot11_is_management(frame_control):
            return _SKIP_FIELD
        return {"hex": _dot11_management_fixed_hex(frame_control, str(domain))}
    if field_name == "tagged_parameters":
        subtype = (frame_control >> 4) & 0x0F
        if not _dot11_is_management(frame_control) or not _dot11_management_subtype_has_tags(subtype):
            return _SKIP_FIELD
        return _dot11_management_tags(ctx.case, str(domain))
    if field_name == "payload":
        return _SKIP_FIELD
    raise ValueError(f"spec error: unsupported dot11 field sampler: {field_name}")


def _dot11_management_fixed_hex(frame_control: int, domain: str) -> str:
    subtype = (frame_control >> 4) & 0x0F
    if subtype in {5, 8}:  # probe response, beacon
        return "000000000000000064000100"
    if subtype == 0:  # association request
        return "31040000"
    if subtype in {1, 3}:  # association/reassociation response
        return "310400000100"
    if subtype == 2:  # reassociation request
        return "3104000000005e005301"
    if subtype == 11:  # authentication
        return "000001000000"
    if subtype in {10, 12}:  # disassociation/deauthentication
        return "0100"
    if subtype in {13, 14}:  # action/action-no-ack category
        return "00"
    if domain == "association_fixed":
        return "31040000"
    if domain == "authentication_fixed":
        return "000001000000"
    return ""


def _dot11_management_tags(case: str, domain: str) -> list[JSONObject]:
    if domain == "absent":
        return []
    if domain == "rsn" or "rsn" in case.replace("_", "-"):
        return [{"id": 48, "value": {"hex": _rsn_information_value_hex()}}]
    if domain == "supported_rates":
        return [{"id": 1, "value": {"hex": "82848b96"}}]
    if domain == "unknown":
        return [{"id": 221, "value": {"hex": "0050f20101"}}]
    return [
        {"id": 0, "value": {"hex": "6c696263726166746572"}},
        {"id": 1, "value": {"hex": "82848b96"}},
        {"id": 221, "value": {"hex": "0050f20101"}},
    ]


def _dot11_management_subtype_has_tags(subtype: int) -> bool:
    return subtype in {0, 2, 4, 5, 8}


def _dot11_frame_control_for_case(case: str, stack: Sequence[str]) -> int:
    key = case.replace("_", "-")
    if "llc_snap" in stack:
        return 2 << 2
    if "control" in key:
        return (1 << 2) | (11 << 4)
    if "management" in key or "rsn" in key:
        return (0 << 2) | (8 << 4)
    subtype = 8 if "qos" in key else 0
    flags = 0x4000 if "protected" in key else 0
    if "tods-fromds" in key:
        flags |= 0x0300
    return (2 << 2) | (subtype << 4) | flags


def _dot11_is_control(frame_control: int) -> bool:
    return ((frame_control >> 2) & 0x3) == 1


def _dot11_is_data(frame_control: int) -> bool:
    return ((frame_control >> 2) & 0x3) == 2


def _dot11_header_has_three_addresses(frame_control: int) -> bool:
    return not _dot11_is_control(frame_control)


def _dot11_header_has_sequence_control(frame_control: int) -> bool:
    return not _dot11_is_control(frame_control)


def _dot11_has_qos_control(frame_control: int) -> bool:
    return ((frame_control >> 2) & 0x3) == 2 and (((frame_control >> 4) & 0xF) & 0x8) != 0


def _dot11_has_addr4(fields: Mapping[str, object]) -> bool:
    return bool(fields.get("to_ds")) and bool(fields.get("from_ds"))


def _dot11_control_address_count(frame_control: int) -> int:
    if not _dot11_is_control(frame_control):
        return 3
    subtype = (frame_control >> 4) & 0xF
    return 1 if subtype in {12, 13} else 2


def _sample_dot11(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter: dot11 reads ctx/field_name/domain/current_fields."""

    return _sample_dot11_field(ctx, field_name, domain, current_fields)


register(
    ProtocolSampler(
        layer="dot11",
        supported_fields=_DOT11_SUPPORTED_FIELDS,
        sample=_sample_dot11,
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
