"""Generator-stage sampler plugin for the IGMP layer.

Moves the IGMP case/behavior mapping helpers (``_igmp_behavior_for_case``,
``_igmp_feature_for_case``), the IGMP behavior free functions (converted in the
preceding step), the ``_igmp_group_record`` helper, and the IGMP documentation
constants out of :mod:`generator` and registers them through the uniform
:class:`~.base.ProtocolSampler` contract. The logic is moved verbatim (behavior
must stay byte-identical); only the dispatch moves out of the generator's legacy
``feature.startswith("igmp_")`` branch into this self-contained module, which
self-registers on import.

IGMP has no sampled fields: every field in ``specs/layers/igmp.yaml`` is driven by
a feature behavior, never by ``_sample_field_value`` (the former
``generator._SUPPORTED_FIELDS`` had no ``igmp`` entry, so ``_sample_layer_fields``
skipped every igmp field). The registered :class:`ProtocolSampler` therefore
declares an empty ``supported_fields`` set — identical to the legacy
``_SUPPORTED_FIELDS.get("igmp", set())`` fallback — and its ``sample`` callback is
never invoked. ``igmp_query``/``igmp_report``/``igmp_extension`` are IGMP sub-layers
(``igmp.yaml`` children), not top-level spec layers, so they are not registered.

The plugin owns every ``igmp_*`` feature. The legacy
``_apply_feature_behavior`` branch gated on ``feature.startswith("igmp_") and
"igmp" in stack``; the registry-first feature loop admits a plugin when its layer
is in the sampled ``fields`` *or* in ``stack``, so gating ``handles_feature`` on the
``igmp_`` prefix reproduces the exact legacy condition (the loop already checks
``"igmp" in stack``). The generator threads ``self.grammar`` into the
``apply_behavior`` call; the IGMP behaviors do not consult it, so it is accepted and
ignored.

``_igmp_behavior_for_case`` and ``_igmp_feature_for_case`` are re-imported into
:mod:`generator` (case-to-behavior orchestration the generator's ``_choose_behavior``
and ``generate_plan`` still call), the same co-locate-and-re-import pattern used for
the IPv6 extension-header builders. Relative imports only so the package resolves
under both the ``engine.*`` (CLI) and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import _SamplingContext
from .base import ProtocolSampler, register


# IGMP documentation-space addresses and deterministic raw-byte blobs the IGMP
# behaviors emit. Mirror the former ``generator`` module-level constants verbatim.
_IGMP_DOC_GROUP = "233.252.0.17"
_IGMP_DOC_GROUP_ALT = "233.252.0.61"
_IGMP_SSM_DOC_GROUP = "232.0.0.17"
_IGMP_DOC_SOURCE = "192.0.2.44"
_IGMP_BYTES_EMPTY: JSONObject = {"hex": ""}
_IGMP_BYTES_RAW: JSONObject = {"hex": "deadbeef"}
_IGMP_BYTES_PADDED_WORD: JSONObject = {"hex": "aabbccdd"}
_IGMP_BYTES_UNKNOWN_TYPE: JSONObject = {"hex": "756e6b6e"}
_IGMP_BYTES_UNSUPPORTED_ASSIGNED_TYPE: JSONObject = {"hex": "64766d72"}
_IGMP_BYTES_IGNORED_EXTRA: JSONObject = {"hex": "aabbccdd"}
_IGMP_BYTES_E_FLAG_CLEAR_EXTENSION: JSONObject = {"hex": "00000000"}

# IGMP samples no fields: every igmp.yaml field is behavior-driven, so the
# generator's legacy ``_SUPPORTED_FIELDS`` table had no ``igmp`` entry and
# ``_sample_layer_fields`` skipped every igmp field. An empty allowlist reproduces
# the legacy ``_SUPPORTED_FIELDS.get("igmp", set())`` fallback exactly.
_IGMP_SUPPORTED_FIELDS: frozenset[str] = frozenset()


def _igmp_behavior_for_case(feature: str, case: str) -> str | None:
    cases = {
        "igmp_header": {
            "igmp-membership-query": "v1-query",
            "igmp-v2-membership-query": "v2-query",
            "igmp-v1-membership-report": "v1-membership-report",
            "igmp-v2-membership-report": "v2-membership-report",
            "igmp-v2-leave-group": "v2-leave-group",
            "igmp-checksum-explicit-invalid": "checksum-explicit",
            "igmp-unknown-type-raw": "unknown-type-raw",
            "igmp-unsupported-assigned-type-raw": "unsupported-assigned-type-raw",
        },
        "igmp_v3_query": {
            "igmp-v3-query-general": "general-query",
            "igmp-v3-query-group-specific": "group-specific-query",
            "igmp-v3-query-group-and-source-specific": "group-and-source-specific-query",
            "igmp-v3-query-source-count-override": "query-source-count-override",
            "igmp-v3-query-checksum-explicit-invalid": "checksum-explicit",
            "igmp-v3-query-ignored-extra-octets": "ignored-extra-query-octets",
        },
        "igmp_v3_report": {
            "igmp-v3-report-empty": "empty-report",
            "igmp-v3-report-include-record": "include-record",
            "igmp-v3-report-exclude-record": "exclude-record",
            "igmp-v3-report-source-list-change-records": "source-list-change-records",
            "igmp-v3-report-auxiliary-data-record": "auxiliary-data-record",
            "igmp-v3-report-unknown-record-type": "unknown-record-type",
            "igmp-v3-report-count-override": "report-count-override",
            "igmp-v3-report-checksum-explicit-invalid": "checksum-explicit",
        },
        "igmp_extensions": {
            "igmp-extension-query-noop": "query-noop-extension",
            "igmp-extension-report-noop-zero-length": "report-noop-extension",
            "igmp-extension-unassigned-type": "unassigned-extension-type",
            "igmp-extension-experimental-type": "experimental-extension-type",
            "igmp-extension-ordered-tlvs": "ordered-extension-tlvs",
            "igmp-extension-e-flag-clear-raw-tail": "e-flag-clear-extension-looking-bytes",
        },
        "igmp_mrd": {
            "igmp-mrd-advertisement": "multicast-router-advertisement",
            "igmp-mrd-solicitation": "multicast-router-solicitation",
            "igmp-mrd-termination": "multicast-router-termination",
            "igmp-mrd-explicit-checksum-invalid": "mrd-explicit-checksum",
            "igmp-mrd-reserved-override": "mrd-reserved-override",
        },
    }
    return cases.get(feature, {}).get(case)


def _igmp_feature_for_case(case: str) -> str | None:
    for feature in (
        "igmp_header",
        "igmp_v3_query",
        "igmp_v3_report",
        "igmp_extensions",
        "igmp_mrd",
    ):
        if _igmp_behavior_for_case(feature, case) is not None:
            return feature
    return None


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Unreachable IGMP field sampler.

    IGMP declares an empty ``supported_fields`` set, so ``_sample_layer_fields``
    skips every igmp field and never calls this adapter. It exists only to satisfy
    the :class:`ProtocolSampler` contract (``sample`` is required) and mirrors the
    legacy generator, which had no ``igmp`` branch in ``_sample_field_value``.
    """

    raise ValueError(f"spec error: unsupported igmp field sampler: {field_name}")


def _apply_igmp_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None = None,
) -> None:
    """Apply the selected ``igmp_*`` feature behavior to the IGMP/IPv4 fields.

    Byte-identical to the legacy ``feature.startswith("igmp_") and "igmp" in stack``
    branch of ``generator._apply_feature_behavior``. The registry-first feature loop
    already checks ``"igmp" in stack`` before calling here, reproducing the legacy
    gate. ``grammar`` is part of the uniform ``apply_behavior`` call path; the IGMP
    behaviors do not consult it.
    """

    ipv4 = fields.setdefault("ipv4", {})
    ipv4["protocol"] = "igmp"
    ipv4["flags"] = "none"
    ipv4["fragment_offset"] = 0

    igmp = fields.setdefault("igmp", {})
    if feature == "igmp_header":
        _apply_igmp_header_behavior(igmp, behavior=behavior)
    elif feature == "igmp_v3_query":
        _apply_igmp_v3_query_behavior(igmp, behavior=behavior)
    elif feature == "igmp_v3_report":
        _apply_igmp_v3_report_behavior(igmp, behavior=behavior)
    elif feature == "igmp_extensions":
        _apply_igmp_extension_behavior(igmp, behavior=behavior)
    elif feature == "igmp_mrd":
        _apply_igmp_mrd_behavior(ipv4, igmp, behavior=behavior)


def _handles_igmp_feature(feature: str) -> bool:
    return feature.startswith("igmp_")


def _apply_igmp_header_behavior(igmp: JSONObject, *, behavior: str) -> None:
    igmp.update({"type": "membership_query", "code": 0, "group_address": "0.0.0.0"})
    if behavior == "v2-query":
        igmp.update({"code": 100, "group_address": _IGMP_DOC_GROUP})
    elif behavior == "v1-membership-report":
        igmp.update({"type": "v1_membership_report", "group_address": _IGMP_DOC_GROUP})
    elif behavior == "v2-membership-report":
        igmp.update({"type": "v2_membership_report", "group_address": _IGMP_DOC_GROUP})
    elif behavior == "v2-leave-group":
        igmp.update({"type": "v2_leave_group", "group_address": _IGMP_DOC_GROUP})
    elif behavior == "checksum-explicit":
        igmp["checksum"] = "explicit_invalid"
    elif behavior == "unknown-type-raw":
        igmp.update({"type": "unassigned", "raw_tail": _IGMP_BYTES_UNKNOWN_TYPE})
    elif behavior == "unsupported-assigned-type-raw":
        igmp.update(
            {
                "type": "dvmrp_unsupported_assigned",
                "raw_tail": _IGMP_BYTES_UNSUPPORTED_ASSIGNED_TYPE,
            }
        )


def _apply_igmp_v3_query_behavior(igmp: JSONObject, *, behavior: str) -> None:
    igmp.update(
        {
            "type": "membership_query",
            "code": 100,
            "group_address": "0.0.0.0",
            "query_flags": 0,
            "qqic": 10,
            "source_addresses": [],
        }
    )
    if behavior == "group-specific-query":
        igmp.update({"group_address": _IGMP_DOC_GROUP_ALT, "query_flags": 0x08, "qqic": 0x81})
    elif behavior == "group-and-source-specific-query":
        igmp.update(
            {
                "group_address": _IGMP_SSM_DOC_GROUP,
                "query_flags": 0x02,
                "source_addresses": [_IGMP_DOC_SOURCE],
            }
        )
    elif behavior == "query-source-count-override":
        igmp.update(
            {
                "group_address": _IGMP_SSM_DOC_GROUP,
                "number_of_sources": 0,
                "source_addresses": [_IGMP_DOC_SOURCE],
            }
        )
    elif behavior == "checksum-explicit":
        igmp["checksum"] = "explicit_invalid"
    elif behavior == "ignored-extra-query-octets":
        igmp["raw_tail"] = _IGMP_BYTES_IGNORED_EXTRA


def _apply_igmp_v3_report_behavior(igmp: JSONObject, *, behavior: str) -> None:
    igmp.update({"type": "v3_membership_report", "report_flags": 0, "group_records": []})
    if behavior == "include-record":
        igmp["group_records"] = [_igmp_group_record("mode_is_include")]
    elif behavior == "exclude-record":
        igmp["group_records"] = [_igmp_group_record("mode_is_exclude")]
    elif behavior == "source-list-change-records":
        igmp["group_records"] = [
            _igmp_group_record("allow_new_sources", group=_IGMP_SSM_DOC_GROUP),
            _igmp_group_record("block_old_sources", group=_IGMP_DOC_GROUP_ALT),
        ]
    elif behavior == "auxiliary-data-record":
        igmp["group_records"] = [
            _igmp_group_record(
                "change_to_exclude_mode", auxiliary_data=_IGMP_BYTES_PADDED_WORD
            )
        ]
    elif behavior == "unknown-record-type":
        igmp["group_records"] = [_igmp_group_record("unknown", auxiliary_data=_IGMP_BYTES_RAW)]
    elif behavior == "report-count-override":
        igmp.update(
            {
                "number_of_group_records": 0,
                "group_records": [_igmp_group_record("mode_is_include")],
            }
        )
    elif behavior == "checksum-explicit":
        igmp["checksum"] = "explicit_invalid"


def _apply_igmp_extension_behavior(igmp: JSONObject, *, behavior: str) -> None:
    if behavior in {
        "query-noop-extension",
        "unassigned-extension-type",
        "ordered-extension-tlvs",
        "e-flag-clear-extension-looking-bytes",
    }:
        _apply_igmp_v3_query_behavior(igmp, behavior="general-query")
    else:
        _apply_igmp_v3_report_behavior(igmp, behavior="empty-report")

    if behavior == "query-noop-extension":
        igmp.update(
            {
                "query_flags": 0x10,
                "extension_tlvs": [
                    {"extension_type": "noop", "extension_value": _IGMP_BYTES_RAW}
                ],
            }
        )
    elif behavior == "report-noop-extension":
        igmp.update(
            {
                "report_flags": 0x8000,
                "extension_tlvs": [
                    {
                        "extension_type": "noop",
                        "extension_length": 0,
                        "extension_value": _IGMP_BYTES_EMPTY,
                    }
                ],
            }
        )
    elif behavior == "unassigned-extension-type":
        igmp.update(
            {
                "query_flags": 0x10,
                "extension_tlvs": [
                    {"extension_type": "unassigned", "extension_value": _IGMP_BYTES_RAW}
                ],
            }
        )
    elif behavior == "experimental-extension-type":
        igmp.update(
            {
                "report_flags": 0x8000,
                "extension_tlvs": [
                    {"extension_type": "experimental", "extension_value": _IGMP_BYTES_RAW}
                ],
            }
        )
    elif behavior == "ordered-extension-tlvs":
        igmp.update(
            {
                "query_flags": 0x10,
                "extension_tlvs": [
                    {
                        "extension_type": "noop",
                        "extension_length": 0,
                        "extension_value": _IGMP_BYTES_EMPTY,
                    },
                    {"extension_type": "unassigned", "extension_value": _IGMP_BYTES_RAW},
                    {"extension_type": "experimental", "extension_value": _IGMP_BYTES_RAW},
                ],
            }
        )
    elif behavior == "e-flag-clear-extension-looking-bytes":
        igmp.update({"query_flags": 0, "raw_tail": _IGMP_BYTES_E_FLAG_CLEAR_EXTENSION})


def _apply_igmp_mrd_behavior(
    ipv4: JSONObject, igmp: JSONObject, *, behavior: str
) -> None:
    ipv4["ttl"] = 1
    ipv4["dst"] = "224.0.0.106"
    igmp.update({"type": "multicast_router_solicitation", "code": 0})
    if behavior == "multicast-router-advertisement":
        igmp.update(
            {
                "type": "multicast_router_advertisement",
                "code": 20,
                "mrd_query_interval": 125,
                "mrd_robustness_variable": 2,
            }
        )
    elif behavior == "multicast-router-termination":
        igmp["type"] = "multicast_router_termination"
    elif behavior == "mrd-explicit-checksum":
        igmp.update(
            {
                "type": "multicast_router_advertisement",
                "code": 20,
                "mrd_query_interval": 125,
                "mrd_robustness_variable": 2,
                "checksum": "explicit_invalid",
            }
        )
    elif behavior == "mrd-reserved-override":
        igmp["code"] = 7


def _igmp_group_record(
    record_type: str,
    *,
    group: str = _IGMP_DOC_GROUP,
    auxiliary_data: object = _IGMP_BYTES_EMPTY,
) -> JSONObject:
    return {
        "record_type": record_type,
        "multicast_address": group,
        "source_addresses": [_IGMP_DOC_SOURCE],
        "auxiliary_data": auxiliary_data,
    }


register(
    ProtocolSampler(
        layer="igmp",
        supported_fields=_IGMP_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_igmp_behavior,
        handles_feature=_handles_igmp_feature,
    )
)
