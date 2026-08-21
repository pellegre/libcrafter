"""Shared packet corpus contract for oracle validation modes."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .directions import normalize_direction
from .model import (
    JSONObject,
    JSONValue,
    JsonModel,
    PacketPlan,
    coerce_json_value,
    dumps_json,
    json_object,
    optional_string,
    read_json,
    string_list,
    write_json,
)

CORPUS_SCHEMA_VERSION = 1
CORPUS_MODE = "corpus"
SKIP_BACKEND_UNSUPPORTED = "backend_unsupported"
SKIP_OFFLINE_PCAP_FILE_FIXTURE = "offline_pcap_file_fixture"
SKIP_PCAP_LINK_TYPE_UNAVAILABLE = "pcap_link_type_unavailable"
SKIP_PCAP_NORMALIZED_ONLY = "pcap_normalized_only"
SKIP_PCAP_STRUCTURED_ERROR = "pcap_structured_error"
# Case byte policies that pcap mode cannot represent safely. A ``normalized``
# case intentionally carries wire bytes that differ from the libcrafter encode
# (for example compressed names), so a strict pcap roundtrip would not preserve
# the source bytes. A ``structured_error`` case is malformed input with no clean
# pcap representation. Both are skipped with an explicit reason rather than
# silently dropped.
_PCAP_INELIGIBLE_BYTE_POLICIES = {
    "normalized": SKIP_PCAP_NORMALIZED_ONLY,
    "structured_error": SKIP_PCAP_STRUCTURED_ERROR,
}
_PCAP_LINK_TYPES_BY_ROOT = {
    "link:ethernet": "DLT_EN10MB",
    "link:dot11": "DLT_IEEE802_11",
    "link:radiotap": "DLT_IEEE802_11_RADIO",
    "link:linux-cooked": "DLT_LINUX_SLL",
    "link:null-loopback": "DLT_NULL",
    "l3:ipv4": "DLT_RAW",
    "l3:ipv4-ntp": "DLT_RAW",
    "l3:ipv6": "DLT_RAW",
    "l3:ipv6-ntp": "DLT_RAW",
}


class CorpusFormatError(ValueError):
    """Raised when a corpus artifact does not match the contract."""


@dataclass(frozen=True, slots=True)
class CorpusEligibility(JsonModel):
    """Per-mode eligibility shell for a generated packet."""

    eligible: bool | None = None
    reason: str | None = None
    skip_reasons: list[str] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)

    @classmethod
    def from_dict(cls, value: object, name: str) -> "CorpusEligibility":
        raw = _json_object(value, name)
        eligible = raw.get("eligible")
        if eligible is not None and not isinstance(eligible, bool):
            raise CorpusFormatError(f"{name}.eligible must be a boolean or null")
        reason = raw.get("reason")
        if reason is not None and not isinstance(reason, str):
            raise CorpusFormatError(f"{name}.reason must be a string or null")
        try:
            skip_reasons = string_list(
                raw.get("skip_reasons", []), f"{name}.skip_reasons"
            )
            metadata = json_object(raw.get("metadata", {}), f"{name}.metadata")
        except ValueError as exc:
            raise CorpusFormatError(str(exc)) from exc
        if reason is not None and reason not in skip_reasons:
            skip_reasons.insert(0, reason)
        if reason is None and skip_reasons:
            reason = skip_reasons[0]
        return cls(
            eligible=eligible,
            reason=reason,
            skip_reasons=skip_reasons,
            metadata=metadata,
        )

    def to_dict(self) -> JSONObject:
        output: JSONObject = {
            "eligible": self.eligible,
            "reason": self.reason,
            "skip_reasons": list(self.skip_reasons),
            "metadata": dict(self.metadata),
        }
        return output


@dataclass(frozen=True, slots=True)
class CorpusPacket(JsonModel):
    """One ordered packet plan with stable offline and pcap eligibility."""

    packet_id: str
    index: int
    plan: PacketPlan
    offline: CorpusEligibility = field(default_factory=CorpusEligibility)
    pcap: CorpusEligibility = field(default_factory=CorpusEligibility)

    @classmethod
    def from_plan(
        cls,
        plan: PacketPlan,
        *,
        packet_id: str | None = None,
        index: int | None = None,
    ) -> "CorpusPacket":
        return cls(
            packet_id=packet_id or packet_id_for_plan(plan),
            index=plan.index if index is None else index,
            plan=plan,
        )

    @classmethod
    def from_dict(cls, value: object, name: str) -> "CorpusPacket":
        raw = _json_object(value, name)
        eligibility = raw.get("eligibility")
        if isinstance(eligibility, Mapping):
            eligibility_raw = _json_object(eligibility, f"{name}.eligibility")
        else:
            eligibility_raw = {}
        packet_id = _required_string(raw, "packet_id", name)
        index = _required_int(raw, "index", name)
        plan = packet_plan_from_object(_required(raw, "plan", name), f"{name}.plan")
        return cls(
            packet_id=packet_id,
            index=index,
            plan=plan,
            offline=CorpusEligibility.from_dict(
                _eligibility_value(raw, eligibility_raw, "offline", name),
                f"{name}.offline",
            ),
            pcap=CorpusEligibility.from_dict(
                _eligibility_value(raw, eligibility_raw, "pcap", name),
                f"{name}.pcap",
            ),
        )

    def to_dict(self) -> JSONObject:
        offline = self.offline.to_dict()
        pcap = self.pcap.to_dict()
        return {
            "packet_id": self.packet_id,
            "index": self.index,
            "plan": self.plan.to_dict(),
            "offline": offline,
            "pcap": pcap,
            "eligibility": {
                "offline": offline,
                "pcap": pcap,
            },
        }


@dataclass(frozen=True, slots=True)
class CorpusReport(JsonModel):
    """Corpus report shared by deterministic offline and pcap oracle modes."""

    mode: str
    backend: str
    profile: str
    seed: int
    count: int
    corpus_id: str
    selected_specs: list[str] = field(default_factory=list)
    packets: list[CorpusPacket] = field(default_factory=list)
    schema_version: int = CORPUS_SCHEMA_VERSION
    metadata: JSONObject = field(default_factory=dict)

    @classmethod
    def from_packets(
        cls,
        *,
        backend: str,
        profile: str,
        seed: int,
        count: int,
        packets: Sequence[CorpusPacket],
        selected_specs: Sequence[str] = (),
        corpus_id: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> "CorpusReport":
        ordered_packets = list(packets)
        specs = list(
            dict.fromkeys(
                [*selected_specs, *_selected_specs_from_packets(ordered_packets)]
            )
        )
        resolved_metadata = json_object(metadata or {}, "metadata")
        return cls(
            mode=CORPUS_MODE,
            backend=backend,
            profile=profile,
            seed=seed,
            count=count,
            corpus_id=corpus_id
            or corpus_id_for_packets(
                backend=backend,
                profile=profile,
                seed=seed,
                count=count,
                selected_specs=specs,
                packets=ordered_packets,
            ),
            selected_specs=specs,
            packets=ordered_packets,
            metadata=resolved_metadata,
        )

    @classmethod
    def from_plans(
        cls,
        *,
        backend: str,
        profile: str,
        seed: int,
        count: int,
        plans: Sequence[PacketPlan],
        selected_specs: Sequence[str] = (),
        corpus_id: str | None = None,
        metadata: Mapping[str, object] | None = None,
        case_byte_policies: Mapping[str, str] | None = None,
    ) -> "CorpusReport":
        if case_byte_policies is None:
            case_byte_policies = _default_case_byte_policies()
        packets = populate_corpus_eligibility(
            backend=backend,
            packets=[CorpusPacket.from_plan(plan) for plan in plans],
            case_byte_policies=case_byte_policies,
        )
        resolved_metadata = json_object(metadata or {}, "metadata")
        resolved_metadata["eligibility"] = corpus_eligibility_summary(packets)
        return cls.from_packets(
            backend=backend,
            profile=profile,
            seed=seed,
            count=count,
            packets=packets,
            selected_specs=selected_specs,
            corpus_id=corpus_id,
            metadata=resolved_metadata,
        )

    @classmethod
    def from_dict(cls, value: object, source: str = "corpus report") -> "CorpusReport":
        raw = _json_object(value, source)
        schema_version = _required_int(raw, "schema_version", source)
        if schema_version != CORPUS_SCHEMA_VERSION:
            raise CorpusFormatError(
                f"{source}.schema_version must be {CORPUS_SCHEMA_VERSION}, got {schema_version}"
            )
        mode = _required_string(raw, "mode", source)
        if mode != CORPUS_MODE:
            raise CorpusFormatError(
                f"{source}.mode must be {CORPUS_MODE!r}, got {mode!r}"
            )
        metadata = _json_object(raw.get("metadata", {}), f"{source}.metadata")
        packets_value = _required(metadata, "packets", f"{source}.metadata")
        if not isinstance(packets_value, Sequence) or isinstance(
            packets_value,
            (str, bytes, bytearray),
        ):
            raise CorpusFormatError(f"{source}.metadata.packets must be a list")
        packets = [
            CorpusPacket.from_dict(packet, f"{source}.metadata.packets[{index}]")
            for index, packet in enumerate(packets_value)
        ]
        return cls(
            mode=mode,
            backend=_required_string(raw, "backend", source),
            profile=_required_string(raw, "profile", source),
            seed=_required_int(raw, "seed", source),
            count=_required_int(raw, "count", source),
            corpus_id=_required_string(raw, "corpus_id", source),
            selected_specs=_string_list_value(
                raw.get("selected_specs", []),
                f"{source}.selected_specs",
            ),
            packets=packets,
            schema_version=schema_version,
            metadata=_metadata_without_packets(metadata),
        )

    def to_dict(self) -> JSONObject:
        metadata = dict(self.metadata)
        metadata["packets"] = [packet.to_dict() for packet in self.packets]
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "backend": self.backend,
            "profile": self.profile,
            "seed": self.seed,
            "count": self.count,
            "corpus_id": self.corpus_id,
            "selected_specs": list(self.selected_specs),
            "metadata": metadata,
        }

    def to_json(self, *, indent: int = 2) -> str:
        return dumps_json(self.to_dict(), indent=indent)


def build_corpus_report(
    *,
    backend: str,
    profile: str,
    seed: int,
    count: int,
    plans: Sequence[PacketPlan],
    selected_specs: Sequence[str] = (),
    metadata: Mapping[str, object] | None = None,
    case_byte_policies: Mapping[str, str] | None = None,
) -> CorpusReport:
    """Wrap generated plans in the shared corpus report contract."""

    return CorpusReport.from_plans(
        backend=backend,
        profile=profile,
        seed=seed,
        count=count,
        plans=plans,
        selected_specs=selected_specs,
        metadata=metadata,
        case_byte_policies=case_byte_policies,
    )


def _default_case_byte_policies() -> dict[str, str]:
    """Resolve the spec-declared case byte policies for pcap eligibility.

    Loaded lazily from the generator so the shared corpus module stays decoupled
    from spec loading at import time. Returns an empty map if the specs cannot be
    loaded, leaving prior (link-type only) pcap eligibility behavior intact.
    """

    try:
        from .generator import case_byte_policy_index

        return case_byte_policy_index()
    except Exception:
        return {}


def populate_corpus_eligibility(
    *,
    backend: str,
    packets: Sequence[CorpusPacket],
    case_byte_policies: Mapping[str, str] | None = None,
) -> list[CorpusPacket]:
    """Return packets with offline and pcap eligibility populated."""

    return [
        CorpusPacket(
            packet_id=packet.packet_id,
            index=packet.index,
            plan=packet.plan,
            offline=_offline_eligibility(packet.plan, backend),
            pcap=_pcap_eligibility(
                packet.plan,
                backend,
                case_byte_policies=case_byte_policies,
            ),
        )
        for packet in packets
    ]


def corpus_eligibility_summary(packets: Sequence[CorpusPacket]) -> JSONObject:
    """Aggregate corpus skip counts by mode and stable reason string."""

    modes = ("offline", "pcap")
    eligible_counts: dict[str, int] = {mode: 0 for mode in modes}
    skipped_counts: dict[str, int] = {mode: 0 for mode in modes}
    skip_counts: dict[str, dict[str, int]] = {mode: {} for mode in modes}
    for packet in packets:
        for mode in modes:
            eligibility = getattr(packet, mode)
            if eligibility.eligible is True:
                eligible_counts[mode] += 1
                continue
            skipped_counts[mode] += 1
            reasons = _eligibility_skip_reasons(eligibility)
            if not reasons:
                reasons = [SKIP_BACKEND_UNSUPPORTED]
            for reason in reasons:
                skip_counts[mode][reason] = skip_counts[mode].get(reason, 0) + 1

    return {
        "total_packets": len(packets),
        "eligible_counts": eligible_counts,
        "skipped_counts": skipped_counts,
        "skip_counts_by_mode": skip_counts,
    }


def _offline_eligibility(plan: PacketPlan, backend: str) -> CorpusEligibility:
    required = ("encode", "decode")
    missing = _missing_backend_capabilities(backend, required)
    reasons = [SKIP_BACKEND_UNSUPPORTED] if missing else []
    file_format = _plan_file_format(plan)
    if file_format == "pcap":
        reasons.append(SKIP_OFFLINE_PCAP_FILE_FIXTURE)
    return CorpusEligibility(
        eligible=not reasons,
        reason=_first_reason(reasons),
        skip_reasons=reasons,
        metadata={
            "required_backend_capabilities": list(required),
            "missing_backend_capabilities": missing,
            "backend_capabilities": _enabled_backend_capabilities(backend),
            "root": _packet_root(plan),
            "stack": list(plan.stack),
            "family": plan.family,
            "case": plan.case,
            "feature_tags": list(plan.feature_tags),
            "file_format": file_format,
        },
    )


def _plan_file_format(plan: PacketPlan) -> str | None:
    for fields in plan.fields.values():
        if isinstance(fields, Mapping):
            value = fields.get("file_format")
            if isinstance(value, str):
                return value
    return None


def _pcap_eligibility(
    plan: PacketPlan,
    backend: str,
    *,
    case_byte_policies: Mapping[str, str] | None = None,
) -> CorpusEligibility:
    required = ("pcap_read", "pcap_write")
    missing = _missing_backend_capabilities(backend, required)
    reasons: list[str] = []
    if missing:
        reasons.append(SKIP_BACKEND_UNSUPPORTED)
    root = _packet_root(plan)
    link_type = _PCAP_LINK_TYPES_BY_ROOT.get(root or "")
    if link_type is None:
        reasons.append(SKIP_PCAP_LINK_TYPE_UNAVAILABLE)
    byte_policy = None
    if case_byte_policies and plan.case is not None:
        byte_policy = case_byte_policies.get(plan.case)
    policy_reason = (
        _PCAP_INELIGIBLE_BYTE_POLICIES.get(byte_policy)
        if byte_policy is not None
        else None
    )
    if policy_reason is not None:
        reasons.append(policy_reason)
    reasons = _unique_strings(reasons)
    return CorpusEligibility(
        eligible=not reasons,
        reason=_first_reason(reasons),
        skip_reasons=reasons,
        metadata={
            "required_backend_capabilities": list(required),
            "missing_backend_capabilities": missing,
            "backend_capabilities": _enabled_backend_capabilities(backend),
            "root": root,
            "pcap_link_type": link_type,
            "byte_policy": byte_policy,
            "stack": list(plan.stack),
            "family": plan.family,
            "case": plan.case,
            "feature_tags": list(plan.feature_tags),
        },
    )


def _missing_backend_capabilities(backend: str, required: Sequence[str]) -> list[str]:
    try:
        from .backends import get_backend

        registration = get_backend(backend)
    except ValueError:
        return list(required)
    capabilities = registration.capabilities
    return [
        capability
        for capability in required
        if not bool(getattr(capabilities, capability, False))
    ]


def _enabled_backend_capabilities(backend: str) -> list[str]:
    try:
        from .backends import get_backend

        return get_backend(backend).capabilities.enabled()
    except ValueError:
        return []


def _packet_root(plan: PacketPlan) -> str | None:
    root = plan.metadata.get("root_decoder", plan.metadata.get("root"))
    return root if isinstance(root, str) and root else None


def _first_reason(reasons: Sequence[str]) -> str | None:
    return reasons[0] if reasons else None


def _unique_strings(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _eligibility_skip_reasons(eligibility: CorpusEligibility) -> list[str]:
    if eligibility.skip_reasons:
        return list(eligibility.skip_reasons)
    if eligibility.reason is not None:
        return [eligibility.reason]
    return []


def load_corpus_report(path: str | Path) -> CorpusReport:
    """Load and validate a corpus report from JSON."""

    try:
        value = read_json(path)
    except json.JSONDecodeError as exc:
        raise CorpusFormatError(f"{path}: invalid JSON: {exc}") from exc
    return CorpusReport.from_dict(value, source=str(path))


def write_corpus_report(path: str | Path, report: CorpusReport) -> None:
    """Validate and write a corpus report as deterministic JSON."""

    validated = CorpusReport.from_dict(report.to_dict(), source="corpus report")
    write_json(path, validated.to_dict())


def packet_id_for_plan(plan: PacketPlan) -> str:
    """Return a stable packet id, reusing the generator plan id when present."""

    plan_id = plan.metadata.get("plan_id")
    if isinstance(plan_id, str) and plan_id:
        return plan_id
    digest = _stable_digest(
        {
            "schema_version": CORPUS_SCHEMA_VERSION,
            "plan": plan.to_dict(),
        }
    )
    return f"packet-v{CORPUS_SCHEMA_VERSION}-{digest[:16]}"


def corpus_id_for_packets(
    *,
    backend: str,
    profile: str,
    seed: int,
    count: int,
    selected_specs: Sequence[str],
    packets: Sequence[CorpusPacket],
) -> str:
    """Return a stable corpus id for the ordered packet sequence."""

    digest = _stable_digest(
        {
            "schema_version": CORPUS_SCHEMA_VERSION,
            "backend": backend,
            "profile": profile,
            "seed": seed,
            "count": count,
            "selected_specs": list(selected_specs),
            "packets": [
                {
                    "packet_id": packet.packet_id,
                    "index": packet.index,
                    "plan": packet.plan.to_dict(),
                }
                for packet in packets
            ],
        }
    )
    return f"corpus-v{CORPUS_SCHEMA_VERSION}-{digest[:16]}"


def packet_plan_from_object(value: object, name: str = "packet plan") -> PacketPlan:
    """Parse a packet plan object with required corpus-level validation."""

    plan = _json_object(value, name)
    fields_object = _json_object(_required(plan, "fields", name), f"{name}.fields")
    fields = {
        layer: _json_object(layer_fields, f"{name}.fields.{layer}")
        for layer, layer_fields in fields_object.items()
    }
    strict_bytes = plan.get("strict_bytes", True)
    if not isinstance(strict_bytes, bool):
        raise CorpusFormatError(f"{name}.strict_bytes must be a boolean when present")
    return PacketPlan(
        stack=_string_list_value(_required(plan, "stack", name), f"{name}.stack"),
        fields=fields,
        profile=_required_string(plan, "profile", name),
        seed=_required_int(plan, "seed", name),
        index=_required_int(plan, "index", name),
        direction=normalize_direction(_required_string(plan, "direction", name)),
        family=optional_string(plan.get("family")),
        feature_tags=_string_list_value(
            plan.get("feature_tags", []), f"{name}.feature_tags"
        ),
        case=optional_string(plan.get("case")),
        strict_bytes=strict_bytes,
        metadata=_json_object(plan.get("metadata", {}), f"{name}.metadata"),
    )


def _selected_specs_from_packets(packets: Sequence[CorpusPacket]) -> list[str]:
    specs: list[str] = []
    for packet in packets:
        raw_specs = packet.plan.metadata.get("selected_specs", [])
        if isinstance(raw_specs, Sequence) and not isinstance(
            raw_specs, (str, bytes, bytearray)
        ):
            for item in raw_specs:
                if isinstance(item, str) and item not in specs:
                    specs.append(item)
    return specs


def _metadata_without_packets(metadata: JSONObject) -> JSONObject:
    output = dict(metadata)
    output.pop("packets", None)
    return output


def _stable_digest(value: Mapping[str, object]) -> str:
    text = json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _json_value(value: object) -> JSONValue:
    try:
        return coerce_json_value(value)
    except Exception as exc:  # pragma: no cover - defensive context for callers.
        raise CorpusFormatError(f"value is not JSON-compatible: {exc}") from exc


def _json_object(value: object, name: str) -> JSONObject:
    try:
        return json_object(value, name)
    except ValueError as exc:
        raise CorpusFormatError(str(exc)) from exc


def _string_list_value(value: object, name: str) -> list[str]:
    try:
        return string_list(value, name)
    except ValueError as exc:
        raise CorpusFormatError(str(exc)) from exc


def _eligibility_value(
    raw: Mapping[str, object],
    eligibility: Mapping[str, object],
    key: str,
    name: str,
) -> object:
    if key in eligibility:
        return eligibility[key]
    return _required(raw, key, name)


def _required(raw: Mapping[str, object], key: str, name: str) -> object:
    if key not in raw:
        raise CorpusFormatError(f"{name}.{key} is required")
    return raw[key]


def _required_string(raw: Mapping[str, object], key: str, name: str) -> str:
    value = _required(raw, key, name)
    if not isinstance(value, str) or not value:
        raise CorpusFormatError(f"{name}.{key} must be a non-empty string")
    return value


def _required_int(raw: Mapping[str, object], key: str, name: str) -> int:
    value = _required(raw, key, name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise CorpusFormatError(f"{name}.{key} must be an integer")
    return value
