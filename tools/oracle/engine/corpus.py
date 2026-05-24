"""Shared packet corpus contract for oracle validation modes."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
SKIP_PCAP_LINK_TYPE_UNAVAILABLE = "pcap_link_type_unavailable"
SKIP_REQUIRES_IPV4 = "requires_ipv4"
SKIP_REQUIRES_IPV6 = "requires_ipv6"
SKIP_REQUIRES_L2 = "requires_l2"
SKIP_REQUIRES_BROADCAST = "requires_broadcast"
SKIP_REQUIRES_PROVIDER_MAC = "requires_provider_mac"
SKIP_REQUIRES_CONTROLLED_SERVICE = "requires_controlled_service"
SKIP_PROVIDER_CAPABILITY_UNAVAILABLE = "provider_capability_unavailable"

_PCAP_LINK_TYPES_BY_ROOT = {
    "link:ethernet": "DLT_EN10MB",
    "link:linux-cooked": "DLT_LINUX_SLL",
    "link:null-loopback": "DLT_NULL",
    "l3:ipv4": "DLT_RAW",
    "l3:ipv6": "DLT_RAW",
}
_WIRE_DEFAULT_PROVIDER = "hetzner"
_WIRE_PROVIDER_CAPABILITY_PROFILES: dict[str, JSONObject] = {
    "local-dry-run": {
        "provider": "local-dry-run",
        "live_packet_exchange": False,
        "ipv4": True,
        "ipv6": True,
        "l2": False,
        "broadcast": False,
        "provider_mac": False,
        "controlled_service": False,
    },
    "hetzner": {
        "provider": "hetzner",
        "live_packet_exchange": True,
        "ipv4": True,
        "ipv6": False,
        "l2": False,
        "broadcast": False,
        "provider_mac": False,
        "controlled_service": False,
    },
}


class CorpusFormatError(ValueError):
    """Raised when a corpus artifact does not match the contract."""


@dataclass(frozen=True, slots=True)
class CorpusEligibility(JsonModel):
    """Per-mode eligibility shell for a generated packet."""

    eligible: bool | None = None
    reason: str | None = None
    skip_reasons: list[str] = field(default_factory=list)
    compare_root: str | None = None
    strict_bytes: bool | None = None
    mutable_fields: list[str] = field(default_factory=list)
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
        compare_root = raw.get("compare_root")
        if compare_root is not None and not isinstance(compare_root, str):
            raise CorpusFormatError(f"{name}.compare_root must be a string or null")
        strict_bytes = raw.get("strict_bytes")
        if strict_bytes is not None and not isinstance(strict_bytes, bool):
            raise CorpusFormatError(f"{name}.strict_bytes must be a boolean or null")
        try:
            skip_reasons = string_list(raw.get("skip_reasons", []), f"{name}.skip_reasons")
            mutable_fields = string_list(raw.get("mutable_fields", []), f"{name}.mutable_fields")
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
            compare_root=compare_root,
            strict_bytes=strict_bytes,
            mutable_fields=mutable_fields,
            metadata=metadata,
        )

    def to_dict(self) -> JSONObject:
        output: JSONObject = {
            "eligible": self.eligible,
            "reason": self.reason,
            "skip_reasons": list(self.skip_reasons),
            "mutable_fields": list(self.mutable_fields),
            "metadata": dict(self.metadata),
        }
        if self.compare_root is not None:
            output["compare_root"] = self.compare_root
        if self.strict_bytes is not None:
            output["strict_bytes"] = self.strict_bytes
        return output


@dataclass(frozen=True, slots=True)
class CorpusPacket(JsonModel):
    """One ordered packet plan with stable identity and mode eligibility."""

    packet_id: str
    index: int
    plan: PacketPlan
    offline: CorpusEligibility = field(default_factory=CorpusEligibility)
    pcap: CorpusEligibility = field(default_factory=CorpusEligibility)
    wire: CorpusEligibility = field(default_factory=CorpusEligibility)

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
            wire=CorpusEligibility.from_dict(
                _eligibility_value(raw, eligibility_raw, "wire", name),
                f"{name}.wire",
            ),
        )

    def to_dict(self) -> JSONObject:
        offline = self.offline.to_dict()
        pcap = self.pcap.to_dict()
        wire = self.wire.to_dict()
        return {
            "packet_id": self.packet_id,
            "index": self.index,
            "plan": self.plan.to_dict(),
            "offline": offline,
            "pcap": pcap,
            "wire": wire,
            "eligibility": {
                "offline": offline,
                "pcap": pcap,
                "wire": wire,
            },
        }


@dataclass(frozen=True, slots=True)
class CorpusReport(JsonModel):
    """Corpus report shared by offline, pcap, and live oracle modes."""

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
    ) -> "CorpusReport":
        packets = populate_corpus_eligibility(
            backend=backend,
            packets=[CorpusPacket.from_plan(plan) for plan in plans],
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
            raise CorpusFormatError(f"{source}.mode must be {CORPUS_MODE!r}, got {mode!r}")
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
    )


def populate_corpus_eligibility(
    *,
    backend: str,
    packets: Sequence[CorpusPacket],
    provider_capabilities: Mapping[str, object] | None = None,
    wire_provider: str = _WIRE_DEFAULT_PROVIDER,
) -> list[CorpusPacket]:
    """Return packets with offline, pcap, and wire eligibility populated."""

    profiles = _wire_provider_capability_profiles(provider_capabilities)
    return [
        CorpusPacket(
            packet_id=packet.packet_id,
            index=packet.index,
            plan=packet.plan,
            offline=_offline_eligibility(packet.plan, backend),
            pcap=_pcap_eligibility(packet.plan, backend),
            wire=_wire_eligibility(
                packet.plan,
                backend,
                profiles=profiles,
                selected_provider=wire_provider,
            ),
        )
        for packet in packets
    ]


def corpus_eligibility_summary(packets: Sequence[CorpusPacket]) -> JSONObject:
    """Aggregate corpus skip counts by mode and stable reason string."""

    modes = ("offline", "pcap", "wire")
    eligible_counts: dict[str, int] = {mode: 0 for mode in modes}
    skipped_counts: dict[str, int] = {mode: 0 for mode in modes}
    skip_counts: dict[str, dict[str, int]] = {mode: {} for mode in modes}
    wire_provider_counts = _wire_provider_eligibility_counts(packets)

    for packet in packets:
        for mode in modes:
            eligibility = getattr(packet, mode)
            if eligibility.eligible is True:
                eligible_counts[mode] += 1
                continue
            skipped_counts[mode] += 1
            reasons = _eligibility_skip_reasons(eligibility)
            if not reasons:
                reasons = [SKIP_PROVIDER_CAPABILITY_UNAVAILABLE]
            for reason in reasons:
                skip_counts[mode][reason] = skip_counts[mode].get(reason, 0) + 1

    return {
        "total_packets": len(packets),
        "eligible_counts": eligible_counts,
        "skipped_counts": skipped_counts,
        "skip_counts_by_mode": skip_counts,
        "wire_default_provider": _WIRE_DEFAULT_PROVIDER,
        "wire_provider_profiles": sorted(_WIRE_PROVIDER_CAPABILITY_PROFILES),
        "wire_provider_eligible_counts": wire_provider_counts["eligible"],
        "wire_provider_skipped_counts": wire_provider_counts["skipped"],
        "wire_provider_skip_counts_by_reason": wire_provider_counts["skip_reasons"],
    }


def _offline_eligibility(plan: PacketPlan, backend: str) -> CorpusEligibility:
    required = ("encode", "decode")
    missing = _missing_backend_capabilities(backend, required)
    reasons = [SKIP_BACKEND_UNSUPPORTED] if missing else []
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
        },
    )


def _pcap_eligibility(plan: PacketPlan, backend: str) -> CorpusEligibility:
    required = ("pcap_read", "pcap_write")
    missing = _missing_backend_capabilities(backend, required)
    reasons: list[str] = []
    if missing:
        reasons.append(SKIP_BACKEND_UNSUPPORTED)
    root = _packet_root(plan)
    link_type = _PCAP_LINK_TYPES_BY_ROOT.get(root or "")
    if link_type is None:
        reasons.append(SKIP_PCAP_LINK_TYPE_UNAVAILABLE)
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
            "stack": list(plan.stack),
            "family": plan.family,
            "case": plan.case,
            "feature_tags": list(plan.feature_tags),
        },
    )


def _wire_eligibility(
    plan: PacketPlan,
    backend: str,
    *,
    profiles: Mapping[str, JSONObject],
    selected_provider: str,
) -> CorpusEligibility:
    profile_decisions: dict[str, JSONObject] = {}
    for provider, capabilities in profiles.items():
        profile_decisions[provider] = _wire_profile_decision(
            plan,
            backend,
            capabilities=capabilities,
        )

    selected = profile_decisions.get(selected_provider)
    if selected is None:
        selected = {
            "provider": selected_provider,
            "eligible": False,
            "skip_reasons": [SKIP_PROVIDER_CAPABILITY_UNAVAILABLE],
            "compare_root": _wire_compare_root(plan),
            "strict_bytes": bool(plan.strict_bytes),
            "mutable_fields": [],
            "metadata": {
                "provider_available": False,
                "available_providers": sorted(profile_decisions),
            },
        }
    reasons = _string_list_value(selected.get("skip_reasons", []), "wire.skip_reasons")
    compare_root = _optional_string_value(
        selected.get("compare_root"),
        "wire.compare_root",
    )
    strict_bytes = _optional_bool_value(
        selected.get("strict_bytes"),
        "wire.strict_bytes",
    )
    mutable_fields = _string_list_value(
        selected.get("mutable_fields", []),
        "wire.mutable_fields",
    )
    metadata = _json_object(selected.get("metadata", {}), "wire.metadata")
    return CorpusEligibility(
        eligible=bool(selected.get("eligible")),
        reason=_first_reason(reasons),
        skip_reasons=reasons,
        compare_root=compare_root,
        strict_bytes=strict_bytes,
        mutable_fields=mutable_fields,
        metadata={
            **metadata,
            "provider": selected_provider,
            "provider_profiles": profile_decisions,
        },
    )


def _wire_profile_decision(
    plan: PacketPlan,
    backend: str,
    *,
    capabilities: Mapping[str, object],
) -> JSONObject:
    required = ("encode", "decode", "live_endpoint")
    missing = _missing_backend_capabilities(backend, required)
    reasons: list[str] = []
    if missing:
        reasons.append(SKIP_BACKEND_UNSUPPORTED)
    if not _capability_bool(capabilities, "live_packet_exchange"):
        reasons.append(SKIP_PROVIDER_CAPABILITY_UNAVAILABLE)
    if _requires_ipv4(plan) and not _capability_bool(capabilities, "ipv4"):
        reasons.append(SKIP_REQUIRES_IPV4)
    if _requires_ipv6(plan) and not _capability_bool(capabilities, "ipv6"):
        reasons.append(SKIP_REQUIRES_IPV6)
    if _requires_l2(plan) and not _capability_bool(capabilities, "l2"):
        reasons.append(SKIP_REQUIRES_L2)
    if _requires_broadcast(plan) and not _capability_bool(capabilities, "broadcast"):
        reasons.append(SKIP_REQUIRES_BROADCAST)
    if _requires_provider_mac(plan) and not _capability_bool(capabilities, "provider_mac"):
        reasons.append(SKIP_REQUIRES_PROVIDER_MAC)
    if _requires_controlled_service(plan) and not _capability_bool(
        capabilities,
        "controlled_service",
    ):
        reasons.append(SKIP_REQUIRES_CONTROLLED_SERVICE)
    if _is_wire_provider_unsafe_feature(plan):
        reasons.append(SKIP_PROVIDER_CAPABILITY_UNAVAILABLE)

    reasons = _unique_strings(reasons)
    provider = str(capabilities.get("provider", "unknown"))
    policy = wire_comparison_policy(plan, provider=provider)
    mutable_fields = _string_list_value(
        policy.get("mutable_fields", []),
        "wire.mutable_fields",
    )
    compare_root = _optional_string_value(
        policy.get("compare_root"),
        "wire.compare_root",
    )
    strict_bytes = _optional_bool_value(
        policy.get("strict_bytes"),
        "wire.strict_bytes",
    )
    return {
        "provider": provider,
        "eligible": not reasons,
        "reason": _first_reason(reasons),
        "skip_reasons": reasons,
        "compare_root": compare_root,
        "strict_bytes": strict_bytes,
        "mutable_fields": mutable_fields,
        "metadata": {
            "required_backend_capabilities": list(required),
            "missing_backend_capabilities": missing,
            "backend_capabilities": _enabled_backend_capabilities(backend),
            "capabilities": _wire_capability_metadata(capabilities),
            "root": _packet_root(plan),
            "stack": list(plan.stack),
            "family": plan.family,
            "case": plan.case,
            "feature_tags": list(plan.feature_tags),
            "requirements": {
                "ipv4": _requires_ipv4(plan),
                "ipv6": _requires_ipv6(plan),
                "l2": _requires_l2(plan),
                "broadcast": _requires_broadcast(plan),
                "provider_mac": _requires_provider_mac(plan),
                "controlled_service": _requires_controlled_service(plan),
            },
            "mutation_policy": policy,
        },
    }


def _wire_provider_capability_profiles(
    provider_capabilities: Mapping[str, object] | None,
) -> dict[str, JSONObject]:
    profiles = {
        name: dict(profile)
        for name, profile in _WIRE_PROVIDER_CAPABILITY_PROFILES.items()
    }
    if provider_capabilities is None:
        return profiles

    if isinstance(provider_capabilities.get("provider"), str):
        provider = str(provider_capabilities["provider"])
        base = profiles.get(provider, {"provider": provider})
        profiles[provider] = {
            **base,
            **json_object(provider_capabilities, "provider_capabilities"),
        }
        return profiles

    for provider, raw_profile in provider_capabilities.items():
        if not isinstance(provider, str) or not isinstance(raw_profile, Mapping):
            continue
        base = profiles.get(provider, {"provider": provider})
        profiles[provider] = {
            **base,
            **json_object(raw_profile, f"provider_capabilities.{provider}"),
        }
    return profiles


def _wire_capability_metadata(capabilities: Mapping[str, object]) -> JSONObject:
    keys = (
        "provider",
        "live_packet_exchange",
        "ipv4",
        "ipv6",
        "l2",
        "broadcast",
        "provider_mac",
        "controlled_service",
    )
    return {
        key: coerce_json_value(capabilities[key])
        for key in keys
        if key in capabilities
    }


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


def _requires_ipv4(plan: PacketPlan) -> bool:
    root = _packet_root(plan)
    return root == "l3:ipv4" or plan.family == "ipv4" or "ipv4" in plan.stack


def _requires_ipv6(plan: PacketPlan) -> bool:
    root = _packet_root(plan)
    return root == "l3:ipv6" or plan.family == "ipv6" or bool(
        set(plan.stack).intersection({"ipv6", "icmpv6", "ipv6_fragment", "ipv6_routing"})
    )


def _requires_l2(plan: PacketPlan) -> bool:
    root = _packet_root(plan)
    return bool(root and root.startswith("link:")) or bool(
        set(plan.stack).intersection(
            {
                "ethernet",
                "vlan",
                "arp",
                "dhcp",
                "linux_cooked",
                "null_loopback",
            }
        )
    )


def _requires_broadcast(plan: PacketPlan) -> bool:
    if set(plan.stack).intersection({"arp", "dhcp"}):
        return True
    return _fields_contain_value(
        plan.fields,
        {
            "ff:ff:ff:ff:ff:ff",
            "255.255.255.255",
            "broadcast",
        },
    )


def _requires_provider_mac(plan: PacketPlan) -> bool:
    return bool(
        set(plan.stack).intersection(
            {
                "ethernet",
                "vlan",
                "arp",
                "dhcp",
                "linux_cooked",
            }
        )
    )


def _requires_controlled_service(plan: PacketPlan) -> bool:
    case = (plan.case or "").replace("_", "-")
    if "dhcp" in plan.stack:
        return True
    if "dns" in plan.stack and "response" in case:
        return True
    if "tcp" in plan.stack and ("open" in case or "service" in case):
        return True
    return False


def _is_wire_provider_unsafe_feature(plan: PacketPlan) -> bool:
    if bool(plan.metadata.get("malformed")):
        return True
    return bool(set(plan.feature_tags).intersection({"malformed", "non_strict_reencode"}))


def wire_comparison_policy(
    plan: PacketPlan,
    *,
    provider: str = _WIRE_DEFAULT_PROVIDER,
) -> JSONObject:
    """Return the wire byte-comparison policy for a packet and provider."""

    compare_root = _wire_compare_root(plan)
    mutable_fields = _wire_mutable_fields(plan, provider=provider)
    byte_mutable_fields = _wire_byte_mutable_fields(plan, provider=provider)
    strict_bytes = bool(plan.strict_bytes and not byte_mutable_fields)
    return {
        "provider": provider,
        "compare_root": compare_root,
        "strict_bytes": strict_bytes,
        "mutable_fields": mutable_fields,
        "byte_mutable_fields": byte_mutable_fields,
        "transit_mutations": _wire_transit_mutations(plan, provider=provider),
    }


def _wire_compare_root(plan: PacketPlan) -> str | None:
    root = _packet_root(plan)
    if root is not None:
        return root
    if _requires_ipv4(plan):
        return "l3:ipv4"
    if _requires_ipv6(plan):
        return "l3:ipv6"
    return None


def _wire_mutable_fields(
    plan: PacketPlan,
    *,
    provider: str = _WIRE_DEFAULT_PROVIDER,
) -> list[str]:
    fields: list[str] = []
    if provider != "hetzner":
        return fields
    if "ipv4" in plan.stack:
        fields.extend(["ipv4.ttl", "ipv4.checksum"])
    if _wire_provider_adds_link_layer_metadata(plan, provider=provider):
        fields.extend(["ethernet.src", "ethernet.dst", "ethernet.ethertype"])
    return _unique_strings(fields)


def _wire_transit_mutations(
    plan: PacketPlan,
    *,
    provider: str = _WIRE_DEFAULT_PROVIDER,
) -> list[JSONObject]:
    mutations: list[JSONObject] = []
    if provider != "hetzner":
        return mutations
    if "ipv4" in plan.stack:
        mutations.extend(
            [
                {
                    "field": "ipv4.ttl",
                    "reason": "provider live transit may decrement TTL before capture",
                },
                {
                    "field": "ipv4.checksum",
                    "reason": "IPv4 header checksum follows provider TTL mutation",
                },
            ]
        )
    if _wire_provider_adds_link_layer_metadata(plan, provider=provider):
        mutations.append(
            {
                "field": "ethernet.*",
                "reason": "provider capture may expose Ethernet metadata around an L3 send",
                "covered_fields": ["ethernet.src", "ethernet.dst", "ethernet.ethertype"],
            }
        )
    return mutations


def _wire_byte_mutable_fields(
    plan: PacketPlan,
    *,
    provider: str = _WIRE_DEFAULT_PROVIDER,
) -> list[str]:
    compare_root = _wire_compare_root(plan) or ""
    return [
        field
        for field in _wire_mutable_fields(plan, provider=provider)
        if _wire_mutable_field_affects_compare_bytes(field, compare_root)
    ]


def _wire_mutable_field_affects_compare_bytes(field: str, compare_root: str) -> bool:
    layer = field.split(".", 1)[0]
    if compare_root.startswith("l3:"):
        return layer not in {"ethernet", "linux_cooked", "null_loopback"}
    if compare_root.startswith("link:"):
        return True
    return True


def _wire_provider_adds_link_layer_metadata(
    plan: PacketPlan,
    *,
    provider: str,
) -> bool:
    return provider == "hetzner" and (_wire_compare_root(plan) or "").startswith("l3:")


def _fields_contain_value(value: object, needles: set[str]) -> bool:
    if isinstance(value, str):
        return value.lower() in needles
    if isinstance(value, Mapping):
        return any(_fields_contain_value(item, needles) for item in value.values())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_fields_contain_value(item, needles) for item in value)
    return False


def _capability_bool(capabilities: Mapping[str, object], key: str) -> bool:
    return bool(capabilities.get(key))


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


def _wire_provider_eligibility_counts(
    packets: Sequence[CorpusPacket],
) -> dict[str, dict[str, int] | dict[str, dict[str, int]]]:
    eligible: dict[str, int] = {}
    skipped: dict[str, int] = {}
    skip_reasons: dict[str, dict[str, int]] = {}
    for packet in packets:
        profiles = packet.wire.metadata.get("provider_profiles")
        if not isinstance(profiles, Mapping):
            continue
        for provider, raw_decision in profiles.items():
            if not isinstance(provider, str) or not isinstance(raw_decision, Mapping):
                continue
            decision = _json_object(raw_decision, f"wire.provider_profiles.{provider}")
            if bool(decision.get("eligible")):
                eligible[provider] = eligible.get(provider, 0) + 1
                continue
            skipped[provider] = skipped.get(provider, 0) + 1
            reasons = _string_list_value(
                decision.get("skip_reasons", []),
                f"wire.provider_profiles.{provider}.skip_reasons",
            )
            if not reasons:
                reasons = [SKIP_PROVIDER_CAPABILITY_UNAVAILABLE]
            provider_counts = skip_reasons.setdefault(provider, {})
            for reason in reasons:
                provider_counts[reason] = provider_counts.get(reason, 0) + 1
    return {
        "eligible": eligible,
        "skipped": skipped,
        "skip_reasons": skip_reasons,
    }


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
        direction=_required_string(plan, "direction", name),
        family=optional_string(plan.get("family")),
        feature_tags=_string_list_value(plan.get("feature_tags", []), f"{name}.feature_tags"),
        case=optional_string(plan.get("case")),
        strict_bytes=strict_bytes,
        metadata=_json_object(plan.get("metadata", {}), f"{name}.metadata"),
    )


def _selected_specs_from_packets(packets: Sequence[CorpusPacket]) -> list[str]:
    specs: list[str] = []
    for packet in packets:
        raw_specs = packet.plan.metadata.get("selected_specs", [])
        if isinstance(raw_specs, Sequence) and not isinstance(raw_specs, (str, bytes, bytearray)):
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


def _optional_string_value(value: object, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise CorpusFormatError(f"{name} must be a string or null")
    return value


def _optional_bool_value(value: object, name: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise CorpusFormatError(f"{name} must be a boolean or null")
    return value


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
