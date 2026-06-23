"""Deterministic packet plan generation primitives for oracle."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import random
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from .model import JSONObject, PacketPlan
from .sampling import (
    EPHEMERAL_PORT_MAX,
    EPHEMERAL_PORT_MIN,
    T,
    _ICMP_EXTENSION_BYTES,
    _ICMP_MPLS_EXTENSION_BYTES,
    _ICMP_QUOTED_IPV4_DATAGRAM,
    _SKIP_FIELD,
    _SamplingContext,
    _SkipField,
    _string_or_none,
    _declared_ethertype_for_stack,
    _different_ipv4,
    _different_ipv6,
    _different_mac,
    _different_port,
    _field_bits,
    _identifier_part,
    _integer_domain_value,
    _IPV4_DOCUMENTATION_NETWORKS,
    _IPV6_DOCUMENTATION_NETWORK,
    _ipv6_next_header_for_stack,
    _json_object,
    _next_layer_after,
    _object,
    _object_list,
    _payload_hex_from_fields,
    _string_list,
    _udp_option_checksum_intent,
    _udp_options_field,
    _udp_options_items,
    bounded_int,
    byte_payload,
    documentation_ipv4,
    documentation_ipv6,
    documentation_mac,
    ephemeral_port,
    plan_identifier,
    weighted_choice,
)
from .spec_loader import load_oracle_specs
# Importing the protocols package runs its ``autodiscover`` so every per-protocol
# sampler module self-registers; ``SAMPLER_REGISTRY`` is then consulted before the
# legacy sampling/feature branches below. No protocol is migrated yet, so the
# registry is empty and every layer falls through to the legacy code.
from .protocols import SAMPLER_REGISTRY
# The IGMP case/behavior mapping helpers moved to the IGMP sampler plugin
# (``protocols/igmp.py``) along with the IGMP behaviors. They are re-imported here
# because the generator's ``generate_plan`` and ``_choose_behavior`` orchestration
# still call them to map an IGMP case onto its feature/behavior (the same
# co-locate-and-re-import pattern as the IPv6 ext-header builders in ``packets``).
from .protocols.igmp import _igmp_behavior_for_case, _igmp_feature_for_case
# ``_apply_bgp_behavior`` moved to the BGP sampler plugin (``protocols/bgp.py``)
# with the rest of the BGP feature behavior. It is re-imported here because the
# focused bgp-smoke profile path in ``generate_plan`` calls it directly (with
# ``behavior=""``) outside the registry feature loop, the same co-locate-and-
# re-import pattern as the IGMP case/behavior helpers above.
from .protocols.bgp import _apply_bgp_behavior
# ``_apply_ospf_behavior`` moved to the OSPF sampler plugin (``protocols/ospf.py``)
# with the rest of the OSPF body injection. It is re-imported here because the
# focused ospf-smoke profile path in ``generate_plan`` calls it directly (with
# ``behavior=""``) outside the registry feature loop, the same co-locate-and-
# re-import pattern as the BGP body injector above. OSPF has no feature behavior,
# so only this smoke-path entry point is re-imported.
from .protocols.ospf import _apply_ospf_behavior
# ``_apply_rip_behavior`` and ``_rip_command_for_case`` moved to the RIP sampler
# plugin (``protocols/rip.py``) with the rest of the RIP feature behavior. They are
# re-imported here because the focused rip-smoke profile path in ``generate_plan``
# calls ``_apply_rip_behavior`` directly (with ``behavior=""``) outside the registry
# feature loop — the same co-locate-and-re-import pattern as the BGP/OSPF body
# injectors above.
from .protocols.rip import _apply_rip_behavior, _rip_command_for_case
# ``_apply_ripng_behavior`` moved to the RIPng sampler plugin
# (``protocols/ripng.py``) with the rest of the RIPng feature behavior. It is
# re-imported here because the focused rip-smoke profile path in ``generate_plan``
# calls it directly (with ``behavior=""``) outside the registry feature loop, the
# same co-locate-and-re-import pattern as ``_apply_rip_behavior`` above.
from .protocols.ripng import _apply_ripng_behavior
# ``_dns_behavior_emits_raw`` moved to the DNS sampler plugin
# (``protocols/dns.py``) with the rest of the DNS sampler and ``dns_behavior``
# feature behavior. It is re-imported here because the generic name-selection code
# in ``_select_behavior_name`` (which stays in the generator) still calls it to
# avoid pairing a typed case with a compressed raw-byte builder only the reference
# backend can encode — the same co-locate-and-re-import pattern as the
# BGP/OSPF/RIP body injectors above.
from .protocols.dns import _dns_behavior_emits_raw
# ``DHCP_OPTION_MATRIX_TOKENS`` moved to the DHCP sampler plugin
# (``protocols/dhcp.py``) with the rest of the DHCP sampler and ``dhcp_behavior``
# feature behavior. It is re-imported here because
# ``tools/oracle/tests/test_dhcp_oracle.py`` imports it from ``generator`` to pin
# the cross-backend option matrix — the same co-locate-and-re-import pattern as
# the DNS ``_dns_behavior_emits_raw`` helper above.
from .protocols.dhcp import DHCP_OPTION_MATRIX_TOKENS
# The ``radiotap`` / ``dot11`` / ``eapol`` / ``rsn`` samplers and the
# ``_rsn_information_value_hex`` helper all live in the Wi-Fi sampler plugin
# (``protocols/wifi.py``); the generator reaches them through ``SAMPLER_REGISTRY``
# and no longer re-imports any 802.11 helper.


SUPPORTED_LAYER_BACKEND = "libcrafter"

_DERIVED_DOMAINS = {"derived"}

def _supported_fields(layer: str) -> frozenset[str]:
    """Return the fields the generator samples for ``layer``.

    Every layer declares its field allowlist on its registered
    :class:`~.protocols.base.ProtocolSampler` (``supported_fields``); the registry
    is the sole source. An unregistered layer is a spec error and
    :meth:`~.plugin_registry.PluginRegistry.require` raises.
    """

    return SAMPLER_REGISTRY.require(layer).supported_fields


_SUPPORTED_FIELD_DOMAINS: dict[tuple[str, str], set[object]] = {
    ("dns", "answers"): set(),
    ("icmp", "type"): {"echo_reply", "echo_request"},
    ("icmpv6", "type"): {"echo_reply", "echo_request"},
    ("ipv4", "options"): {
        "eol",
        "nop",
        "record_route",
        "loose_source_route",
        "timestamp",
        "traceroute",
        "generic",
    },
    ("tcp", "options"): {
        "eol",
        "nop",
        "mss",
        "window_scale",
        "sack_permitted",
        "sack_blocks",
        "timestamp",
        "mptcp",
        "fast_open",
        "edo",
        "generic",
    },
    ("udp", "checksum"): {"zero_ipv4"},
    ("udp", "options"): {
        "known",
        "ocs",
        "apc",
        "unknown_safe",
        "unknown_unsafe",
        "unsupported_frag",
        "surplus_application_boundary",
    },
}
_SCAPY_MATERIALIZED_LAYERS = {
    "arp",
    "dhcp",
    "dot11",
    "dot15d4",
    "dot15d4_radio",
    "eapol",
    "dns",
    "ethernet",
    "icmp",
    "icmpv6",
    "ipv4",
    "ipv6",
    "llc_snap",
    "ospf",
    "payload",
    "radiotap",
    "rsn",
    "tcp",
    "udp",
    "vlan",
    "bgp",
    "zigbee_aps",
    "zigbee_nwk",
}


def load_stack_grammar(path: str | Path | None = None) -> JSONObject:
    """Load the executable YAML specs as generator grammar."""

    spec_root = None if path is None else Path(path)
    specs = load_oracle_specs(spec_root)
    return {
        "version": 1,
        "roots": {
            root.name: {
                "layers": list(root.layers),
                "families": list(root.families),
            }
            for root in specs.roots.values()
        },
        "families": {
            family.name: {
                "stack": list(family.default_stack),
                "feature_tags": list(family.feature_tags),
            }
            for family in specs.families.values()
        },
        "stacks": {
            stack.name: {
                "name": stack.name,
                "root": stack.root,
                "layers": list(stack.layers),
                "coverage_cases": list(stack.coverage_cases),
                "families": _stack_families(stack.layers, specs.roots[stack.root].families),
            }
            for stack in specs.stacks.values()
        },
        "profiles": {
            profile.name: {
                "default_count": profile.default_count,
                "family_weights": [
                    {"name": weight.name, "weight": weight.weight}
                    for weight in profile.family_weights
                ],
                "payload_length": profile.payload_length.as_pair(),
                "feature_weights": dict(profile.feature_weights),
            }
            for profile in specs.profiles.values()
        },
        "layers": {
            layer.name: {
                "name": layer.name,
                "fields": [
                    _layer_field_grammar(layer.raw, field.name, field.field_type, field.required, field.domains)
                    for field in layer.fields
                ],
                "coverage_cases": list(layer.coverage_cases),
                "backend_support": {
                    name: {
                        "status": support.status,
                        "encode": support.encode,
                        "decode": support.decode,
                    }
                    for name, support in layer.backend_support.items()
                },
            }
            for layer in specs.layers.values()
        },
        "features": {
            feature.name: {
                "name": feature.name,
                "layers": list(feature.layers),
                "directions": list(feature.directions),
                "strict_bytes": feature.strict_bytes,
                "malformed": feature.malformed,
                "coverage_cases": list(feature.coverage_cases),
                "behaviors": list(_object_list(feature.raw.get("behaviors", []), "feature.behaviors")),
                "supported_cases": list(
                    _object_list(feature.raw.get("supported_cases", []), "feature.supported_cases")
                ),
                "live_matrix": list(_object_list(feature.raw.get("live_matrix", []), "feature.live_matrix")),
                "categories": _feature_categories(
                    feature.name,
                    feature.directions,
                    feature.malformed,
                    feature.coverage_cases,
                ),
            }
            for feature in specs.features.values()
        },
    }


def case_byte_policy_index(path: str | Path | None = None) -> dict[str, str]:
    """Map each declared supported case to its byte policy.

    Built from every feature's ``supported_cases`` block so other oracle modes
    (pcap eligibility in particular) can honor the same per-case byte policy the
    generator reads. Cases without a ``supported_cases`` entry are absent from
    the map; cases that declare no ``byte_policy`` are absent as well. The result
    is data-driven from the specs, never a hardcoded case list.
    """

    grammar = load_stack_grammar(path)
    features = grammar.get("features", {})
    index: dict[str, str] = {}
    if not isinstance(features, Mapping):
        return index
    for raw_feature in features.values():
        if not isinstance(raw_feature, Mapping):
            continue
        supported = raw_feature.get("supported_cases", [])
        if not isinstance(supported, Sequence) or isinstance(supported, (str, bytes)):
            continue
        for raw_case in supported:
            if not isinstance(raw_case, Mapping):
                continue
            name = raw_case.get("name")
            byte_policy = raw_case.get("byte_policy")
            if isinstance(name, str) and isinstance(byte_policy, str):
                index[name] = byte_policy
    return index


def _layer_field_grammar(
    layer_raw: JSONObject,
    name: str,
    field_type: str,
    required: bool,
    domains: Sequence[object],
) -> JSONObject:
    output: JSONObject = {
        "name": name,
        "type": field_type,
        "required": required,
        "domains": list(domains),  # type: ignore[list-item]
    }
    raw_fields = layer_raw.get("fields", [])
    if isinstance(raw_fields, list):
        for raw_field in raw_fields:
            if not isinstance(raw_field, Mapping) or raw_field.get("name") != name:
                continue
            for key in ("profile_domains", "profiles", "sampling"):
                if key in raw_field:
                    output[key] = raw_field[key]  # type: ignore[assignment]
            break
    return output


class PacketGenerator:
    """Seeded packet plan generator independent of any backend."""

    def __init__(
        self,
        *,
        seed: int,
        profile: str,
        backend: str = "scapy",
        grammar: Mapping[str, object] | None = None,
    ) -> None:
        self.grammar = _json_object(load_stack_grammar() if grammar is None else grammar)
        profiles = _object(self.grammar.get("profiles"), "profiles")
        if profile not in profiles:
            raise ValueError(f"unsupported profile: {profile}")
        self.seed = seed
        self.profile = profile
        self.backend = backend

    def generate(
        self,
        *,
        index: int,
        root: str | None = None,
        family: str | None = None,
        case: str | None = None,
        feature: str | None = None,
        direction: str = "reference_to_libcrafter",
    ) -> PacketPlan:
        if index < 0:
            raise ValueError(f"index must be non-negative: {index}")

        rng = random.Random(
            _derive_seed(
                self.seed,
                self.profile,
                index,
                root,
                family,
                case,
                feature,
                direction,
            )
        )
        selected_stack = self._choose_stack(
            index=index,
            root=root,
            family=family,
            case=case,
            feature=feature,
            direction=direction,
        )
        stack_name = _string(selected_stack.get("name"), "stack.name")
        selected_root = _string(selected_stack.get("root"), f"stacks.{stack_name}.root")
        stack = _string_list(selected_stack.get("layers"), f"stacks.{stack_name}.layers")
        stack_families = _string_list(
            selected_stack.get("families", []),
            f"stacks.{stack_name}.families",
        )
        selected_family = self._selected_family(stack_families, family, stack)
        selected_case = case or self._choose_case(
            rng,
            selected_stack,
            feature,
            family=selected_family,
            direction=direction,
        )
        selected_feature = self._choose_feature(
            rng,
            stack=stack,
            case=selected_case,
            feature=feature,
            direction=direction,
        )
        if selected_feature is None:
            selected_feature = _igmp_feature_for_case(selected_case)
        strict_bytes = self._strict_bytes(selected_feature)
        feature_tags = self._feature_tags(
            stack=stack,
            family=selected_family,
            feature=selected_feature,
        )

        fields = self._fields(
            rng,
            stack,
            feature=selected_feature,
            case=selected_case,
        )
        behavior = self._feature_behavior(
            rng,
            feature=selected_feature,
            case=selected_case,
        )
        if behavior is not None:
            self._apply_feature_behavior(
                fields,
                stack=stack,
                feature=selected_feature,
                case=selected_case,
                behavior=behavior,
            )
        elif _is_bgp_smoke_case(selected_case) and "bgp" in fields:
            _apply_bgp_behavior(fields, stack=stack, case=selected_case, behavior="")
        elif _is_rip_smoke_case(selected_case) and "rip" in fields:
            _apply_rip_behavior(fields, stack=stack, case=selected_case, behavior="")
        elif _is_rip_smoke_case(selected_case) and "ripng" in fields:
            _apply_ripng_behavior(fields, stack=stack, case=selected_case, behavior="")
        elif _is_ospf_smoke_case(selected_case) and "ospf" in fields:
            _apply_ospf_behavior(fields, stack=stack, case=selected_case, behavior="")
        live_behavior = self._apply_icmp_live_fields(
            rng,
            fields,
            feature=selected_feature,
            case=selected_case,
        )
        if live_behavior is not None:
            behavior = live_behavior
        feature_tags = self._augment_feature_tags(
            feature_tags,
            feature=selected_feature,
            case=selected_case,
            behavior=behavior,
        )
        feature_metadata = self._feature_metadata(
            fields,
            stack=stack,
            feature=selected_feature,
            case=selected_case,
            behavior=behavior,
        )
        malformed = self._is_malformed_case(selected_feature, selected_case)
        if malformed:
            strict_bytes = False
            feature_tags = list(dict.fromkeys([*feature_tags, "malformed", "non_strict_reencode"]))
        plan_id = plan_identifier(
            seed=self.seed,
            profile=self.profile,
            index=index,
            root=selected_root,
            stack_name=stack_name,
            family=selected_family,
            case=selected_case,
            feature=selected_feature,
        )
        reproduction = {
            "seed": self.seed,
            "profile": self.profile,
            "index": index,
            "count": 1,
            "root": selected_root,
            "family": selected_family,
            "case": selected_case,
            "feature": selected_feature,
            "direction": direction,
        }

        selected_specs = [
            "tools/oracle/specs/stacks.yaml",
            "tools/oracle/specs/profiles.yaml",
            f"root:{selected_root}",
            f"stack:{stack_name}",
            f"case:{selected_case}",
        ]
        if selected_feature is not None:
            selected_specs.append(f"feature:{selected_feature}")

        return PacketPlan(
            stack=stack,
            fields=fields,
            profile=self.profile,
            seed=self.seed,
            index=index,
            direction=direction,
            family=selected_family,
            feature_tags=feature_tags,
            case=selected_case,
            strict_bytes=strict_bytes,
            metadata={
                "plan_id": plan_id,
                "generator": "oracle.seeded.v1",
                "root": selected_root,
                "root_decoder": selected_root,
                "stack_name": stack_name,
                "stack_families": stack_families,
                "feature": selected_feature,
                "feature_behavior": behavior,
                "malformed": malformed,
                **feature_metadata,
                "selected_specs": selected_specs,
                "strict_bytes": strict_bytes,
                "comparison_policy": "non_strict_reencode" if malformed else "strict_reencode",
                "reproduction": reproduction,
            },
        )

    def _choose_stack(
        self,
        *,
        index: int,
        root: str | None,
        family: str | None,
        case: str | None,
        feature: str | None,
        direction: str,
    ) -> JSONObject:
        candidates = self._stack_candidates(
            root=root,
            family=family,
            case=case,
            feature=feature,
            direction=direction,
        )
        if not candidates:
            detail = []
            if root is not None:
                detail.append(f"root={root!r}")
            if family is not None:
                detail.append(f"family={family!r}")
            if case is not None:
                detail.append(f"case={case!r}")
            if feature is not None:
                detail.append(f"feature={feature!r}")
            joined = " ".join(detail) or "current filters"
            raise ValueError(f"no stack specs match {joined}")

        deck = self._stack_deck(candidates)
        if not deck:
            raise ValueError("no stack specs have positive sampling weight")
        return deck[index % len(deck)]

    def _stack_candidates(
        self,
        *,
        root: str | None,
        family: str | None,
        case: str | None,
        feature: str | None,
        direction: str,
    ) -> list[JSONObject]:
        roots = _object(self.grammar.get("roots"), "roots")
        if root is not None and root not in roots:
            raise ValueError(f"unsupported root: {root}")

        families = _object(self.grammar.get("families"), "families")
        profile_family_names = set(self._family_weights())
        if family is not None and family not in families and family not in profile_family_names:
            all_families = {
                item
                for stack in _object(self.grammar.get("stacks"), "stacks").values()
                for item in _string_list(
                    _object(stack, "stack").get("families", []),
                    "stack.families",
                )
            }
            if family not in all_families:
                raise ValueError(f"unsupported family: {family}")

        feature_spec = self._feature_spec(feature) if feature is not None else None
        stacks = _object(self.grammar.get("stacks"), "stacks")
        candidates: list[JSONObject] = []
        for raw_stack in stacks.values():
            stack = _object(raw_stack, "stack")
            stack_layers = _string_list(stack.get("layers"), "stack.layers")
            stack_root = _string(stack.get("root"), "stack.root")
            stack_families = _string_list(stack.get("families", []), "stack.families")
            coverage_cases = _string_list(
                stack.get("coverage_cases", []),
                "stack.coverage_cases",
            )

            if root is not None and stack_root != root:
                continue
            if family is not None and family not in stack_families:
                continue
            if case is not None and case not in coverage_cases:
                continue
            if feature_spec is not None:
                feature_layers = _string_list(feature_spec.get("layers"), "feature.layers")
                feature_directions = _string_list(
                    feature_spec.get("directions"),
                    "feature.directions",
                )
                if not _layers_cover_feature(stack_layers, feature_layers):
                    continue
                if direction not in feature_directions and "roundtrip" not in feature_directions:
                    continue
            if (
                feature is None
                and case is None
                and root is None
                and family is None
                and self.profile == "smoke"
            ):
                if stack_layers not in (
                    ["ipv4", "udp", "payload"],
                    ["ipv6", "udp", "payload"],
                    ["ble_radio", "ble_adv"],
                ):
                    continue
            if (
                feature is None
                and case is None
                and root is None
                and family is None
                and self.profile in {
                    "dot11-smoke",
                    "radiotap-smoke",
                    "dot11-pcap",
                    "eapol-smoke",
                    "rsn-smoke",
                    "bgp-smoke",
                    "ospf-smoke",
                    *_IPSEC_SMOKE_PROFILES,
                }
            ):
                profile_families = set(profile_family_names)
                if not profile_families.intersection(stack_families):
                    continue
            if feature is None and case is None and self.profile == "smoke" and "dhcp" in stack_layers:
                continue
            if (
                feature is None
                and case is None
                and self.profile == "tcp-header"
                and not _has_tcp_header_case(coverage_cases)
            ):
                continue
            if (
                feature is None
                and case is None
                and self.profile == "tcp-options"
                and not _has_tcp_options_case(coverage_cases)
            ):
                continue
            if (
                feature is None
                and case is None
                and self.profile == "tcp-smoke"
                and not _has_tcp_smoke_case(coverage_cases)
            ):
                continue
            if (
                feature is None
                and case is None
                and self.profile == "bgp-smoke"
                and not _has_bgp_smoke_case(coverage_cases)
            ):
                continue
            if (
                feature is None
                and case is None
                and self.profile == "rip-smoke"
                and not _has_rip_smoke_case(coverage_cases)
            ):
                continue
            if (
                feature is None
                and case is None
                and self.profile == "ospf-smoke"
                and not _has_ospf_smoke_case(coverage_cases)
            ):
                continue
            if (
                feature is None
                and case is None
                and self.profile == "ipv4-enrichment"
                and not _has_ipv4_enrichment_case(coverage_cases, self.grammar)
            ):
                continue
            if (
                feature is None
                and case is None
                and self.profile == "ipv6-enrichment"
                and not _has_ipv6_enrichment_case(coverage_cases)
            ):
                continue
            if (
                feature is None
                and case is None
                and self.profile in _IP_FRAGMENT_SMOKE_PROFILES
                and not _has_ip_fragment_smoke_case(coverage_cases)
            ):
                continue
            candidates.append(stack)
        return candidates

    def _stack_deck(self, stacks: Sequence[JSONObject]) -> list[JSONObject]:
        if self.profile == "ipv6-enrichment":
            deck: list[JSONObject] = []
            for stack in stacks:
                coverage_cases = _string_list(
                    stack.get("coverage_cases", []),
                    "stack.coverage_cases",
                )
                for case in coverage_cases:
                    if not _is_ipv6_enrichment_case(case):
                        continue
                    deck.append({**stack, "coverage_cases": [case]})
            if deck:
                return deck
        if self.profile in _IP_FRAGMENT_SMOKE_PROFILES:
            deck = []
            for stack in stacks:
                coverage_cases = _string_list(
                    stack.get("coverage_cases", []),
                    "stack.coverage_cases",
                )
                for case in coverage_cases:
                    if not _is_ip_fragment_smoke_case(case):
                        continue
                    deck.append({**stack, "coverage_cases": [case]})
            if deck:
                return deck

        weighted: list[JSONObject] = []
        for stack in stacks:
            weight = self._stack_weight(stack)
            weighted.extend([stack] * weight)

        seed = _derive_deck_seed(
            self.seed,
            self.profile,
            [_string(stack.get("name"), "stack.name") for stack in stacks],
        )
        rng = random.Random(seed)
        rng.shuffle(weighted)
        return weighted

    def _stack_weight(self, stack: JSONObject) -> int:
        family_weights = self._family_weights()
        feature_weights = self._profile_feature_weights()
        stack_families = _string_list(stack.get("families", []), "stack.families")
        coverage_cases = _string_list(stack.get("coverage_cases", []), "stack.coverage_cases")
        weight = sum(family_weights.get(family, 0) for family in stack_families)
        if weight <= 0:
            weight = 1

        categories = _case_categories(coverage_cases)
        category_weight = max((feature_weights.get(category, 0) for category in categories), default=1)
        return max(1, weight * max(1, category_weight))

    def _family_weights(self) -> dict[str, int]:
        profiles = _object(self.grammar.get("profiles"), "profiles")
        profile_spec = _object(profiles.get(self.profile), f"profiles.{self.profile}")
        raw_weights = profile_spec.get("family_weights")
        if raw_weights is None:
            raise ValueError(f"profiles.{self.profile}.family_weights is required")

        weights: dict[str, int] = {}
        if not isinstance(raw_weights, Sequence) or isinstance(raw_weights, (str, bytes)):
            raise ValueError("family_weights must be a list")
        for item in raw_weights:
            item_obj = _object(item, "family_weights item")
            name = item_obj.get("name")
            weight = item_obj.get("weight")
            if not isinstance(name, str) or not isinstance(weight, int):
                raise ValueError("family_weights entries require string name and integer weight")
            weights[name] = weight
        return weights

    def _profile_feature_weights(self) -> dict[str, int]:
        profiles = _object(self.grammar.get("profiles"), "profiles")
        profile_spec = _object(profiles.get(self.profile), f"profiles.{self.profile}")
        raw_weights = _object(profile_spec.get("feature_weights"), "feature_weights")
        weights: dict[str, int] = {}
        for name, weight in raw_weights.items():
            if not isinstance(weight, int):
                raise ValueError("feature_weights entries must be integers")
            weights[name] = weight
        return weights

    def _selected_family(
        self,
        stack_families: Sequence[str],
        requested_family: str | None,
        stack: Sequence[str],
    ) -> str:
        if requested_family is not None:
            return requested_family
        family_weights = self._family_weights()
        for family in family_weights:
            if family in stack_families:
                return family
        if stack_families:
            return stack_families[0]
        for layer in stack:
            if layer in {"ipv4", "ipv6", "arp", "dns", "dhcp"}:
                return layer
        return "link"

    def _feature_tags(
        self,
        *,
        stack: Sequence[str],
        family: str,
        feature: str | None,
    ) -> list[str]:
        tags = ["baseline", family, *stack]
        if feature is not None:
            tags.append(feature)
            tags.extend(self._feature_categories(feature))
        return list(dict.fromkeys(tags))

    def _augment_feature_tags(
        self,
        tags: Sequence[str],
        *,
        feature: str | None,
        case: str,
        behavior: str | None,
    ) -> list[str]:
        output = list(tags)
        if feature == "udp_options":
            output.extend(_udp_option_feature_tags(case, behavior))
        return list(dict.fromkeys(output))

    def _feature_metadata(
        self,
        fields: Mapping[str, JSONObject],
        *,
        stack: Sequence[str],
        feature: str | None,
        case: str,
        behavior: str | None,
    ) -> JSONObject:
        if feature == "udp_options":
            return {
                "udp_options": _udp_options_metadata(
                    fields,
                    stack=stack,
                    case=case,
                    behavior=behavior,
                )
            }
        return {}

    def _choose_case(
        self,
        rng: random.Random,
        stack: JSONObject,
        feature: str | None,
        *,
        family: str | None,
        direction: str,
    ) -> str:
        coverage_cases = _string_list(stack.get("coverage_cases", []), "stack.coverage_cases")
        if feature is None and self.profile == "ipv4-enrichment":
            # Focused IPv4 profile: restrict to the IPv4 layer's declared
            # enrichment cases so the run stays data-driven from layers/ipv4.yaml.
            coverage_cases = _ipv4_enrichment_cases(coverage_cases, self.grammar)
        if feature is None and self.profile == "tcp-header":
            # Focused profile: restrict the stack's own coverage cases to the
            # tcp_header set so case selection never falls through to the other
            # cases (ipv4-tcp-syn, tcp-options*) the IPv4/IPv6 TCP stacks declare.
            coverage_cases = [case for case in coverage_cases if _has_tcp_header_case([case])]
        if feature is None and self.profile == "tcp-options":
            # Focused profile: restrict to the tcp-option-* single-option cases so
            # case selection never falls through to the broad option-list cases
            # (ipv4-tcp-syn, tcp-options, tcp-header-*) the TCP stacks declare.
            coverage_cases = [case for case in coverage_cases if _has_tcp_options_case([case])]
        if feature is None and self.profile == "tcp-smoke":
            # Representative TCP smoke set: restrict to the union of the focused
            # tcp-header-* and tcp-option-* cases so case selection stays on TCP
            # behavior and never falls through to unrelated cases.
            coverage_cases = [case for case in coverage_cases if _has_tcp_smoke_case([case])]
        if feature is None and self.profile == "bgp-smoke":
            # Focused BGP smoke set: keep case selection on BGP message cases so
            # a default/raw payload case is never paired with a BGP stack.
            coverage_cases = [case for case in coverage_cases if _is_bgp_smoke_case(case)]
        if feature is None and self.profile == "rip-smoke":
            # Focused RIP/RIPng smoke set: keep case selection on the RIP and
            # RIPng message cases so a default/raw payload case is never paired
            # with a RIP/RIPng stack.
            coverage_cases = [case for case in coverage_cases if _is_rip_smoke_case(case)]
        if feature is None and self.profile == "ospf-smoke":
            # Focused OSPF smoke set: keep case selection on the five OSPFv2
            # packet-type cases so a default/raw payload case is never paired
            # with the ipv4/ospf stack.
            coverage_cases = [case for case in coverage_cases if _is_ospf_smoke_case(case)]
        if feature is None and self.profile == "ipv6-enrichment":
            # Focused IPv6 enrichment profile: restrict to stack-declared
            # base/unknown-next-header and strict-byte extension cases. This
            # avoids the generic feature expansion below, which is too broad for
            # extension chains because any ipv6_routing stack can otherwise draw
            # cases whose terminal layer belongs to a different stack.
            coverage_cases = [case for case in coverage_cases if _is_ipv6_enrichment_case(case)]
        if feature is None and self.profile in _IP_FRAGMENT_SMOKE_PROFILES:
            # Focused fragmentation profile: keep case selection on the stack's
            # own pcap-eligible fragment cases. Transform feature contract cases
            # are many-record stream cases and must not be paired with unrelated
            # packet stacks by the generic feature expansion below.
            coverage_cases = [case for case in coverage_cases if _is_ip_fragment_smoke_case(case)]
        if feature is not None:
            feature_spec = self._feature_spec(feature)
            feature_cases = _string_list(feature_spec.get("coverage_cases"), "feature.coverage_cases")
            matching = [
                case
                for case in coverage_cases
                if case in feature_cases and self._case_supported_in_direction(case, direction)
            ]
            if matching:
                return weighted_choice(rng, tuple((case, 1) for case in matching))
            compatible = self._compatible_feature_cases(
                stack=_string_list(stack.get("layers"), "stack.layers"),
                feature=feature,
                direction=direction,
            )
            if compatible:
                return weighted_choice(rng, tuple((case, 1) for case in compatible))
        if not coverage_cases:
            coverage_cases = []

        choices: list[tuple[str, int]] = []
        for stack_case in coverage_cases:
            if not self._case_supported_in_direction(stack_case, direction):
                continue
            weight = self._case_weight(stack_case, categories=_case_categories([stack_case]))
            if weight > 0:
                choices.append((stack_case, weight))
        stack_layers = _string_list(stack.get("layers"), "stack.layers")
        # Focused tcp-header profile: select only from the stack's declared
        # tcp-header coverage cases (filtered above) so an IPv4-checksum case is
        # never drawn for the IPv6 stack and vice versa. The cross-feature case
        # expansion below is intentionally skipped for this profile.
        if feature is None and self.profile == "tcp-header":
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        # Focused tcp-options profile: same discipline for the tcp-option-* cases.
        # The cross-feature case expansion below is skipped so only the focused
        # single-option cases are drawn.
        if feature is None and self.profile == "tcp-options":
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        # tcp-smoke profile: select only from the union of the tcp-header-* and
        # tcp-option-* coverage cases (filtered above) so the smoke run stays on
        # TCP behavior. The cross-feature case expansion below is skipped.
        if feature is None and self.profile == "tcp-smoke":
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        # bgp-smoke profile: select only from stack-declared BGP message cases
        # and skip the generic cross-feature expansion below.
        if feature is None and self.profile == "bgp-smoke":
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        # rip-smoke profile: select only from stack-declared RIP/RIPng message
        # cases and skip the generic cross-feature expansion below.
        if feature is None and self.profile == "rip-smoke":
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        # ospf-smoke profile: select only from the stack-declared OSPFv2 packet
        # cases and skip the generic cross-feature expansion below so an
        # unrelated case is never paired with the ipv4/ospf stack.
        if feature is None and self.profile == "ospf-smoke":
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        # ipv4-enrichment profile: the stack was pre-filtered to IPv4 layer
        # enrichment cases, and cross-feature expansion is skipped so unrelated
        # features that happen to ride IPv4 stacks cannot enter the sample.
        if feature is None and self.profile == "ipv4-enrichment":
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        # Focused IPv6 enrichment profile: select only from the stack's declared
        # enrichment cases. The cross-feature case expansion below intentionally
        # stays disabled so routing/TCP/ICMPv6 terminal chains remain aligned
        # with their declared stack shapes.
        if feature is None and self.profile == "ipv6-enrichment":
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        # Focused fragmentation smoke profile: select only stack-declared
        # fragment cases so dry-run plans stay packet-shape consistent.
        if feature is None and self.profile in _IP_FRAGMENT_SMOKE_PROFILES:
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        if (
            feature is None
            and self.profile == "smoke"
            and stack_layers == ["ble_radio", "ble_adv"]
        ):
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        if feature is None and self.profile in {
            "dot11-smoke",
            "radiotap-smoke",
            "dot11-pcap",
            "eapol-smoke",
            "rsn-smoke",
        }:
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        # Focused IPSec smoke profiles: select only from the stack's own declared
        # ESP/AH/IKEv2 coverage cases. The cross-feature case expansion below is
        # skipped so an unrelated case (DNS, fragment, pcap, ...) is never paired
        # with an ESP/AH/IKEv2 stack.
        if feature is None and self.profile in _IPSEC_SMOKE_PROFILES:
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        for feature_name, feature_spec in self._matching_features_for_stack(
            stack=stack_layers,
            direction=direction,
        ):
            if family == "udp" and feature_name != "udp_options":
                continue
            categories = _string_list(feature_spec.get("categories", []), "feature.categories")
            for feature_case in self._compatible_feature_cases(
                stack=stack_layers,
                feature=feature_name,
                direction=direction,
            ):
                if feature_case in coverage_cases:
                    continue
                if not self._case_supported_in_direction(feature_case, direction):
                    continue
                weight = self._case_weight(
                    feature_case,
                    categories=[*categories, *_case_categories([feature_case])],
                )
                if weight > 0:
                    choices.append((feature_case, weight))
        if not choices:
            return "default"
        return weighted_choice(rng, choices)

    def _choose_feature(
        self,
        rng: random.Random,
        *,
        stack: Sequence[str],
        case: str,
        feature: str | None,
        direction: str,
    ) -> str | None:
        if feature is not None:
            return feature

        matches = self._matching_features(stack=stack, case=case, direction=direction)
        if not matches:
            return None
        feature_weights = self._profile_feature_weights()
        choices: list[tuple[str, int]] = []
        for name, spec in matches:
            categories = _string_list(spec.get("categories", []), "feature.categories")
            weight = max((feature_weights.get(category, 0) for category in categories), default=0)
            if weight > 0:
                choices.append((name, weight))
        if not choices:
            return None
        return weighted_choice(rng, choices)

    def _matching_features(
        self,
        *,
        stack: Sequence[str],
        case: str,
        direction: str,
    ) -> list[tuple[str, JSONObject]]:
        features = _object(self.grammar.get("features", {}), "features")
        output: list[tuple[str, JSONObject]] = []
        for name, feature in self._matching_features_for_stack(stack=stack, direction=direction):
            cases = _string_list(
                feature.get("coverage_cases", []),
                f"features.{name}.coverage_cases",
            )
            if case not in cases:
                continue
            output.append((name, feature))
        return output

    def _matching_features_for_stack(
        self,
        *,
        stack: Sequence[str],
        direction: str,
    ) -> list[tuple[str, JSONObject]]:
        features = _object(self.grammar.get("features", {}), "features")
        output: list[tuple[str, JSONObject]] = []
        for name, raw_feature in features.items():
            if not _auto_sample_feature(name):
                continue
            # The tcp-header profile is a focused offline run: only the
            # tcp_header feature is auto-sampled so the seeded selection stays on
            # the TCP header cases instead of mixing in tcp_options or other
            # features that also ride the IPv4/IPv6 TCP stacks.
            if self.profile == "tcp-header" and name != "tcp_header":
                continue
            # The tcp-options profile is the analogous focused run: only the
            # tcp_options feature is auto-sampled so the seeded selection stays on
            # the focused single-option cases.
            if self.profile == "tcp-options" and name != "tcp_options":
                continue
            # The tcp-smoke profile is the representative TCP smoke run: both the
            # tcp_header and tcp_options features are auto-sampled so the seeded
            # selection materializes a mix of TCP header and TCP option cases
            # without mixing in unrelated features.
            if self.profile == "tcp-smoke" and name not in ("tcp_header", "tcp_options"):
                continue
            # The BGP smoke profile auto-samples only BGP feature specs, keeping
            # pcap/IPsec/fragment features off the BGP TCP stacks.
            if self.profile == "bgp-smoke" and not name.startswith("bgp_"):
                continue
            # The RIP smoke profile auto-samples only RIP/RIPng feature specs
            # (rip_header, rip_entries, rip_auth, ripng_header, ripng_rtes),
            # keeping pcap/IPsec/fragment features off the RIP/RIPng UDP stacks.
            if self.profile == "rip-smoke" and not name.startswith("rip"):
                continue
            # The OSPF smoke profile materializes the OSPFv2 body through the
            # smoke-case path (_apply_ospf_behavior), not the feature path: the
            # Scapy reference backend builds the body from the ospf body fields,
            # not from an ospf_* feature materialization. Keep every feature out
            # of the automatic sampler so the case stays feature-less and the
            # smoke body injection drives the packet.
            if self.profile == "ospf-smoke":
                continue
            # IGMP profiles are IPv4-only packet-layer runs. Keep the automatic
            # feature sampler on IGMP specs so unrelated IPv4 features never
            # attach to the ipv4/igmp stack.
            if self.profile.startswith("igmp-") and not name.startswith("igmp_"):
                continue
            # The IPv4 enrichment profile auto-samples only the IPv4 option
            # feature; all non-option IPv4 layer cases remain plain header cases.
            if self.profile == "ipv4-enrichment" and name != "ipv4_options":
                continue
            # The ipv6-enrichment profile is a focused offline run over the
            # IPv6 fragment/routing feature plus plain IPv6 base-header cases.
            # Keep other IPv6-adjacent features (UDP/TCP/pcap/live) out of the
            # automatic feature sampler for reproducibility.
            if self.profile == "ipv6-enrichment" and name != "ipv6_fragment_routing":
                continue
            # The fragmentation smoke profile keeps generated packet cases on
            # IP fragment behavior; pcap itself is selected by pcap mode later.
            if self.profile in _IP_FRAGMENT_SMOKE_PROFILES and name not in (
                "ip_fragment_transforms",
                "ipv6_fragment_routing",
            ):
                continue
            feature = _object(raw_feature, f"features.{name}")
            layers = _string_list(feature.get("layers"), f"features.{name}.layers")
            directions = _string_list(feature.get("directions"), f"features.{name}.directions")
            if not _layers_cover_feature(stack, layers):
                continue
            if direction not in directions and "roundtrip" not in directions:
                continue
            output.append((name, feature))
        return output

    def _compatible_feature_cases(
        self,
        *,
        stack: Sequence[str],
        feature: str,
        direction: str,
    ) -> list[str]:
        feature_spec = self._feature_spec(feature)
        layers = _string_list(feature_spec.get("layers"), "feature.layers")
        directions = _string_list(feature_spec.get("directions"), "feature.directions")
        if not _layers_cover_feature(stack, layers):
            return []
        if direction not in directions and "roundtrip" not in directions:
            return []
        cases = _string_list(feature_spec.get("coverage_cases", []), "feature.coverage_cases")
        if feature == "ipv6_fragment_routing":
            return _ipv6_extension_cases_for_stack(stack, cases)
        if feature == "udp_options":
            return _udp_option_cases_for_stack(stack, cases)
        return cases

    def _case_weight(self, case: str, *, categories: Sequence[str]) -> int:
        weights = self._profile_feature_weights()
        normalized = [*categories]
        if _is_malformed_case_name(case):
            normalized.append("malformed")
        return max((weights.get(category, 0) for category in normalized), default=0)

    def _strict_bytes(self, feature: str | None) -> bool:
        if feature is None:
            return True
        feature_spec = self._feature_spec(feature)
        strict_bytes = feature_spec.get("strict_bytes")
        if not isinstance(strict_bytes, bool):
            raise ValueError(f"features.{feature}.strict_bytes must be a boolean")
        return strict_bytes

    def _feature_spec(self, feature: str | None) -> JSONObject:
        if feature is None:
            raise ValueError("feature is required")
        features = _object(self.grammar.get("features"), "features")
        if feature not in features:
            raise ValueError(f"unsupported feature: {feature}")
        return _object(features[feature], f"features.{feature}")

    def _feature_categories(self, feature: str) -> list[str]:
        feature_spec = self._feature_spec(feature)
        return _string_list(feature_spec.get("categories", []), f"features.{feature}.categories")

    def _supported_case_index(self) -> dict[str, JSONObject]:
        """Map each declared supported case to its directions and byte policy.

        Built from every feature's ``supported_cases`` block so case selection
        can honor the per-case ``directions`` and ``byte_policy`` contract that
        the feature specs declare. Cases without a ``supported_cases`` entry are
        absent from the map and keep the historical sampling behavior.
        """

        cached = getattr(self, "_supported_case_index_cache", None)
        if cached is not None:
            return cached
        index: dict[str, JSONObject] = {}
        features = _object(self.grammar.get("features", {}), "features")
        for feature_name, raw_feature in features.items():
            feature_spec = _object(raw_feature, f"features.{feature_name}")
            supported = _object_list(
                feature_spec.get("supported_cases", []),
                f"features.{feature_name}.supported_cases",
            )
            for raw_case in supported:
                if not isinstance(raw_case, Mapping):
                    continue
                name = raw_case.get("name")
                if not isinstance(name, str):
                    continue
                directions = _string_list(
                    raw_case.get("directions", []),
                    f"features.{feature_name}.supported_cases.{name}.directions",
                )
                byte_policy = raw_case.get("byte_policy")
                index[name] = {
                    "directions": list(directions),
                    "byte_policy": byte_policy if isinstance(byte_policy, str) else None,
                }
        self._supported_case_index_cache = index  # type: ignore[attr-defined]
        return index

    def _case_supported_in_direction(self, case: str, direction: str) -> bool:
        """Return whether ``case`` may be generated for ``direction``.

        A case that declares ``supported_cases`` directions is excluded from a
        direction it does not list, and any ``structured_error`` case is excluded
        from offline encode/decode sampling entirely (the oracle has no offline
        malformed comparison pathway). Undeclared cases keep the prior behavior.
        """

        entry = self._supported_case_index().get(case)
        if entry is None:
            return True
        if entry.get("byte_policy") == "structured_error":
            return False
        directions = entry.get("directions") or []
        if not directions:
            return True
        return direction in directions or "roundtrip" in directions

    def _family_spec(self, family: str) -> JSONObject:
        families = _object(self.grammar.get("families"), "families")
        return _object(families.get(family), f"families.{family}")

    def _payload_bounds(self) -> tuple[int, int]:
        profiles = _object(self.grammar.get("profiles"), "profiles")
        profile_spec = _object(profiles.get(self.profile), f"profiles.{self.profile}")
        value = profile_spec.get("payload_length")
        if value is None:
            raise ValueError(f"profiles.{self.profile}.payload_length is required")
        if (
            not isinstance(value, Sequence)
            or isinstance(value, (str, bytes))
            or len(value) != 2
            or not isinstance(value[0], int)
            or not isinstance(value[1], int)
        ):
            raise ValueError("payload_length must be a two-integer list")
        return value[0], value[1]

    def _layer_spec(self, layer: str) -> JSONObject:
        layers = _object(self.grammar.get("layers"), "layers")
        if layer not in layers:
            raise ValueError(f"spec error: no layer spec declares {layer}")
        return _object(layers[layer], f"layers.{layer}")

    def _fields(
        self,
        rng: random.Random,
        stack: Sequence[str],
        *,
        feature: str | None,
        case: str,
    ) -> dict[str, JSONObject]:
        payload_min, payload_max = self._payload_bounds()
        ctx = _SamplingContext(
            rng=rng,
            profile=self.profile,
            feature_weights=self._profile_feature_weights(),
            stack=list(stack),
            payload_min=payload_min,
            payload_max=payload_max,
            feature=feature,
            case=case,
        )

        fields: dict[str, JSONObject] = {}
        for layer in stack:
            if layer == "ipv6_fragment":
                sampled = {
                    "next_header": _ipv6_next_header_for_stack(stack, "ipv6_fragment"),
                    "fragment_offset": 0,
                    "more_fragments": False,
                    "identification": bounded_int(rng, 0, (1 << 32) - 1),
                }
            elif layer == "ipv6_hop_by_hop":
                sampled = {
                    "next_header": _ipv6_next_header_for_stack(stack, "ipv6_hop_by_hop"),
                    "options": _ipv6_extension_options_for_case(layer, case),
                }
            elif layer == "ipv6_destination_options":
                sampled = {
                    "next_header": _ipv6_next_header_for_stack(stack, "ipv6_destination_options"),
                    "options": _ipv6_extension_options_for_case(layer, case),
                }
            elif layer == "ipv6_routing":
                sampled = {
                    "next_header": _ipv6_next_header_for_stack(stack, "ipv6_routing"),
                    "type": 0,
                    "segments_left": 0,
                }
            elif layer == "payload" and ("bgp" in stack or "ospf" in stack):
                sampled = {"hex": "", "length": 0}
            else:
                spec = self._layer_spec(layer)
                self._validate_layer_backend_support(layer, spec)
                sampled = self._sample_layer_fields(ctx, layer, spec)
                self._validate_sampled_fields(layer, spec, sampled)
            if sampled:
                fields[layer] = sampled
                ctx.sampled_layers[layer] = sampled

        # Post-sample hook: after every layer is sampled, give each stack layer's
        # plugin a chance to run an ordered post-sampling step. The IPsec plugin
        # uses it to attach the pinned key/salt/IV crypto material to its
        # esp/ah/ikev2 layer dict (the determinism seam: both backends seal ESP/AH
        # and the IKEv2 SK payload with these identical inputs so ciphertext and
        # ICV are byte-reproducible, and the block also guarantees the layer is
        # always present in the plan even when every sampled field is
        # derived/skipped). Running it here, after field sampling, preserves the
        # legacy "after field sampling" ordering; iterating in stack order keeps
        # any cross-layer ordering stable.
        for layer in stack:
            plugin = SAMPLER_REGISTRY.get(layer)
            if plugin is not None and plugin.post_sample is not None:
                plugin.post_sample(fields, stack=stack, case=case)

        return fields

    def _feature_behavior(
        self,
        rng: random.Random,
        *,
        feature: str | None,
        case: str,
    ) -> str | None:
        if feature is None:
            return None
        feature_spec = self._feature_spec(feature)
        behaviors = _object_list(feature_spec.get("behaviors", []), f"features.{feature}.behaviors")
        names = [
            _string(behavior.get("name"), f"features.{feature}.behaviors.name")
            for behavior in behaviors
            if isinstance(behavior, Mapping) and isinstance(behavior.get("name"), str)
        ]
        if not names:
            return None
        if feature.startswith("igmp_"):
            mapped = _igmp_behavior_for_case(feature, case)
            if mapped in names:
                return mapped
        case_id = _identifier_part(case)
        case_key = f"-{case_id}-"
        if feature == "tcp_header":
            # tcp_header cases are named tcp-header-<behavior>; match the behavior
            # whose id is the exact case suffix so tcp-header-syn-ack selects the
            # syn-ack behavior rather than the shorter syn substring match.
            suffix = case_id[len("tcp-header-"):] if case_id.startswith("tcp-header-") else case_id
            for name in names:
                if _identifier_part(name) == suffix:
                    return name
        if feature == "tcp_options":
            # Focused single-option cases are named tcp-option-<behavior>; match
            # the behavior whose id is the exact case suffix so tcp-option-sack
            # selects the sack behavior rather than the longer sack-permitted /
            # advanced-generic substring matches. Broad option-list cases
            # (tcp-options*, tcp-all-flags-reserved-offset) keep the existing
            # substring matching below and never select a focused behavior.
            if case_id.startswith("tcp-option-"):
                suffix = case_id[len("tcp-option-"):]
                for name in names:
                    if _identifier_part(name) == suffix:
                        return name
            else:
                names = [name for name in names if not _is_focused_tcp_option_behavior(name)]
        for name in names:
            name_id = _identifier_part(name)
            if feature == "udp_options":
                if f"-{name_id}-" in case_key:
                    return name
            elif name_id in case_id:
                return name
        # No behavior identifier is a substring of the case id, so fall back to a
        # deterministic weighted pick. Drop any DNS behavior that would emit a raw
        # compressed-bytes spec the libcrafter materializer cannot encode, unless
        # the case id itself opts into the raw path. This keeps a typed case such
        # as dns-record-txt from being materialized through the name-records
        # compressed raw builder in the libcrafter_to_reference direction.
        if feature == "dns_behavior":
            typed = [name for name in names if not _dns_behavior_emits_raw(case, name)]
            if typed:
                names = typed
        return weighted_choice(rng, tuple((name, 1) for name in names))

    def _apply_feature_behavior(
        self,
        fields: dict[str, JSONObject],
        *,
        stack: Sequence[str],
        feature: str | None,
        case: str,
        behavior: str,
    ) -> None:
        # The owning plugin (if any) handles the feature exactly once. A plugin owns
        # the feature when its handles_feature matches, it carries an apply_behavior,
        # and its layer is present in the sampled fields or the stack (igmp gates on
        # the stack). Every feature is owned by a registered plugin; a feature with
        # no owner is simply a no-op here.
        if feature is not None:
            for plugin in SAMPLER_REGISTRY.values():
                if (
                    plugin.handles_feature is None
                    or plugin.apply_behavior is None
                    or not plugin.handles_feature(feature)
                ):
                    continue
                if plugin.layer not in fields and plugin.layer not in stack:
                    continue
                plugin.apply_behavior(
                    fields,
                    stack=stack,
                    feature=feature,
                    case=case,
                    behavior=behavior,
                    grammar=self.grammar,
                )
                return

    def _apply_icmp_live_fields(
        self,
        rng: random.Random,
        fields: dict[str, JSONObject],
        *,
        feature: str | None,
        case: str,
    ) -> str | None:
        """Fill ICMP rest-of-header and type-specific body fields per behavior.

        Driven by the live coverage matrix in the feature spec rather than by
        backend-specific special cases: each matrix entry names a coverage case,
        its ICMP type, the representative code or pair, and (via the behavior
        name) which rest-of-header body the live exchange exercises. Only the
        fields a given behavior needs are added, and only deterministic, well
        formed bytes both backends can emit and parse are sampled.
        """

        if feature is None or "icmp" not in fields:
            return None
        feature_spec = self._feature_spec(feature)
        matrix = _object_list(
            feature_spec.get("live_matrix", []),
            f"features.{feature}.live_matrix",
        )
        if not matrix:
            return None
        entry = _icmp_live_matrix_entry(matrix, case)
        if entry is None:
            return None
        icmp = fields["icmp"]
        return _apply_icmp_live_entry(rng, icmp, case=case, entry=entry)

    def _is_malformed_case(self, feature: str | None, case: str) -> bool:
        if _is_malformed_case_name(case):
            return True
        if feature is None:
            return False
        feature_spec = self._feature_spec(feature)
        malformed = feature_spec.get("malformed")
        if not isinstance(malformed, bool):
            raise ValueError(f"features.{feature}.malformed must be a boolean")
        return malformed

    def _validate_layer_backend_support(self, layer: str, spec: JSONObject) -> None:
        support = _object(spec.get("backend_support"), f"layers.{layer}.backend_support")
        for backend_name in (self.backend, SUPPORTED_LAYER_BACKEND):
            if backend_name not in support:
                raise ValueError(
                    f"spec error: layer {layer} has no backend_support for {backend_name}"
                )
            entry = _object(
                support[backend_name],
                f"layers.{layer}.backend_support.{backend_name}",
            )
            status = _string(entry.get("status"), f"layers.{layer}.backend_support.{backend_name}.status")
            if status == "planned":
                raise ValueError(
                    f"spec error: layer {layer} is planned, not supported, for {backend_name}"
                )
            if layer in _SCAPY_MATERIALIZED_LAYERS and backend_name == self.backend:
                if entry.get("encode") is not True:
                    raise ValueError(
                        f"spec error: layer {layer} cannot be encoded by backend {backend_name}"
                    )

    def _sample_layer_fields(
        self,
        ctx: "_SamplingContext",
        layer: str,
        spec: JSONObject,
    ) -> JSONObject:
        output: JSONObject = {}
        for raw_field in _field_specs(spec, layer):
            field_name = _string(raw_field.get("name"), f"layers.{layer}.fields.name")
            if field_name not in _supported_fields(layer):
                continue
            sampled = self._sample_field_value(ctx, layer, raw_field, output)
            if sampled is _SKIP_FIELD:
                continue
            output[field_name] = sampled  # type: ignore[assignment]
        return output

    def _validate_sampled_fields(
        self,
        layer: str,
        spec: JSONObject,
        sampled: Mapping[str, object],
    ) -> None:
        declared = {
            _string(field.get("name"), f"layers.{layer}.fields.name")
            for field in _field_specs(spec, layer)
        }
        supported = SAMPLER_REGISTRY.require(layer).supported_fields
        for field_name in sampled:
            if field_name not in declared:
                raise ValueError(
                    f"spec error: sampler emitted undeclared field {layer}.{field_name}"
                )
            if field_name not in supported:
                supported_list = ", ".join(sorted(supported)) or "<none>"
                raise ValueError(
                    f"spec error: sampler emitted unsupported field {layer}.{field_name}; "
                    f"{self.backend}/{SUPPORTED_LAYER_BACKEND} supports {supported_list}"
                )

    def _sample_field_value(
        self,
        ctx: "_SamplingContext",
        layer: str,
        field_spec: JSONObject,
        current_fields: Mapping[str, object],
    ) -> object:
        field_name = _string(field_spec.get("name"), f"layers.{layer}.fields.name")
        domains = self._field_domains(layer, field_name, field_spec)
        domain = self._choose_domain(ctx, layer, field_name, domains)

        if domain is _SKIP_FIELD:
            return _SKIP_FIELD
        plugin = SAMPLER_REGISTRY.get(layer)
        if plugin is not None:
            return plugin.sample(
                ctx,
                field_name,
                domain,
                field_spec=field_spec,
                current_fields=current_fields,
            )

        raise ValueError(f"spec error: no sampler registered for layer: {layer}")

    def _field_domains(
        self,
        layer: str,
        field_name: str,
        field_spec: JSONObject,
    ) -> list[object]:
        default_domains = _object_list(field_spec.get("domains"), f"layers.{layer}.{field_name}.domains")
        profile_domains = field_spec.get("profile_domains")
        if isinstance(profile_domains, Mapping) and self.profile in profile_domains:
            return _object_list(
                profile_domains[self.profile],
                f"layers.{layer}.{field_name}.profile_domains.{self.profile}",
            )
        profiles = field_spec.get("profiles")
        if isinstance(profiles, Mapping) and self.profile in profiles:
            profile_entry = profiles[self.profile]
            if isinstance(profile_entry, Mapping) and "domains" in profile_entry:
                return _object_list(
                    profile_entry["domains"],
                    f"layers.{layer}.{field_name}.profiles.{self.profile}.domains",
                )
            if isinstance(profile_entry, list):
                return list(profile_entry)
        sampling = field_spec.get("sampling")
        if isinstance(sampling, Mapping):
            profiles_obj = sampling.get("profiles")
            if isinstance(profiles_obj, Mapping) and self.profile in profiles_obj:
                profile_entry = profiles_obj[self.profile]
                if isinstance(profile_entry, Mapping) and "domains" in profile_entry:
                    return _object_list(
                        profile_entry["domains"],
                        f"layers.{layer}.{field_name}.sampling.profiles.{self.profile}.domains",
                    )
        return default_domains

    def _choose_domain(
        self,
        ctx: "_SamplingContext",
        layer: str,
        field_name: str,
        domains: Sequence[object],
    ) -> object:
        supported_domains = _SUPPORTED_FIELD_DOMAINS.get((layer, field_name))
        choices: list[tuple[object, int]] = []
        for domain in domains:
            if isinstance(domain, str) and domain in _DERIVED_DOMAINS:
                continue
            if supported_domains is not None and domain not in supported_domains:
                continue
            weight = _domain_weight(ctx, layer, field_name, domain)
            if weight > 0:
                choices.append((domain, weight))
        if not choices:
            return _SKIP_FIELD
        return weighted_choice(ctx.rng, choices)


def _field_specs(spec: JSONObject, layer: str) -> list[JSONObject]:
    raw_fields = spec.get("fields")
    if not isinstance(raw_fields, Sequence) or isinstance(raw_fields, (str, bytes)):
        raise ValueError(f"layers.{layer}.fields must be a list")
    return [_object(field, f"layers.{layer}.fields item") for field in raw_fields]


def _domain_weight(ctx: _SamplingContext, layer: str, field_name: str, domain: object) -> int:
    if field_name == "options" and layer == "ipv4":
        if ctx.feature == "ipv4_options" or "ipv4-options" in ctx.case:
            return max(1, ctx.feature_weights.get("boundary", 1))
        return 0
    if field_name == "options" and layer == "tcp":
        if ctx.feature == "tcp_options" or "tcp-options" in ctx.case or ctx.case == "tcp-all-flags-reserved-offset":
            return max(1, ctx.feature_weights.get("boundary", 1))
        return 0
    if field_name == "options" and layer == "udp":
        if ctx.feature == "udp_options" or "udp-options" in ctx.case:
            return max(1, ctx.feature_weights.get("boundary", 1))
        return 0
    if field_name == "answers" and layer == "dns":
        if ctx.feature == "dns_behavior" and "response" in ctx.case:
            return max(1, ctx.feature_weights.get("boundary", 1))
        return 0
    if ctx.profile == "smoke" and _is_boundary_domain(domain):
        return 0
    if ctx.profile == "smoke" and layer in {"dns", "dhcp"}:
        smoke_domains = {
            False,
            0,
            6,
            "a_in",
            "bootrequest",
            "deterministic",
            "documentation_ipv4",
            "documentation_mac_padded",
            "ethernet",
            "message_type",
            "none",
            "query",
            "zero",
        }
        return 0 if domain not in smoke_domains else 10
    if _is_boundary_domain(domain):
        return max(0, ctx.feature_weights.get("boundary", 0))
    return max(1, ctx.feature_weights.get("baseline", 1))


def _is_boundary_domain(domain: object) -> bool:
    if isinstance(domain, bool):
        return domain is True
    if isinstance(domain, int):
        return domain in {0, 1, 255, 4094, 65535}
    if not isinstance(domain, str):
        return False
    return domain in {
        "all",
        "boundary",
        "broadcast",
        "mf",
        "packet_too_big",
        "parameter_problem",
        "time_exceeded",
        "truncated",
        "zero",
        "zero_ipv4",
    }


def _ipv6_extension_options_for_case(layer: str, case: str) -> list[JSONObject]:
    normalized = case.replace("_", "-")
    if "option-metadata" in normalized:
        return [
            {
                "kind": "unknown",
                "option_type": 0x22,
                "data": {"hex": "aabbccdd"},
            }
        ]
    if layer == "ipv6_hop_by_hop":
        return [
            {"kind": "router_alert", "value": 0},
            {"kind": "padn", "total_length": 2},
        ]
    return [
        {"kind": "home_address", "address": "2001:db8::42"},
        {"kind": "padn", "total_length": 4},
    ]


# Stable per-code mapping for the representative ICMP destination-unreachable
# codes named by the live matrix. Each behavior names at most one code so the
# generated plan exercises a deterministic code byte rather than a random one.
_ICMP_DEST_UNREACHABLE_CODES: dict[str, int] = {
    "net_unreachable": 0,
    "host_unreachable": 1,
    "protocol_unreachable": 2,
    "port_unreachable": 3,
    "fragmentation_needed": 4,
}
# Raw rest-of-header bytes for legacy/raw-compatible types whose four reserved
# bytes both backends emit and parse identically. Deterministic and well formed.
_ICMP_LEGACY_REST_OF_HEADER = "00000000"
# ``_ICMP_EXTENSION_BYTES`` / ``_ICMP_MPLS_EXTENSION_BYTES`` /
# ``_ICMP_QUOTED_IPV4_DATAGRAM`` live in ``sampling`` so the ICMP error behavior
# plugin can share them without importing ``generator``; re-imported above for the
# still-resident ICMP live-matrix body sampler.


def _icmp_live_matrix_entry(
    matrix: Sequence[object],
    case: str,
) -> JSONObject | None:
    """Return the live-matrix entry whose coverage case matches ``case``."""

    for raw_entry in matrix:
        if not isinstance(raw_entry, Mapping):
            continue
        entry = _json_object(raw_entry)
        coverage_case = entry.get("coverage_case")
        if isinstance(coverage_case, str) and coverage_case == case:
            return entry
    return None


def _icmp_live_pick(rng: random.Random, values: Sequence[object]) -> object | None:
    """Deterministically pick one value from a non-empty matrix list."""

    options = [value for value in values if isinstance(value, str)]
    if not options:
        return None
    return weighted_choice(rng, tuple((value, 1) for value in options))


def _apply_icmp_live_entry(
    rng: random.Random,
    icmp: JSONObject,
    *,
    case: str,
    entry: JSONObject,
) -> str:
    """Apply one ICMP live-matrix entry's type, code, and body fields in place.

    Returns the resolved behavior name recorded in plan metadata.
    """

    behavior = _string_or_none(entry.get("behavior")) or case
    icmp_type = _string_or_none(entry.get("icmp_type"))

    # Request/reply pairs alternate deterministically by plan rng so both members
    # of the pair appear across a seeded run.
    pairs = entry.get("pairs")
    if isinstance(pairs, Sequence) and not isinstance(pairs, (str, bytes)):
        picked = _icmp_live_pick(rng, pairs)
        if picked is not None:
            icmp_type = str(picked)

    # Representative legacy/raw-compatible types likewise rotate over the named
    # representative set.
    representative = entry.get("representative_types")
    if isinstance(representative, Sequence) and not isinstance(representative, (str, bytes)):
        picked = _icmp_live_pick(rng, representative)
        if picked is not None:
            icmp_type = str(picked)

    if icmp_type is None:
        # An entry without a concrete ICMP type (e.g. a pure pair/representative
        # listing handled above) leaves the base echo type untouched.
        return behavior

    icmp["type"] = icmp_type

    # Representative code for the destination-unreachable family.
    codes = entry.get("codes")
    if isinstance(codes, Sequence) and not isinstance(codes, (str, bytes)):
        picked_code = _icmp_live_pick(rng, codes)
        if isinstance(picked_code, str) and picked_code in _ICMP_DEST_UNREACHABLE_CODES:
            icmp["code"] = _ICMP_DEST_UNREACHABLE_CODES[picked_code]

    _apply_icmp_live_body(rng, icmp, behavior=behavior, icmp_type=icmp_type, entry=entry)
    return behavior


def _apply_icmp_live_body(
    rng: random.Random,
    icmp: JSONObject,
    *,
    behavior: str,
    icmp_type: str,
    entry: JSONObject,
) -> None:
    """Populate the type-specific rest-of-header body for one ICMP behavior."""

    # RFC 4884/4950 extension framing: ICMP error packets carry a quoted
    # datagram before deterministic, raw-compatible extension bytes. Extended
    # echo uses the same extension byte field without an embedded datagram.
    embeds = entry.get("embeds")
    if isinstance(embeds, Sequence) and not isinstance(embeds, (str, bytes)):
        embed_names = {value for value in embeds if isinstance(value, str)}
        is_error_type = icmp_type in {
            "destination_unreachable",
            "time_exceeded",
            "parameter_problem",
        }
        if "icmp_extension_mpls" in embed_names:
            if is_error_type:
                icmp["embedded_header"] = {"hex": _ICMP_QUOTED_IPV4_DATAGRAM}
            icmp["extension_bytes"] = {"hex": _ICMP_MPLS_EXTENSION_BYTES}
        elif embed_names.intersection(
            {"icmp_extension_header", "icmp_extension_object"}
        ):
            if is_error_type:
                icmp["embedded_header"] = {"hex": _ICMP_QUOTED_IPV4_DATAGRAM}
            icmp["extension_bytes"] = {"hex": _ICMP_EXTENSION_BYTES}

    if behavior == "redirect" or icmp_type == "redirect":
        icmp["gateway"] = "192.0.2.1"
    elif behavior == "parameter_problem" or icmp_type == "parameter_problem":
        icmp["pointer"] = 20
    elif behavior == "frag_needed_next_hop_mtu":
        icmp["next_hop_mtu"] = 1280
    elif icmp_type in {"timestamp", "timestamp_reply"}:
        icmp["originate_timestamp"] = bounded_int(rng, 0, (1 << 31) - 1)
        icmp["receive_timestamp"] = bounded_int(rng, 0, (1 << 31) - 1)
        icmp["transmit_timestamp"] = bounded_int(rng, 0, (1 << 31) - 1)
    elif icmp_type in {"address_mask_request", "address_mask_reply"}:
        icmp["address_mask"] = "255.255.255.0"
    elif icmp_type == "router_advertisement":
        icmp["router_address_entry_size"] = 2
        icmp["router_lifetime"] = 1800
        icmp["router_addresses"] = [
            {"address": "192.0.2.1", "preference": 0},
            {"address": "192.0.2.2", "preference": 0},
        ]
    elif icmp_type == "router_solicitation":
        icmp["rest_of_header"] = {"hex": _ICMP_LEGACY_REST_OF_HEADER}
    elif icmp_type in {"extended_echo_request", "extended_echo_reply"}:
        # Scapy has no typed extended-echo class; emit a deterministic rest of
        # header plus a generic extension object both sides parse identically.
        icmp["rest_of_header"] = {"hex": "00000100"}
        icmp.setdefault("extension_bytes", {"hex": _ICMP_EXTENSION_BYTES})
    elif behavior == "legacy_raw_compatible_types" or icmp_type in {
        "source_quench",
        "traceroute",
        "mobile_host_redirect",
        "domain_name_request",
        "photuris",
    }:
        icmp["rest_of_header"] = {"hex": _ICMP_LEGACY_REST_OF_HEADER}


def _is_ospf_smoke_case(case: str) -> bool:
    """Whether ``case`` is sampled by the focused ospf-smoke profile."""

    return case.replace("_", "-").startswith("ospf-")


# --------------------------------------------------------------------------
# RIPng sampler/behavior moved to ``protocols/ripng.py`` and is registered in
# ``SAMPLER_REGISTRY`` (so ``_sample_field_value`` routes ``ripng`` to its sampler
# and ``_apply_feature_behavior`` routes ``ripng_`` features to it). Its
# ``_apply_ripng_behavior`` body injector is re-imported at the top of this module
# because the focused rip-smoke profile path calls it directly with ``behavior=""``
# outside the registry feature loop.


def _udp_option_feature_tags(case: str, behavior: str | None) -> list[str]:
    key = f"{case} {behavior or ''}".replace("_", "-")
    tags = ["udp_options"]
    if "udp-options" in key:
        tags.append("udp_surplus")
    if "ocs" in key:
        tags.extend(["udp_ocs", "udp_option_checksum"])
    if "apc" in key:
        tags.extend(["udp_apc", "udp_additional_payload_checksum"])
    if "unknown-safe" in key:
        tags.append("udp_unknown_safe")
    if "unknown-unsafe" in key:
        tags.append("udp_unknown_unsafe")
    if "unsupported-frag" in key:
        tags.extend(["udp_frag", "udp_unsupported_frag"])
    if "ipv4-zero-checksum" in key:
        tags.extend(["udp_checksum_status", "udp_ipv4_zero_checksum"])
    if "ipv6-zero-checksum" in key:
        tags.extend(["udp_checksum_status", "udp_ipv6_zero_checksum"])
    if "surplus-application-boundary" in key:
        tags.extend(["udp_application_boundary", "udp_surplus_application_boundary"])
    return list(dict.fromkeys(tags))


def _udp_options_metadata(
    fields: Mapping[str, JSONObject],
    *,
    stack: Sequence[str],
    case: str,
    behavior: str | None,
) -> JSONObject:
    key = f"{case} {behavior or ''}".replace("_", "-")
    payload_hex = _payload_hex_from_fields(fields.get("payload", {})) if "payload" in fields else None
    checksum_status = "generated"
    if "ipv4-zero-checksum" in key:
        checksum_status = "ipv4_no_checksum"
    elif "ipv6-zero-checksum" in key:
        checksum_status = "ipv6_zero_checksum_exception_required"

    options_field = _udp_options_field(key, payload_hex=payload_hex)
    options = _udp_options_items(options_field)
    surplus = options_field is not None
    return {
        "intent": "logical_plan_fields",
        "requires_backend_materialization": True,
        "stack": list(stack),
        "case": case,
        "behavior": behavior,
        "checksum_status": checksum_status,
        "udp_length_scope": "header_and_application_payload",
        "application_payload_hex": payload_hex,
        "surplus_area": {
            "present": surplus,
            "placement": "after_udp_length",
            "option_checksum": _udp_option_checksum_intent(key, surplus),
            "options": options,
        },
        "application_boundary": {
            "payload_excludes_surplus": surplus,
            "surplus_excluded_from_udp_checksum": surplus,
        },
        "logical_fields": {
            "application_payload": "fields.payload.hex"
            if payload_hex is not None
            else "materialized_udp_payload",
            "udp_options": "fields.udp.options",
        },
    }


def _is_malformed_case_name(case: str) -> bool:
    return "malformed" in case.replace("_", "-")


def _has_tcp_header_case(cases: Sequence[str]) -> bool:
    """Whether ``cases`` contains a tcp_header coverage case.

    Used by the focused tcp-header profile to keep stack and case selection on
    the ``tcp-header-*`` cases declared by the IPv4/IPv6 TCP stacks.
    """

    return any(case.replace("_", "-").startswith("tcp-header-") for case in cases)


def _has_tcp_options_case(cases: Sequence[str]) -> bool:
    """Whether ``cases`` contains a focused tcp_options coverage case.

    Used by the focused tcp-options profile to keep stack and case selection on
    the ``tcp-option-*`` single-option cases declared by the IPv4/IPv6 TCP
    stacks, rather than the broad ``tcp-options*`` option-list cases that ride
    the wild/ci/boundary profiles.
    """

    return any(case.replace("_", "-").startswith("tcp-option-") for case in cases)


def _has_tcp_smoke_case(cases: Sequence[str]) -> bool:
    """Whether ``cases`` contains a TCP smoke coverage case.

    The tcp-smoke profile is the representative TCP smoke set used by
    provider-backed dry-run validation. It keeps stack and case selection on the
    union of the focused ``tcp-header-*`` and ``tcp-option-*`` cases declared by
    the IPv4/IPv6 TCP stacks, so a single small run materializes a mix of TCP
    header and TCP option cases without falling through to unrelated stacks.
    """

    return _has_tcp_header_case(cases) or _has_tcp_options_case(cases)


def _is_bgp_smoke_case(case: str) -> bool:
    """Whether ``case`` is sampled by the focused bgp-smoke profile."""

    return case.replace("_", "-").startswith("bgp-")


def _has_bgp_smoke_case(cases: Sequence[str]) -> bool:
    """Whether ``cases`` contains a BGP smoke coverage case."""

    return any(_is_bgp_smoke_case(case) for case in cases)


def _is_rip_smoke_case(case: str) -> bool:
    """Whether ``case`` is sampled by the focused rip-smoke profile.

    Covers the RIP (UDP/520) and RIPng (UDP/521) coverage cases declared on the
    ``ipv4_udp_rip`` / ``ipv6_udp_ripng`` stacks and the ``rip-`` / ``ripng-``
    feature cases, including the ``crafter-rip-*`` / ``crafter-ripng-*`` matrix
    cases. The ``crafter-`` materialize/decode prefix is stripped first so those
    matrix cases match the same ``rip-`` / ``ripng-`` prefixes.
    """

    normalized = case.replace("_", "-")
    if normalized.startswith("crafter-"):
        normalized = normalized[len("crafter-") :]
    return normalized.startswith("rip-") or normalized.startswith("ripng-")


def _has_rip_smoke_case(cases: Sequence[str]) -> bool:
    """Whether ``cases`` contains a RIP/RIPng smoke coverage case."""

    return any(_is_rip_smoke_case(case) for case in cases)


def _has_ospf_smoke_case(cases: Sequence[str]) -> bool:
    """Whether ``cases`` contains an OSPF smoke coverage case."""

    return any(_is_ospf_smoke_case(case) for case in cases)


def _ipv4_enrichment_cases(cases: Sequence[str], grammar: Mapping[str, object]) -> list[str]:
    declared = _layer_coverage_cases(grammar, "ipv4")
    return [case for case in cases if case in declared]


def _has_ipv4_enrichment_case(cases: Sequence[str], grammar: Mapping[str, object]) -> bool:
    return bool(_ipv4_enrichment_cases(cases, grammar))


def _layer_coverage_cases(grammar: Mapping[str, object], layer: str) -> set[str]:
    layers = _object(grammar.get("layers"), "layers")
    layer_spec = _object(layers.get(layer), f"layers.{layer}")
    return set(_string_list(layer_spec.get("coverage_cases", []), f"layers.{layer}.coverage_cases"))


_IPV6_ENRICHMENT_CASES = frozenset(
    {
        "crafter-ipv6-boundary-fields",
        "crafter-ipv6-fragment-udp",
        "crafter-ipv6-routing-generic",
        "crafter-ipv6-routing-icmpv6",
        "crafter-ipv6-routing-tcp-raw",
        "crafter-ipv6-segment-routing-udp",
        "crafter-ipv6-unknown-next-header-raw",
        "ipv6-boundary-fields",
        "ipv6-destination-options",
        "ipv6-extension-chain-tcp-raw",
        "ipv6-fragment-udp",
        "ipv6-hop-by-hop-options",
        "ipv6-mobile-routing",
        "ipv6-option-metadata",
        "ipv6-routing-generic",
        "ipv6-routing-icmpv6",
        "ipv6-segment-routing-udp",
        "ipv6-unknown-next-header-raw",
    }
)


def _is_ipv6_enrichment_case(case: str) -> bool:
    """Whether ``case`` is sampled by the focused ipv6-enrichment profile."""

    return case.replace("_", "-") in _IPV6_ENRICHMENT_CASES


def _has_ipv6_enrichment_case(cases: Sequence[str]) -> bool:
    """Whether ``cases`` contains an ipv6-enrichment coverage case."""

    return any(_is_ipv6_enrichment_case(case) for case in cases)


_IP_FRAGMENT_SMOKE_PROFILES = frozenset(
    {
        "fragmentation-smoke",
        "ip-fragment-smoke",
    }
)
# Focused IPSec offline profiles. Like the dot11/rsn smoke profiles they keep the
# stack and case selection on their own IPSec families (esp/ah/ikev2) rather than
# letting the generic cross-feature case expansion draw unrelated cases onto the
# ESP/AH/IKEv2 stacks.
_IPSEC_SMOKE_PROFILES = frozenset(
    {
        "ipsec-smoke",
        "esp",
        "ah",
        "ikev2",
    }
)


def _has_ip_fragment_smoke_case(cases: Sequence[str]) -> bool:
    """Whether ``cases`` contains an IP fragmentation smoke coverage case."""

    return any(_is_ip_fragment_smoke_case(case) for case in cases)


def _is_ip_fragment_smoke_case(case: str) -> bool:
    return "fragment" in case.replace("_", "-")


# Behavior names of the focused single-option tcp_options cases (tcp-option-*).
# These select exactly one option kind so they must not be matched against the
# broad option-list cases (tcp-options*, tcp-all-flags-reserved-offset), which
# keep their own common_options / sack_blocks / advanced_generic_options /
# header_boundary behaviors.
_FOCUSED_TCP_OPTION_BEHAVIORS = frozenset(
    {
        "mss",
        "window-scale",
        "sack-permitted",
        "sack",
        "timestamp",
        "fast-open",
        "mptcp-generic",
        "unknown-generic",
        "user-timeout",
        "tcp-ao",
        "tcp-eno",
        "accurate-ecn",
        "experimental",
        "malformed-length",
    }
)


def _is_focused_tcp_option_behavior(name: str) -> bool:
    """Whether ``name`` is a focused single-option tcp_options behavior."""

    return _identifier_part(name) in _FOCUSED_TCP_OPTION_BEHAVIORS


def _auto_sample_feature(feature: str) -> bool:
    return feature != "icmpv4_errors"


# The ``dot11`` field sampler and its frame-control/management-tag helpers moved
# to ``protocols/wifi.py`` with the registered ``ProtocolSampler`` (the last 802.11
# layer to migrate). The generator now reaches the ``dot11`` sampler through
# ``SAMPLER_REGISTRY``; nothing in the generator references the moved helpers or the
# ``_rsn_information_value_hex`` builder anymore.


def generate_plans(
    *,
    seed: int,
    profile: str,
    count: int,
    backend: str = "scapy",
    root: str | None = None,
    family: str | None = None,
    case: str | None = None,
    feature: str | None = None,
    direction: str = "reference_to_libcrafter",
    index: int | None = None,
) -> list[PacketPlan]:
    """Generate a deterministic sequence, or one explicit index."""

    if count < 1:
        raise ValueError(f"count must be positive: {count}")
    generator = PacketGenerator(seed=seed, profile=profile, backend=backend)
    indices = [index] if index is not None else list(range(count))
    return [
        generator.generate(
            index=item,
            root=root,
            family=family,
            case=case,
            feature=feature,
            direction=direction,
        )
        for item in indices
    ]


def run_self_checks() -> None:
    """Run unit-style checks for the generator without importing any backend."""

    rng_a = random.Random(123)
    rng_b = random.Random(123)
    if [weighted_choice(rng_a, (("a", 1), ("b", 3))) for _ in range(5)] != [
        weighted_choice(rng_b, (("a", 1), ("b", 3))) for _ in range(5)
    ]:
        raise AssertionError("weighted choice is not deterministic")

    rng = random.Random(1)
    if not 10 <= bounded_int(rng, 10, 20) <= 20:
        raise AssertionError("bounded integer escaped its bounds")
    if len(byte_payload(random.Random(1), min_length=4, max_length=4)) != 4:
        raise AssertionError("byte payload did not honor fixed length")
    ipv4_address = ipaddress.IPv4Address(documentation_ipv4(random.Random(1)))
    if not any(ipv4_address in network for network in _IPV4_DOCUMENTATION_NETWORKS):
        raise AssertionError("IPv4 helper left documentation space")
    if ipaddress.IPv6Address(documentation_ipv6(random.Random(1))) not in _IPV6_DOCUMENTATION_NETWORK:
        raise AssertionError("IPv6 helper left documentation space")
    if not documentation_mac(random.Random(1)).startswith("00:00:5e:00:53:"):
        raise AssertionError("MAC helper left documentation block")
    if not EPHEMERAL_PORT_MIN <= ephemeral_port(random.Random(1)) <= EPHEMERAL_PORT_MAX:
        raise AssertionError("ephemeral port escaped dynamic/private range")

    first = PacketGenerator(seed=1, profile="smoke").generate(index=0).to_dict()
    second = PacketGenerator(seed=1, profile="smoke").generate(index=0).to_dict()
    third = PacketGenerator(seed=2, profile="smoke").generate(index=0).to_dict()
    if first != second:
        raise AssertionError("identical generator coordinates produced different plans")
    if first == third:
        raise AssertionError("different seeds produced identical plans")
    plan_id = first["metadata"]["plan_id"]
    if not isinstance(plan_id, str) or "seed-1/profile-smoke/index-000000/" not in plan_id:
        raise AssertionError("plan identifier is missing reproduction coordinates")
    ci_stacks = {
        PacketGenerator(seed=12345, profile="ci").generate(index=item).metadata["stack_name"]
        for item in range(200)
    }
    expected_stacks = {"ethernet_arp", "ipv4_tcp_payload", "ipv6_icmpv6", "vlan_ipv4_udp"}
    if not expected_stacks.intersection(ci_stacks):
        raise AssertionError("ci profile did not sample stack specs")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run oracle generator self checks.")
    parser.parse_args(argv)
    run_self_checks()
    sys.stdout.write("generator self-checks passed\n")
    return 0


def _derive_seed(
    seed: int,
    profile: str,
    index: int,
    root: str | None,
    family: str | None,
    case: str | None,
    feature: str | None,
    direction: str,
) -> int:
    material = "\0".join(
        (
            str(seed),
            profile,
            str(index),
            root or "",
            family or "",
            case or "",
            feature or "",
            direction,
        )
    ).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:16], byteorder="big")


def _derive_deck_seed(seed: int, profile: str, names: Sequence[str]) -> int:
    material = "\0".join((str(seed), profile, *names, "stack-deck")).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:16], byteorder="big")


def _string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _stack_families(layers: Sequence[str], root_families: Sequence[str]) -> list[str]:
    families: list[str] = []
    layer_set = set(layers)
    for family in root_families:
        if family in layer_set:
            families.append(family)
    if "transport" in root_families and layer_set.intersection({"tcp", "udp"}):
        families.append("transport")
    if "icmp" in root_families and layer_set.intersection({"icmp", "icmpv6"}):
        families.append("icmp")
    if "link" in root_families and layer_set.intersection(
        {"ethernet", "vlan", "payload", "linux_cooked", "null_loopback"}
    ):
        families.append("link")
    if layer_set.intersection({"ipv4", "ipv6", "ipv6_fragment"}):
        families.append("ip")
    if not families:
        families.extend(root_families)
    return list(dict.fromkeys(families))


def _feature_categories(
    name: str,
    directions: Sequence[str],
    malformed: bool,
    cases: Sequence[str],
) -> list[str]:
    categories = ["malformed" if malformed else "baseline"]
    tokens = " ".join((name, *cases)).replace("_", "-")
    if any(direction.startswith("live") for direction in directions):
        categories.append("live")
    if "pcap" in tokens:
        categories.append("pcap")
    if any(token in tokens for token in ("boundary", "option", "fragment", "routing", "error")):
        categories.append("boundary")
    return list(dict.fromkeys(categories))


def _case_categories(cases: Sequence[str]) -> list[str]:
    if not cases:
        return ["baseline"]
    categories = ["baseline"]
    tokens = " ".join(cases)
    if "malformed" in tokens:
        categories.append("malformed")
    if "pcap" in tokens:
        categories.append("pcap")
    if "live" in tokens:
        categories.append("live")
    if any(token in tokens for token in ("boundary", "options", "fragment", "routing", "errors")):
        categories.append("boundary")
    return list(dict.fromkeys(categories))


def _layers_cover_feature(stack: Sequence[str], feature_layers: Sequence[str]) -> bool:
    stack_set = set(stack)
    feature_set = set(feature_layers)
    ipv6_extension_layers = {
        "ipv6_destination_options",
        "ipv6_fragment",
        "ipv6_hop_by_hop",
        "ipv6_routing",
    }
    if {"ipv4", "ipv6"}.issubset(feature_set):
        return bool(stack_set.intersection(feature_set))
    if "ipv6" in feature_set and feature_set.intersection(ipv6_extension_layers):
        return "ipv6" in stack_set and bool(stack_set.intersection(ipv6_extension_layers))
    return all(layer in stack_set for layer in feature_layers)


def _ipv6_extension_cases_for_stack(stack: Sequence[str], cases: Sequence[str]) -> list[str]:
    stack_set = set(stack)
    output: list[str] = []
    for case in cases:
        normalized = case.replace("_", "-")
        if (
            ("hop-by-hop" in normalized or "option-metadata" in normalized)
            and "ipv6_hop_by_hop" in stack_set
        ):
            output.append(case)
        elif (
            ("destination-options" in normalized or "option-metadata" in normalized)
            and "ipv6_destination_options" in stack_set
        ):
            output.append(case)
        elif "ipv6-fragment" in normalized and "ipv6_fragment" in stack_set:
            output.append(case)
        elif (
            any(token in normalized for token in ("routing", "segment", "mobile", "extension-chain"))
            and "ipv6_routing" in stack_set
        ):
            output.append(case)
    return output


def _udp_option_cases_for_stack(stack: Sequence[str], cases: Sequence[str]) -> list[str]:
    stack_set = set(stack)
    if "udp" not in stack_set or "payload" not in stack_set:
        return []
    # UDP surplus options model the application payload as the bytes UDP carries
    # directly, so they only apply when UDP terminates in a payload layer. When an
    # intermediate protocol (e.g. ESP) sits between UDP and payload, the declared
    # application payload no longer equals the materialized UDP payload, so skip
    # the pairing rather than emit a plan that cannot round-trip.
    if _next_layer_after(stack, "udp") != "payload":
        return []

    output: list[str] = []
    for case in cases:
        normalized = case.replace("_", "-")
        if "ipv4-zero-checksum" in normalized and "ipv4" not in stack_set:
            continue
        if "ipv6-zero-checksum" in normalized and "ipv6" not in stack_set:
            continue
        output.append(case)
    return output


if __name__ == "__main__":
    raise SystemExit(main())
