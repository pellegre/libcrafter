"""Deterministic packet plan generation primitives for oracle."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import random
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypeVar

from .model import JSONObject, PacketPlan
from .spec_loader import load_oracle_specs


T = TypeVar("T")

EPHEMERAL_PORT_MIN = 49152
EPHEMERAL_PORT_MAX = 65535
SUPPORTED_LAYER_BACKEND = "libcrafter"

_IPV4_DOCUMENTATION_NETWORKS = (
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
)
_IPV6_DOCUMENTATION_NETWORK = ipaddress.IPv6Network("2001:db8::/32")
_DERIVED_DOMAINS = {"derived"}
_SUPPORTED_FIELDS: dict[str, set[str]] = {
    "arp": {
        "hardware_type",
        "protocol_type",
        "hardware_length",
        "protocol_length",
        "opcode",
        "sender_hardware_address",
        "sender_protocol_address",
        "target_hardware_address",
        "target_protocol_address",
    },
    "dhcp": {
        "op",
        "hardware_type",
        "hardware_length",
        "transaction_id",
        "flags",
        "client_ip",
        "your_ip",
        "client_hardware_address",
        "options",
    },
    "dns": {
        "transaction_id",
        "is_response",
        "opcode",
        "flags",
        "response_code",
        "questions",
    },
    "ethernet": {"dst", "src", "ethertype"},
    "icmp": {"type", "code", "identifier", "sequence"},
    "icmpv6": {"type", "code", "identifier", "sequence"},
    "ipv4": {
        "src",
        "dst",
        "ttl",
        "protocol",
        "identification",
        "flags",
        "fragment_offset",
        "options",
    },
    "ipv6": {"src", "dst", "traffic_class", "flow_label", "next_header", "hop_limit"},
    "linux_cooked": {"packet_type", "address_type", "address_length", "source_address", "protocol"},
    "null_loopback": {"type"},
    "payload": {"hex", "length"},
    "tcp": {
        "src_port",
        "dst_port",
        "sequence",
        "acknowledgement",
        "reserved",
        "flags",
        "window",
        "urgent_pointer",
        "options",
    },
    "udp": {"src_port", "dst_port", "checksum", "options"},
    "vlan": {"priority", "drop_eligible", "vlan_id", "ethertype"},
}
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
    "dns",
    "ethernet",
    "icmp",
    "icmpv6",
    "ipv4",
    "ipv6",
    "payload",
    "tcp",
    "udp",
    "vlan",
}


def weighted_choice(rng: random.Random, choices: Sequence[tuple[T, int]]) -> T:
    """Choose one item from integer weights using only the supplied RNG."""

    if not choices:
        raise ValueError("weighted choice requires at least one option")

    total = 0
    for _, weight in choices:
        if weight < 0:
            raise ValueError(f"weights must be non-negative: {weight}")
        total += weight
    if total <= 0:
        raise ValueError("weighted choice requires a positive total weight")

    cursor = rng.randrange(total)
    seen = 0
    for value, weight in choices:
        seen += weight
        if cursor < seen:
            return value

    raise RuntimeError("weighted choice cursor escaped total weight")


def bounded_int(rng: random.Random, minimum: int, maximum: int) -> int:
    """Return an inclusive integer in the configured bounds."""

    if minimum > maximum:
        raise ValueError(f"minimum cannot exceed maximum: {minimum} > {maximum}")
    return rng.randint(minimum, maximum)


def byte_payload(
    rng: random.Random,
    *,
    min_length: int = 0,
    max_length: int = 64,
) -> bytes:
    """Generate a deterministic byte payload with a deterministic length."""

    length = bounded_int(rng, min_length, max_length)
    return bytes(rng.randrange(256) for _ in range(length))


def documentation_ipv4(rng: random.Random) -> str:
    """Select an IPv4 address from RFC 5737 documentation networks."""

    network = weighted_choice(
        rng,
        tuple((network, 1) for network in _IPV4_DOCUMENTATION_NETWORKS),
    )
    host = bounded_int(rng, 1, network.num_addresses - 2)
    return str(network.network_address + host)


def documentation_ipv6(rng: random.Random) -> str:
    """Select an IPv6 address from the RFC 3849 documentation prefix."""

    host = bounded_int(rng, 1, (1 << 96) - 2)
    return str(ipaddress.IPv6Address(int(_IPV6_DOCUMENTATION_NETWORK.network_address) + host))


def documentation_mac(rng: random.Random) -> str:
    """Select an EUI-48 documentation address from the RFC 7042 block."""

    suffix = bounded_int(rng, 0, 255)
    return f"00:00:5e:00:53:{suffix:02x}"


def ephemeral_port(rng: random.Random) -> int:
    """Select an IANA dynamic/private port."""

    return bounded_int(rng, EPHEMERAL_PORT_MIN, EPHEMERAL_PORT_MAX)


def plan_identifier(
    *,
    seed: int,
    profile: str,
    index: int,
    root: str,
    stack_name: str,
    family: str,
    case: str | None = None,
    feature: str | None = None,
) -> str:
    """Build a stable packet plan identifier with reproduction coordinates."""

    subject_kind = "case" if case is not None else "feature"
    subject = case if case is not None else feature
    if subject is None:
        subject_kind = "case"
        subject = "default"
    return "/".join(
        (
            f"seed-{seed}",
            f"profile-{profile}",
            f"index-{index:06d}",
            f"root-{_identifier_part(root)}",
            f"stack-{_identifier_part(stack_name)}",
            f"family-{family}",
            f"{subject_kind}-{_identifier_part(subject)}",
        )
    )


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
                if stack_layers not in (["ipv4", "udp", "payload"], ["ipv6", "udp", "payload"]):
                    continue
            if feature is None and case is None and self.profile == "smoke" and "dhcp" in stack_layers:
                continue
            candidates.append(stack)
        return candidates

    def _stack_deck(self, stacks: Sequence[JSONObject]) -> list[JSONObject]:
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
        if feature is not None:
            feature_spec = self._feature_spec(feature)
            feature_cases = _string_list(feature_spec.get("coverage_cases"), "feature.coverage_cases")
            matching = [case for case in coverage_cases if case in feature_cases]
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
            weight = self._case_weight(stack_case, categories=_case_categories([stack_case]))
            if weight > 0:
                choices.append((stack_case, weight))
        stack_layers = _string_list(stack.get("layers"), "stack.layers")
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
            elif layer == "ipv6_routing":
                sampled = {
                    "next_header": _ipv6_next_header_for_stack(stack, "ipv6_routing"),
                    "type": 0,
                    "segments_left": 0,
                }
            else:
                spec = self._layer_spec(layer)
                self._validate_layer_backend_support(layer, spec)
                sampled = self._sample_layer_fields(ctx, layer, spec)
                self._validate_sampled_fields(layer, spec, sampled)
            if sampled:
                fields[layer] = sampled
                ctx.sampled_layers[layer] = sampled

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
        case_id = _identifier_part(case)
        case_key = f"-{case_id}-"
        for name in names:
            name_id = _identifier_part(name)
            if feature == "udp_options":
                if f"-{name_id}-" in case_key:
                    return name
            elif name_id in case_id:
                return name
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
        if feature == "tcp_options" and "tcp" in fields:
            fields["tcp"]["options"] = {"hex": _tcp_options_hex(case, behavior)}
            if case == "tcp-all-flags-reserved-offset":
                fields["tcp"]["flags"] = "all"
                fields["tcp"]["reserved"] = 7
        elif feature == "ipv4_options" and "ipv4" in fields:
            fields["ipv4"]["options"] = {"hex": _ipv4_options_hex(case, behavior)}
            fields["ipv4"]["flags"] = "none"
            fields["ipv4"]["fragment_offset"] = 0
        elif feature == "ipv6_fragment_routing":
            if "ipv6_fragment" in fields:
                fields["ipv6_fragment"]["more_fragments"] = False
                fields["ipv6_fragment"]["fragment_offset"] = 0
            if "ipv6_routing" in fields:
                routing = fields["ipv6_routing"]
                if "segment" in case:
                    routing["type"] = 4
                    routing["segments_left"] = 1
                    routing["addresses"] = ["2001:db8:ffff::1"]
                elif "mobile" in case:
                    routing["type"] = 2
                    routing["segments_left"] = 1
                    routing["addresses"] = ["2001:db8:ffff::2"]
                else:
                    routing["type"] = 0
                    routing["segments_left"] = 0
        elif feature == "icmpv4_errors" and "icmp" in fields:
            fields["icmp"]["type"] = _icmp_error_type_for_case(case, behavior, ipv6=False)
            fields["icmp"]["code"] = 0
        elif feature == "icmpv6_errors" and "icmpv6" in fields:
            fields["icmpv6"]["type"] = _icmp_error_type_for_case(case, behavior, ipv6=True)
            fields["icmpv6"]["code"] = 0
        elif feature == "dns_behavior" and "dns" in fields:
            _apply_dns_behavior(fields["dns"], case=case, behavior=behavior)
        elif feature == "dhcp_behavior" and "dhcp" in fields:
            _apply_dhcp_behavior(fields["dhcp"], case=case, behavior=behavior)
        elif feature == "udp_options" and "udp" in fields:
            _apply_udp_options_behavior(fields, case=case, behavior=behavior)

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
            if field_name not in _SUPPORTED_FIELDS.get(layer, set()):
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
        supported = _SUPPORTED_FIELDS.get(layer, set())
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
        if layer == "payload":
            return ctx.payload.hex() if field_name == "hex" else len(ctx.payload)
        if layer == "ethernet":
            if field_name == "src":
                return _mac_for_domain(ctx, domain, ctx.src_mac)
            if field_name == "dst":
                return _mac_for_domain(ctx, domain, ctx.dst_mac)
            if field_name == "ethertype":
                return _declared_ethertype_for_stack(ctx.stack, "ethernet")
        if layer == "vlan":
            if field_name == "ethertype":
                return _declared_ethertype_for_stack(ctx.stack, "vlan")
            return _integer_domain_value(ctx, domain, field_name, bits=_field_bits(field_spec))
        if layer == "arp":
            return _sample_arp_field(ctx, field_name, domain)
        if layer == "ipv4":
            return _sample_ipv4_field(ctx, field_name, domain, current_fields)
        if layer == "ipv6":
            return _sample_ipv6_field(ctx, field_name, domain)
        if layer == "udp":
            return _sample_udp_field(ctx, field_name, domain)
        if layer == "tcp":
            return _sample_tcp_field(ctx, field_name, domain, field_spec)
        if layer == "icmp":
            return _sample_icmp_field(ctx, field_name, domain)
        if layer == "icmpv6":
            return _sample_icmp_field(ctx, field_name, domain)
        if layer == "dns":
            return _sample_dns_field(ctx, field_name, domain)
        if layer == "dhcp":
            return _sample_dhcp_field(ctx, field_name, domain)
        if layer == "linux_cooked":
            return _sample_linux_cooked_field(ctx, field_name, domain)
        if layer == "null_loopback":
            return _sample_null_loopback_field(ctx, field_name)

        raise ValueError(f"spec error: unsupported layer sampler: {layer}")

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


class _SkipField:
    pass


_SKIP_FIELD = _SkipField()


@dataclass(slots=True)
class _SamplingContext:
    rng: random.Random
    profile: str
    feature_weights: Mapping[str, int]
    stack: list[str]
    payload_min: int
    payload_max: int
    feature: str | None
    case: str
    sampled_layers: dict[str, JSONObject] = field(default_factory=dict)
    _payload: bytes | None = None
    _src_mac: str | None = None
    _dst_mac: str | None = None
    _src_port: int | None = None
    _dst_port: int | None = None
    _src_ipv4: str | None = None
    _dst_ipv4: str | None = None
    _src_ipv6: str | None = None
    _dst_ipv6: str | None = None
    _arp_sender_ip: str | None = None
    _arp_target_ip: str | None = None

    @property
    def payload(self) -> bytes:
        if self._payload is None:
            self._payload = byte_payload(
                self.rng,
                min_length=self.payload_min,
                max_length=self.payload_max,
            )
        return self._payload

    @property
    def src_mac(self) -> str:
        if self._src_mac is None:
            self._src_mac = documentation_mac(self.rng)
        return self._src_mac

    @property
    def dst_mac(self) -> str:
        if self._dst_mac is None:
            self._dst_mac = _different_mac(self.rng, self.src_mac)
        return self._dst_mac

    @property
    def src_port(self) -> int:
        if self._src_port is None:
            self._src_port = ephemeral_port(self.rng)
        return self._src_port

    @property
    def dst_port(self) -> int:
        if self._dst_port is None:
            self._dst_port = _different_port(self.rng, self.src_port)
        return self._dst_port

    @property
    def src_ipv4(self) -> str:
        if self._src_ipv4 is None:
            self._src_ipv4 = documentation_ipv4(self.rng)
        return self._src_ipv4

    @property
    def dst_ipv4(self) -> str:
        if self._dst_ipv4 is None:
            self._dst_ipv4 = _different_ipv4(self.rng, self.src_ipv4)
        return self._dst_ipv4

    @property
    def src_ipv6(self) -> str:
        if self._src_ipv6 is None:
            self._src_ipv6 = documentation_ipv6(self.rng)
        return self._src_ipv6

    @property
    def dst_ipv6(self) -> str:
        if self._dst_ipv6 is None:
            self._dst_ipv6 = _different_ipv6(self.rng, self.src_ipv6)
        return self._dst_ipv6

    @property
    def arp_sender_ip(self) -> str:
        if self._arp_sender_ip is None:
            self._arp_sender_ip = documentation_ipv4(self.rng)
        return self._arp_sender_ip

    @property
    def arp_target_ip(self) -> str:
        if self._arp_target_ip is None:
            self._arp_target_ip = _different_ipv4(self.rng, self.arp_sender_ip)
        return self._arp_target_ip


def _field_specs(spec: JSONObject, layer: str) -> list[JSONObject]:
    raw_fields = spec.get("fields")
    if not isinstance(raw_fields, Sequence) or isinstance(raw_fields, (str, bytes)):
        raise ValueError(f"layers.{layer}.fields must be a list")
    return [_object(field, f"layers.{layer}.fields item") for field in raw_fields]


def _object_list(value: object, name: str) -> list[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{name} must be a list")
    return list(value)


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


def _field_bits(field_spec: JSONObject) -> int:
    field_type = _string(field_spec.get("type"), "field.type")
    if field_type.startswith("uint"):
        return int(field_type.removeprefix("uint"))
    return 16


def _integer_domain_value(
    ctx: _SamplingContext,
    domain: object,
    field_name: str,
    *,
    bits: int,
) -> int:
    maximum = (1 << bits) - 1
    if isinstance(domain, bool):
        return int(domain)
    if isinstance(domain, int):
        return domain
    if domain == "boundary":
        return weighted_choice(ctx.rng, ((0, 1), (maximum, 1)))
    if domain == "deterministic":
        return bounded_int(ctx.rng, 0, maximum)
    if domain == "dynamic":
        return ephemeral_port(ctx.rng)
    if domain == "http":
        return 80
    if domain == "https":
        return 443
    if domain == "dns_client":
        return ephemeral_port(ctx.rng)
    if domain == "dns_server":
        return 53
    if domain == "bootpc":
        return 68
    if domain == "bootps":
        return 67
    raise ValueError(f"spec error: unsupported integer domain for {field_name}: {domain!r}")


def _mac_for_domain(ctx: _SamplingContext, domain: object, default: str) -> str:
    if domain == "broadcast":
        return "ff:ff:ff:ff:ff:ff"
    if domain == "zero":
        return "00:00:00:00:00:00"
    return default


def _is_ipv4_root_dhcp_stack(stack: Sequence[str]) -> bool:
    """Return True for the IPv4-root, unicast live DHCP stack.

    The ``ipv4 / udp / dhcp`` stack carries DHCP as a one-way unicast oracle
    packet between provider endpoints. It has no Ethernet frame, so link-layer
    broadcast delivery, the IPv4 limited-broadcast destination, and the DHCP
    broadcast flag have no meaning and would make the packet ineligible for
    provider-backed live exchange. The Ethernet-root DHCP stack keeps those
    domains for offline link-layer coverage.
    """

    return "dhcp" in stack and "ethernet" not in stack


def _ipv4_for_domain(ctx: _SamplingContext, domain: object, default: str, *, dst: bool) -> str:
    if domain == "zero":
        return "0.0.0.0"
    if domain == "broadcast" and dst:
        if _is_ipv4_root_dhcp_stack(ctx.stack):
            return default
        return "255.255.255.255"
    return default


def _declared_ethertype_for_stack(stack: Sequence[str], layer: str) -> str:
    value = _ethertype_for_stack(stack, layer)
    return "experimental" if value == "unknown" else value


def _sample_arp_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "hardware_type":
        return "ethernet"
    if field_name == "protocol_type":
        return "ipv4"
    if field_name == "hardware_length":
        return _integer_domain_value(ctx, domain, field_name, bits=8)
    if field_name == "protocol_length":
        return _integer_domain_value(ctx, domain, field_name, bits=8)
    if field_name == "opcode":
        return domain
    if field_name == "sender_hardware_address":
        return _mac_for_domain(ctx, domain, ctx.src_mac)
    if field_name == "target_hardware_address":
        return _mac_for_domain(ctx, domain, ctx.dst_mac)
    if field_name == "sender_protocol_address":
        return _arp_protocol_address_for_domain(ctx, domain, ctx.arp_sender_ip)
    if field_name == "target_protocol_address":
        return _arp_protocol_address_for_domain(ctx, domain, ctx.arp_target_ip)
    raise ValueError(f"spec error: unsupported arp field sampler: {field_name}")


def _arp_protocol_address_for_domain(ctx: _SamplingContext, domain: object, default: str) -> str:
    if domain == "zero":
        return "0.0.0.0"
    return default


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
    if field_name == "ttl":
        return _integer_domain_value(ctx, domain, field_name, bits=8)
    if field_name == "protocol":
        return _ipv4_protocol_for_stack(ctx.stack)
    if field_name == "identification":
        return _integer_domain_value(ctx, domain, field_name, bits=16)
    if field_name == "flags":
        if any(layer in ctx.stack for layer in ("tcp", "udp", "icmp", "dns", "dhcp")):
            return "none"
        if ctx.profile == "smoke":
            return "none"
        return str(domain)
    if field_name == "fragment_offset":
        if any(layer in ctx.stack for layer in ("tcp", "udp", "icmp", "dns", "dhcp")):
            return 0
        if current_fields.get("flags") == "mf":
            return _integer_domain_value(ctx, domain, field_name, bits=13)
        return 0
    if field_name == "options":
        return {"hex": _ipv4_options_hex(ctx.case, str(domain))}
    raise ValueError(f"spec error: unsupported ipv4 field sampler: {field_name}")


def _sample_ipv6_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "src":
        return ctx.src_ipv6
    if field_name == "dst":
        return ctx.dst_ipv6
    if field_name == "traffic_class":
        return _integer_domain_value(ctx, domain, field_name, bits=8)
    if field_name == "flow_label":
        return _integer_domain_value(ctx, domain, field_name, bits=20)
    if field_name == "next_header":
        return _ipv6_next_header_for_stack(ctx.stack, "ipv6")
    if field_name == "hop_limit":
        return _integer_domain_value(ctx, domain, field_name, bits=8)
    raise ValueError(f"spec error: unsupported ipv6 field sampler: {field_name}")


def _sample_udp_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "src_port":
        if "dhcp" in ctx.stack:
            return 68
        if "dns" in ctx.stack:
            return ephemeral_port(ctx.rng)
        if domain in {"bootpc", "dns_client", "dynamic"}:
            return _integer_domain_value(ctx, domain, field_name, bits=16)
        return ctx.src_port
    if field_name == "dst_port":
        if "dhcp" in ctx.stack:
            return 67
        if "dns" in ctx.stack:
            return 53
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


def _sample_icmp_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "type":
        return str(domain).replace("_", "-") if domain in {"echo_reply", "echo_request"} else domain
    if field_name == "code":
        return 0
    if field_name in {"identifier", "sequence"}:
        return bounded_int(ctx.rng, 0, 65535)
    raise ValueError(f"spec error: unsupported icmp field sampler: {field_name}")


def _sample_dns_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "transaction_id":
        return _integer_domain_value(ctx, domain, field_name, bits=16)
    if field_name == "is_response":
        return False
    if field_name == "opcode":
        return "query"
    if field_name == "flags":
        return ["recursion_desired"]
    if field_name == "response_code":
        return "no_error"
    if field_name == "questions":
        question_count = 2 if domain == "multiple_questions" and ctx.profile in {"boundary", "fuzz"} else 1
        names = ("example.com.", "example.net.", "libcrafter.test.")
        questions: list[JSONObject] = []
        for index in range(question_count):
            questions.append(
                {
                    "qname": names[index % len(names)],
                    "qtype": weighted_choice(ctx.rng, (("A", 3), ("AAAA", 1))),
                }
            )
        return questions
    if field_name == "answers":
        return _dns_answers_for_domain(ctx, domain)
    raise ValueError(f"spec error: unsupported dns field sampler: {field_name}")


def _sample_dhcp_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "op":
        return domain
    if field_name == "hardware_type":
        return "ethernet"
    if field_name == "hardware_length":
        return 6
    if field_name == "transaction_id":
        return bounded_int(ctx.rng, 0, (1 << 32) - 1)
    if field_name == "flags":
        if domain == "broadcast" and _is_ipv4_root_dhcp_stack(ctx.stack):
            return "none"
        return domain
    if field_name == "client_ip":
        return "0.0.0.0" if domain == "zero" else ctx.src_ipv4
    if field_name == "your_ip":
        return "0.0.0.0" if domain == "zero" else ctx.dst_ipv4
    if field_name == "client_hardware_address":
        return ctx.src_mac
    if field_name == "options":
        return _dhcp_option_domains(ctx, domain)
    raise ValueError(f"spec error: unsupported dhcp field sampler: {field_name}")


def _dhcp_option_domains(ctx: _SamplingContext, domain: object) -> list[object]:
    options: list[object] = ["message-type=discover"]
    boundary = ctx.profile in {"boundary", "fuzz"}
    if domain == "hostname" and ctx.profile != "smoke":
        options.append("hostname=libcrafter-oracle")
    elif domain == "domain_name" and boundary:
        options.append("domain=example.com")
    elif domain == "requested_ip" and boundary:
        options.append(f"requested_addr={ctx.dst_ipv4}")
    elif domain == "server_id" and boundary:
        options.append(f"server_id={ctx.src_ipv4}")
    elif domain == "lease_time" and boundary:
        options.append(("lease_time", 3600))
    elif domain == "router" and boundary:
        options.append(f"router={ctx.src_ipv4}")
    elif domain == "dns_server" and boundary:
        options.append(f"name_server={ctx.dst_ipv4}")
    elif domain == "vendor_class" and boundary:
        options.append(["vendor_class_id", "6c6962637261667465722d6f7261636c65"])
    elif domain == "client_identifier" and boundary:
        options.append(["client_id", "01" + ctx.src_mac.replace(":", "")])
    elif domain == "classless_static_route" and boundary:
        options.append(["classless_static_routes", [f"192.0.2.0/24:{ctx.src_ipv4}"]])
    elif domain == "relay_agent" and boundary:
        options.append(["relay_agent_information", "0103616263"])
    elif domain == "parameter_request_list" and boundary:
        options.append(["param_req_list", [1, 3, 6]])
    options.append("end")
    return options


def _tcp_options_hex(case: str, behavior: str) -> str:
    key = f"{case} {behavior}".replace("_", "-")
    if "sack" in key:
        return "0402050a0000000100000002"
    if any(token in key for token in ("mptcp", "fast-open", "edo", "generic", "advanced")):
        return "1e04000122040102fd040000fe040102"
    if "header-boundary" in key or "all-flags" in key:
        return "01010101"
    return "020405b4010303070402080a0102030405060708"


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


def _apply_dns_behavior(fields: JSONObject, *, case: str, behavior: str) -> None:
    key = f"{case} {behavior}".replace("_", "-")
    if "compressed-names" in key:
        fields.clear()
        fields["dns_raw"] = _dns_compressed_names_raw_spec()
        return
    if "name-records-compressed" in key:
        # Compressed NS/CNAME/PTR input: the Scapy reference owns hand-built
        # bytes whose owner and RDATA names are compression pointers, and
        # libcrafter normalizes to the same uncompressed DnsRecordData::Name
        # model on decode. Checked before the uncompressed name-records branch
        # because that token is a substring of this one.
        fields.clear()
        fields["dns_raw"] = _dns_name_records_compressed_raw_spec()
        return
    if "raw-unknown-records" in key:
        # A response carrying record types this crate intentionally keeps as
        # DnsRecordData::Raw: an unknown private-use numeric TYPE plus the
        # deferred NSEC3PARAM (51), TLSA (52), KEY (25), and NAPTR (35) types
        # from docs/dns.md. Each RDATA is a deterministic opaque blob carried as
        # hex so neither backend reinterprets it, and the TYPE is given as a
        # numeric IANA codepoint so both the Scapy DNSRR(type=N) reference and the
        # libcrafter DnsRecordData::Raw materializer agree byte-for-byte. The
        # owner names, TTLs, and IN class are stable. libcrafter must decode every
        # answer to DnsRecordData::Raw (never a mis-typed record) and recompile the
        # same RDATA bytes. (raw-unknown-records is not a substring of any other
        # case id, so the matcher resolves this branch unambiguously.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": 65280}]
        fields["answers"] = [
            {
                # Private-use unknown TYPE 65280 (RFC 6895 Section 3.1): no named
                # mapping on either backend; preserved as a numeric codepoint.
                "name": "unknown.example.com.",
                "type": 65280,
                "ttl": 3600,
                "data": {"hex": "deadbeef"},
            },
            {
                # NSEC3PARAM (51): deferred to Raw (docs/dns.md). Bytes look like a
                # plausible NSEC3PARAM RDATA but are never parsed into typed fields.
                "name": "example.com.",
                "type": 51,
                "ttl": 300,
                "data": {"hex": "0100000a04aabbccdd"},
            },
            {
                # TLSA (52): deferred certificate-association record, kept Raw.
                "name": "_443._tcp.example.com.",
                "type": 52,
                "ttl": 300,
                "data": {"hex": "030101a1b2c3d4e5f6"},
            },
            {
                # KEY (25): cryptographic-key transport type, kept Raw.
                "name": "example.com.",
                "type": 25,
                "ttl": 300,
                "data": {"hex": "010003080a0b0c0d"},
            },
            {
                # NAPTR (35): deferred naming-authority-pointer record, kept Raw.
                "name": "example.com.",
                "type": 35,
                "ttl": 300,
                "data": {"hex": "0064000a0153000455524c00"},
            },
        ]
        return
    if "dnssec-ds-dnskey-rrsig" in key:
        # An authoritative response carrying the three core DNSSEC delegation and
        # signature records (RFC 4034) with raw numeric fields and opaque
        # key/digest/signature material that neither backend interprets
        # cryptographically. The DS RDATA is Key Tag, Algorithm, Digest Type, and
        # Digest (Section 5.1); the DNSKEY RDATA is Flags, Protocol, Algorithm,
        # and Public Key (Section 2.1); the RRSIG RDATA is Type Covered,
        # Algorithm, Labels, Original TTL, Signature Expiration, Signature
        # Inception, Key Tag, the uncompressed Signer's Name, and the Signature
        # (Section 3.1). Every name is uncompressed and the records use stable
        # values, so both backends agree byte-for-byte in both directions.
        # (dnssec-ds-dnskey-rrsig is not a substring of any other case id, so the
        # dispatcher resolves this branch unambiguously.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "DS"}]
        fields["answers"] = [
            {
                # DS: Key Tag 12345, Algorithm 8 (RSASHA256), Digest Type 2
                # (SHA-256), and a 32-octet opaque digest.
                "name": "example.com.",
                "type": "DS",
                "class": "IN",
                "ttl": 3600,
                "key_tag": 12345,
                "algorithm": 8,
                "digest_type": 2,
                "digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            },
            {
                # DNSKEY: Flags 257 (Zone Key + SEP), Protocol 3, Algorithm 8, and
                # an opaque public-key blob.
                "name": "example.com.",
                "type": "DNSKEY",
                "class": "IN",
                "ttl": 3600,
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "public_key": "03010001deadbeefcafebabe",
            },
            {
                # RRSIG over the DS RRset: every fixed field carries a stable raw
                # value, the Signer's Name is uncompressed example.com., and the
                # signature is opaque bytes.
                "name": "example.com.",
                "type": "RRSIG",
                "class": "IN",
                "ttl": 3600,
                "type_covered": "DS",
                "algorithm": 8,
                "labels": 2,
                "original_ttl": 3600,
                "signature_expiration": 0x65005D00,
                "signature_inception": 0x645E0B80,
                "key_tag": 12345,
                "signer_name": "example.com.",
                "signature": "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            },
        ]
        return
    if "dnssec-nsec-bitmaps" in key:
        # An authoritative response carrying two NSEC (type 47) answers whose
        # Type Bit Maps (RFC 4034 Section 4.1.2) exercise the full encoder:
        #
        #   * the first answer mirrors the RFC 4034 Section 4.3 example owner
        #     alfa.example.com. with next name host.example.com. and the present
        #     types A (1), MX (15), RRSIG (46), NSEC (47), and the unknown
        #     codepoint TYPE1234, which spans window block 0 and window block 4;
        #   * the second answer feeds an UNSORTED list with a DUPLICATE entry
        #     spanning three window blocks so that the libcrafter
        #     DnsTypeBitmaps::from_types sort/de-dup and the Scapy DNSRRNSEC
        #     RRlist2bitmap normalization both collapse to the same minimal,
        #     window-ordered encoding.
        #
        # Both backends sort, de-duplicate, and emit minimal windows, so the
        # decoded type set agrees in both directions even though the second
        # answer's source order is deliberately scrambled. The reference-built
        # bytes therefore match the RFC-style minimal encoding, and the
        # libcrafter-built bytes verify the sorted output. (dnssec-nsec-bitmaps
        # is dispatched here before the shorter dnssec-nsec / dnssec-nsec-bitmap
        # substrings, so resolution stays deterministic.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "alfa.example.com.", "qtype": "NSEC"}]
        fields["answers"] = [
            {
                # RFC 4034 Section 4.3 NSEC example: window 0 (A, MX, RRSIG,
                # NSEC) plus window 4 (the unknown codepoint TYPE1234). The
                # neutral type names and the bare numeric codepoint map to the
                # same RR-type values on both backends.
                "name": "alfa.example.com.",
                "type": "NSEC",
                "class": "IN",
                "ttl": 86400,
                "next_name": "host.example.com.",
                "type_bitmaps": ["A", "MX", "RRSIG", "NSEC", 1234],
            },
            {
                # Unsorted input with a duplicate A (1) entry spanning window
                # blocks 0, 1, and 255 (codepoints 0xff01). libcrafter sorts and
                # de-duplicates on construction and Scapy normalizes identically,
                # so the minimal, window-ordered encoding is deterministic.
                "name": "host.example.com.",
                "type": "NSEC",
                "class": "IN",
                "ttl": 86400,
                "next_name": "alfa.example.com.",
                "type_bitmaps": [47, 1, 300, 1, 0xFF01, 15],
            },
        ]
        return
    if "dnssec-nsec3" in key:
        # An authoritative response carrying three NSEC3 (type 50) answers whose
        # RDATA exercises the full RFC 5155 Section 3.2 wire layout: Hash
        # Algorithm, Flags, Iterations, Salt Length + Salt, Hash Length + next
        # hashed owner name, then Type Bit Maps. NSEC3 hash, salt, and next
        # hashed owner material is wire data only; libcrafter preserves the bytes
        # and never validates DNSSEC cryptography.
        #
        #   * answer 1 uses a NON-EMPTY salt, a non-empty next hashed owner name,
        #     and MULTIPLE type bitmap entries (A, NS, SOA, RRSIG, DNSKEY) in a
        #     single window block;
        #   * answer 2 uses an EMPTY salt (Salt Length 0 omits the Salt field)
        #     with a different next hashed owner name and a small bitmap;
        #   * answer 3 uses an UNKNOWN hash algorithm value (0xfe) and an UNKNOWN
        #     high type bitmap codepoint (TYPE65280) spanning a later window block,
        #     proving the numeric fields and minimal window encoding survive.
        #
        # Salt and next hashed owner are carried as hex blobs so both backends
        # preserve the exact octets as bytes, not text. The Scapy DNSRRNSEC3
        # reference and the libcrafter DnsRecord::nsec3 materializer produce the
        # same uncompressed bytes, so the case is strict-byte in both directions.
        # (dnssec-nsec3 is dispatched here, after dnssec-nsec-bitmaps and before
        # any shorter dnssec-nsec substring branch, so resolution is
        # deterministic.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "NSEC3"}]
        fields["answers"] = [
            {
                # Non-empty salt, non-empty next hashed owner name, and multiple
                # type bitmap entries in a single window block.
                "name": "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.com.",
                "type": "NSEC3",
                "class": "IN",
                "ttl": 86400,
                "hash_algorithm": 1,  # SHA-1
                "flags": 1,  # Opt-Out
                "iterations": 12,
                "salt": {"hex": "aabbccdd"},
                "next_hashed_owner": {
                    "hex": "1112131415161718191a1b1c1d1e1f2021222324"
                },
                "type_bitmaps": ["A", "NS", "SOA", "RRSIG", "DNSKEY"],
            },
            {
                # Empty salt: Salt Length 0 omits the Salt field entirely.
                "name": "2vptu5timamqttgl4luu9kg21e0aor3s.example.com.",
                "type": "NSEC3",
                "class": "IN",
                "ttl": 86400,
                "hash_algorithm": 1,
                "flags": 0,
                "iterations": 0,
                "salt": {"hex": ""},
                "next_hashed_owner": {
                    "hex": "25262728292a2b2c2d2e2f30313233343536373839"
                },
                "type_bitmaps": ["A", "RRSIG"],
            },
            {
                # Unknown hash algorithm value and an unknown high type bitmap
                # codepoint spanning a later window block; both stay raw numeric
                # wire data.
                "name": "th1q5pl8ku5b8c98er8gj7p9hf2d8jcm.example.com.",
                "type": "NSEC3",
                "class": "IN",
                "ttl": 86400,
                "hash_algorithm": 0xFE,  # unassigned hash algorithm
                "flags": 0,
                "iterations": 2500,
                "salt": {"hex": "deadbeef"},
                "next_hashed_owner": {
                    "hex": "393a3b3c3d3e3f404142434445464748494a4b4c"
                },
                "type_bitmaps": ["A", "RRSIG", 65280],
            },
        ]
        return
    if "header-flags-opcodes" in key:
        fields["is_response"] = True
        fields["opcode"] = "status"
        fields["response_code"] = "refused"
        fields["flags"] = [
            "authoritative",
            "truncated",
            "recursion_available",
            "authentic_data",
            "checking_disabled",
        ]
        fields.pop("answers", None)
        return
    if "header-empty-sections" in key:
        # Empty answer/authority/additional sections so the auto-filled counts
        # stay zero while the single question keeps QDCOUNT at one.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        fields.pop("authority", None)
        fields.pop("authorities", None)
        fields.pop("additional", None)
        fields.pop("additionals", None)
        return
    if "header-counts" in key:
        # One record in each of the three response sections so the encoder
        # auto-fills ANCOUNT/NSCOUNT/ARCOUNT to nonzero values from the typed
        # vectors rather than from any user-set count field.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative", "recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields["answers"] = [
            {"name": "example.com.", "type": "A", "ttl": 60, "address": "192.0.2.10"}
        ]
        fields["authority"] = [
            {"name": "example.com.", "type": "NS", "ttl": 300, "target": "ns1.example.com."}
        ]
        fields["additional"] = [
            {"name": "ns1.example.com.", "type": "A", "ttl": 300, "address": "192.0.2.53"}
        ]
        return
    if "header-raw-flags" in key:
        # Reserved Z header bit set through the raw-flags escape hatch; the
        # encoder must preserve a bit that has no named setter.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["reserved_z"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        return
    if "header-opcode" in key:
        # A non-default named opcode on a plain query; STATUS keeps the message
        # otherwise minimal so the four opcode bits are the load-bearing field.
        fields["is_response"] = False
        fields["opcode"] = "status"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_desired"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        return
    if "header-rcode" in key:
        # A named rcode on a response; REFUSED is representable in both
        # materializers and exercises the low four flag-word bits.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "refused"
        fields["flags"] = ["recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        return
    if "header-flags" in key:
        # Every named header flag bit set on a recursive query so each flag is
        # exercised independently of opcode/rcode.
        fields["is_response"] = False
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = [
            "authoritative",
            "truncated",
            "recursion_desired",
            "recursion_available",
            "authentic_data",
            "checking_disabled",
        ]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        return
    if "header-qr" in key:
        # Response-bit set with recursion-available, the canonical server reply
        # header shape, paired with the matching query via the QR bit.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        return
    if "header-id" in key:
        # Nonzero transaction ID on an otherwise plain query so the 16-bit ID
        # field is the load-bearing header value.
        fields["is_response"] = False
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_desired"]
        fields["transaction_id"] = 0x1A2B
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        return
    if "name-root-escaped" in key:
        # Byte-preserving name shapes in one message: the root name as the
        # question owner, a trailing-dot text answer name, a CNAME target that
        # carries literal dot and backslash octets via the RFC 1035 Section 5.1
        # \DDD escape, and a PTR target whose label is a non-UTF-8 byte run
        # (\000 and \255). The libcrafter materializer parses these presentation
        # strings back into the exact wire octets, so the decoded header/section
        # model agrees in both directions. The compared subset is header plus
        # section counts, so the special label octets never need a lossless
        # Scapy high-level encode; the faithful byte-preserving assertions live
        # in the crate name tests.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_available"]
        fields["questions"] = [{"qname": ".", "qtype": "A"}]
        fields["answers"] = [
            {"name": "example.com.", "type": "A", "ttl": 60, "address": "192.0.2.10"},
            {
                "name": "trailing.example.com.",
                "type": "CNAME",
                "ttl": 300,
                # Literal '.' (\046) and '\' (\092) inside a single label.
                "target": "lit\\046dot\\092slash.example.com.",
            },
            {
                "name": "ptr.example.com.",
                "type": "PTR",
                "ttl": 300,
                # Non-UTF-8 label: NUL (\000) and 0xff (\255) octets.
                "target": "\\000\\255.example.com.",
            },
        ]
        return
    if "record-soa" in key:
        # Focused single-SOA response so a SOA decode failure reproduces without
        # the SRV answer in the message. Every fixed SOA field carries a distinct
        # nonzero value (SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM) and both nested
        # names (MNAME, RNAME) are documentation names, so the strict byte encode
        # pins each field against the Scapy reference. Checked before the combined
        # soa-srv-records branch; the focused id never contains that token.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "SOA"}]
        fields["answers"] = [
            {
                "name": "example.com.",
                "type": "SOA",
                "ttl": 300,
                "primary_name": "ns1.example.com.",
                "responsible_name": "hostmaster.example.com.",
                "serial": 2024010101,
                "refresh": 7200,
                "retry": 3600,
                "expire": 1209600,
                "minimum": 300,
            }
        ]
        return
    if "record-srv" in key:
        # Focused single-SRV response so an SRV decode failure reproduces without
        # the SOA answer. The three fixed 16-bit fields (priority, weight, port)
        # are distinct nonzero values and the target is a documentation name, so
        # the strict byte encode pins every SRV field against the Scapy reference.
        # Checked before the combined soa-srv-records branch; the focused id never
        # contains that token.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "_sip._tcp.example.com.", "qtype": "SRV"}]
        fields["answers"] = [
            {
                "name": "_sip._tcp.example.com.",
                "type": "SRV",
                "ttl": 60,
                "priority": 10,
                "weight": 60,
                "port": 5060,
                "target": "sip.example.com.",
            }
        ]
        return
    if "soa-srv-records" in key:
        # A response carrying one SOA authority-style answer and one SRV answer
        # so the libcrafter materializer exercises both typed record builders in
        # a single message and compares against the Scapy reference.
        fields["is_response"] = True
        fields["questions"] = [{"qname": "example.com.", "qtype": "SOA"}]
        fields["answers"] = [
            {
                "name": "example.com.",
                "type": "SOA",
                "ttl": 300,
                "primary_name": "ns1.example.com.",
                "responsible_name": "hostmaster.example.com.",
                "serial": 2024010101,
                "refresh": 7200,
                "retry": 3600,
                "expire": 1209600,
                "minimum": 300,
            },
            {
                "name": "_sip._tcp.example.com.",
                "type": "SRV",
                "ttl": 60,
                "priority": 10,
                "weight": 60,
                "port": 5060,
                "target": "sip.example.com.",
            },
        ]
        return
    if "a-aaaa-records" in key:
        # An authoritative response carrying A and AAAA answers for the same
        # owner name, with stable TTLs and documentation IPv4/IPv6 addresses.
        # The two answers are ordered AAAA before A so the case also exercises a
        # non-canonical answer ordering; both materializers must preserve the
        # supplied order and emit identical uncompressed names so the encode is
        # byte-exact in both directions.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative", "recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields["answers"] = [
            {
                "name": "host.example.com.",
                "type": "AAAA",
                "ttl": 3600,
                "address": "2001:db8:1::10",
            },
            {
                "name": "host.example.com.",
                "type": "A",
                "ttl": 3600,
                "address": "192.0.2.10",
            },
            {
                "name": "alt.example.net.",
                "type": "A",
                "ttl": 300,
                "address": "198.51.100.20",
            },
            {
                "name": "alt.example.net.",
                "type": "AAAA",
                "ttl": 300,
                "address": "2001:db8:2::20",
            },
        ]
        return
    if "name-records" in key:
        # An authoritative response carrying NS, CNAME, and PTR answers. NS,
        # CNAME, and PTR all carry their RDATA as a single nested <domain-name>,
        # so all three map to DnsRecordData::Name and must match Scapy in both
        # the record owner and the RDATA name. The CNAME target is root-adjacent
        # (a single label directly under the root) and the PTR owner is a
        # reverse-DNS name, so the case spans ordinary and boundary name shapes.
        # Both materializers emit every name uncompressed, so the encode is
        # byte-exact in both directions. The compressed companion is the separate
        # dns-name-records-compressed case. (Checked after name-records-compressed,
        # which returns early at the top of this dispatcher.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "NS"}]
        fields["answers"] = [
            {
                "name": "example.com.",
                "type": "NS",
                "ttl": 3600,
                "target": "ns1.example.com.",
            },
            {
                "name": "www.example.com.",
                "type": "CNAME",
                "ttl": 300,
                # Root-adjacent target: a single label directly under the root.
                "target": "host.example.",
            },
            {
                "name": "20.113.0.203.in-addr.arpa.",
                "type": "PTR",
                "ttl": 300,
                "target": "host.example.com.",
            },
        ]
        return
    if "mx-txt-records" in key:
        # A response carrying one MX answer and a sequence of TXT answers so a
        # single message exercises the MX preference + nested exchange name plus
        # every TXT character-string shape libcrafter must preserve: one string,
        # multiple strings, an empty string, a non-UTF-8 binary string (carried
        # as hex so neither materializer mangles the octets), and a single
        # string at the 255-octet length boundary. Both materializers emit
        # uncompressed names and exact-length character-strings, so the encode is
        # byte-exact in both directions.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative", "recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "MX"}]
        fields["answers"] = [
            {
                "name": "example.com.",
                "type": "MX",
                "ttl": 3600,
                "preference": 10,
                "exchange": "mail.example.com.",
            },
            {
                "name": "example.com.",
                "type": "TXT",
                "ttl": 300,
                "strings": ["v=spf1 -all"],
            },
            {
                "name": "example.com.",
                "type": "TXT",
                "ttl": 300,
                "strings": ["first chunk", "second chunk"],
            },
            {
                "name": "empty.example.com.",
                "type": "TXT",
                "ttl": 300,
                "strings": [""],
            },
            {
                "name": "bin.example.com.",
                "type": "TXT",
                "ttl": 300,
                # Non-UTF-8 octets (NUL, 0xfe, 0xff, DEL) carried as hex so the
                # character-string bytes survive both materializers verbatim.
                "strings": [{"hex": "000a1ffeff617f"}],
            },
            {
                "name": "max.example.com.",
                "type": "TXT",
                "ttl": 300,
                # A single character-string at the 255-octet length boundary.
                "strings": [{"hex": "78" * 255}],
            },
        ]
        return
    if "multi-question-classes" in key:
        # A single query carrying several questions in a deterministic order that
        # exercise the QTYPE and QCLASS axes together: named QTYPEs (A, AAAA, MX,
        # TXT, ANY) and a private unknown numeric QTYPE, paired with every named
        # QCLASS (IN, CH, HS, NONE, ANY) and a private unknown numeric QCLASS.
        # Section counts must auto-fill QDCOUNT from this questions vector, and
        # both materializers must preserve the unknown numeric codepoints.
        fields["is_response"] = False
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_desired"]
        fields["questions"] = [
            {"qname": "example.com.", "qtype": "A", "qclass": "IN"},
            {"qname": "example.net.", "qtype": "AAAA", "qclass": "CH"},
            {"qname": "mail.example.com.", "qtype": "MX", "qclass": "HS"},
            {"qname": "txt.example.com.", "qtype": "TXT", "qclass": "NONE"},
            {"qname": "any.example.com.", "qtype": "ANY", "qclass": "ANY"},
            # Private-use QTYPE 65280 (RFC 6895 Section 3.1) and QCLASS 65280
            # (RFC 6895 Section 3.2) as raw numeric codepoints neither backend
            # maps to a named type or class.
            {"qname": "unknown.example.com.", "qtype": 65280, "qclass": 65280},
        ]
        fields.pop("answers", None)
        return
    if "edns-options" in key:
        # A response carrying a single EDNS(0) OPT pseudo-record (RFC 6891
        # Section 6.1) whose RDATA holds an ordered list of option TLVs
        # (Section 6.1.2). The matrix spans the three source-backed options with
        # named constructors (NSID RFC 5001, COOKIE RFC 7873, Padding RFC 7830),
        # one option that has a registry mnemonic but no named constructor (DAU
        # RFC 6975, code 5), and one unknown option code (65534) that has no
        # mnemonic at all. The option order is fixed so the encoded byte stream
        # is deterministic, and every OPTION-DATA payload is carried as raw hex
        # so neither backend reinterprets the per-option bit field: Scapy emits
        # each as a generic EDNS0TLV(optcode=N, optdata=...) and libcrafter
        # carries each as an EdnsOption preserving the exact code and data bytes.
        # ("edns-options" is a substring only of this case id, never of
        # dns-edns-opt-basic, so the dispatcher resolves this branch
        # unambiguously and before the edns-opt-basic branch below.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        fields["additional"] = [
            {
                "name": ".",
                "type": "OPT",
                "udp_payload_size": 4096,
                "extended_rcode": 0,
                "version": 0,
                "dnssec_ok": True,
                "options": [
                    # NSID (code 3): opaque name-server identifier bytes.
                    {"option_code": 3, "option_data": "6e733031"},
                    # COOKIE (code 10): an 8-octet client cookie.
                    {"option_code": 10, "option_data": "0102030405060708"},
                    # Padding (code 12): zero octets used only for size padding.
                    {"option_code": 12, "option_data": "0000000000000000"},
                    # DAU (code 5): a registered option with a mnemonic but no
                    # named libcrafter constructor; raw algorithm-list bytes.
                    {"option_code": 5, "option_data": "0501080a"},
                    # Unknown option code 65534: no IANA mnemonic, preserved as
                    # opaque bytes.
                    {"option_code": 65534, "option_data": "cafe"},
                ],
            },
        ]
        return
    if "edns-opt-basic" in key:
        # A response carrying several EDNS(0) OPT pseudo-records in the additional
        # section (RFC 6891 Section 6.1). Each OPT exercises a different basic
        # field combination so a regression in any one packed field reproduces in
        # isolation: the UDP payload size lives in the OPT CLASS, while the
        # extended RCODE, EDNS version, and DO flag are packed into the OPT TTL.
        # The owner name is always root ("."), the option list is empty (the
        # option-TLV matrix is the separate dns-edns-options-* cases), and every
        # value round trips byte-for-byte because both the Scapy DNSRROPT
        # reference and the libcrafter DnsRecord::opt builder pack the same wire
        # fields. (edns-opt-basic is a substring only of this case id, so the
        # dispatcher resolves this branch unambiguously.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        fields["additional"] = [
            {
                # Bare OPT: default UDP payload size, no extended RCODE/version,
                # DO clear, empty option list.
                "name": ".",
                "type": "OPT",
                "udp_payload_size": 4096,
                "extended_rcode": 0,
                "version": 0,
                "dnssec_ok": False,
                "options": [],
            },
            {
                # Non-default small UDP payload size with the DO flag set.
                "name": ".",
                "type": "OPT",
                "udp_payload_size": 512,
                "extended_rcode": 0,
                "version": 0,
                "dnssec_ok": True,
                "options": [],
            },
            {
                # Non-zero extended RCODE (upper 8 bits of the 12-bit RCODE) on a
                # 1232-octet payload size, DO clear.
                "name": ".",
                "type": "OPT",
                "udp_payload_size": 1232,
                "extended_rcode": 0x12,
                "version": 0,
                "dnssec_ok": False,
                "options": [],
            },
            {
                # Maximum UDP payload size, a non-default EDNS version, DO set.
                "name": ".",
                "type": "OPT",
                "udp_payload_size": 65535,
                "extended_rcode": 0,
                "version": 1,
                "dnssec_ok": True,
                "options": [],
            },
        ]
        return
    if "response" in key:
        fields["is_response"] = True
        fields.pop("answers", None)
    if "multiple-questions" in key:
        fields["questions"] = [
            {"qname": "example.com.", "qtype": "A"},
            {"qname": "example.net.", "qtype": "AAAA"},
        ]
    if "truncated" in key:
        fields["flags"] = ["recursion_desired", "truncated"]
        fields["response_code"] = "server_failure"


def _dns_compressed_names_raw_spec() -> JSONObject:
    """Raw DNS spec with explicit compression pointers for the raw helper.

    The question name ``example.com.`` lands at the fixed offset 12 (right after
    the 12-octet header), so every compressed name in the message points back to
    offset 12. The case exercises a compressed question owner name (re-used as the
    first answer owner via a bare pointer) and a compression pointer in the
    embedded <domain-name> of each byte-preserving record type libcrafter
    decodes: CNAME/NS/PTR (name at RDATA start), MX (after the 2-octet
    preference), SOA (compressed MNAME and RNAME before the 20 fixed octets), SRV
    (after priority/weight/port), RRSIG signer (after the 18 fixed octets), NSEC
    next-domain (before the type bitmap), and SVCB/HTTPS target (after the 2-octet
    priority). Scapy's high-level fields will not emit these pointers, so the
    bytes are built by hand while staying under the Scapy reference backend.
    libcrafter re-encodes every name uncompressed, so this case is normalized: the
    decoded DNS name model agrees while the recompiled bytes differ from the
    pointer input (see specs/features/dns-behavior.yaml byte_policy).
    """

    ptr = 12  # The question name example.com. is at the fixed 12-octet offset.
    # The 20 fixed SOA octets after MNAME/RNAME: serial, refresh, retry, expire,
    # minimum (all 32-bit). The 18 fixed RRSIG octets: type covered (A=0x0001),
    # algorithm, labels, original TTL, expiration, inception, key tag. The NSEC
    # type bitmap is window 0, a 6-octet bitmap, with the A (1), RRSIG (46), and
    # NSEC (47) bits set.
    soa_fixed = "0000000100000e1000000708001baf8000000384"
    rrsig_fixed = "0001050200000e10655f5d00655e0b800539"
    nsec_bitmap = "0006400000000003"
    return {
        "transaction_id": 0x1234,
        "is_response": True,
        "flags": ["recursion_desired", "recursion_available"],
        "response_code": "no_error",
        "questions": [
            {"name": "example.com.", "type": "A", "class": "IN"},
        ],
        "answers": [
            # CNAME owner is a bare pointer to the question name; the RDATA target
            # is the label "alias" plus a pointer back to example.com.
            {
                "name_with_pointer": {"prefix": None, "pointer_offset": ptr},
                "type": "CNAME",
                "class": "IN",
                "ttl": 300,
                "target_with_pointer": {"prefix": "alias", "pointer_offset": ptr},
            },
            # NS RDATA is a bare pointer to the question name.
            {
                "name": "example.com.",
                "type": "NS",
                "class": "IN",
                "ttl": 300,
                "target_with_pointer": {"prefix": "ns1", "pointer_offset": ptr},
            },
            # PTR RDATA is a compressed name.
            {
                "name": "1.2.0.192.in-addr.arpa.",
                "type": "PTR",
                "class": "IN",
                "ttl": 300,
                "target_with_pointer": {"prefix": "host", "pointer_offset": ptr},
            },
            # MX exchange is a compressed name after the 2-octet preference (10).
            {
                "name": "example.com.",
                "type": "MX",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "prefix_hex": "000a",
                    "pointers": [{"prefix": "mail", "pointer_offset": ptr}],
                },
            },
            # SOA MNAME and RNAME are both compression pointers before 20 fixed
            # octets.
            {
                "name": "example.com.",
                "type": "SOA",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "pointers": [
                        {"prefix": "ns1", "pointer_offset": ptr},
                        {"prefix": "hostmaster", "pointer_offset": ptr},
                    ],
                    "suffix_hex": soa_fixed,
                },
            },
            # SRV target is a compressed name after priority/weight/port.
            {
                "name": "_sip._tcp.example.com.",
                "type": "SRV",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "prefix_hex": "000a0005162c",
                    "pointers": [{"prefix": "sip", "pointer_offset": ptr}],
                },
            },
            # RRSIG signer name is a compression pointer after the 18 fixed
            # octets; the remaining bytes are an opaque signature blob.
            {
                "name": "example.com.",
                "type": "RRSIG",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "prefix_hex": rrsig_fixed,
                    "pointers": [{"prefix": None, "pointer_offset": ptr}],
                    "suffix_hex": "abcdef0123456789",
                },
            },
            # NSEC next-domain name is a compression pointer before the type
            # bitmap window.
            {
                "name": "example.com.",
                "type": "NSEC",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "pointers": [{"prefix": "next", "pointer_offset": ptr}],
                    "suffix_hex": nsec_bitmap,
                },
            },
            # SVCB target is a compression pointer after the 2-octet priority.
            {
                "name": "_dns.example.com.",
                "type": "SVCB",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "prefix_hex": "0001",
                    "pointers": [{"prefix": "svc", "pointer_offset": ptr}],
                },
            },
            # HTTPS target is a compression pointer after the 2-octet priority.
            {
                "name": "example.com.",
                "type": "HTTPS",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "prefix_hex": "0001",
                    "pointers": [{"prefix": None, "pointer_offset": ptr}],
                },
            },
        ],
    }


def _dns_name_records_compressed_raw_spec() -> JSONObject:
    """Raw DNS spec for the compressed NS/CNAME/PTR name-records case.

    The question name ``example.com.`` is at the fixed 12-octet offset, so every
    owner and embedded RDATA name in this message is a compression pointer back
    to offset 12. NS, CNAME, and PTR all carry their RDATA as a single nested
    <domain-name> at the start of the RDATA, so each answer's target is a label
    prefix plus a pointer to the question name. Scapy's high-level fields will not
    emit these pointers, so the bytes are built by hand under the Scapy reference
    backend; libcrafter follows each pointer on decode and re-encodes every name
    uncompressed, so this case is normalized and matches the uncompressed
    ``dns-name-records`` decoded DnsRecordData::Name model.
    """

    ptr = 12  # The question name example.com. is at the fixed 12-octet offset.
    return {
        "transaction_id": 0x4E43,
        "is_response": True,
        "flags": ["authoritative"],
        "response_code": "no_error",
        "questions": [
            {"name": "example.com.", "type": "NS", "class": "IN"},
        ],
        "answers": [
            # NS owner is a bare pointer to the question name; the RDATA target is
            # the label "ns1" plus a pointer back to example.com.
            {
                "name": "example.com.",
                "type": "NS",
                "class": "IN",
                "ttl": 3600,
                "target_with_pointer": {"prefix": "ns1", "pointer_offset": ptr},
            },
            # CNAME owner is "www" plus a pointer; the RDATA target is "host"
            # plus a pointer back to example.com.
            {
                "name_with_pointer": {"prefix": "www", "pointer_offset": ptr},
                "type": "CNAME",
                "class": "IN",
                "ttl": 300,
                "target_with_pointer": {"prefix": "host", "pointer_offset": ptr},
            },
            # PTR owner is "ptr" plus a pointer; the RDATA target is "host" plus a
            # pointer back to example.com.
            {
                "name_with_pointer": {"prefix": "ptr", "pointer_offset": ptr},
                "type": "PTR",
                "class": "IN",
                "ttl": 300,
                "target_with_pointer": {"prefix": "host", "pointer_offset": ptr},
            },
        ],
    }


def _dns_answers_for_domain(ctx: _SamplingContext, domain: object) -> list[JSONObject]:
    if domain == "aaaa":
        return [{"name": "example.net.", "type": "AAAA", "ttl": 60, "address": ctx.dst_ipv6}]
    if domain == "cname":
        return [{"name": "example.org.", "type": "CNAME", "ttl": 60, "target": "alias.example.org."}]
    return [{"name": "example.com.", "type": "A", "ttl": 60, "address": ctx.dst_ipv4}]


# Backend-neutral DHCP option kinds that materialize byte-for-byte through both
# the Scapy reference backend and the libcrafter adapter, in fixed option order.
# Kinds the dhcp_behavior option_matrix lists that Scapy cannot encode
# byte-for-byte (parameter_request_list, vendor_class, client_identifier,
# classless_static_route, relay_agent, generic) are covered by native libcrafter
# fixtures rather than this cross-backend matrix; see
# tools/oracle/specs/layers/dhcp.yaml and features/dhcp-behavior.yaml.
DHCP_OPTION_MATRIX_TOKENS: tuple[str, ...] = (
    "message-type=discover",
    "hostname=libcrafter-oracle",
    "domain_name=example.com",
    "requested_ip=192.0.2.100",
    "server_id=192.0.2.1",
    "router=192.0.2.1",
    "domain_name_server=192.0.2.53",
    "lease_time=3600",
    "end",
)


def _dhcp_option_matrix() -> list[object]:
    """Return the deterministic byte-safe DHCP option matrix in option order.

    The matrix spans every cross-backend option kind the dhcp_behavior
    option_matrix lists as Scapy-byte-safe, in a fixed order, so a single
    generated plan exercises the whole matrix and the kinds are deterministic
    for both directions and both DHCP roots.
    """

    return list(DHCP_OPTION_MATRIX_TOKENS)


def _apply_dhcp_behavior(fields: JSONObject, *, case: str, behavior: str) -> None:
    key = f"{case} {behavior}".replace("_", "-")
    if "option-matrix" in key:
        fields["options"] = _dhcp_option_matrix()
        return
    if "offer" in key or "ack" in key:
        fields["op"] = "bootreply"
        fields["your_ip"] = "192.0.2.100"
        message = "ack" if "ack" in key else "offer"
        fields["options"] = [f"message-type={message}", "server_id=192.0.2.1", "end"]
    elif "nak" in key:
        fields["op"] = "bootreply"
        fields["options"] = ["message-type=nak", "server_id=192.0.2.1", "end"]
    elif "request" in key:
        fields["options"] = ["message-type=request", "requested_addr=192.0.2.100", "end"]
    elif "decline" in key:
        fields["options"] = ["message-type=decline", "requested_addr=192.0.2.100", "end"]
    elif "inform" in key:
        fields["options"] = ["message-type=inform", "hostname=libcrafter-oracle", "end"]
    elif "release" in key:
        fields["options"] = ["message-type=release", "server_id=192.0.2.1", "end"]
    elif "force-renew" in key:
        fields["op"] = "bootreply"
        fields["options"] = ["message-type=force_renew", "server_id=192.0.2.1", "end"]
    elif "lease-query" in key:
        fields["options"] = ["message-type=lease_query", "end"]


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


def _payload_hex_from_fields(payload: object) -> str:
    if not isinstance(payload, Mapping):
        return ""
    payload_hex = payload.get("hex", "")
    return payload_hex if isinstance(payload_hex, str) else ""


def _payload_hex_length(payload_hex: str) -> int:
    try:
        return len(bytes.fromhex(payload_hex))
    except ValueError:
        return 0


def _udp_options_field(key: str, *, payload_hex: str | None) -> JSONObject | None:
    options = _udp_option_intent(key)
    if not options:
        return None
    field: JSONObject = {
        "format": "udp_surplus_options",
        "placement": "after_udp_length",
        "udp_length_scope": "header_and_application_payload",
        "surplus_excluded_from_udp_checksum": True,
        "option_checksum": _udp_option_checksum_intent(key, True),
        "items": options,
    }
    if payload_hex is not None:
        field["application_payload"] = {
            "layer": "payload",
            "hex": payload_hex,
            "length": _payload_hex_length(payload_hex),
        }
    return field


def _udp_options_items(options_field: JSONObject | None) -> list[JSONObject]:
    if options_field is None:
        return []
    items = options_field.get("items")
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
        return []
    return [dict(item) for item in items if isinstance(item, Mapping)]


def _udp_option_checksum_intent(key: str, surplus: bool) -> JSONObject:
    if not surplus:
        return {"mode": "absent"}
    if "ipv4-zero-checksum" in key:
        return {"mode": "zero_allowed_when_udp_checksum_zero"}
    return {"mode": "auto_internet_checksum"}


def _udp_option_intent(key: str) -> list[JSONObject]:
    if "ipv4-zero-checksum" in key or "ipv6-zero-checksum" in key:
        return []
    if "apc" in key:
        return [
            {
                "kind": 2,
                "name": "apc",
                "length": 6,
                "checksum": "auto_crc32c_application_payload",
            }
        ]
    if "unknown-safe" in key:
        return [
            {
                "kind": 10,
                "name": "unassigned_safe",
                "length": 4,
                "data_hex": "aabb",
                "safety": "safe",
                "expected_status": "unknown_safe",
            }
        ]
    if "unknown-unsafe" in key:
        return [
            {
                "kind": 194,
                "name": "unassigned_unsafe",
                "length": 4,
                "data_hex": "dead",
                "safety": "unsafe",
                "expected_status": "unknown_unsafe",
            }
        ]
    if "unsupported-frag" in key:
        return [
            {
                "kind": 3,
                "name": "frag",
                "length": 10,
                "data_hex": "00010003aabbccdd",
                "expected_status": "unsupported_fragmentation",
            }
        ]
    if "surplus-application-boundary" in key:
        return [
            {"kind": 1, "name": "nop", "length": 1},
            {"kind": 0, "name": "eol", "length": 1},
        ]
    return [
        {"kind": 1, "name": "nop", "length": 1},
        {"kind": 4, "name": "mds", "length": 4, "max_datagram_size": 1440},
        {
            "kind": 5,
            "name": "mrds",
            "length": 5,
            "max_reassembled_size": 1500,
            "segment_count": 2,
        },
        {"kind": 6, "name": "req", "length": 6, "token": 16909060},
        {"kind": 7, "name": "res", "length": 6, "token": 168496141},
        {"kind": 8, "name": "time", "length": 10, "tsval": 16909060, "tsecr": 168496141},
    ]


def _is_malformed_case_name(case: str) -> bool:
    return "malformed" in case.replace("_", "-")


def _auto_sample_feature(feature: str) -> bool:
    return feature != "icmpv4_errors"


def _sample_linux_cooked_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "packet_type":
        return domain
    if field_name == "address_type":
        return "ethernet"
    if field_name == "address_length":
        return 6
    if field_name == "source_address":
        return {"hex": f"{ctx.src_mac.replace(':', '')}0000"}
    if field_name == "protocol":
        return _declared_ethertype_for_stack(ctx.stack, "linux_cooked")
    raise ValueError(f"spec error: unsupported linux_cooked field sampler: {field_name}")


def _sample_null_loopback_field(ctx: _SamplingContext, field_name: str) -> object:
    if field_name == "type":
        return "ipv4" if "ipv4" in ctx.stack else "ipv6"
    raise ValueError(f"spec error: unsupported null_loopback field sampler: {field_name}")


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


def _identifier_part(value: str) -> str:
    output = []
    for char in value.lower():
        output.append(char if char.isalnum() else "-")
    return "".join(output).strip("-") or "default"


def _json_object(value: object) -> JSONObject:
    if not isinstance(value, Mapping):
        raise ValueError("expected a JSON object")
    output: JSONObject = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError(f"JSON object key must be a string: {key!r}")
        output[key] = item  # type: ignore[assignment]
    return output


def _object(value: object, name: str) -> JSONObject:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return _json_object(value)


def _string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _string_list(value: object, name: str) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{name} must be a list of strings")
    if not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be a list of strings")
    return list(value)


def _string_or_none(value: object) -> str | None:
    if value is None or isinstance(value, str):
        return value
    raise ValueError(f"expected string or null: {value!r}")


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
    if {"ipv6_fragment", "ipv6_routing"}.issubset(feature_set):
        return "ipv6" in stack_set and bool(stack_set.intersection({"ipv6_fragment", "ipv6_routing"}))
    if {"ipv4", "ipv6"}.issubset(feature_set):
        return bool(stack_set.intersection(feature_set))
    return all(layer in stack_set for layer in feature_layers)


def _ipv6_extension_cases_for_stack(stack: Sequence[str], cases: Sequence[str]) -> list[str]:
    stack_set = set(stack)
    output: list[str] = []
    for case in cases:
        normalized = case.replace("_", "-")
        if "ipv6-fragment" in normalized and "ipv6_fragment" in stack_set:
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

    output: list[str] = []
    for case in cases:
        normalized = case.replace("_", "-")
        if "ipv4-zero-checksum" in normalized and "ipv4" not in stack_set:
            continue
        if "ipv6-zero-checksum" in normalized and "ipv6" not in stack_set:
            continue
        output.append(case)
    return output


def _ethertype_for_stack(stack: Sequence[str], layer: str) -> str:
    next_layer = _next_layer_after(stack, layer)
    if next_layer == "vlan":
        return "vlan"
    if next_layer == "arp":
        return "arp"
    if next_layer == "ipv4":
        return "ipv4"
    if next_layer == "ipv6":
        return "ipv6"
    return "unknown"


def _ipv4_protocol_for_stack(stack: Sequence[str]) -> str:
    next_layer = _next_layer_after(stack, "ipv4")
    if next_layer in {"icmp", "tcp", "udp"}:
        return next_layer
    return "unknown"


def _ipv6_next_header_for_stack(stack: Sequence[str], layer: str) -> str:
    next_layer = _next_layer_after(stack, layer)
    if next_layer == "ipv6_fragment":
        return "fragment"
    if next_layer == "ipv6_routing":
        return "routing"
    if next_layer in {"icmpv6", "tcp", "udp"}:
        return next_layer
    return "unknown"


def _next_layer_after(stack: Sequence[str], layer: str) -> str | None:
    try:
        index = list(stack).index(layer)
    except ValueError:
        return None
    for next_layer in stack[index + 1 :]:
        if next_layer != "payload":
            return next_layer
    return "payload" if "payload" in stack[index + 1 :] else None


def _different_mac(rng: random.Random, first: str) -> str:
    second = documentation_mac(rng)
    if second != first:
        return second
    suffix = (int(first.rsplit(":", 1)[1], 16) + 1) % 256
    return f"00:00:5e:00:53:{suffix:02x}"


def _different_port(rng: random.Random, first: int) -> int:
    second = ephemeral_port(rng)
    if second != first:
        return second
    port_count = EPHEMERAL_PORT_MAX - EPHEMERAL_PORT_MIN + 1
    return EPHEMERAL_PORT_MIN + ((first - EPHEMERAL_PORT_MIN + 1) % port_count)


def _different_ipv4(rng: random.Random, first: str) -> str:
    second = documentation_ipv4(rng)
    if second != first:
        return second
    address = ipaddress.IPv4Address(first)
    network = next(network for network in _IPV4_DOCUMENTATION_NETWORKS if address in network)
    offset = int(address) - int(network.network_address)
    next_offset = 1 + (offset % (network.num_addresses - 2))
    return str(network.network_address + next_offset)


def _different_ipv6(rng: random.Random, first: str) -> str:
    second = documentation_ipv6(rng)
    if second != first:
        return second
    address = ipaddress.IPv6Address(first)
    next_host = int(address) - int(_IPV6_DOCUMENTATION_NETWORK.network_address) + 1
    if next_host >= _IPV6_DOCUMENTATION_NETWORK.num_addresses - 1:
        next_host = 1
    return str(ipaddress.IPv6Address(int(_IPV6_DOCUMENTATION_NETWORK.network_address) + next_host))


if __name__ == "__main__":
    raise SystemExit(main())
