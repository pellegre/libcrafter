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
    "udp": {"src_port", "dst_port", "checksum"},
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
                direction="reference_to_libcrafter",
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
            direction="reference_to_libcrafter",
        ):
            if family == "udp" and feature_name != "udp_options":
                continue
            categories = _string_list(feature_spec.get("categories", []), "feature.categories")
            for feature_case in self._compatible_feature_cases(
                stack=stack_layers,
                feature=feature_name,
                direction="reference_to_libcrafter",
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
        for name in names:
            if _identifier_part(name) in _identifier_part(case):
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
    if field_name == "answers" and layer == "dns":
        if ctx.feature == "dns_behavior" and "response" in ctx.case:
            return max(1, ctx.feature_weights.get("boundary", 1))
        return 0
    if ctx.profile == "smoke" and _is_boundary_domain(domain):
        return 0
    if ctx.profile == "smoke" and layer in {"dns", "dhcp"}:
        return 0 if domain not in {False, 0, 6, "a_in", "bootrequest", "ethernet", "message_type", "none", "query", "zero"} else 10
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
    payload = fields.get("payload", {})
    payload_hex = payload.get("hex", "")
    if not isinstance(payload_hex, str):
        payload_hex = ""
    checksum_status = "generated"
    if "ipv4-zero-checksum" in key:
        checksum_status = "ipv4_no_checksum"
    elif "ipv6-zero-checksum" in key:
        checksum_status = "ipv6_zero_checksum_exception_required"

    options = _udp_option_intent(key)
    surplus = bool(options)
    return {
        "intent": "metadata_only",
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
    }


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
