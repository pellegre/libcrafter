"""Deterministic packet plan generation primitives for oracle."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import random
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TypeVar

from .model import JSONObject, PacketPlan
from .spec_loader import load_oracle_specs


T = TypeVar("T")

EPHEMERAL_PORT_MIN = 49152
EPHEMERAL_PORT_MAX = 65535

_IPV4_DOCUMENTATION_NETWORKS = (
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
)
_IPV6_DOCUMENTATION_NETWORK = ipaddress.IPv6Network("2001:db8::/32")


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
        "features": {
            feature.name: {
                "name": feature.name,
                "layers": list(feature.layers),
                "directions": list(feature.directions),
                "strict_bytes": feature.strict_bytes,
                "malformed": feature.malformed,
                "coverage_cases": list(feature.coverage_cases),
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


class PacketGenerator:
    """Seeded packet plan generator independent of any backend."""

    def __init__(
        self,
        *,
        seed: int,
        profile: str,
        grammar: Mapping[str, object] | None = None,
    ) -> None:
        self.grammar = _json_object(load_stack_grammar() if grammar is None else grammar)
        profiles = _object(self.grammar.get("profiles"), "profiles")
        if profile not in profiles:
            raise ValueError(f"unsupported profile: {profile}")
        self.seed = seed
        self.profile = profile

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
        selected_case = case or self._choose_case(rng, selected_stack, feature)
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

        fields = self._fields(rng, stack)
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
                "selected_specs": selected_specs,
                "strict_bytes": strict_bytes,
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
            if feature is None and case is None and "dhcp" in stack_layers:
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

    def _choose_case(
        self,
        rng: random.Random,
        stack: JSONObject,
        feature: str | None,
    ) -> str:
        coverage_cases = _string_list(stack.get("coverage_cases", []), "stack.coverage_cases")
        if feature is not None:
            feature_spec = self._feature_spec(feature)
            feature_cases = _string_list(feature_spec.get("coverage_cases"), "feature.coverage_cases")
            matching = [case for case in coverage_cases if case in feature_cases]
            if matching:
                return weighted_choice(rng, tuple((case, 1) for case in matching))
        if not coverage_cases:
            return "default"
        return weighted_choice(rng, tuple((case, 1) for case in coverage_cases))

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
        for name, raw_feature in features.items():
            feature = _object(raw_feature, f"features.{name}")
            layers = _string_list(feature.get("layers"), f"features.{name}.layers")
            directions = _string_list(feature.get("directions"), f"features.{name}.directions")
            cases = _string_list(
                feature.get("coverage_cases", []),
                f"features.{name}.coverage_cases",
            )
            if case not in cases:
                continue
            if not _layers_cover_feature(stack, layers):
                continue
            if direction not in directions and "roundtrip" not in directions:
                continue
            output.append((name, feature))
        return output

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

    def _fields(self, rng: random.Random, stack: Sequence[str]) -> dict[str, JSONObject]:
        payload_min, payload_max = self._payload_bounds()
        payload = byte_payload(rng, min_length=payload_min, max_length=payload_max)
        src_mac = documentation_mac(rng)
        dst_mac = _different_mac(rng, src_mac)
        src_port = ephemeral_port(rng)
        dst_port = _different_port(rng, src_port)

        fields: dict[str, JSONObject] = {}
        if "ethernet" in stack:
            fields["ethernet"] = {
                "src": src_mac,
                "dst": dst_mac,
                "type": _ethertype_for_stack(stack, "ethernet"),
            }
        if "vlan" in stack:
            fields["vlan"] = {
                "priority": bounded_int(rng, 0, 7),
                "drop_eligible": bounded_int(rng, 0, 1),
                "vlan_id": bounded_int(rng, 1, 4094),
                "ethertype": _ethertype_for_stack(stack, "vlan"),
            }
        if "arp" in stack:
            sender_ip = documentation_ipv4(rng)
            target_ip = _different_ipv4(rng, sender_ip)
            fields["arp"] = {
                "opcode": weighted_choice(rng, (("request", 3), ("reply", 1))),
                "sender_hardware_address": src_mac,
                "target_hardware_address": dst_mac,
                "sender_protocol_address": sender_ip,
                "target_protocol_address": target_ip,
            }
        if "udp" in stack:
            if "dns" in stack:
                dst_port = 53
            elif "dhcp" in stack:
                src_port, dst_port = 68, 67
            fields["udp"] = {
                "src_port": src_port,
                "dst_port": dst_port,
            }
        if "tcp" in stack:
            fields["tcp"] = {
                "src_port": src_port,
                "dst_port": weighted_choice(rng, ((80, 2), (443, 2), (8080, 1))),
                "flags": weighted_choice(rng, (("syn", 5), ("ack", 2), ("all", 1))),
                "sequence": bounded_int(rng, 0, (1 << 32) - 1),
                "window": bounded_int(rng, 1, 65535),
            }
        if "icmp" in stack:
            fields["icmp"] = {
                "type": weighted_choice(rng, (("echo-request", 3), ("echo-reply", 1))),
                "code": 0,
                "identifier": bounded_int(rng, 0, 65535),
                "sequence": bounded_int(rng, 0, 65535),
            }
        if "icmpv6" in stack:
            fields["icmpv6"] = {
                "type": weighted_choice(rng, (("echo_request", 3), ("echo_reply", 1))),
                "identifier": bounded_int(rng, 0, 65535),
                "sequence": bounded_int(rng, 0, 65535),
            }
        if "dns" in stack:
            fields["dns"] = {
                "transaction_id": bounded_int(rng, 0, 65535),
                "questions": [
                    {
                        "qname": weighted_choice(
                            rng,
                            (("example.com.", 3), ("example.net.", 1), ("libcrafter.test.", 1)),
                        ),
                        "qtype": weighted_choice(rng, (("A", 3), ("AAAA", 1))),
                    }
                ],
            }
        if "dhcp" in stack:
            fields["dhcp"] = {
                "op": "bootrequest",
                "hardware_type": "ethernet",
                "hardware_length": 6,
                "transaction_id": bounded_int(rng, 0, (1 << 32) - 1),
                "flags": weighted_choice(rng, (("none", 3), ("broadcast", 1))),
                "client_ip": "0.0.0.0",
                "your_ip": "0.0.0.0",
                "client_hardware_address": src_mac,
                "options": ["message-type=discover", "end"],
            }
        if "payload" in stack:
            fields["payload"] = {
                "hex": payload.hex(),
                "length": len(payload),
            }

        if "ipv4" in stack:
            src_ip = documentation_ipv4(rng)
            dst_ip = _different_ipv4(rng, src_ip)
            fields["ipv4"] = {
                "src": src_ip,
                "dst": dst_ip,
                "identification": bounded_int(rng, 0, 65535),
                "ttl": bounded_int(rng, 1, 255),
                "protocol": _ipv4_protocol_for_stack(stack),
            }
        if "ipv6" in stack:
            src_ip = documentation_ipv6(rng)
            dst_ip = _different_ipv6(rng, src_ip)
            fields["ipv6"] = {
                "src": src_ip,
                "dst": dst_ip,
                "traffic_class": bounded_int(rng, 0, 255),
                "flow_label": bounded_int(rng, 0, (1 << 20) - 1),
                "hop_limit": bounded_int(rng, 1, 255),
                "next_header": _ipv6_next_header_for_stack(stack, "ipv6"),
            }
        if "ipv6_fragment" in stack:
            fields["ipv6_fragment"] = {
                "next_header": _ipv6_next_header_for_stack(stack, "ipv6_fragment"),
                "fragment_offset": 0,
                "more_fragments": False,
                "identification": bounded_int(rng, 0, (1 << 32) - 1),
            }
        if "ipv6_routing" in stack:
            fields["ipv6_routing"] = {
                "next_header": _ipv6_next_header_for_stack(stack, "ipv6_routing"),
                "type": 0,
                "segments_left": 0,
            }

        return fields


def generate_plans(
    *,
    seed: int,
    profile: str,
    count: int,
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
    generator = PacketGenerator(seed=seed, profile=profile)
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
    return all(layer in stack_set for layer in feature_layers)


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
