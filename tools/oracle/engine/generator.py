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
            f"family-{family}",
            f"{subject_kind}-{_identifier_part(subject)}",
        )
    )


def load_stack_grammar(path: str | Path | None = None) -> JSONObject:
    """Load the executable YAML specs as generator grammar."""

    spec_root = None if path is None else Path(path)
    return load_oracle_specs(spec_root).to_generator_grammar()


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
        family: str | None = None,
        case: str | None = None,
        feature: str | None = None,
    ) -> PacketPlan:
        if index < 0:
            raise ValueError(f"index must be non-negative: {index}")

        rng = random.Random(_derive_seed(self.seed, self.profile, index, family, case, feature))
        selected_family = family or self._choose_family(rng)
        families = _object(self.grammar.get("families"), "families")
        if selected_family not in families:
            raise ValueError(f"unsupported family: {selected_family}")

        family_spec = self._family_spec(selected_family)
        stack = _string_list(family_spec.get("stack"), f"{selected_family}.stack")
        default_case = _string_or_none(family_spec.get("case")) or "default"
        selected_case = case or default_case
        feature_tags = _string_list(
            family_spec.get("feature_tags", []),
            f"{selected_family}.feature_tags",
        )
        if feature is not None and feature not in feature_tags:
            feature_tags = [*feature_tags, feature]

        fields = self._fields(rng, selected_family)
        plan_id = plan_identifier(
            seed=self.seed,
            profile=self.profile,
            index=index,
            family=selected_family,
            case=selected_case,
            feature=feature,
        )

        return PacketPlan(
            stack=stack,
            fields=fields,
            profile=self.profile,
            seed=self.seed,
            index=index,
            direction="reference_to_libcrafter",
            family=selected_family,
            feature_tags=feature_tags,
            case=selected_case,
            strict_bytes=True,
            metadata={
                "plan_id": plan_id,
                "generator": "oracle.seeded.v1",
                "feature": feature,
            },
        )

    def _choose_family(self, rng: random.Random) -> str:
        profiles = _object(self.grammar.get("profiles"), "profiles")
        profile_spec = _object(profiles.get(self.profile), f"profiles.{self.profile}")
        raw_weights = profile_spec.get("family_weights")
        if raw_weights is None:
            raise ValueError(f"profiles.{self.profile}.family_weights is required")

        choices: list[tuple[str, int]] = []
        if not isinstance(raw_weights, Sequence) or isinstance(raw_weights, (str, bytes)):
            raise ValueError("family_weights must be a list")
        for item in raw_weights:
            item_obj = _object(item, "family_weights item")
            name = item_obj.get("name")
            weight = item_obj.get("weight")
            if not isinstance(name, str) or not isinstance(weight, int):
                raise ValueError("family_weights entries require string name and integer weight")
            choices.append((name, weight))
        return weighted_choice(rng, choices)

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

    def _fields(self, rng: random.Random, family: str) -> dict[str, JSONObject]:
        payload_min, payload_max = self._payload_bounds()
        payload = byte_payload(rng, min_length=payload_min, max_length=payload_max)
        src_mac = documentation_mac(rng)
        dst_mac = _different_mac(rng, src_mac)
        src_port = ephemeral_port(rng)
        dst_port = _different_port(rng, src_port)

        fields: dict[str, JSONObject] = {
            "ethernet": {
                "src": src_mac,
                "dst": dst_mac,
                "type": family,
            },
            "udp": {
                "src_port": src_port,
                "dst_port": dst_port,
            },
            "payload": {
                "hex": payload.hex(),
                "length": len(payload),
            },
        }

        if family == "ipv4":
            src_ip = documentation_ipv4(rng)
            dst_ip = _different_ipv4(rng, src_ip)
            fields["ipv4"] = {
                "src": src_ip,
                "dst": dst_ip,
                "ttl": bounded_int(rng, 1, 255),
                "protocol": "udp",
            }
        elif family == "ipv6":
            src_ip = documentation_ipv6(rng)
            dst_ip = _different_ipv6(rng, src_ip)
            fields["ipv6"] = {
                "src": src_ip,
                "dst": dst_ip,
                "hop_limit": bounded_int(rng, 1, 255),
                "next_header": "udp",
            }
        else:
            raise ValueError(f"unsupported family: {family}")

        return fields


def generate_plans(
    *,
    seed: int,
    profile: str,
    count: int,
    family: str | None = None,
    case: str | None = None,
    feature: str | None = None,
    index: int | None = None,
) -> list[PacketPlan]:
    """Generate a deterministic sequence, or one explicit index."""

    if count < 1:
        raise ValueError(f"count must be positive: {count}")
    generator = PacketGenerator(seed=seed, profile=profile)
    indices = [index] if index is not None else list(range(count))
    return [
        generator.generate(index=item, family=family, case=case, feature=feature)
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
    family: str | None,
    case: str | None,
    feature: str | None,
) -> int:
    material = "\0".join(
        (
            str(seed),
            profile,
            str(index),
            family or "",
            case or "",
            feature or "",
        )
    ).encode("utf-8")
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
