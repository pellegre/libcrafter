"""Generator-stage shared sampling primitives for the oracle.

These are the backend-neutral value/domain/MAC helpers, the public sampling
helpers (``weighted_choice``, ``bounded_int``, ``documentation_ipv4``,
``ephemeral_port``, ``plan_identifier``), and the ``_SamplingContext`` carrier
that per-protocol sampler plugins depend on. They are extracted here so those
plugins can import them without a circular dependency back on
``engine/generator.py``. This module must not import from ``generator``.
"""

from __future__ import annotations

import ipaddress
import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TypeVar

from .model import JSONObject


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


def _identifier_part(value: str) -> str:
    output = []
    for char in value.lower():
        output.append(char if char.isalnum() else "-")
    return "".join(output).strip("-") or "default"


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
