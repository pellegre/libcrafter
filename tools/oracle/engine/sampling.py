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


def _field_bits(field_spec: JSONObject) -> int:
    """Return the integer width declared by a field spec's ``type``.

    A ``uintN`` type yields ``N`` bits; anything else defaults to 16. This is a
    backend-neutral spec helper shared by the per-protocol sampler plugins (and
    re-imported into ``generator`` to preserve its call sites).
    """

    field_type = field_spec.get("type")
    if not isinstance(field_type, str):
        raise ValueError("field.type must be a string")
    if field_type.startswith("uint"):
        return int(field_type.removeprefix("uint"))
    return 16


def _next_layer_after(stack: Sequence[str], layer: str) -> str | None:
    """Return the next non-payload layer after ``layer`` in ``stack``.

    Cross-layer stack-grammar routing shared by the framing/IP samplers; kept
    here so the per-protocol plugins can resolve their next-protocol fields
    without importing ``generator`` (which would create a cycle).
    """

    try:
        index = list(stack).index(layer)
    except ValueError:
        return None
    for next_layer in stack[index + 1 :]:
        if next_layer != "payload":
            return next_layer
    return "payload" if "payload" in stack[index + 1 :] else None


def _ipv6_next_header_for_stack(stack: Sequence[str], layer: str) -> str:
    """Resolve the IPv6 ``next_header`` name the layer after ``layer`` implies.

    Cross-layer stack-grammar routing shared by the base IPv6 sampler and the
    IPv6 extension-header sampling in ``generator``; kept here so the per-protocol
    plugins can resolve their next-header field without importing ``generator``
    (which would create a cycle).
    """

    next_layer = _next_layer_after(stack, layer)
    if next_layer == "ipv6_destination_options":
        return "destination-options"
    if next_layer == "ipv6_fragment":
        return "fragment"
    if next_layer == "ipv6_hop_by_hop":
        return "hop-by-hop"
    if next_layer == "ipv6_routing":
        return "routing"
    if next_layer in {"icmpv6", "tcp", "udp"}:
        return next_layer
    return "unknown"


def _ethertype_for_stack(stack: Sequence[str], layer: str) -> str:
    """Resolve the EtherType name the layer after ``layer`` implies."""

    next_layer = _next_layer_after(stack, layer)
    if next_layer == "vlan":
        return "vlan"
    if next_layer == "arp":
        return "arp"
    if next_layer == "ipv4":
        return "ipv4"
    if next_layer == "ipv6":
        return "ipv6"
    if next_layer == "eapol":
        return "eapol"
    return "unknown"


def _declared_ethertype_for_stack(stack: Sequence[str], layer: str) -> str:
    """EtherType name for ``layer``, mapping the unknown case to experimental."""

    value = _ethertype_for_stack(stack, layer)
    return "experimental" if value == "unknown" else value


def _dot11_is_management(frame_control: int) -> bool:
    """Report whether an 802.11 frame-control word denotes a management frame.

    Shared sampling primitive: the framing-layer ``payload`` sampler uses it to
    suppress the payload of a Dot11 management frame, and the (still legacy) dot11
    sampler uses it for its management-frame branches. Kept here so the migrated
    framing plugin can import it without depending on ``generator``.
    """

    return ((frame_control >> 2) & 0x3) == 0


def _is_ipv4_root_dhcp_stack(stack: Sequence[str]) -> bool:
    """Return True for the IPv4-root, unicast live DHCP stack.

    The ``ipv4 / udp / dhcp`` stack carries DHCP as a one-way unicast oracle
    packet between provider endpoints. It has no Ethernet frame, so link-layer
    broadcast delivery, the IPv4 limited-broadcast destination, and the DHCP
    broadcast flag have no meaning and would make the packet ineligible for
    provider-backed live exchange. The Ethernet-root DHCP stack keeps those
    domains for offline link-layer coverage.

    Shared sampling primitive: the IPv4 sampler plugin uses it to resolve the
    IPv4 destination domain, and the (still legacy) DHCP sampler uses it for the
    broadcast destination. Kept here so the migrated IPv4 plugin can import it
    without depending on ``generator``.
    """

    return "dhcp" in stack and "ethernet" not in stack


# ---------------------------------------------------------------------------
# UDP surplus-options intent helpers.
#
# These build the backend-neutral ``udp.options`` spec (the surplus-area option
# list, checksum intent, and application-payload binding) that both the migrated
# UDP sampler/behavior plugin and the (still in ``generator``) ``udp_options``
# metadata/feature-tag emitters consume. They are pure functions over the spec
# key and payload, so they live here as shared sampling primitives, letting the
# UDP plugin import them without depending on ``generator``.
# ---------------------------------------------------------------------------


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
