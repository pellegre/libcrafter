"""Substrate-independent probe validation constants and address helpers."""

from __future__ import annotations

import ipaddress


FAILURE_TIMEOUT = "timeout"
FAILURE_WRONG_PEER = "wrong_peer"
FAILURE_WRONG_PAYLOAD = "wrong_payload"
FAILURE_WRONG_FLAGS = "wrong_flags"
FAILURE_DECODE_FAILED = "decode_failed"
FAILURE_TARGET_SETUP_FAILED = "target_setup_failed"


def eui64_link_local_ipv6(mac: str) -> str:
    """Return the RFC 4291 modified-EUI-64 link-local address for a MAC."""

    octets = [int(part, 16) for part in mac.split(":")]
    if len(octets) != 6:
        raise ValueError(f"expected a six-octet MAC address, got {mac!r}")
    interface_id = bytes(
        [
            octets[0] ^ 0x02,
            octets[1],
            octets[2],
            0xFF,
            0xFE,
            octets[3],
            octets[4],
            octets[5],
        ]
    )
    address = bytearray(bytes(8) + interface_id)
    address[0] = 0xFE
    address[1] = 0x80
    return str(ipaddress.IPv6Address(bytes(address)))


# Kept as a private alias for existing deterministic plan builders.
_eui64_link_local_ipv6 = eui64_link_local_ipv6
