"""Independent HE Basic Trigger body encoder (IEEE802.11ax-2021 9.3.1.22).

This is a wire oracle, not an RF scheduling policy. Synthetic parameters only.
"""
import struct


def basic_trigger_body(entropy: bytes) -> bytes:
    """Emit Common Info, one normal User Info and canonical padding.

    Derive bounded fields from deterministic sampler bytes without consulting
    libcrafter. Preserve the one-octet Basic dependent User Info explicitly.
    """
    seed = int.from_bytes(entropy[:4].ljust(4, b"\0"), "little")
    length = 1 + seed % 4095
    aid = 1 + (seed >> 12) % 2007
    mcs = (seed >> 8) % 12
    common = (length << 4) | (1 << 20) | (511 << 54)
    user = aid | (mcs << 21)
    return struct.pack("<Q", common) + user.to_bytes(5, "little") + b"\0\xff\xff"
