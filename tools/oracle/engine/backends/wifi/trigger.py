"""Independent HE/EHT Basic Trigger body encoders.

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


def eht_basic_trigger_body() -> bytes:
    """Emit one source-fixed EHT Basic Trigger scheduling record.

    The first User Info is the AID 2007 Special User Info. Both User Info
    records carry Basic Trigger's one-octet dependent field.
    """
    common = (
        (301 << 4)
        | (1 << 17)
        | (1 << 20)
        | (1 << 27)
        | (42 << 28)
        | (2 << 34)
        | (1 << 36)
        | (0x4321 << 37)
        | (127 << 56)
    )
    special = 2007 | (3 << 17) | (12 << 21) | (4095 << 25)
    user = 37 | (4 << 12) | (1 << 20) | (11 << 21) | (68 << 32)
    return (
        struct.pack("<Q", common)
        + special.to_bytes(5, "little")
        + b"\x5a"
        + user.to_bytes(5, "little")
        + b"\xa5\xff\x0f"
    )
