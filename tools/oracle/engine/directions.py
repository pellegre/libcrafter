"""Canonical oracle direction names and legacy aliases."""

from __future__ import annotations

BACKEND_TO_LIBCRAFTER = "backend_to_libcrafter"
LIBCRAFTER_TO_BACKEND = "libcrafter_to_backend"
ROUNDTRIP = "roundtrip"

ONE_WAY_DIRECTIONS = (BACKEND_TO_LIBCRAFTER, LIBCRAFTER_TO_BACKEND)
FEATURE_DIRECTIONS = (*ONE_WAY_DIRECTIONS, ROUNDTRIP)
OFFLINE_DIRECTIONS = ONE_WAY_DIRECTIONS
PCAP_DIRECTIONS = (*ONE_WAY_DIRECTIONS, ROUNDTRIP)

DIRECTION_ALIASES = {
    "reference_to_libcrafter": BACKEND_TO_LIBCRAFTER,
    "scapy_to_libcrafter": BACKEND_TO_LIBCRAFTER,
    "libcrafter_to_reference": LIBCRAFTER_TO_BACKEND,
    "libcrafter_to_scapy": LIBCRAFTER_TO_BACKEND,
}


def normalize_direction(direction: str) -> str:
    """Return the canonical spelling for one oracle direction."""

    value = direction.strip()
    return DIRECTION_ALIASES.get(value, value)


def seed_direction(direction: str) -> str:
    """Return the stable pre-rename seed token for deterministic sampling."""

    normalized = normalize_direction(direction)
    if normalized == BACKEND_TO_LIBCRAFTER:
        return "reference_to_libcrafter"
    if normalized == LIBCRAFTER_TO_BACKEND:
        return "libcrafter_to_reference"
    return normalized


def normalize_direction_list(directions: object) -> list[str]:
    """Normalize a JSON-style list of direction strings."""

    if not isinstance(directions, list):
        return []
    output: list[str] = []
    for item in directions:
        if not isinstance(item, str):
            continue
        normalized = normalize_direction(item)
        if normalized not in output:
            output.append(normalized)
    return output
