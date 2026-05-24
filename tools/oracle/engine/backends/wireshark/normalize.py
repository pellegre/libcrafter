"""Wireshark/tshark decoded-model normalization interface."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from ...model import DecodedModel, EncodedVector, JSONObject
from ..registry import get_backend


BACKEND_NAME = "wireshark"


class WiresharkNormalizationUnsupported(RuntimeError):
    """Raised until tshark JSON normalization is implemented."""


def availability_metadata() -> JSONObject:
    """Return current tshark availability metadata."""

    return get_backend(BACKEND_NAME).availability.to_dict()


def unsupported_decoded_model(
    *,
    root: str | None = None,
    source_hex: str | None = None,
    feature_tags: Sequence[str] = (),
) -> DecodedModel:
    """Return a structured unsupported model for parser-only report paths."""

    return DecodedModel(
        backend=BACKEND_NAME,
        layers=[],
        fields={},
        root=root,
        source_hex=source_hex,
        feature_tags=list(feature_tags),
        metadata={
            "unsupported": True,
            "reason": "tshark decoded-model normalization is not implemented yet",
            "availability": availability_metadata(),
        },
    )


def decode_bytes(
    raw: bytes,
    *,
    root: str,
    source_hex: str | None = None,
    feature_tags: Sequence[str] = (),
) -> DecodedModel:
    """Decode bytes through tshark once the adapter is implemented."""

    raise WiresharkNormalizationUnsupported(
        "tshark decoded-model normalization is not implemented yet"
    )


def decode_vector(vector: EncodedVector) -> DecodedModel:
    """Decode one vector through the parser-only tshark interface."""

    root = vector.root or vector.decoder
    if root is None:
        raise ValueError("encoded vector is missing root decoder metadata")
    return decode_bytes(
        vector.to_bytes(),
        root=root,
        source_hex=vector.raw_hex,
        feature_tags=vector.plan.feature_tags,
    )


def decode_vectors(vectors: Iterable[EncodedVector]) -> list[DecodedModel]:
    """Decode vectors in order through the parser-only tshark interface."""

    return [decode_vector(vector) for vector in vectors]
