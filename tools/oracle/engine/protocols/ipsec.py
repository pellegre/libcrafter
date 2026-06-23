"""Generator-stage sampler plugins for the IPsec layers (ESP / AH / IKEv2).

Moves the ``_sample_esp_field`` / ``_sample_ah_field`` / ``_sample_ikev2_field``
samplers and the IPsec field helpers out of :mod:`generator` and registers them
through the uniform :class:`~.base.ProtocolSampler` contract, one sampler per
layer. The sampling logic is moved verbatim (behavior must stay byte-identical);
only the dispatch moves from the generator's legacy if/elif into this
self-contained module, which self-registers on import.

IPsec carries an ORDERING DEPENDENCY: after every layer is sampled the generator
must attach the pinned key/salt/IV crypto material to the esp/ah/ikev2 layer
dict. The legacy generator did this inside the sampling loop, after field
validation, via ``sampled["crypto"] = _ipsec_pinned_crypto()`` for every layer in
``_IPSEC_CRYPTO_LAYERS``. That injection is the determinism seam: both backends
seal ESP/AH and the IKEv2 SK payload with these identical inputs so the
ciphertext and ICV are byte-reproducible, and the block also guarantees the layer
is always present in the plan even when every sampled field is derived/skipped.
The hook lives here as ``post_sample(fields, *, stack, case)``: the generator
calls it for each stack layer whose plugin defines it, after the sampling loop, so
the "after field sampling" ordering is preserved. Each esp/ah/ikev2 plugin injects
the crypto block into its own layer dict (mutated in place so the layer object the
generator already stored keeps its identity, exactly as the legacy copy-then-store
did).

This step is generator-stage only: the Scapy SA materialization path
(``_materialize_ipsec_sa_packet``) and the decoders stay on their legacy backend
paths (registered fallbacks) until the next step migrates them. Shared primitives
(``_SamplingContext``, ``_integer_domain_value``, ``weighted_choice``,
``_field_bits``, ``_next_layer_after``) live in :mod:`..sampling` and are imported
here rather than duplicated. Relative imports only so the package resolves under
both the ``engine.*`` (CLI) and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from ..model import JSONObject
from ..sampling import (
    _SamplingContext,
    _field_bits,
    _integer_domain_value,
    _next_layer_after,
    _SKIP_FIELD,
    weighted_choice,
)
from .base import ProtocolSampler, register


# --------------------------------------------------------------------------
# IPSec pinned crypto material (ESP / AH / IKEv2 SK).
#
# THIS IS THE DETERMINISM SEAM FOR ESP/AH BYTE-PARITY. ESP and AH compute
# ciphertext and ICV from a key, a salt, and an IV. If those inputs differed
# between the Scapy reference backend and the libcrafter adapter, the sealed
# bytes would differ and offline byte comparison would never agree. So the
# generator emits FIXED TEST CONSTANTS (never random, never seed-derived) into
# every esp/ah/ikev2 packet plan, and BOTH backends seal/verify with exactly
# these inputs. The values are documentation-only test material, not secrets:
# they exist solely to make the IV || ciphertext || ICV reproducible.
#
# Sizes cover the suites the IPSec stacks exercise:
#   * AES-GCM-16 (AEAD)  : 16-byte key + 4-byte salt, 8-byte explicit IV.
#   * AES-CBC + HMAC     : 16-byte cipher key, 16-byte explicit IV,
#                          separate HMAC-SHA-256 integrity key.
#   * AH / IKEv2 SK      : HMAC integrity key (+ SK cipher key/IV reuse above).
# A backend selects the slice it needs for the SA's algorithm; the full pinned
# block is always present so the plan is self-contained.
_IPSEC_PINNED_ENCRYPTION_KEY = "b0b0b0b0a1a1a1a1c2c2c2c2d3d3d3d3"
_IPSEC_PINNED_SALT = "00010203"
_IPSEC_PINNED_AEAD_IV = "0001020304050607"
_IPSEC_PINNED_CBC_IV = "101112131415161718191a1b1c1d1e1f"
_IPSEC_PINNED_INTEGRITY_KEY = (
    "4a4b4c4d4e4f50515253545556575859"
    "5a5b5c5d5e5f60616263646566676869"
)
# Layers that carry pinned crypto material in their plan field block.
_IPSEC_CRYPTO_LAYERS = frozenset({"esp", "ah", "ikev2"})


def _ipsec_pinned_crypto() -> JSONObject:
    """Return the fixed ESP/AH/IKEv2 crypto material emitted into every plan.

    The block is deterministic test data, not random and not seed-derived: it is
    the seam that lets both backends seal ESP/AH with identical inputs so the
    ciphertext and ICV are byte-reproducible. ``iv`` carries the AEAD explicit IV
    (8 octets); ``cbc_iv`` carries the 16-octet CBC IV. Backends pick the slice
    the SA's algorithm requires.
    """

    return {
        "pinned": True,
        "note": (
            "fixed ESP/AH/IKEv2 test material; never random; both backends seal "
            "and verify with identical key/salt/IV so ciphertext and ICV are "
            "byte-reproducible"
        ),
        "encryption_key": {"hex": _IPSEC_PINNED_ENCRYPTION_KEY},
        "salt": {"hex": _IPSEC_PINNED_SALT},
        "iv": {"hex": _IPSEC_PINNED_AEAD_IV},
        "cbc_iv": {"hex": _IPSEC_PINNED_CBC_IV},
        "integrity_key": {"hex": _IPSEC_PINNED_INTEGRITY_KEY},
    }


# --------------------------------------------------------------------------
# IPSec (ESP / AH / IKEv2) field samplers.
#
# The SPI and sequence domains are DETERMINISTIC (never seed-derived): both
# backends must agree on the SPI and sequence number because they feed the ESP
# AEAD AAD (SPI || Seq) and the AH ICV input. The crypto key/salt/IV material is
# emitted separately as a pinned ``crypto`` block (see _ipsec_pinned_crypto and
# _attach_ipsec_crypto) so the sealed bytes are byte-reproducible across
# backends. Every value here is fixed test data in documentation address space.

# Fixed, non-zero SPIs (RFC 4303/4302 reserve 0; 1-255 for the IKE/IPSec SAs).
# Deterministic so ESP/AH AAD and ICV inputs match across backends.
_IPSEC_SPI_SENDER = 0x10001001
_IPSEC_SPI_RESPONDER = 0x20002002
# IKEv2 SPIs are 8 octets (RFC 7296 §3.1); pinned, non-zero for the initiator.
_IKEV2_SPI_INITIATOR = "1122334455667788"
_IKEV2_SPI_RESPONDER = "99aabbccddeeff00"

_IKEV2_EXCHANGE_TYPES = {
    "ike_sa_init": 34,
    "ike_auth": 35,
    "create_child_sa": 36,
    "informational": 37,
}
_IKEV2_NEXT_PAYLOAD = {
    "sa": "IkeSaPayload",
    "ke": "IkeKePayload",
    "nonce": "IkeNoncePayload",
    "none": "none",
}


def _ipsec_spi_for_domain(
    ctx: _SamplingContext,
    domain: object,
    *,
    bits: int = 32,
    allow_zero: bool = True,
) -> int:
    """Map an SPI domain to a deterministic value.

    ``spi_sender`` / ``spi_responder`` are fixed non-zero SPIs; ``zero`` is the
    reserved 0 SPI; ``boundary`` is 0 or the field maximum. The values never come
    from the seed so both backends share the same SPI in the AEAD AAD / AH ICV.

    ``allow_zero`` gates the reserved zero SPI. ESP must set it ``False``: a
    proto-50 datagram whose SPI is 0 begins with four zero octets, which is the
    RFC 3948 non-ESP marker, so Scapy dissects it as NON_ESP / ISAKMP instead of
    ESP and the decoded model diverges from libcrafter's typed ESP layer. AH has
    no such marker collision, so it keeps the zero SPI as a real boundary.
    """

    maximum = (1 << bits) - 1
    if domain == "spi_sender":
        return _IPSEC_SPI_SENDER & maximum
    if domain == "spi_responder":
        return _IPSEC_SPI_RESPONDER & maximum
    if domain == "zero":
        # ESP cannot use the reserved zero SPI offline (Scapy's non-ESP marker
        # heuristic); fall back to the fixed sender SPI so the case still
        # exercises the SPI path with a comparable decoded model.
        return 0 if allow_zero else (_IPSEC_SPI_SENDER & maximum)
    if domain == "boundary":
        if allow_zero:
            return weighted_choice(ctx.rng, ((0, 1), (maximum, 1)))
        return maximum
    return _integer_domain_value(ctx, domain, "spi", bits=bits)


def _ipsec_sequence_for_domain(ctx: _SamplingContext, domain: object, *, bits: int = 32) -> int:
    """Map a sequence/message-id domain to a deterministic value.

    ``sequence_initial`` is the first on-the-wire value (1 for ESP/AH per
    RFC 4303 §3.3.3; the generator uses 1 for IKEv2 message-id-style fields too);
    ``sequence_boundary`` and ``boundary`` are 0 or the field maximum. Fixed, not
    seed-derived, so the ESP AAD / AH ICV inputs match across backends.
    """

    maximum = (1 << bits) - 1
    if domain == "sequence_initial":
        return 1
    if domain in {"sequence_boundary", "boundary"}:
        return weighted_choice(ctx.rng, ((0, 1), (maximum, 1)))
    return _integer_domain_value(ctx, domain, "sequence", bits=bits)


def _ipsec_next_header_for_stack(stack: Sequence[str], layer: str) -> str:
    """Derive the ESP/AH next-header from the inner layer of the stack.

    ESP/AH carry an upper-layer protocol in transport mode (tcp/udp/icmp/payload)
    or an inner IP datagram in tunnel mode (ipv4/ipv6). Deriving the value from
    the stack keeps the plan self-consistent instead of letting the random domain
    name disagree with the layer that actually follows.
    """

    next_layer = _next_layer_after(stack, layer)
    if next_layer in {"tcp", "udp", "icmp", "ipv4", "ipv6"}:
        return next_layer
    return "payload"


def _sample_esp_field(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    field_spec: JSONObject,
) -> object:
    if field_name == "spi":
        return _ipsec_spi_for_domain(
            ctx, domain, bits=_field_bits(field_spec), allow_zero=False
        )
    if field_name == "sequence":
        return _ipsec_sequence_for_domain(ctx, domain, bits=_field_bits(field_spec))
    if field_name == "next_header":
        return _ipsec_next_header_for_stack(ctx.stack, "esp")
    if field_name == "pad_length":
        # ``derived`` is filtered before sampling; an explicit zero/boundary
        # domain pins the pad length so compile() honors it verbatim.
        if domain == "zero":
            return 0
        return _integer_domain_value(ctx, domain, field_name, bits=_field_bits(field_spec))
    if field_name == "iv":
        # Pinned explicit IV so the CBC/CTR/AEAD IV || ciphertext is reproducible
        # across backends. ``zero`` keeps the all-zero IV the spec allows.
        if domain == "zero":
            return {"hex": "00" * 8}
        return {"hex": _IPSEC_PINNED_AEAD_IV}
    if field_name == "icv":
        # Derived by compile() from the pinned key material; never sampled.
        return _SKIP_FIELD
    raise ValueError(f"spec error: unsupported esp field sampler: {field_name}")


def _sample_ah_field(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    field_spec: JSONObject,
) -> object:
    if field_name == "spi":
        return _ipsec_spi_for_domain(ctx, domain, bits=_field_bits(field_spec))
    if field_name == "sequence":
        return _ipsec_sequence_for_domain(ctx, domain, bits=_field_bits(field_spec))
    if field_name == "next_header":
        return _ipsec_next_header_for_stack(ctx.stack, "ah")
    if field_name == "payload_len":
        # ``derived`` filtered out; only an explicit boundary pins the value.
        return _integer_domain_value(ctx, domain, field_name, bits=_field_bits(field_spec))
    if field_name == "reserved":
        if domain == "zero":
            return 0
        return _integer_domain_value(ctx, domain, field_name, bits=_field_bits(field_spec))
    if field_name == "icv":
        # Derived by compile() over the canonical immutable IP fields and the
        # pinned integrity key; never sampled.
        return _SKIP_FIELD
    raise ValueError(f"spec error: unsupported ah field sampler: {field_name}")


def _sample_ikev2_field(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    field_spec: JSONObject,
) -> object:
    if field_name == "initiator_spi":
        if domain == "zero":
            return {"hex": "00" * 8}
        return {"hex": _IKEV2_SPI_INITIATOR}
    if field_name == "responder_spi":
        # The responder SPI is zero in the initial IKE_SA_INIT request and pinned
        # non-zero once the responder has chosen it.
        if domain == "zero":
            return {"hex": "00" * 8}
        return {"hex": _IKEV2_SPI_RESPONDER}
    if field_name == "next_payload":
        return _IKEV2_NEXT_PAYLOAD.get(str(domain), "none")
    if field_name == "version":
        if domain == "boundary":
            return weighted_choice(ctx.rng, ((0, 1), (255, 1)))
        # RFC 7296 §3.1: major version 2 in the high nibble (0x20).
        return 0x20
    if field_name == "exchange_type":
        return _IKEV2_EXCHANGE_TYPES.get(str(domain), _IKEV2_EXCHANGE_TYPES["ike_sa_init"])
    if field_name == "flags":
        return _ikev2_flags_for_domain(domain)
    if field_name == "message_id":
        return _ipsec_sequence_for_domain(ctx, domain, bits=_field_bits(field_spec))
    if field_name == "length":
        # Derived by compile() from the payload chain; never sampled.
        return _SKIP_FIELD
    raise ValueError(f"spec error: unsupported ikev2 field sampler: {field_name}")


def _ikev2_flags_for_domain(domain: object) -> list[str]:
    """Map an IKEv2 flags domain to the RFC 7296 §3.1 flag set.

    ``initiator`` is the canonical request (I bit set); ``response`` is the reply
    (R bit set); ``version`` exercises the higher-version (V) bit. The flag names
    are stable identifiers both backends resolve to the same bit positions.
    """

    if domain == "response":
        return ["response"]
    if domain == "version":
        return ["initiator", "version"]
    return ["initiator"]


# Per-layer field allowlists, mirroring the former
# ``generator._SUPPORTED_FIELDS`` entries for esp/ah/ikev2.
_ESP_SUPPORTED_FIELDS = frozenset(
    {
        "spi",
        "sequence",
        "next_header",
        "pad_length",
        "iv",
        "icv",
    }
)
_AH_SUPPORTED_FIELDS = frozenset(
    {
        "next_header",
        "payload_len",
        "reserved",
        "spi",
        "sequence",
        "icv",
    }
)
_IKEV2_SUPPORTED_FIELDS = frozenset(
    {
        "initiator_spi",
        "responder_spi",
        "next_payload",
        "version",
        "exchange_type",
        "flags",
        "message_id",
        "length",
    }
)


def _sample_esp(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter for ESP (reads ``ctx``/``field_name``/``domain``/``field_spec``)."""

    return _sample_esp_field(ctx, field_name, domain, field_spec)


def _sample_ah(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter for AH (reads ``ctx``/``field_name``/``domain``/``field_spec``)."""

    return _sample_ah_field(ctx, field_name, domain, field_spec)


def _sample_ikev2(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter for IKEv2 (reads ``ctx``/``field_name``/``domain``/``field_spec``)."""

    return _sample_ikev2_field(ctx, field_name, domain, field_spec)


def _post_sample_crypto(layer: str) -> Callable[..., None]:
    """Build the ordered post-sampling hook that attaches the pinned crypto block.

    Reproduces the legacy generator injection exactly: for an IPsec layer present
    in the stack, after every layer is sampled, the pinned key/salt/IV material is
    attached to that layer's field dict under ``crypto`` (it is not a declared
    layer field). The dict is mutated in place so the layer object the generator
    already stored keeps its identity, matching the legacy copy-then-store that
    placed the same dict in both ``fields`` and ``ctx.sampled_layers``. If the
    layer is not yet present (every sampled field derived/skipped), the block is
    created so the layer is always present in the plan, also as the legacy code
    guaranteed.
    """

    def _post_sample(
        fields: dict[str, JSONObject],
        *,
        stack: Sequence[str],
        case: str,
    ) -> None:
        sampled = fields.get(layer)
        if sampled is None:
            sampled = {}
            fields[layer] = sampled
        sampled["crypto"] = _ipsec_pinned_crypto()

    return _post_sample


register(
    ProtocolSampler(
        layer="esp",
        supported_fields=_ESP_SUPPORTED_FIELDS,
        sample=_sample_esp,
        post_sample=_post_sample_crypto("esp"),
    )
)
register(
    ProtocolSampler(
        layer="ah",
        supported_fields=_AH_SUPPORTED_FIELDS,
        sample=_sample_ah,
        post_sample=_post_sample_crypto("ah"),
    )
)
register(
    ProtocolSampler(
        layer="ikev2",
        supported_fields=_IKEV2_SUPPORTED_FIELDS,
        sample=_sample_ikev2,
        post_sample=_post_sample_crypto("ikev2"),
    )
)
