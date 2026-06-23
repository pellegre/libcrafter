"""Scapy-stage encode/decode plugin for the IPsec layers (ESP / AH / IKEv2).

Moves the per-layer ``_esp`` / ``_ah`` / ``_ikev2`` builders (and the IKEv2
codepoint maps + coercers), the whole-stack SecurityAssociation materialization
path (``_materialize_ipsec_sa_packet`` and its ``_ipsec_*`` / ``_esp_suite`` /
``_chain_layers`` helpers), the crypto/auth/AEAD/transport maps
(``_IPSEC_CRYPT_ALGO_BY_NAME`` / ``_IPSEC_AUTH_ALGO_BY_NAME`` /
``_IPSEC_AEAD_ICV_LEN`` / ``_IPSEC_TRANSPORT_PROTO``), and the esp/ah/ikev2
post-hoc decode tweaks (``_normalize_ipsec_fields`` and the IKEv2 flag table)
verbatim out of :mod:`..packets` / :mod:`..normalize` and registers the ``esp``,
``ah``, and ``ikev2`` layers through the :class:`~.base.ScapyProtocol` contract.
Behavior must stay byte-identical (move, do not rewrite).

ENCODE — two surfaces:

* The per-layer raw builders (``_esp`` / ``_ah`` / ``_ikev2``) materialize the
  opaque (no-SA) ESP layer, the unsealed AH header, and the IKEv2 (ISAKMP) header.
  They are reached through the registered ``ScapyProtocol.build`` adapter from the
  legacy ``_build_layer`` if/elif (the registry consult). They are also reached
  by the SA path's inner-packet builder, which goes back through ``_build_layer``
  (and therefore this registry) to materialize the outer IP / NAT-T UDP / inner
  layers.
* The whole-stack ESP/AH SecurityAssociation path seals the cleartext inner
  packet so SPI || Seq || IV || ciphertext || ICV is byte-reproducible. This is a
  PLAN-DEPENDENT whole-stack decision: the ESP null/opaque case
  (``feature_behavior == "null-opaque"``) is excluded and falls through to the
  per-layer chain instead. The :class:`~.base.StackEncoder` contract only sees the
  ``stack`` (``matches(stack)``), not the plan, so it cannot express the
  null-opaque exclusion; the selection therefore stays in
  ``packets.encode_packet_plan`` (its ``elif _is_ipsec_sa_stack(plan, stack)``
  branch), exactly as the legacy control flow did, while the materialization
  implementation moves here. ``_materialize_ipsec_sa_packet`` takes the
  ``build_layer`` callback so it can build inner Scapy layers without importing
  the ``packets`` orchestrator (which would be a circular import), and ``packets``
  re-imports the moved materializer / maps / predicate-free helpers so its
  selection branch and the ``test_scapy_backend.py`` references keep resolving.

DECODE — the esp/ah/ikev2 layers use the generic alias path plus the
``_normalize_ipsec_fields`` tidy (AH drops the empty trailing ``padding``; IKEv2
resolves the ISAKMP-rendered flag token to the IKEv2 RFC 7296 flag set). The
generic alias path is reproduced here (the per-layer field renames the layer owns,
overlaid on the global cross-layer aliases) so the registered ``normalize`` hook is
byte-identical to the former ``_normalize_fields`` path for these three layers. The
layer-name aliases (``AH`` -> ``ah``, ``ESP`` -> ``esp``, ``ISAKMP`` /
``ISAKMP_v1`` -> ``ikev2``) are declared as ``layer_aliases`` so
``normalize._normalize_layer_name`` resolves them from the registry.

The libcrafter interop adapter (``engine/ipsec_interop.py``) keeps its own API; the
backend never referenced it directly, so nothing here changes that contract.

Shared primitives come from the helper modules so this plugin does not depend on
the ``packets`` / ``normalize`` orchestrators (which would create a circular
import). Relative imports only so the package resolves under both the ``engine.*``
(CLI) and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from ....model import JSONObject, JSONValue, PacketPlan
from ..decode_helpers import _normalize_flags
from ..encode_helpers import (
    _bytes_field,
    _int,
    _layer_fields,
    _optional_field,
)
from .base import ScapyProtocol, register


# ---------------------------------------------------------------------------
# Encode-side field allowlists for ``_validate_layer_fields`` — the canonical
# IPsec field names plus the pinned ``crypto`` block (consumed by the SA
# materializer). Mirror the former ``packets._SUPPORTED_FIELDS_BY_LAYER`` entries
# for esp/ah/ikev2 exactly.
# ---------------------------------------------------------------------------
_ESP_SUPPORTED_FIELDS = frozenset(
    {
        # The pinned key/salt/IV crypto context (see the generator determinism
        # seam) is consumed by the SecurityAssociation materializer.
        "crypto",
        "icv",
        "iv",
        "next_header",
        "pad_length",
        "sequence",
        "spi",
    }
)
_AH_SUPPORTED_FIELDS = frozenset(
    {
        "crypto",
        "icv",
        "next_header",
        "payload_len",
        "reserved",
        "sequence",
        "spi",
    }
)
_IKEV2_SUPPORTED_FIELDS = frozenset(
    {
        "crypto",
        "exchange_type",
        "flags",
        "initiator_spi",
        "length",
        "message_id",
        "next_payload",
        "responder_spi",
        "version",
    }
)


# --------------------------------------------------------------------------
# IPSec (ESP / AH / IKEv2) materialization.
#
# ESP and AH byte-parity is driven by scapy.layers.ipsec.SecurityAssociation:
# the SA seals the cleartext IP packet (transport: the upper-layer data;
# tunnel: the inner IP datagram) with the algorithm, key, salt, and explicit IV
# pinned by the generator's determinism seam, so the emitted
# SPI || Seq || IV || ciphertext || ICV (ESP) or AH header + ICV (AH) matches
# libcrafter octet-for-octet. The ESP-null/opaque case and IKEv2 (ISAKMP) do not
# need an SA and are built as raw layers in the normal chain.
#
# The crypto suite is keyed off the plan's feature/feature_behavior metadata
# (esp_aead -> AES-GCM-16; esp_cbc cbc-hmac -> AES-CBC + HMAC-SHA2-256-128;
# esp_cbc null-opaque -> ENCR_NULL opaque; ah_integrity -> HMAC-SHA2-256-128),
# matching the feature specs and RFC 4106 / RFC 3602 / RFC 4302 placement.

# libcrafter EncryptionAlgorithm / IntegrityAlgorithm names mapped to scapy's
# SecurityAssociation crypt_algo / auth_algo identifiers.
_IPSEC_CRYPT_ALGO_BY_NAME: dict[str, str] = {
    "aes-gcm-16": "AES-GCM",
    "encr_aes_gcm_16": "AES-GCM",
    "aes-cbc": "AES-CBC",
    "encr_aes_cbc": "AES-CBC",
    "aes-ctr": "AES-CTR",
    "encr_aes_ctr": "AES-CTR",
    "null": "NULL",
    "encr_null": "NULL",
}
_IPSEC_AUTH_ALGO_BY_NAME: dict[str, str] = {
    "hmac-sha2-256-128": "SHA2-256-128",
    "auth_hmac_sha2_256_128": "SHA2-256-128",
    "hmac-sha2-384-192": "SHA2-384-192",
    "auth_hmac_sha2_384_192": "SHA2-384-192",
    "hmac-sha2-512-256": "SHA2-512-256",
    "auth_hmac_sha2_512_256": "SHA2-512-256",
    "hmac-sha1-96": "HMAC-SHA1-96",
    "auth_hmac_sha1_96": "HMAC-SHA1-96",
    "aes-xcbc-96": "AES-CMAC-96",
    "auth_aes_xcbc_96": "AES-CMAC-96",
}
# AEAD ICV (tag) length in octets, by suite. AES-GCM-16 is the MUST suite.
_IPSEC_AEAD_ICV_LEN: dict[str, int] = {
    "AES-GCM": 16,
    "AES-CCM": 8,
    "CHACHA20-POLY1305": 16,
}
# IP next-header derived from the plan ESP/AH next_header value for transport
# mode (tunnel mode dispatches an inner IP layer instead).
_IPSEC_TRANSPORT_PROTO: dict[str, int] = {
    "tcp": 6,
    "udp": 17,
    "icmp": 1,
    "payload": 253,
    "raw": 253,
}


def _is_ipsec_sa_stack(plan: PacketPlan, stack: Sequence[str]) -> bool:
    """True when an ESP/AH stack must be sealed with a SecurityAssociation.

    The ESP null/opaque case carries no SA (the body is preserved verbatim) and
    is materialized through the normal chain as a raw ESP layer; every other
    ESP/AH stack is sealed/signed by ``SecurityAssociation`` so the ciphertext
    and ICV are byte-reproducible.
    """

    if "esp" not in stack and "ah" not in stack:
        return False
    if _ipsec_feature_behavior(plan) == "null-opaque":
        return False
    return True


def _ipsec_feature(plan: PacketPlan) -> str:
    feature = plan.metadata.get("feature")
    return feature if isinstance(feature, str) else ""


def _ipsec_feature_behavior(plan: PacketPlan) -> str:
    behavior = plan.metadata.get("feature_behavior")
    return behavior if isinstance(behavior, str) else ""


def _ipsec_crypto_block(layer_fields: Mapping[str, object]) -> Mapping[str, object]:
    crypto = layer_fields.get("crypto")
    if not isinstance(crypto, Mapping):
        raise ValueError("IPSec ESP/AH materialization requires a pinned crypto block")
    return crypto


def _ipsec_crypto_bytes(crypto: Mapping[str, object], *names: str) -> bytes:
    for name in names:
        value = crypto.get(name)
        if value is not None:
            return _bytes_field(value)
    joined = "/".join(names)
    raise ValueError(f"IPSec crypto block requires field {joined}")


def _esp_suite(plan: PacketPlan) -> tuple[str, str | None]:
    """Resolve the (crypt_algo, auth_algo) scapy names for an ESP plan."""

    feature = _ipsec_feature(plan)
    if feature == "esp_aead":
        return "AES-GCM", None
    if feature == "esp_cbc":
        return "AES-CBC", "SHA2-256-128"
    # Default to the MUST AEAD suite so an unkeyed feature still seals.
    return "AES-GCM", None


def _materialize_ipsec_sa_packet(
    plan: PacketPlan,
    stack: Sequence[str],
    scapy_all: Any,
    build_layer: Callable[..., Any],
) -> tuple[bytes, JSONObject]:
    if "esp" in stack:
        return _materialize_esp_sa_packet(plan, stack, scapy_all, build_layer)
    return _materialize_ah_sa_packet(plan, stack, scapy_all, build_layer)


def _materialize_esp_sa_packet(
    plan: PacketPlan,
    stack: Sequence[str],
    scapy_all: Any,
    build_layer: Callable[..., Any],
) -> tuple[bytes, JSONObject]:
    esp_index = stack.index("esp")
    esp_fields = _layer_fields(plan.fields, "esp")
    crypto = _ipsec_crypto_block(esp_fields)
    crypt_algo, auth_algo = _esp_suite(plan)

    if crypt_algo == "AES-GCM":
        crypt_key = _ipsec_crypto_bytes(crypto, "encryption_key") + _ipsec_crypto_bytes(
            crypto, "salt"
        )
        explicit_iv = _ipsec_explicit_iv(esp_fields, crypto, aead=True)
    else:
        crypt_key = _ipsec_crypto_bytes(crypto, "encryption_key")
        explicit_iv = _ipsec_explicit_iv(esp_fields, crypto, aead=False)

    sa_kwargs: dict[str, Any] = {
        "spi": _int(_optional_field(esp_fields, "spi"), 0),
        "crypt_algo": crypt_algo,
        "crypt_key": crypt_key,
    }
    if crypt_algo in _IPSEC_AEAD_ICV_LEN:
        sa_kwargs["crypt_icv_size"] = _IPSEC_AEAD_ICV_LEN[crypt_algo]
    if auth_algo is not None:
        sa_kwargs["auth_algo"] = auth_algo
        sa_kwargs["auth_key"] = _ipsec_crypto_bytes(crypto, "integrity_key")

    tunnel, nat_t, outer, inner = _ipsec_inner_packet(
        plan, stack, esp_index, scapy_all, build_layer
    )
    if tunnel is not None:
        sa_kwargs["tunnel_header"] = tunnel
    if nat_t is not None:
        sa_kwargs["nat_t_header"] = nat_t

    sa = scapy_all.SecurityAssociation(scapy_all.ESP, **sa_kwargs)
    seq = _int(_optional_field(esp_fields, "sequence"), 1)
    sealed = sa.encrypt(inner, seq_num=seq, iv=explicit_iv)
    raw_bytes = bytes(scapy_all.raw(sealed))
    return raw_bytes, {
        "layer": "esp",
        "crypt_algo": crypt_algo,
        "auth_algo": auth_algo,
        "mode": "tunnel" if tunnel is not None else "transport",
        "nat_traversal": nat_t is not None,
        "spi": sa_kwargs["spi"],
        "sequence": seq,
        "explicit_iv_hex": explicit_iv.hex(),
        "native_scapy_support": True,
    }


def _materialize_ah_sa_packet(
    plan: PacketPlan,
    stack: Sequence[str],
    scapy_all: Any,
    build_layer: Callable[..., Any],
) -> tuple[bytes, JSONObject]:
    ah_index = stack.index("ah")
    ah_fields = _layer_fields(plan.fields, "ah")
    crypto = _ipsec_crypto_block(ah_fields)
    auth_algo = "SHA2-256-128"

    sa_kwargs: dict[str, Any] = {
        "spi": _int(_optional_field(ah_fields, "spi"), 0),
        "auth_algo": auth_algo,
        "auth_key": _ipsec_crypto_bytes(crypto, "integrity_key"),
    }
    tunnel, nat_t, outer, inner = _ipsec_inner_packet(
        plan, stack, ah_index, scapy_all, build_layer
    )
    if tunnel is not None:
        sa_kwargs["tunnel_header"] = tunnel
    if nat_t is not None:
        sa_kwargs["nat_t_header"] = nat_t

    sa = scapy_all.SecurityAssociation(scapy_all.AH, **sa_kwargs)
    seq = _int(_optional_field(ah_fields, "sequence"), 1)
    signed = sa.encrypt(inner, seq_num=seq)
    raw_bytes = bytes(scapy_all.raw(signed))
    return raw_bytes, {
        "layer": "ah",
        "auth_algo": auth_algo,
        "mode": "tunnel" if tunnel is not None else "transport",
        "nat_traversal": nat_t is not None,
        "spi": sa_kwargs["spi"],
        "sequence": seq,
        "native_scapy_support": True,
    }


def _ipsec_explicit_iv(
    layer_fields: Mapping[str, object],
    crypto: Mapping[str, object],
    *,
    aead: bool,
) -> bytes:
    """Resolve the pinned explicit IV for an ESP datagram.

    AEAD (RFC 4106): the 8-octet explicit IV. A per-layer ``iv`` override wins
    (the generator pins it, including the all-zero ``zero`` domain) so the
    explicit IV || ciphertext is reproducible. CBC (RFC 3602) uses the 16-octet
    ``cbc_iv`` from the pinned crypto block; the ESP ``iv`` field carries only
    the 8-octet AEAD IV, so it is not used for the CBC IV.
    """

    if aead:
        override = layer_fields.get("iv")
        if override is not None:
            return _bytes_field(override)
        return _ipsec_crypto_bytes(crypto, "iv", "aead_iv")
    return _ipsec_crypto_bytes(crypto, "cbc_iv")


def _ipsec_inner_packet(
    plan: PacketPlan,
    stack: Sequence[str],
    sec_index: int,
    scapy_all: Any,
    build_layer: Callable[..., Any],
) -> tuple[Any | None, Any | None, Any, Any]:
    """Build (tunnel_header, nat_t_header, outer_ip, cleartext_inner).

    Transport mode: the outer IP carries the upper-layer data directly, so the
    inner packet is ``outer_ip / upper_layers`` and there is no tunnel header.
    Tunnel mode: the ESP/AH next-header is an inner IP datagram, so the outer IP
    becomes the tunnel header and the inner packet is the inner IP datagram and
    everything after it. NAT-T (RFC 3948): when a UDP layer sits between the IP
    header and ESP, the UDP layer becomes the SecurityAssociation NAT-T header so
    scapy emits IP / UDP / ESP.
    """

    nat_t_index = sec_index - 1
    if nat_t_index >= 0 and stack[nat_t_index] == "udp":
        nat_t = build_layer(plan, list(stack), nat_t_index, scapy_all)
        outer_index = nat_t_index - 1
    else:
        nat_t = None
        outer_index = sec_index - 1

    if outer_index < 0 or stack[outer_index] not in {"ipv4", "ipv6"}:
        raise ValueError("ESP/AH materialization requires a preceding IP layer")
    outer_ip = build_layer(plan, list(stack), outer_index, scapy_all)

    inner_layers = stack[sec_index + 1 :]
    if inner_layers and inner_layers[0] in {"ipv4", "ipv6"}:
        # Tunnel mode: outer IP is the tunnel header; the inner IP datagram (and
        # any following upper layers) is the cleartext that gets sealed.
        inner = _chain_layers(plan, stack, sec_index + 1, len(stack), scapy_all, build_layer)
        return outer_ip, nat_t, outer_ip, inner

    # Transport mode: the upper-layer data is carried directly under the outer IP.
    inner = outer_ip
    for index in range(sec_index + 1, len(stack)):
        inner = inner / build_layer(plan, list(stack), index, scapy_all)
    return None, nat_t, outer_ip, inner


def _chain_layers(
    plan: PacketPlan,
    stack: Sequence[str],
    start: int,
    end: int,
    scapy_all: Any,
    build_layer: Callable[..., Any],
) -> Any:
    packet = None
    for index in range(start, end):
        piece = build_layer(plan, list(stack), index, scapy_all)
        packet = piece if packet is None else packet / piece
    if packet is None:
        raise ValueError("IPSec inner packet did not produce any layers")
    return packet


def _esp(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    """Build a raw ESP layer for the opaque (no-SA) case.

    The null/opaque case preserves the ESP body verbatim, so the layer carries
    SPI || Seq and the following layer's bytes become the opaque ``data``.
    """

    esp_fields = _layer_fields(fields, "esp")
    kwargs: dict[str, Any] = {
        "spi": _int(_optional_field(esp_fields, "spi"), 0),
        "seq": _int(_optional_field(esp_fields, "sequence"), 1),
    }
    return scapy_all.ESP(**kwargs)


def _ah(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    """Build a raw AH header (used when no SA seals the stack)."""

    ah_fields = _layer_fields(fields, "ah")
    kwargs: dict[str, Any] = {
        "spi": _int(_optional_field(ah_fields, "spi"), 0),
        "seq": _int(_optional_field(ah_fields, "sequence"), 1),
    }
    if "reserved" in ah_fields:
        kwargs["reserved"] = _int(ah_fields.get("reserved"), 0)
    if "payload_len" in ah_fields:
        kwargs["payloadlen"] = _int(ah_fields.get("payload_len"), 0)
    if "icv" in ah_fields:
        kwargs["icv"] = _bytes_field(ah_fields["icv"])
    return scapy_all.AH(**kwargs)


def _ikev2(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    """Build an IKEv2 (ISAKMP) message header via scapy.layers.isakmp.

    The initiator/responder SPIs map to the ISAKMP init/resp cookies, and the
    next-payload, version, exchange type, flags, and message id round-trip. The
    payload chain itself is carried as the following Raw layer in the stack, so
    this builder materializes the 28-byte header only; compile() / the generic
    payload chain belongs to the libcrafter side and later parity steps.
    """

    ike_fields = _layer_fields(fields, "ikev2")
    kwargs: dict[str, Any] = {
        "next_payload": _ikev2_next_payload(_optional_field(ike_fields, "next_payload")),
        "exch_type": _ikev2_exchange_type(_optional_field(ike_fields, "exchange_type")),
        "id": _int(_optional_field(ike_fields, "message_id"), 0),
        "flags": _ikev2_flags(_optional_field(ike_fields, "flags")),
    }
    if "initiator_spi" in ike_fields:
        kwargs["init_cookie"] = _bytes_field(ike_fields["initiator_spi"])
    if "responder_spi" in ike_fields:
        kwargs["resp_cookie"] = _bytes_field(ike_fields["responder_spi"])
    if "version" in ike_fields:
        kwargs["version"] = _int(ike_fields.get("version"), 0x20)
    if "length" in ike_fields:
        kwargs["length"] = _int(ike_fields.get("length"), 0)
    return scapy_all.ISAKMP(**kwargs)


# IKEv2 next-payload codepoints (RFC 7296 §3.2). The plan carries libcrafter
# payload-type layer names; map them to the wire codepoint scapy stores.
_IKEV2_NEXT_PAYLOAD_CODE: dict[str, int] = {
    "none": 0,
    "ikesapayload": 33,
    "sa": 33,
    "ikekepayload": 34,
    "ke": 34,
    "ikeidipayload": 35,
    "ikeidrpayload": 36,
    "ikecertpayload": 37,
    "ikecertreqpayload": 38,
    "ikeauthpayload": 39,
    "auth": 39,
    "ikenoncepayload": 40,
    "nonce": 40,
    "ikenotifypayload": 41,
    "notify": 41,
    "ikedeletepayload": 42,
    "delete": 42,
    "ikevendorpayload": 43,
    "iketsipayload": 44,
    "iketsrpayload": 45,
    "ikeencryptedpayload": 46,
    "encrypted": 46,
    "ikeconfigpayload": 47,
    "ikeeappayload": 48,
}
_IKEV2_EXCHANGE_TYPE_CODE: dict[str, int] = {
    "ike_sa_init": 34,
    "ike_auth": 35,
    "create_child_sa": 36,
    "informational": 37,
}
_IKEV2_FLAG_BIT: dict[str, int] = {
    "initiator": 0x08,
    "version": 0x10,
    "response": 0x20,
}


def _ikev2_next_payload(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.lower().replace("-", "_")
        if lowered in _IKEV2_NEXT_PAYLOAD_CODE:
            return _IKEV2_NEXT_PAYLOAD_CODE[lowered]
        return int(lowered, 0)
    return _int(value, 0)


def _ikev2_exchange_type(value: object) -> int:
    if value is None:
        return 34
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.lower().replace("-", "_")
        if lowered in _IKEV2_EXCHANGE_TYPE_CODE:
            return _IKEV2_EXCHANGE_TYPE_CODE[lowered]
        return int(lowered, 0)
    return _int(value, 34)


def _ikev2_flags(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    items = value if isinstance(value, (list, tuple)) else [value]
    flags = 0
    for item in items:
        if isinstance(item, int) and not isinstance(item, bool):
            flags |= item
            continue
        if isinstance(item, str):
            lowered = item.lower().replace("-", "_")
            if lowered in _IKEV2_FLAG_BIT:
                flags |= _IKEV2_FLAG_BIT[lowered]
    return flags


# ---------------------------------------------------------------------------
# Per-layer ``ScapyProtocol.build`` adapters (uniform build signature).
# ---------------------------------------------------------------------------


def _build_esp(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    return _esp(fields, scapy_all)


def _build_ah(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    return _ah(fields, scapy_all)


def _build_ikev2(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    return _ikev2(fields, scapy_all)


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------


# Decode-side native-name aliases each IPsec layer owns. ``_*_LAYER_ALIASES``
# map the Scapy class name to the oracle layer name (the former
# ``normalize._LAYER_ALIASES`` entries); ``_*_FIELD_ALIASES`` record the
# layer-specific field renames the legacy ``_normalize_field_name`` consulted
# first (the former ``normalize._LAYER_FIELD_ALIASES`` entries).
_ESP_LAYER_ALIASES = (("ESP", "esp"),)
_AH_LAYER_ALIASES = (("AH", "ah"),)
_IKEV2_LAYER_ALIASES = (("ISAKMP", "ikev2"), ("ISAKMP_v1", "ikev2"))

_ESP_FIELD_ALIASES = (("seq", "sequence"),)
_AH_FIELD_ALIASES = (
    ("nh", "next_header"),
    ("payloadlen", "payload_len"),
    ("seq", "sequence"),
)
_IKEV2_FIELD_ALIASES = (
    ("exch_type", "exchange_type"),
    ("id", "message_id"),
    ("init_cookie", "initiator_spi"),
    ("resp_cookie", "responder_spi"),
)

# Global cross-layer field aliases the legacy ``_normalize_field_name`` consulted
# as a fallback after the layer-specific map (mirrors ``normalize._FIELD_ALIASES``).
# None of the IPsec native field names collide with these, so carrying the full
# map keeps the lookup byte-identical to the legacy generic path.
_GLOBAL_FIELD_ALIASES: dict[str, str] = {
    "chksum": "checksum",
    "dataofs": "data_offset",
    "dport": "dst_port",
    "frag": "fragment_offset",
    "hlim": "hop_limit",
    "len": "length",
    "nh": "next_header",
    "proto": "protocol",
    "sport": "src_port",
    "urgptr": "urgent_pointer",
}


def _field_name_map(layer_aliases: tuple[tuple[str, str], ...]) -> dict[str, str]:
    """Effective native-name -> normalized-name map for one IPsec layer.

    Mirrors the legacy ``_normalize_field_name(layer, native)`` lookup precedence
    exactly: the layer-specific renames win, then the global cross-layer aliases,
    then the native name unchanged.
    """

    return {**_GLOBAL_FIELD_ALIASES, **dict(layer_aliases)}


_ESP_FIELD_NAME_MAP = _field_name_map(_ESP_FIELD_ALIASES)
_AH_FIELD_NAME_MAP = _field_name_map(_AH_FIELD_ALIASES)
_IKEV2_FIELD_NAME_MAP = _field_name_map(_IKEV2_FIELD_ALIASES)


# IKEv2 (ISAKMP) flag bits (RFC 7296 §3.1) mapped to the stable domain names the
# generator emits, so a decoded flag set compares against the planned domain.
_IKEV2_FLAG_NAMES: dict[int, str] = {
    0x08: "initiator",
    0x10: "version",
    0x20: "response",
}


def _normalize_ikev2_flags(value: JSONValue) -> JSONValue:
    if isinstance(value, str):
        # Scapy renders the FlagsField as a textual token (e.g. "initiator").
        cleaned = value.strip()
        if not cleaned:
            return []
        tokens = [
            token.lower().replace("-", "_").replace("+", "_")
            for token in cleaned.replace("+", " ").split()
        ]
        return tokens
    if isinstance(value, int) and not isinstance(value, bool):
        return [name for bit, name in sorted(_IKEV2_FLAG_NAMES.items()) if value & bit]
    return value


def _normalize_field_value(field_name: str, value: JSONValue) -> JSONValue:
    # Mirror the generic ``normalize._normalize_field_value`` for these layers:
    # ``flags`` is reduced through ``_normalize_flags`` (the IKEv2 flag set is
    # post-processed afterwards by ``_normalize_ipsec_fields``); ``is_response`` /
    # ``more_fragments`` int-to-bool guards are kept for fidelity though no IPsec
    # field reaches them. ``linux_sll`` never applies here.
    if field_name == "flags":
        return _normalize_flags(value)
    if field_name == "is_response" and isinstance(value, int):
        return bool(value)
    if field_name == "more_fragments" and isinstance(value, int):
        return bool(value)
    return value


def _normalize_ipsec_fields(layer_name: str, output: JSONObject) -> None:
    """Tidy decoded ESP/AH/IKEv2 fields into the comparable oracle shape.

    ESP carries the SPI, sequence, and the opaque encrypted body (``data``); AH
    carries the header fields plus the ICV, with the empty trailing ``padding``
    artifact dropped; IKEv2 (ISAKMP) carries the SPIs, next-payload, version,
    exchange type, flags, message id, and length. The ESP/AH SPI is reported as
    an unsigned integer to match the libcrafter decode model.
    """

    if layer_name == "ah":
        # Scapy appends an empty ``padding`` field on the AH header; it carries
        # no wire bytes (the ICV padding is folded into ``icv``), so drop it.
        padding = output.get("padding")
        if padding in (None, {"hex": "", "ascii": ""}, ""):
            output.pop("padding", None)
    if layer_name == "ikev2":
        flags = output.get("flags")
        if flags is not None:
            output["flags"] = _normalize_ikev2_flags(flags)


def _make_normalize(
    layer_name: str,
    field_name_map: dict[str, str],
) -> Callable[[JSONObject], JSONObject]:
    """Build the per-layer ``ScapyProtocol.normalize`` hook for an IPsec layer.

    Byte-identical to the legacy ``_normalize_fields`` path for these layers:
    each native field name is renamed via the layer's field-name map (the lookup
    order the legacy ``_normalize_field_name`` applied), each value passes through
    the generic ``_normalize_field_value`` transform, and the ``_normalize_ipsec_fields``
    tidy runs last.
    """

    def _normalize(fields: JSONObject) -> JSONObject:
        output: JSONObject = {}
        for native_name, value in fields.items():
            normalized_name = field_name_map.get(native_name, native_name)
            output[normalized_name] = _normalize_field_value(normalized_name, value)
        _normalize_ipsec_fields(layer_name, output)
        return output

    return _normalize


register(
    ScapyProtocol(
        layer="esp",
        scapy_class="ESP",
        supported_fields=_ESP_SUPPORTED_FIELDS,
        build=_build_esp,
        normalize=_make_normalize("esp", _ESP_FIELD_NAME_MAP),
        layer_aliases=_ESP_LAYER_ALIASES,
        field_aliases=_ESP_FIELD_ALIASES,
    )
)
register(
    ScapyProtocol(
        layer="ah",
        scapy_class="AH",
        supported_fields=_AH_SUPPORTED_FIELDS,
        build=_build_ah,
        normalize=_make_normalize("ah", _AH_FIELD_NAME_MAP),
        layer_aliases=_AH_LAYER_ALIASES,
        field_aliases=_AH_FIELD_ALIASES,
    )
)
register(
    ScapyProtocol(
        layer="ikev2",
        scapy_class="ISAKMP",
        supported_fields=_IKEV2_SUPPORTED_FIELDS,
        build=_build_ikev2,
        normalize=_make_normalize("ikev2", _IKEV2_FIELD_NAME_MAP),
        layer_aliases=_IKEV2_LAYER_ALIASES,
        field_aliases=_IKEV2_FIELD_ALIASES,
    )
)
