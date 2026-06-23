"""Scapy raw packet materialization for oracle packet plans."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ...model import EncodedVector, JSONObject, PacketPlan
from ..registry import BackendCapabilities, BackendRegistration, get_backend
from .bootstrap import import_scapy
from .encode_helpers import (
    _IP_PROTOCOLS,
    _canonical_stack,
    _int,
    _internet_checksum,
    _ipv4_flags,
    _layer_fields,
    _layer_fields_for_stack_index,
    _payload_bytes,
    _required_field,
    _string,
)
# Importing the protocols package runs its ``autodiscover`` so every per-protocol
# Scapy encoder/decoder module self-registers. ``STACK_ENCODER_REGISTRY`` is
# consulted before the legacy whole-stack branches and ``SCAPY_REGISTRY`` before the
# per-layer ``_build_layer`` if/elif. No protocol is migrated yet, so both registries
# are empty and every stack/layer falls through to the legacy code.
from .protocols import SCAPY_REGISTRY, STACK_ENCODER_REGISTRY

# The IPv6 extension-header builders live in the co-located ipv6 plugin module
# (``protocols/ipv6.py``) but, unlike the base ``ipv6`` layer, are not registered in
# ``SCAPY_REGISTRY`` because the ext-header names are sub-layers of the ``ipv6`` spec
# rather than top-level spec layers. They are re-imported here so the legacy per-layer
# ``_build_layer`` dispatch keeps routing ``ipv6_hop_by_hop`` /
# ``ipv6_destination_options`` / ``ipv6_fragment`` / ``ipv6_routing`` to them unchanged.
from .protocols.ipv6 import (
    _ipv6_destination_options,
    _ipv6_fragment,
    _ipv6_hop_by_hop,
    _ipv6_routing,
)
# The ``igmp`` layer is migrated to ``protocols/igmp.py`` and registered in
# ``SCAPY_REGISTRY``. Its ``igmp_query`` / ``igmp_report`` / ``igmp_extension``
# sub-layer bytes builders are co-located there but, like the IPv6 ext-header
# builders, are not registered (the sub-layer names are children of the ``igmp``
# spec layer, not top-level spec layers). They are re-imported here so the legacy
# per-layer ``_build_layer`` dispatch keeps wrapping them in a Scapy ``Raw``
# unchanged.
from .protocols.igmp import (
    _igmp_extension_layer_bytes,
    _igmp_query_bytes,
    _igmp_report_bytes,
)
# The ``dns`` layer is migrated to ``protocols/dns.py`` and registered in
# ``SCAPY_REGISTRY`` (its ``ScapyProtocol`` build adapter calls the moved ``_dns``
# materializer). The ``_dns`` builder and the ``_dns_record_entry`` record helper are
# re-imported here so the existing ``test_dns_backend.py`` references
# (``packets._dns`` / ``packets._dns_record_entry``) keep resolving after the move.
from .protocols.dns import _dns, _dns_record_entry
# The ``esp`` / ``ah`` / ``ikev2`` layers are migrated to ``protocols/ipsec.py`` and
# registered in ``SCAPY_REGISTRY`` (their per-layer raw builders are reached through
# the ``_build_layer`` registry consult). The ESP/AH SecurityAssociation path is a
# PLAN-DEPENDENT whole-stack decision (the null/opaque case is excluded by plan
# metadata, which the stack-only ``StackEncoder.matches`` contract cannot see), so
# its selection stays in ``encode_packet_plan`` below; the materializer and its
# crypto maps / predicate are re-imported from the plugin (``_materialize_ipsec_sa_packet``
# takes a ``build_layer`` callback to avoid a circular import). ``_is_ipsec_sa_stack``
# / ``_canonical_stack`` keep resolving through ``packets`` for the existing
# ``test_scapy_backend.py`` references.
from .protocols.ipsec import (
    _is_ipsec_sa_stack,
    _materialize_ipsec_sa_packet,
)
# The ``ble_radio`` / ``ble_adv`` layers are migrated to ``protocols/ble.py`` and
# registered in ``SCAPY_REGISTRY`` (their ``ScapyProtocol`` declares ``scapy_class``
# ``BTLE_PHDR`` / ``BTLE_ADV_IND``). Like Dot11 phase-1.5, BLE bypasses the per-layer
# ``_build_layer`` dispatch and emits the whole stack as raw bytes through a
# :class:`~.protocols.base.StackEncoder` (``_is_ble_stack`` / ``_ble_bytes``), so
# ``encode_packet_plan`` reaches it through ``STACK_ENCODER_REGISTRY`` (consulted
# below). ``_ble_bytes`` is re-imported here because it returns ``(bytes, metadata)``
# and the BLE materialization metadata is reported on the encoded vector; the
# BLE-named encoder is handled directly so that metadata is preserved.
from .protocols.ble import _ble_bytes
# The ``radiotap`` / ``dot11`` / ``eapol`` / ``rsn`` layers are migrated to
# ``protocols/wifi.py`` and registered in ``SCAPY_REGISTRY`` (their
# ``ScapyProtocol``s declare ``scapy_class`` and the native-name decode aliases).
# None is built through the per-layer ``_build_layer`` dispatch — they are part of
# the whole-stack Dot11 phase-1.5 raw-bytes path, which is now registered as a
# :class:`~.protocols.base.StackEncoder` in that module (``_dot11_phase15_bytes`` /
# ``_is_dot11_phase15_stack``). ``encode_packet_plan`` reaches it through
# ``STACK_ENCODER_REGISTRY`` (consulted above), so no Wi-Fi byte serializer is
# re-imported here anymore.


BACKEND_NAME = "scapy"

_SCAPY_LAYER_BY_LAYER: dict[str, str] = {
    # The base ``esp`` / ``ah`` / ``ikev2`` layers are migrated to
    # ``protocols/ipsec.py`` (their ``ScapyProtocol`` declares ``scapy_class``
    # ``ESP`` / ``AH`` / ``ISAKMP``, which drives ``_scapy_layer_name`` and the
    # ``scapy_stack`` metadata); ``_scapy_layer_name`` resolves them from the
    # registry, so they no longer carry literal entries here.
    # The ``ble_adv`` / ``ble_radio`` layers are migrated to ``protocols/ble.py``
    # (their ``ScapyProtocol`` declares ``scapy_class`` ``BTLE_ADV_IND`` / ``BTLE_PHDR``,
    # which drives ``_scapy_layer_name`` and the ``scapy_stack`` metadata);
    # ``_scapy_layer_name`` resolves them from the registry.
    # The ``dot11`` layer is migrated to ``protocols/wifi.py`` (its ``ScapyProtocol``
    # declares ``scapy_class="Dot11"`` and the ``Dot11`` -> ``dot11`` decode alias);
    # ``_scapy_layer_name`` resolves it from the registry.
    # The ``eapol`` layer is migrated to ``protocols/wifi.py`` (its ``ScapyProtocol``
    # declares ``scapy_class="EAPOL"`` and the ``EAPOL`` -> ``eapol`` decode alias);
    # ``_scapy_layer_name`` resolves it from the registry.
    # IGMP contrib classes are not exposed through scapy.all consistently
    # across supported Scapy versions, so the oracle materializer emits exact
    # IGMP bytes through Raw while preserving IPv4 protocol number 2. The base
    # ``igmp`` layer is migrated to ``protocols/igmp.py`` (its ``ScapyProtocol``
    # declares ``scapy_class="Raw"``, which drives ``_scapy_layer_name`` and the
    # ``scapy_stack`` metadata); its ``igmp_query`` / ``igmp_report`` /
    # ``igmp_extension`` sub-layers are not top-level spec layers, so they keep
    # their legacy ``Raw`` mapping here.
    "igmp_extension": "Raw",
    "igmp_query": "Raw",
    "igmp_report": "Raw",
    "ipv6_destination_options": "IPv6ExtHdrDestOpt",
    "ipv6_fragment": "IPv6ExtHdrFragment",
    "ipv6_hop_by_hop": "IPv6ExtHdrHopByHop",
    "ipv6_routing": "IPv6ExtHdrRouting",
    # The ``radiotap`` layer is migrated to ``protocols/wifi.py`` (its
    # ``ScapyProtocol`` declares ``scapy_class="RadioTap"``, which drives
    # ``_scapy_layer_name`` and the ``scapy_stack`` metadata); ``_scapy_layer_name``
    # resolves it from the registry.
    "raw": "Raw",
    # The ``rsn`` layer is migrated to ``protocols/wifi.py`` (its ``ScapyProtocol``
    # declares ``scapy_class="Dot11EltRSN"`` and the ``Dot11EltRSN`` -> ``rsn`` decode
    # alias); ``_scapy_layer_name`` resolves it from the registry.
}
_SCAPY_DECODER_BY_ROOT: dict[str, str] = {
    "link:bluetooth-le-ll-with-phdr": "BTLE_PHDR",
    "link:bluetooth_le_ll_with_phdr": "BTLE_PHDR",
    "link:ethernet": "Ether",
    "link:dot11": "Dot11",
    "link:ieee80211": "Dot11",
    "link:ieee802154": "Dot15d4FCS",
    # The TAP pseudo-header has no native Scapy dissector; the link-type bytes
    # are normalized as raw bytes (libcrafter owns the TAP descriptor decode).
    "link:ieee802154-tap": "Raw",
    "link:ieee802154_tap": "Raw",
    "link:linux-cooked": "CookedLinux",
    "link:linux-sll": "CookedLinux",
    "link:null-loopback": "Loopback",
    "link:radiotap": "RadioTap",
    "link:raw": "Raw",
    "l2:ipv4": "IP",
    "l3:ipv4": "IP",
    "l3:ipv6": "IPv6",
}
_ROOT_FIRST_LAYERS: dict[str, set[str]] = {
    "link:bluetooth-le-ll-with-phdr": {"ble_radio"},
    "link:bluetooth_le_ll_with_phdr": {"ble_radio"},
    "link:dot11": {"dot11"},
    "link:ethernet": {"ethernet"},
    "link:ieee80211": {"dot11"},
    "link:ieee802154": {"dot15d4"},
    "link:ieee802154-tap": {"dot15d4_radio"},
    "link:ieee802154_tap": {"dot15d4_radio"},
    "link:linux-cooked": {"linux_cooked"},
    "link:linux-sll": {"linux_cooked"},
    "link:null-loopback": {"null_loopback"},
    "link:radiotap": {"radiotap"},
    "link:raw": {"payload"},
    "l2:ipv4": {"ipv4"},
    "l3:ipv4": {"ipv4"},
    "l3:ipv6": {"ipv6"},
}
_SCAPY_MATERIALIZED_LAYERS = frozenset(_SCAPY_LAYER_BY_LAYER)


def _is_materialized_layer(layer: str) -> bool:
    """Report whether ``layer`` can be encoded by the Scapy backend.

    A migrated layer is materialized when it has a registered
    :class:`~.protocols.base.ScapyProtocol`; an unmigrated layer stays in the
    legacy ``_SCAPY_MATERIALIZED_LAYERS`` set. Checking the registry first lets the
    two coexist during the migration.
    """

    return layer in _SCAPY_MATERIALIZED_LAYERS or SCAPY_REGISTRY.get(layer) is not None


def _scapy_supported_fields(layer: str) -> frozenset[str] | set[str] | None:
    """Return the encode-side field allowlist for ``layer``.

    A migrated layer declares it on its registered ``ScapyProtocol``; an
    unmigrated layer keeps it in the legacy ``_SUPPORTED_FIELDS_BY_LAYER`` table.
    """

    plugin = SCAPY_REGISTRY.get(layer)
    if plugin is not None:
        return plugin.supported_fields
    return _SUPPORTED_FIELDS_BY_LAYER.get(layer)
_SUPPORTED_FEATURES = {
    "ah_integrity",
    "bgp_communities",
    "bgp_keepalive",
    "bgp_mp_reach",
    "bgp_notification",
    "bgp_open",
    "bgp_route_refresh",
    "bgp_update",
    "ble_advertising",
    "ble-adv-pdu",
    "ble-pcap-link-types",
    "ble-radio-phdr",
    "dhcp_behavior",
    "dns_behavior",
    "dot11_basic",
    "dot11_data_llc",
    "dot11_pcap_link_types",
    "dot15d4-mac",
    "dot15d4-pcap-link-types",
    "dot15d4_mac",
    "dot15d4_pcap_link_types",
    "eapol_basic",
    "esp_aead",
    "esp_cbc",
    "icmpv4_errors",
    "icmpv4_live",
    "icmpv6_errors",
    "igmp_extensions",
    "igmp_header",
    "igmp_mrd",
    "igmp_v3_query",
    "igmp_v3_report",
    "ikev2_header",
    "ikev2_payloads",
    "ip_fragment_transforms",
    "ipv4_options",
    "ipv6_fragment_routing",
    "pcap_contracts",
    "pcap_link_types",
    "radiotap_basic",
    "rip_auth",
    "rip_entries",
    "rip_header",
    "ripng_rtes",
    "rsn_foundations",
    "tcp_header",
    "tcp_options",
    "udp_options",
    "zigbee-nwk-aps",
    "zigbee_nwk_aps",
}
_SUPPORTED_FIELDS_BY_LAYER: dict[str, set[str]] = {
    # The ``ble_adv`` / ``ble_radio`` field allowlists moved to ``protocols/ble.py``
    # (their ``ScapyProtocol.supported_fields``); ``_scapy_supported_fields`` resolves
    # them from the registry.
    # The ``dot11`` field allowlist moved to ``protocols/wifi.py`` (its
    # ``ScapyProtocol.supported_fields``); ``_scapy_supported_fields`` resolves it
    # from the registry.
    # The ``eapol`` field allowlist moved to ``protocols/wifi.py`` (its
    # ``ScapyProtocol.supported_fields``); ``_scapy_supported_fields`` resolves it
    # from the registry.
    # The ``esp`` / ``ah`` / ``ikev2`` field allowlists moved to
    # ``protocols/ipsec.py`` (their ``ScapyProtocol.supported_fields``);
    # ``_scapy_supported_fields`` resolves them from the registry.
    # The base ``igmp`` field allowlist moved to ``protocols/igmp.py`` (its
    # ``ScapyProtocol.supported_fields``); ``_scapy_supported_fields`` resolves it
    # from the registry. The ``igmp_query`` / ``igmp_report`` / ``igmp_extension``
    # sub-layers are not top-level spec layers, so they keep their legacy entries
    # here for the per-layer ``_build_layer`` dispatch.
    "igmp_extension": {
        "extension_length",
        "extension_type",
        "extension_value",
        "length",
        "type",
        "value",
        "value_hex",
    },
    "igmp_query": {
        "flags_qrv",
        "number_of_sources",
        "qqic",
        "query_flags",
        "raw_flags_qrv",
        "source_addresses",
    },
    "igmp_report": {
        "group_records",
        "number_of_group_records",
        "number_of_records",
        "records",
        "report_flags",
        "reserved_flags",
    },
    "ipv6_destination_options": {
        "header_ext_len",
        "len",
        "next_header",
        "nh",
        "options",
    },
    "ipv6_fragment": {
        "fragment_offset",
        "identification",
        "id",
        "m",
        "more_fragments",
        "next_header",
        "nh",
        "offset",
        "reserved",
    },
    "ipv6_hop_by_hop": {
        "header_ext_len",
        "len",
        "next_header",
        "nh",
        "options",
    },
    "ipv6_routing": {
        "addresses",
        "next_header",
        "nh",
        "routing_type",
        "segments_left",
        "segleft",
        "type",
    },
    # The ``radiotap`` and ``rsn`` field allowlists moved to ``protocols/wifi.py``
    # (their ``ScapyProtocol.supported_fields``); ``_scapy_supported_fields``
    # resolves them from the registry.
}


def encode_packet_plan(
    plan: PacketPlan,
    *,
    capabilities: BackendCapabilities | BackendRegistration | None = None,
) -> EncodedVector:
    """Materialize one backend-neutral packet plan as Scapy-generated bytes."""

    _require_encode_capability(capabilities)
    stack = _canonical_stack(plan.stack)
    if not stack:
        raise ValueError("packet plan stack must contain at least one layer")
    root = _plan_root(plan)
    _validate_plan_contract(plan, stack, root)

    # Consult the whole-stack encoder plugins before any legacy special case. The
    # registry is empty until a raw-bytes family is migrated, so this resolves to
    # ``None`` and the legacy branches below run unchanged.
    stack_encoder = next(
        (encoder for encoder in STACK_ENCODER_REGISTRY if encoder.matches(stack)),
        None,
    )

    # The Dot11 phase-1.5 and BLE advertising stack encoders emit deterministic wire
    # bytes without touching Scapy, exactly as the former in-line
    # ``_dot11_phase15_bytes`` / ``_ble_bytes`` branches did; they keep
    # ``scapy_version`` at ``"not-required"`` (BLE may upgrade it from the native
    # ``bluetooth4LE`` import) and skip the Scapy import. Other (future) stack encoders
    # may require Scapy, so they fall through to the import like the legacy per-layer
    # path.
    wifi_materialization = stack_encoder is not None and stack_encoder.name == "dot11_phase15"
    ble_materialization = stack_encoder is not None and stack_encoder.name == "ble_advertising"
    needs_scapy = not (wifi_materialization or ble_materialization)
    scapy_all = None
    scapy_version = "not-required"
    raw = None
    if needs_scapy:
        scapy = import_scapy()
        scapy_all = scapy["all"]
        scapy_version = _string(scapy["version"], "unknown")
        raw = scapy_all.raw

    ipsec_sa_metadata = None
    ble_metadata = None
    if ble_materialization:
        # BLE is a stack encoder, but its byte driver also returns the
        # materialization metadata reported on the encoded vector, so it is invoked
        # directly (rather than through ``stack_encoder.encode``) to keep both halves.
        raw_bytes, ble_metadata = _ble_bytes(plan, stack)
        udp_options_metadata = None
        scapy_version = _string(ble_metadata.get("scapy_version"), scapy_version)
    elif stack_encoder is not None:
        raw_bytes = stack_encoder.encode(plan, scapy_all)
        raw_bytes, udp_options_metadata = _materialize_udp_options(plan, root, raw_bytes)
    elif _is_ipsec_sa_stack(plan, stack):
        if raw is None:
            raise ValueError("Scapy raw materializer was not initialized")
        raw_bytes, ipsec_sa_metadata = _materialize_ipsec_sa_packet(
            plan, stack, scapy_all, _build_layer
        )
        raw_bytes, udp_options_metadata = _materialize_udp_options(plan, root, raw_bytes)
    else:
        packet = None
        for index, layer in enumerate(stack):
            piece = _build_layer(plan, stack, index, scapy_all)
            packet = piece if packet is None else packet / piece

        if packet is None:
            raise ValueError("packet plan did not produce a packet")

        if raw is None:
            raise ValueError("Scapy raw materializer was not initialized")
        raw_bytes = bytes(raw(packet))
        raw_bytes, udp_options_metadata = _materialize_udp_options(plan, root, raw_bytes)
    metadata: JSONObject = {
        "backend": BACKEND_NAME,
        "feature_tags": list(plan.feature_tags),
        "scapy_version": scapy_version,
        "root_decoder": root,
        "stack_tags": list(plan.feature_tags),
        "strict_bytes": plan.strict_bytes,
        "scapy_stack": [_scapy_layer_name(layer) for layer in stack],
        "length": len(raw_bytes),
    }
    if udp_options_metadata is not None:
        metadata["udp_options_materialization"] = udp_options_metadata
    if ipsec_sa_metadata is not None:
        metadata["ipsec_sa_materialization"] = ipsec_sa_metadata
    if ble_metadata is not None:
        metadata["ble_materialization"] = ble_metadata
    if wifi_materialization:
        metadata["dot11_phase15_materialization"] = {
            "native_scapy_support": False,
            "materialization": "deterministic_wire_bytes",
        }
    return EncodedVector.from_bytes(
        plan=plan,
        backend=BACKEND_NAME,
        raw=raw_bytes,
        root=root,
        decoder=_scapy_decoder(root),
        metadata=metadata,
    )


def encode_packet_plans(
    plans: list[PacketPlan],
    *,
    capabilities: BackendCapabilities | BackendRegistration | None = None,
) -> list[EncodedVector]:
    """Materialize packet plans in order."""

    _require_encode_capability(capabilities)
    return [encode_packet_plan(plan, capabilities=capabilities) for plan in plans]


def _build_layer(plan: PacketPlan, stack: list[str], index: int, scapy_all: Any) -> Any:
    layer = stack[index]
    fields = plan.fields

    # Consult the per-layer Scapy encoder plugins before the legacy if/elif. The
    # registry is empty until a protocol is migrated, so this resolves to ``None``
    # and the legacy branches below build the layer unchanged.
    plugin = SCAPY_REGISTRY.get(layer)
    if plugin is not None:
        return plugin.build(plan, fields, stack, index, scapy_all)

    if layer == "raw":
        return scapy_all.Raw(load=_payload_bytes(fields))
    if layer == "ipv6_hop_by_hop":
        return _ipv6_hop_by_hop(fields, stack, index, scapy_all)
    if layer == "ipv6_destination_options":
        return _ipv6_destination_options(fields, stack, index, scapy_all)
    if layer == "ipv6_fragment":
        return _ipv6_fragment(fields, stack, index, scapy_all)
    if layer == "ipv6_routing":
        return _ipv6_routing(fields, stack, index, scapy_all)
    if layer == "igmp_query":
        return scapy_all.Raw(load=_igmp_query_bytes(fields))
    if layer == "igmp_report":
        return scapy_all.Raw(load=_igmp_report_bytes(fields))
    if layer == "igmp_extension":
        return scapy_all.Raw(load=_igmp_extension_layer_bytes(_layer_fields_for_stack_index(fields, stack, index)))

    raise ValueError(f"unsupported Scapy materialization layer: {layer}")


# --------------------------------------------------------------------------
# RIP (RFC 1058 / RFC 2453) materialization moved to ``protocols/rip.py`` and
# RIPng (RFC 2080) materialization moved to ``protocols/ripng.py``; both are
# registered in ``SCAPY_REGISTRY`` (so ``_build_layer`` routes ``rip`` / ``ripng``
# to their ``build``). ``ripng`` shares the ``_rip_command`` symbolic-command
# resolver, which the ripng plugin imports from the co-located ``rip`` plugin.

# --------------------------------------------------------------------------
# IPSec (ESP / AH / IKEv2) materialization moved to ``protocols/ipsec.py``. The
# ``esp`` / ``ah`` / ``ikev2`` per-layer raw builders are registered in
# ``SCAPY_REGISTRY`` (so ``_build_layer`` routes them to their ``build``), and the
# crypto/auth/AEAD/transport maps, the ESP/AH SecurityAssociation materializer, and
# the ``_is_ipsec_sa_stack`` predicate live there too. The SA path is a
# plan-dependent whole-stack decision (the null/opaque case is excluded by plan
# metadata, which the stack-only ``StackEncoder.matches`` contract cannot see), so
# ``encode_packet_plan`` keeps the selection branch and calls the moved
# ``_materialize_ipsec_sa_packet`` (re-imported above), passing ``_build_layer`` so
# the materializer can build inner Scapy layers without importing this module.


def _validate_plan_contract(plan: PacketPlan, stack: list[str], root: str) -> None:
    supported_roots = _ROOT_FIRST_LAYERS.get(root)
    if supported_roots is None:
        raise ValueError(f"unsupported Scapy materialization root: {root!r}")
    if stack[0] not in supported_roots:
        raise ValueError(
            f"packet plan root/stack mismatch for Scapy materialization: "
            f"root={root!r} first_layer={stack[0]!r}"
        )

    feature = plan.metadata.get("feature")
    if feature is not None:
        if not isinstance(feature, str):
            raise ValueError("packet plan metadata.feature must be a string when present")
        if feature not in _SUPPORTED_FEATURES:
            raise ValueError(
                f"unsupported Scapy feature materialization: {feature!r}; "
                f"supported features: {', '.join(sorted(_SUPPORTED_FEATURES))}"
            )

    if "igmp" in stack and (
        plan.case.startswith("malformed-igmp-") or plan.metadata.get("malformed") is True
    ):
        raise ValueError(
            "IGMP structured-error cases are not materialized by the Scapy strict-byte path"
        )

    for index, layer in enumerate(stack):
        if not _is_materialized_layer(layer):
            raise ValueError(f"unsupported Scapy materialization layer: {layer}")
        fields = _layer_fields_for_stack_index(plan.fields, stack, index)
        _validate_layer_fields(layer, fields)
        if layer == "payload":
            if not fields:
                raise ValueError("payload materialization requires payload fields")
            _payload_bytes(plan.fields)


def _validate_layer_fields(layer: str, fields: Mapping[str, object]) -> None:
    supported = _scapy_supported_fields(layer)
    if supported is None:
        raise ValueError(f"unsupported Scapy materialization layer: {layer}")
    unknown = sorted(set(fields) - supported)
    if unknown:
        raise ValueError(
            f"unsupported Scapy materialization fields for {layer}: {', '.join(unknown)}"
        )


def _plan_root(plan: PacketPlan) -> str:
    root = plan.metadata.get("root_decoder", plan.metadata.get("root"))
    if not isinstance(root, str) or not root:
        raise ValueError("packet plan metadata must include root_decoder or root")
    return root


def _materialize_udp_options(
    plan: PacketPlan,
    root: str,
    raw: bytes,
) -> tuple[bytes, JSONObject | None]:
    udp_fields = _layer_fields(plan.fields, "udp")
    options = udp_fields.get("options")
    if not isinstance(options, Mapping):
        return raw, None
    if options.get("format") != "udp_surplus_options":
        raise ValueError("udp.options format must be udp_surplus_options")

    layout = _udp_layout(root, raw)
    payload = raw[layout["udp_payload_start"] : layout["udp_payload_end"]]
    declared_payload = _udp_options_application_payload(options)
    if declared_payload is not None and declared_payload != payload:
        raise ValueError(
            "udp.options application payload does not match materialized UDP payload"
        )

    option_bytes = _udp_surplus_option_bytes(options, payload)
    if not option_bytes and _udp_options_checksum_mode(options) == "absent":
        return raw, None

    l3_relative_surplus_start = layout["surplus_start"] - layout["l3_start"]
    alignment = b"\x00" * (l3_relative_surplus_start & 1)
    option_checksum = _udp_option_checksum_value(
        options,
        alignment=alignment,
        option_bytes=option_bytes,
        udp_checksum=int.from_bytes(
            raw[layout["udp_start"] + 6 : layout["udp_start"] + 8],
            "big",
        ),
    )
    surplus = alignment + option_checksum.to_bytes(2, "big") + option_bytes
    materialized = raw[: layout["surplus_start"]] + surplus + raw[layout["surplus_start"] :]
    materialized = _patch_ip_payload_length(materialized, layout, len(surplus))

    return materialized, {
        "format": "udp_surplus_options",
        "native_scapy_support": False,
        "materialization": "udp_payload_bytes_plus_explicit_surplus",
        "application_payload_hex": payload.hex(),
        "udp_length": layout["udp_length"],
        "udp_checksum": int.from_bytes(
            materialized[layout["udp_start"] + 6 : layout["udp_start"] + 8],
            "big",
        ),
        "surplus_hex": surplus.hex(),
        "surplus_length": len(surplus),
        "surplus_start": layout["surplus_start"],
        "option_checksum": option_checksum,
        "option_bytes_hex": option_bytes.hex(),
        "alignment_hex": alignment.hex(),
        "placement": "after_udp_length",
    }


def _udp_options_application_payload(options: Mapping[str, object]) -> bytes | None:
    value = options.get("application_payload")
    if not isinstance(value, Mapping):
        return None
    hex_value = value.get("hex")
    if not isinstance(hex_value, str):
        return None
    payload = bytes.fromhex(hex_value)
    length = value.get("length")
    if isinstance(length, int) and length != len(payload):
        raise ValueError(
            f"udp.options application payload length mismatch: "
            f"declared={length} actual={len(payload)}"
        )
    return payload


def _udp_surplus_option_bytes(options: Mapping[str, object], payload: bytes) -> bytes:
    items = options.get("items")
    if not isinstance(items, list):
        raise ValueError("udp.options.items must be a list")
    output = bytearray()
    for item in items:
        if not isinstance(item, Mapping):
            raise ValueError("udp.options.items entries must be objects")
        output.extend(_udp_surplus_option_item_bytes(item, payload))
    return bytes(output)


def _udp_surplus_option_item_bytes(item: Mapping[str, object], payload: bytes) -> bytes:
    kind = _int(_required_field(item, "udp.options", "kind"), 0)
    if kind in {0, 1}:
        return bytes([kind])

    declared_length = _int(_required_field(item, "udp.options", "length"), 0)
    data = _udp_surplus_option_item_data(kind, item, payload)
    actual_length = 2 + len(data)
    if declared_length != actual_length:
        raise ValueError(
            f"udp option length mismatch for kind {kind}: "
            f"declared={declared_length} materialized={actual_length}"
        )
    if not 2 <= declared_length <= 255:
        raise ValueError(f"udp option length must fit one byte: {declared_length}")
    return bytes([kind, declared_length]) + data


def _udp_surplus_option_item_data(
    kind: int,
    item: Mapping[str, object],
    payload: bytes,
) -> bytes:
    data_hex = item.get("data_hex")
    if isinstance(data_hex, str):
        return bytes.fromhex(data_hex)

    if kind == 2:
        checksum = item.get("checksum")
        if checksum == "auto_crc32c_application_payload":
            return _crc32c(payload).to_bytes(4, "big")
        if isinstance(checksum, int):
            return checksum.to_bytes(4, "big")
    if kind == 4:
        return _int(
            _required_field(item, "udp.options", "max_datagram_size"),
            0,
        ).to_bytes(2, "big")
    if kind == 5:
        return (
            _int(
                _required_field(item, "udp.options", "max_reassembled_size"),
                0,
            ).to_bytes(2, "big")
            + bytes(
                [
                    _int(
                        _required_field(item, "udp.options", "segment_count"),
                        0,
                    )
                ]
            )
        )
    if kind in {6, 7}:
        return _int(_required_field(item, "udp.options", "token"), 0).to_bytes(4, "big")
    if kind == 8:
        return (
            _int(_required_field(item, "udp.options", "tsval"), 0).to_bytes(4, "big")
            + _int(_required_field(item, "udp.options", "tsecr"), 0).to_bytes(4, "big")
        )

    declared_length = _int(_required_field(item, "udp.options", "length"), 0)
    return b"\x00" * max(0, declared_length - 2)


def _udp_options_checksum_mode(options: Mapping[str, object]) -> str:
    checksum = options.get("option_checksum")
    if isinstance(checksum, Mapping):
        mode = checksum.get("mode")
        if isinstance(mode, str):
            return mode
    return "auto_internet_checksum"


def _udp_option_checksum_value(
    options: Mapping[str, object],
    *,
    alignment: bytes,
    option_bytes: bytes,
    udp_checksum: int,
) -> int:
    checksum = options.get("option_checksum")
    if isinstance(checksum, Mapping):
        value = checksum.get("value")
        if isinstance(value, int):
            return value
        mode = checksum.get("mode")
        if mode == "absent":
            return 0
        if mode == "zero_allowed_when_udp_checksum_zero" and udp_checksum == 0:
            return 0

    surplus_len = len(alignment) + 2 + len(option_bytes)
    if surplus_len > 0xFFFF:
        raise ValueError("udp options surplus length must fit in two bytes")
    checksum_value = _internet_checksum(
        surplus_len.to_bytes(2, "big") + b"\x00\x00" + option_bytes
    )
    return 0xFFFF if checksum_value == 0 else checksum_value


def _udp_layout(root: str, raw: bytes) -> dict[str, int]:
    l3_start = _l3_start_offset(root, raw)
    if l3_start >= len(raw):
        raise ValueError(f"packet is too short for root {root!r}")
    version = raw[l3_start] >> 4
    if version == 4:
        ihl = (raw[l3_start] & 0x0F) * 4
        if ihl < 20 or l3_start + ihl + 8 > len(raw):
            raise ValueError("IPv4 packet is too short to locate UDP header")
        protocol = raw[l3_start + 9]
        if protocol != 17:
            raise ValueError(f"IPv4 next protocol is not UDP: {protocol}")
        ip_end = l3_start + int.from_bytes(raw[l3_start + 2 : l3_start + 4], "big")
        udp_start = l3_start + ihl
    elif version == 6:
        if l3_start + 48 > len(raw):
            raise ValueError("IPv6 packet is too short to locate UDP header")
        payload_len = int.from_bytes(raw[l3_start + 4 : l3_start + 6], "big")
        ip_end = l3_start + 40 + payload_len
        udp_start = _ipv6_udp_start(raw, l3_start)
    else:
        raise ValueError(f"unsupported IP version for UDP options: {version}")

    if udp_start + 8 > len(raw):
        raise ValueError("packet is too short for UDP header")
    udp_length = int.from_bytes(raw[udp_start + 4 : udp_start + 6], "big")
    if udp_length < 8:
        raise ValueError(f"UDP length is too short: {udp_length}")
    udp_payload_start = udp_start + 8
    udp_payload_end = udp_start + udp_length
    if udp_payload_end > len(raw) or udp_payload_end > ip_end:
        raise ValueError(
            f"UDP length exceeds materialized packet: udp_end={udp_payload_end} ip_end={ip_end}"
        )
    return {
        "ip_version": version,
        "l3_start": l3_start,
        "ip_end": ip_end,
        "udp_start": udp_start,
        "udp_length": udp_length,
        "udp_payload_start": udp_payload_start,
        "udp_payload_end": udp_payload_end,
        "surplus_start": udp_payload_end,
    }


def _l3_start_offset(root: str, raw: bytes) -> int:
    if root in {"l3:ipv4", "l3:ipv6", "IP", "IPv6"}:
        return 0
    if root in {"link:linux-cooked", "link:linux-sll", "CookedLinux"}:
        return 16
    if root in {"link:null-loopback", "Loopback"}:
        return 4
    if root in {"link:ethernet", "Ether"}:
        offset = 14
        while len(raw) >= offset + 4:
            ethertype = int.from_bytes(raw[offset - 2 : offset], "big")
            if ethertype not in {0x8100, 0x88A8, 0x9100}:
                return offset
            offset += 4
        return offset
    raise ValueError(f"unsupported UDP option materialization root: {root!r}")


def _ipv6_udp_start(raw: bytes, l3_start: int) -> int:
    next_header = raw[l3_start + 6]
    cursor = l3_start + 40
    while next_header != 17:
        if cursor + 8 > len(raw):
            raise ValueError("IPv6 extension header chain is truncated before UDP")
        if next_header == 44:
            next_header = raw[cursor]
            cursor += 8
            continue
        if next_header in {0, 43, 60}:
            header_len = (raw[cursor + 1] + 1) * 8
            next_header = raw[cursor]
            cursor += header_len
            continue
        raise ValueError(f"IPv6 next header is not UDP: {next_header}")
    return cursor


def _patch_ip_payload_length(raw: bytes, layout: Mapping[str, int], added_len: int) -> bytes:
    if added_len == 0:
        return raw
    output = bytearray(raw)
    l3_start = layout["l3_start"]
    if layout["ip_version"] == 4:
        total_length = int.from_bytes(output[l3_start + 2 : l3_start + 4], "big")
        total_length += added_len
        if total_length > 0xFFFF:
            raise ValueError("IPv4 total length must fit in two bytes")
        output[l3_start + 2 : l3_start + 4] = total_length.to_bytes(2, "big")
        output[l3_start + 10 : l3_start + 12] = b"\x00\x00"
        ihl = (output[l3_start] & 0x0F) * 4
        checksum = _internet_checksum(bytes(output[l3_start : l3_start + ihl]))
        output[l3_start + 10 : l3_start + 12] = checksum.to_bytes(2, "big")
    else:
        payload_length = int.from_bytes(output[l3_start + 4 : l3_start + 6], "big")
        payload_length += added_len
        if payload_length > 0xFFFF:
            raise ValueError("IPv6 payload length must fit in two bytes")
        output[l3_start + 4 : l3_start + 6] = payload_length.to_bytes(2, "big")
    return bytes(output)


def _crc32c(data: bytes) -> int:
    crc = 0xFFFF_FFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x82F6_3B78
            else:
                crc >>= 1
    return (~crc) & 0xFFFF_FFFF


def _require_encode_capability(
    capabilities: BackendCapabilities | BackendRegistration | None,
) -> None:
    resolved = _capability_contract(capabilities)
    if not resolved.encode:
        raise ValueError("unsupported backend capability: Scapy packet materialization requires encode")


def _capability_contract(
    capabilities: BackendCapabilities | BackendRegistration | None,
) -> BackendCapabilities:
    if capabilities is None:
        return get_backend(BACKEND_NAME).capabilities
    if isinstance(capabilities, BackendRegistration):
        return capabilities.capabilities
    return capabilities


# The DHCP (BOOTP / DHCP) materializer ``_dhcp`` and its ``_dhcp_op`` /
# ``_dhcp_flags`` / ``_dhcp_chaddr`` / ``_dhcp_options`` option helpers moved to
# ``protocols/dhcp.py`` and are registered in ``SCAPY_REGISTRY`` (so ``_build_layer``
# routes ``dhcp`` to the plugin's ``build``).


def _scapy_decoder(root: str) -> str:
    decoder = _SCAPY_DECODER_BY_ROOT.get(root)
    if decoder is None:
        raise ValueError(f"unsupported Scapy root decoder: {root!r}")
    return decoder


def _scapy_layer_name(layer: str) -> str:
    plugin = SCAPY_REGISTRY.get(layer)
    if plugin is not None and plugin.scapy_class is not None:
        return plugin.scapy_class
    return _SCAPY_LAYER_BY_LAYER.get(layer, layer)
