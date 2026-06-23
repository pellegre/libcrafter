"""Wireshark-stage decode plugin for the Wi-Fi (802.11) stack.

This module is the home for the 802.11 tshark normalizers (``radiotap``,
``dot11``, ``eapol``, ``rsn``); all four are migrated here. It moves the
``_normalize_radiotap`` / ``_normalize_dot11`` / ``_normalize_eapol`` /
``_normalize_rsn`` tshark normalizers and their helpers verbatim out of
:mod:`..normalize` and registers them through the
:class:`~.base.WiresharkProtocol` contract; only the dispatch moves out of the
legacy if/elif. Behavior must stay byte-identical.

Shared primitives come from :mod:`..decode_helpers` so this plugin does not depend
on the ``normalize`` orchestrator (which would create a circular import). Relative
imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from ....model import JSONObject
from ..decode_helpers import (
    _field,
    _field_list,
    _fields_from_aliases,
    _hex_bytes,
    _layer,
    _layer_any,
    _parse_int,
    _parse_int_fields,
    _string_field,
    _truthy_field,
)
from .base import WiresharkProtocol, register


# tshark field aliases the radiotap layer owns: canonical oracle name -> the native
# tshark field names that carry it.
_RADIOTAP_TSHARK_ALIASES: JSONObject = {
    "version": ("radiotap.version",),
    "pad": ("radiotap.pad",),
    "length": ("radiotap.length",),
    "flags": ("radiotap.flags",),
    "rate": ("radiotap.datarate", "radiotap.rate"),
    "channel_frequency": ("radiotap.channel.freq", "radiotap.channel.frequency"),
    "channel_flags": ("radiotap.channel.flags",),
    "dbm_antenna_signal": ("radiotap.dbm_antsignal", "radiotap.dbm_antenna_signal"),
    "antenna": ("radiotap.antenna",),
    "rx_flags": ("radiotap.rxflags", "radiotap.rx_flags"),
    "tx_flags": ("radiotap.txflags", "radiotap.tx_flags"),
}


def _normalize_radiotap_layer(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(layer, dict(_RADIOTAP_TSHARK_ALIASES))
    _parse_int_fields(
        output,
        "version",
        "pad",
        "length",
        "flags",
        "channel_frequency",
        "channel_flags",
        "dbm_antenna_signal",
        "antenna",
        "rx_flags",
        "tx_flags",
    )
    rate = _parse_radiotap_rate(output.get("rate"))
    if rate is not None:
        output["rate"] = rate
    else:
        output.pop("rate", None)

    present_words = [
        parsed
        for parsed in (
            _parse_int(item)
            for item in _field_list(
                layer,
                "radiotap.present.word",
                "radiotap.present",
            )
        )
        if parsed is not None
    ]
    if present_words:
        output["present_words"] = present_words

    flags = output.get("flags")
    if isinstance(flags, int):
        output["fcs_status"] = _radiotap_fcs_status(flags)
    elif _truthy_field(layer, "radiotap.flags.fcs"):
        output["fcs_status"] = (
            "present_failed"
            if _truthy_field(layer, "radiotap.flags.badfcs")
            else "present"
        )
    elif _truthy_field(layer, "radiotap.flags.badfcs"):
        output["fcs_status"] = "failed"
    return output


def _parse_radiotap_rate(value: object) -> int | None:
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed
    if not isinstance(value, str):
        return None
    candidate = value.strip().split(" ", 1)[0]
    try:
        return int(round(float(candidate) * 2))
    except ValueError:
        return None


def _radiotap_fcs_status(flags: int) -> str:
    present = bool(flags & 0x10)
    failed = bool(flags & 0x40)
    if present and failed:
        return "present_failed"
    if present:
        return "present"
    if failed:
        return "failed"
    return "absent"


def _normalize_radiotap(
    layers: JSONObject, *, source_hex: str | None = None
) -> JSONObject:
    return _normalize_radiotap_layer(_layer(layers, "radiotap"))


register(
    WiresharkProtocol(
        layer="radiotap",
        normalize=_normalize_radiotap,
        tshark_aliases=dict(_RADIOTAP_TSHARK_ALIASES),
    )
)


# tshark field aliases the dot11 layer owns: canonical oracle name -> the native
# tshark field names that carry it.
_DOT11_TSHARK_ALIASES: JSONObject = {
    "frame_control": ("wlan.fc", "wlan.fc.raw"),
    "protocol_version": ("wlan.fc.version",),
    "frame_type": ("wlan.fc.type",),
    "subtype": ("wlan.fc.subtype",),
    "duration_id": ("wlan.duration", "wlan.duration_id"),
    "sequence_control": ("wlan.seq_control", "wlan.seqctl"),
    "sequence_number": ("wlan.seq", "wlan.seq.seq"),
    "fragment_number": ("wlan.frag", "wlan.seq.frag"),
    "qos_control": ("wlan.qos", "wlan.qos.control"),
    "ht_control": ("wlan.ht.control", "wlan.ht_control"),
}


def _normalize_dot11_layer(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(layer, dict(_DOT11_TSHARK_ALIASES))
    _parse_int_fields(
        output,
        "frame_control",
        "protocol_version",
        "frame_type",
        "subtype",
        "duration_id",
        "sequence_control",
        "sequence_number",
        "fragment_number",
        "qos_control",
        "ht_control",
    )

    bool_fields = {
        "to_ds": ("wlan.fc.tods",),
        "from_ds": ("wlan.fc.fromds",),
        "more_fragments": ("wlan.fc.frag",),
        "retry": ("wlan.fc.retry",),
        "power_management": ("wlan.fc.pwrmgt",),
        "more_data": ("wlan.fc.moredata",),
        "protected": ("wlan.fc.protected", "wlan.fc.wep"),
        "order": ("wlan.fc.order",),
    }
    for target, aliases in bool_fields.items():
        value = _field(layer, *aliases)
        if value is not None:
            output[target] = _truthy_value(value)
    ds = _parse_int(_field(layer, "wlan.fc.ds"))
    if ds is not None:
        output.setdefault("to_ds", bool(ds & 0x01))
        output.setdefault("from_ds", bool(ds & 0x02))

    addresses = [str(item) for item in _field_list(layer, "wlan.addr")]
    for index, address in enumerate(addresses[:4], start=1):
        output.setdefault(f"addr{index}", address)
    _copy_string_field(output, "addr1", layer, "wlan.addr1", "wlan.ra", "wlan.da")
    _copy_string_field(output, "addr2", layer, "wlan.addr2", "wlan.ta", "wlan.sa")
    _copy_string_field(output, "addr3", layer, "wlan.addr3", "wlan.bssid")
    _copy_string_field(output, "addr4", layer, "wlan.addr4")

    sequence_number = output.get("sequence_number")
    fragment_number = output.get("fragment_number")
    if "sequence_control" not in output and isinstance(sequence_number, int):
        fragment = fragment_number if isinstance(fragment_number, int) else 0
        output["sequence_control"] = (sequence_number << 4) | (fragment & 0x0F)
    if "sequence_number" not in output and isinstance(output.get("sequence_control"), int):
        output["sequence_number"] = output["sequence_control"] >> 4
    if "fragment_number" not in output and isinstance(output.get("sequence_control"), int):
        output["fragment_number"] = output["sequence_control"] & 0x0F
    return output


def _truthy_value(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value not in {"", "0", "0x0", "False", "false"}
    return bool(value)


def _copy_string_field(
    output: JSONObject,
    target: str,
    layer: JSONObject,
    *names: str,
) -> None:
    value = _string_field(layer, *names)
    if value is not None:
        output[target] = value


def _normalize_dot11(
    layers: JSONObject, *, source_hex: str | None = None
) -> JSONObject:
    return _normalize_dot11_layer(_layer(layers, "wlan"))


register(
    WiresharkProtocol(
        layer="dot11",
        normalize=_normalize_dot11,
        tshark_aliases=dict(_DOT11_TSHARK_ALIASES),
    )
)


# tshark field aliases the eapol layer owns: canonical oracle name -> the native
# tshark field names that carry it.
_EAPOL_TSHARK_ALIASES: JSONObject = {
    "version": ("eapol.version",),
    "packet_type": ("eapol.type",),
    "body_length": ("eapol.len", "eapol.length"),
    "descriptor_type": ("eapol.keydes.type",),
    "key_information": ("eapol.keydes.key_info",),
    "key_length": ("eapol.keydes.key_len",),
    "replay_counter": ("eapol.keydes.replay_counter",),
    "key_nonce": ("eapol.keydes.nonce",),
    "key_iv": ("eapol.keydes.key_iv",),
    "key_rsc": ("eapol.keydes.key_rsc",),
    "key_id": ("eapol.keydes.key_id",),
    "key_mic": ("eapol.keydes.key_mic",),
    "key_data_length": ("eapol.keydes.keydes_data_len",),
    "key_data": ("eapol.keydes.data",),
}

# tshark field aliases the rsn layer owns: canonical oracle name -> the native
# tshark field names that carry it.
_RSN_TSHARK_ALIASES: JSONObject = {
    "element_id": ("wlan.rsn.tag", "wlan.rsn.element_id"),
    "length": ("wlan.rsn.length",),
    "version": ("wlan.rsn.version",),
    "capabilities": ("wlan.rsn.capabilities",),
}


def _normalize_eapol_layer(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(layer, dict(_EAPOL_TSHARK_ALIASES))
    _parse_int_fields(
        output,
        "version",
        "packet_type",
        "body_length",
        "descriptor_type",
        "key_information",
        "key_length",
        "replay_counter",
        "key_data_length",
    )
    for name in ("key_nonce", "key_iv", "key_rsc", "key_id", "key_mic", "key_data"):
        value = output.get(name)
        if isinstance(value, str):
            output[name] = {"hex": _hex_bytes(value)}
    return output


def _normalize_rsn_layer(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(layer, dict(_RSN_TSHARK_ALIASES))
    _parse_int_fields(output, "element_id", "length", "version", "capabilities")
    group = _rsn_suite_from_layer(
        layer,
        kind="cipher",
        value_names=("wlan.rsn.gcs", "wlan.rsn.group_cipher_suite"),
        oui_names=("wlan.rsn.gcs.oui",),
        type_names=("wlan.rsn.gcs.type",),
    )
    if group is not None:
        output["group_cipher_suite"] = group
    pairwise = _rsn_suite_list_from_layer(
        layer,
        kind="cipher",
        value_names=("wlan.rsn.pcs", "wlan.rsn.pcs.type"),
        oui_names=("wlan.rsn.pcs.oui",),
    )
    if pairwise:
        output["pairwise_cipher_suites"] = pairwise
    akms = _rsn_suite_list_from_layer(
        layer,
        kind="akm",
        value_names=("wlan.rsn.akms", "wlan.rsn.akms.type"),
        oui_names=("wlan.rsn.akms.oui",),
    )
    if akms:
        output["akm_suites"] = akms
    return output


def _rsn_suite_from_layer(
    layer: JSONObject,
    *,
    kind: str,
    value_names: tuple[str, ...],
    oui_names: tuple[str, ...],
    type_names: tuple[str, ...],
) -> JSONObject | None:
    value = _field(layer, *value_names)
    suite = _rsn_suite_from_value(value, kind=kind)
    if suite is not None:
        return suite
    oui = _string_field(layer, *oui_names)
    suite_type = _parse_int(_field(layer, *type_names))
    if oui is None or suite_type is None:
        return None
    return _rsn_suite_from_oui_type(oui, suite_type, kind=kind)


def _rsn_suite_list_from_layer(
    layer: JSONObject,
    *,
    kind: str,
    value_names: tuple[str, ...],
    oui_names: tuple[str, ...],
) -> list[JSONObject]:
    values = _field_list(layer, *value_names)
    suites = [
        suite
        for suite in (_rsn_suite_from_value(value, kind=kind) for value in values)
        if suite is not None
    ]
    if suites:
        return suites
    oui_values = [str(value) for value in _field_list(layer, *oui_names)]
    if not oui_values:
        oui_values = ["00:0f:ac"] * len(values)
    output: list[JSONObject] = []
    for index, value in enumerate(values):
        suite_type = _parse_int(value)
        if suite_type is None:
            continue
        oui = oui_values[index] if index < len(oui_values) else oui_values[0]
        suite = _rsn_suite_from_oui_type(oui, suite_type, kind=kind)
        if suite is not None:
            output.append(suite)
    return output


def _rsn_suite_from_oui_type(oui: str, suite_type: int, *, kind: str) -> JSONObject | None:
    try:
        oui_bytes = bytes.fromhex(_hex_bytes(oui))
    except ValueError:
        return None
    if len(oui_bytes) < 3:
        return None
    return _rsn_suite_selector(oui_bytes[:3] + bytes([suite_type & 0xFF]), kind=kind)


def _rsn_suite_from_value(value: object, *, kind: str) -> JSONObject | None:
    if value is None:
        return None
    parsed = _parse_int(value)
    if parsed is not None:
        return _rsn_suite_selector(b"\x00\x0f\xac" + bytes([parsed & 0xFF]), kind=kind)
    if not isinstance(value, str):
        return None
    raw_hex = _hex_bytes(value)
    if len(raw_hex) < 8:
        return None
    try:
        raw = bytes.fromhex(raw_hex[:8])
    except ValueError:
        return None
    return _rsn_suite_selector(raw, kind=kind)


def _rsn_suite_selector(raw: bytes, *, kind: str) -> JSONObject:
    selector = bytes(raw)
    label = _rsn_cipher_label(selector) if kind == "cipher" else _rsn_akm_label(selector)
    output: JSONObject = {
        "selector": selector.hex(),
        "oui": selector[:3].hex(),
        "suite_type": selector[3],
    }
    if label is not None:
        output["label"] = label
    return output


def _rsn_cipher_label(selector: bytes) -> str | None:
    if selector[:3] != b"\x00\x0f\xac":
        return None
    return {
        0: "use-group",
        2: "tkip",
        4: "ccmp-128",
        6: "aes-128-cmac",
        7: "no-group-addressed",
        8: "gcmp-128",
        9: "gcmp-256",
        10: "ccmp-256",
        11: "bip-gmac-128",
        12: "bip-gmac-256",
        13: "bip-cmac-256",
        18: "ccm-star",
    }.get(selector[3])


def _rsn_akm_label(selector: bytes) -> str | None:
    if selector[:3] != b"\x00\x0f\xac":
        return None
    return {
        1: "802.1x",
        2: "psk",
        3: "ft-802.1x",
        4: "ft-psk",
        5: "802.1x-sha256",
        6: "psk-sha256",
        7: "tdls",
        8: "sae",
        9: "ft-sae",
        10: "ap-peer-key",
        11: "802.1x-suite-b",
        12: "802.1x-suite-b-192",
        13: "ft-802.1x-sha384-cmp-256",
        14: "fils-sha256",
        15: "fils-sha384",
        16: "ft-fils-sha256",
        17: "ft-fils-sha384",
        18: "owe",
        19: "ft-psk-sha384",
        20: "psk-sha384",
        21: "pasn",
        22: "ft-802.1x-sha384",
        23: "802.1x-sha384",
        24: "sae-pmk384",
        25: "ft-sae-pmk384",
        26: "pasn-defined-key-wrap",
        29: "edpke",
    }.get(selector[3])


def _normalize_eapol(
    layers: JSONObject, *, source_hex: str | None = None
) -> JSONObject:
    return _normalize_eapol_layer(_layer(layers, "eapol"))


def _normalize_rsn(
    layers: JSONObject, *, source_hex: str | None = None
) -> JSONObject:
    return _normalize_rsn_layer(_layer_any(layers, "wlan_mgt.rsn", "wlan.rsn"))


register(
    WiresharkProtocol(
        layer="eapol",
        normalize=_normalize_eapol,
        tshark_aliases=dict(_EAPOL_TSHARK_ALIASES),
    )
)


register(
    WiresharkProtocol(
        layer="rsn",
        normalize=_normalize_rsn,
        tshark_aliases=dict(_RSN_TSHARK_ALIASES),
    )
)
