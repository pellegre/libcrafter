"""Generator-stage sampler plugin for typed, offline CoAP packet plans.

The sampler emits documentation-only addresses and deterministic message
metadata.  It models one datagram or one complete reliable frame; transactions,
stream reassembly, credentials, and endpoint selection remain outside the
oracle plan.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import _SKIP_FIELD, _SamplingContext
from .base import ProtocolSampler, register


_COAP_PORT = 5683
_COAPS_PORT = 5684
_CLIENT_PORT = 49152
_IPV4_CLIENT = "192.0.2.10"
_IPV4_SERVER = "198.51.100.20"
_IPV6_CLIENT = "2001:db8::10"
_IPV6_SERVER = "2001:db8::20"

_SUPPORTED_FIELDS = frozenset(
    {
        "transport",
        "version",
        "message_type",
        "code",
        "message_id",
        "token",
        "token_length",
        "reliable_length",
        "options",
        "payload_marker",
        "payload",
        "signaling_options",
    }
)


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    del field_spec, current_fields
    reliable = "tcp" in ctx.stack
    if field_name == "transport":
        return "reliable" if reliable else "datagram"
    if field_name == "version":
        if reliable:
            return _SKIP_FIELD
        if domain == "reserved_preserved":
            return {"raw": 2}
        return 1
    if field_name == "message_type":
        if reliable:
            return _SKIP_FIELD
        return _message_type(ctx.case, domain)
    if field_name == "code":
        return _code(ctx.case, domain, reliable=reliable)
    if field_name == "message_id":
        if reliable:
            return _SKIP_FIELD
        return 0x1234
    if field_name == "token":
        return {"hex": _token_hex(domain)}
    if field_name == "token_length":
        return _token_length(domain)
    if field_name == "reliable_length":
        if not reliable or domain == "derived":
            return _SKIP_FIELD
        return _reliable_length(domain)
    if field_name == "options":
        return _options(domain)
    if field_name == "payload_marker":
        if domain in {"present", "explicit_empty"}:
            return "present"
        return "absent"
    if field_name == "payload":
        return {"hex": _payload_hex(domain)}
    if field_name == "signaling_options":
        if not reliable:
            return _SKIP_FIELD
        return _signaling_options(domain)
    raise ValueError(f"spec error: unsupported coap field sampler: {field_name}")


def _message_type(case: str, domain: object) -> str:
    if "content" in case or "notification" in case:
        return "non_confirmable"
    if domain in {"confirmable", "non_confirmable", "acknowledgement", "reset"}:
        return str(domain)
    return "confirmable"


def _code(case: str, domain: object, *, reliable: bool) -> int:
    if reliable:
        if "ping" in case:
            return 0xE2
        if "release" in case:
            return 0xE4
        if "abort" in case:
            return 0xE5
        return 0xE1
    if "content" in case or "notification" in case or "link-format-canonical" in case:
        return 0x45
    if domain == "unknown_preserved":
        return 0x1F
    return 0x01


def _token_hex(domain: object) -> str:
    if domain == "empty":
        return ""
    if domain == "extended8":
        return "a5" * 13
    if domain in {"extended16", "maximum"}:
        length = 269 if domain == "extended16" else 65_804
        return "a5" * length
    return "aa"


def _token_length(domain: object) -> object:
    if domain == "derived":
        return _SKIP_FIELD
    if domain == "direct":
        return {"nibble": 1, "extension_hex": "", "declared_length": 1}
    if domain == "extended8":
        return {"nibble": 13, "extension_hex": "00", "declared_length": 13}
    if domain == "extended16":
        return {"nibble": 14, "extension_hex": "0000", "declared_length": 269}
    return {"nibble": 1, "extension_hex": "", "declared_length": 1}


def _reliable_length(domain: object) -> JSONObject:
    if domain == "extended8":
        return {"nibble": 13, "extension_hex": "00", "declared_length": 13}
    if domain == "extended16":
        return {"nibble": 14, "extension_hex": "0000", "declared_length": 269}
    if domain == "extended32":
        return {"nibble": 15, "extension_hex": "00000000", "declared_length": 65_805}
    return {"nibble": 0, "extension_hex": "", "declared_length": 0}


def _option(number: int, value_hex: str) -> JSONObject:
    return {"number": number, "value_hex": value_hex}


def _options(domain: object) -> list[JSONObject]:
    if domain == "empty":
        return []
    if domain == "uri":
        return [_option(11, "737461747573")]
    if domain == "representation":
        return [_option(12, "")]
    if domain == "observe":
        return [_option(6, "ffffff")]
    if domain == "blockwise":
        return [_option(23, "2a")]
    if domain == "qblock":
        return [_option(31, "12")]
    if domain == "oscore":
        return [_option(9, "09")]
    if domain == "unknown_preserved":
        return [_option(65000, "deadbeef")]
    return []


def _payload_hex(domain: object) -> str:
    if domain == "text":
        return "68656c6c6f"
    if domain == "binary":
        return "000102ff"
    if domain == "link_format":
        return "3c2f732f74656d703e3b72743d227422"
    if domain == "protected_opaque":
        return "d18b3b5563bf"
    return ""


def _signaling_options(domain: object) -> list[JSONObject]:
    if domain == "csm":
        return [_option(2, "0480")]
    if domain == "ping_pong":
        return [_option(2, "")]
    if domain == "release":
        return [_option(2, "616c742e6578616d706c65")]
    if domain == "abort":
        return [_option(2, "01")]
    if domain == "unknown_preserved":
        return [_option(65000, "dead")]
    return []


def _post_sample(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    case: str,
) -> None:
    coap = fields.setdefault("coap", {})
    reliable = "tcp" in stack
    coap.clear()
    if reliable:
        coap.update(
            {
                "transport": "reliable",
                "code": 0xE1,
                "token": {"hex": ""},
                "options": [],
                "payload_marker": "absent",
                "payload": {"hex": ""},
            }
        )
    else:
        coap.update(
            {
                "transport": "datagram",
                "version": 1,
                "message_type": "confirmable",
                "code": 0x01,
                "message_id": 0x1234,
                "token": {"hex": "aa"},
                "options": [],
                "payload_marker": "absent",
                "payload": {"hex": ""},
            }
        )

    if "ipv4" in fields:
        fields["ipv4"]["src"] = _IPV4_CLIENT
        fields["ipv4"]["dst"] = _IPV4_SERVER
    if "ipv6" in fields:
        fields["ipv6"]["src"] = _IPV6_CLIENT
        fields["ipv6"]["dst"] = _IPV6_SERVER

    transport = "tcp" if reliable else "udp"
    if transport in fields:
        fields[transport]["src_port"] = _CLIENT_PORT
        fields[transport]["dst_port"] = (
            _COAPS_PORT if case == "coap-secure-port-raw" else _COAP_PORT
        )


def _apply_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
    grammar: Mapping[str, object],
) -> None:
    del stack, feature, behavior, grammar
    coap = fields.setdefault("coap", {})

    if case == "coap-datagram-get":
        _set_datagram(coap, message_type="confirmable", code=0x01, token="aa")
    elif case == "coap-datagram-content":
        _set_datagram(coap, message_type="non_confirmable", code=0x45, token="aa")
    elif case == "coap-options-payload":
        _set_datagram(coap, message_type="confirmable", code=0x02, token="aabb")
        coap["options"] = [_option(11, "737461747573"), _option(12, "")]
        coap["payload_marker"] = "present"
        coap["payload"] = {"hex": "000102ff"}
    elif case == "coap-observe-register":
        _set_datagram(coap, message_type="confirmable", code=0x01, token="aa")
        coap["options"] = [_option(6, "")]
    elif case in {"coap-observe-notification", "coap-observe-wrap"}:
        _set_datagram(coap, message_type="non_confirmable", code=0x45, token="aa")
        coap["options"] = [_option(6, "ffffff")]
    elif case in {"coap-block1", "coap-block2", "coap-qblock1", "coap-qblock2"}:
        _set_datagram(coap, message_type="confirmable", code=0x01, token="aa")
        number = {"coap-block1": 27, "coap-block2": 23, "coap-qblock1": 19, "coap-qblock2": 31}[case]
        coap["options"] = [_option(number, "2a")]
    elif case.startswith("coap-reliable-") or case == "coap-bert":
        coap["transport"] = "reliable"
        coap["code"] = 0xE2 if "ping" in case else 0xE1
        coap["token"] = {"hex": "aa" if "ping" in case else ""}
        coap.pop("message_id", None)
        coap.pop("message_type", None)
        coap["signaling_options"] = [_option(2, "0480")] if "csm" in case else []
    elif case.startswith("coap-extended-token-"):
        token_length = 269 if "extended16" in case else 13 if "extended8" in case else 8
        coap["token"] = {"hex": "a5" * token_length}
    elif case == "coap-link-format-canonical":
        _set_datagram(coap, message_type="non_confirmable", code=0x45, token="aa")
        coap["options"] = [_option(12, "28")]
        coap["payload_marker"] = "present"
        coap["payload"] = {"hex": _payload_hex("link_format")}
    elif case.startswith("coap-oscore-") or case == "coap-secure-port-raw":
        _set_datagram(coap, message_type="confirmable", code=0x02, token="aa")
        coap["options"] = [_option(9, "09")]
        coap["payload_marker"] = "present"
        coap["payload"] = {"hex": _payload_hex("protected_opaque")}


def _set_datagram(
    coap: JSONObject,
    *,
    message_type: str,
    code: int,
    token: str,
) -> None:
    coap.update(
        {
            "transport": "datagram",
            "version": 1,
            "message_type": message_type,
            "code": code,
            "message_id": 0x1234,
            "token": {"hex": token},
        }
    )
    coap.pop("reliable_length", None)
    coap.pop("signaling_options", None)


register(
    ProtocolSampler(
        layer="coap",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_behavior,
        handles_feature=lambda feature: feature.startswith("coap_"),
        post_sample=_post_sample,
    )
)
