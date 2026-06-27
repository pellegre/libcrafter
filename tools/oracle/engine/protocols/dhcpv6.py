"""Generator-stage sampler plugin for the DHCPv6 layer."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import _SKIP_FIELD, _SamplingContext, bounded_int
from .base import ProtocolSampler, register


_SUPPORTED_FIELDS = frozenset(
    {
        "message_type",
        "transaction_id",
        "hop_count",
        "link_address",
        "peer_address",
        "options",
    }
)

_CLIENT_DUID = "0003000102005e000601"
_SERVER_DUID = "0003000102005e000602"
_RELAY_DUID = "0003000102005e000603"


def _sample_dhcpv6_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    case = ctx.case.replace("_", "-")
    relay = "relay" in case
    if field_name == "message_type":
        if relay:
            return "relay_reply" if "reply" in case else "relay_forward"
        return domain
    if field_name == "transaction_id":
        if relay:
            return _SKIP_FIELD
        return bounded_int(ctx.rng, 0, (1 << 24) - 1)
    if field_name == "hop_count":
        return 1 if relay else _SKIP_FIELD
    if field_name == "link_address":
        return "2001:db8:100::" if relay else _SKIP_FIELD
    if field_name == "peer_address":
        return ctx.src_ipv6 if relay else _SKIP_FIELD
    if field_name == "options":
        return _dhcpv6_option_domains(ctx, domain)
    raise ValueError(f"spec error: unsupported dhcpv6 field sampler: {field_name}")


def _dhcpv6_option_domains(ctx: _SamplingContext, domain: object) -> list[JSONObject]:
    case = ctx.case.replace("_", "-")
    if "relay" in case:
        return _relay_options("relay-reply" in case)
    if domain == "option_matrix" or "option-matrix" in case:
        return _option_matrix()
    if "ia-na" in case:
        return [_client_id(), _server_id(), _ia_na()]
    if "ia-pd" in case:
        return [_client_id(), _server_id(), _ia_pd()]
    if "unknown-option" in case:
        return [_client_id(), _server_id(), _unknown_option()]
    if "reply" in case and "information" not in case:
        return [_client_id(), _server_id(), _status_success()]
    if "information-reply" in case:
        return [_client_id(), _server_id(), _dns_servers(), _domain_list()]
    return [_client_id(), _oro(), _elapsed_time()]


def _apply_dhcpv6_behavior(
    fields: dict[str, JSONObject],
    *,
    case: str,
    behavior: str,
) -> None:
    dhcpv6 = fields.setdefault("dhcpv6", {})
    udp = fields.setdefault("udp", {})
    key = f"{case} {behavior}".replace("_", "-")

    if "relay" in key:
        dhcpv6["message_type"] = "relay_reply" if "reply" in key else "relay_forward"
        dhcpv6.pop("transaction_id", None)
        dhcpv6["hop_count"] = 1
        dhcpv6["link_address"] = "2001:db8:100::"
        dhcpv6["peer_address"] = "2001:db8::10"
        dhcpv6["options"] = _relay_options("reply" in key)
        udp["src_port"] = 547
        udp["dst_port"] = 547
        return

    dhcpv6.pop("hop_count", None)
    dhcpv6.pop("link_address", None)
    dhcpv6.pop("peer_address", None)
    dhcpv6.setdefault("transaction_id", 0x010203)
    if "information-request" in key:
        dhcpv6["message_type"] = "information_request"
        dhcpv6["options"] = [_client_id(), _oro(), _elapsed_time()]
    elif "information-reply" in key:
        dhcpv6["message_type"] = "reply"
        dhcpv6["options"] = [_client_id(), _server_id(), _dns_servers(), _domain_list()]
    elif "request" in key:
        dhcpv6["message_type"] = "request"
        dhcpv6["options"] = [_client_id(), _server_id(), _oro()]
    elif "reply" in key:
        dhcpv6["message_type"] = "reply"
        dhcpv6["options"] = [_client_id(), _server_id(), _status_success()]
    elif "ia-na" in key:
        dhcpv6["message_type"] = "reply"
        dhcpv6["options"] = [_client_id(), _server_id(), _ia_na()]
    elif "ia-pd" in key:
        dhcpv6["message_type"] = "reply"
        dhcpv6["options"] = [_client_id(), _server_id(), _ia_pd()]
    elif "unknown" in key:
        dhcpv6["message_type"] = "reply"
        dhcpv6["options"] = [_client_id(), _server_id(), _unknown_option()]
    elif "option-matrix" in key:
        dhcpv6["message_type"] = "reply"
        dhcpv6["options"] = _option_matrix()
    else:
        dhcpv6["message_type"] = "solicit"
        dhcpv6["options"] = [_client_id(), _oro(), _elapsed_time()]

    if dhcpv6["message_type"] == "reply":
        udp["src_port"] = 547
        udp["dst_port"] = 546
    else:
        udp["src_port"] = 546
        udp["dst_port"] = 547


def _client_id() -> JSONObject:
    return {"name": "client_id", "duid": _CLIENT_DUID}


def _server_id() -> JSONObject:
    return {"name": "server_id", "duid": _SERVER_DUID}


def _oro() -> JSONObject:
    return {"name": "oro", "codes": [23, 24]}


def _elapsed_time() -> JSONObject:
    return {"name": "elapsed_time", "centiseconds": 1}


def _status_success() -> JSONObject:
    return {"name": "status_code", "status": "success", "message": ""}


def _dns_servers() -> JSONObject:
    return {"name": "dns_servers", "servers": ["2001:db8::53"]}


def _domain_list() -> JSONObject:
    return {"name": "domain_list", "domains": ["example.com"]}


def _ia_na() -> JSONObject:
    return {
        "name": "ia_na",
        "iaid": 0x01020304,
        "t1": 60,
        "t2": 120,
        "options": [
            {
                "name": "ia_addr",
                "address": "2001:db8::100",
                "preferred_lifetime": 300,
                "valid_lifetime": 600,
            }
        ],
    }


def _ia_pd() -> JSONObject:
    return {
        "name": "ia_pd",
        "iaid": 0x05060708,
        "t1": 90,
        "t2": 180,
        "options": [
            {
                "name": "ia_prefix",
                "prefix": "2001:db8:200::",
                "prefix_length": 56,
                "preferred_lifetime": 300,
                "valid_lifetime": 600,
            }
        ],
    }


def _unknown_option() -> JSONObject:
    return {"name": "unknown", "code": 65000, "payload_hex": "deadbeef"}


def _relay_options(reply: bool) -> list[JSONObject]:
    inner_type = "reply" if reply else "solicit"
    inner_options = [_client_id(), _server_id()] if reply else [_client_id(), _oro()]
    return [
        {"name": "interface_id", "payload_hex": "6163636573732d6c6f6f702d31"},
        {
            "name": "relay_msg",
            "message": {
                "message_type": inner_type,
                "transaction_id": 0x0A0B0C,
                "options": inner_options,
            },
        },
    ]


def _option_matrix() -> list[JSONObject]:
    return [
        _client_id(),
        _server_id(),
        _oro(),
        _elapsed_time(),
        _status_success(),
        _ia_na(),
        _ia_pd(),
        _unknown_option(),
    ]


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    return _sample_dhcpv6_field(ctx, field_name, domain)


def _apply_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None = None,
) -> None:
    _apply_dhcpv6_behavior(fields, case=case, behavior=behavior)


def _handles_feature(feature: str) -> bool:
    return feature == "dhcpv6_behavior"


register(
    ProtocolSampler(
        layer="dhcpv6",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_behavior,
        handles_feature=_handles_feature,
    )
)
