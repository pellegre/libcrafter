"""Provider-neutral wire comparison policy helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject, PacketPlan, json_object, string_list


WIRE_COMPARE_ROOT_ALIASES = {
    "Ether": "link:ethernet",
    "IP": "l3:ipv4",
    "IPv4": "l3:ipv4",
    "IPv6": "l3:ipv6",
    "link:ethernet": "link:ethernet",
    "l3:ipv4": "l3:ipv4",
    "l3:ipv6": "l3:ipv6",
}

_WIRE_PROVIDER_POLICY_PROFILES: dict[str, JSONObject] = {
    "local-dry-run": {
        "provider": "local-dry-run",
        "ipv4_header_mutable": False,
        "l3_send_adds_link_layer_metadata": False,
        "transit_decrements_ipv4_ttl": False,
    },
    "hetzner": {
        "provider": "hetzner",
        "ipv4_header_mutable": True,
        "l3_send_adds_link_layer_metadata": True,
        "transit_decrements_ipv4_ttl": True,
    },
}


def wire_comparison_policy(
    plan: PacketPlan,
    *,
    provider: str,
    provider_capabilities: Mapping[str, object] | None = None,
) -> JSONObject:
    """Return the wire byte-comparison policy for a packet and provider."""

    override = _wire_policy_override(provider_capabilities)
    compare_root = _policy_compare_root(plan, override)
    mutable_fields = _policy_mutable_fields(
        plan,
        provider=provider,
        provider_capabilities=provider_capabilities,
        compare_root=compare_root,
        override=override,
    )
    byte_mutable_fields = _policy_byte_mutable_fields(
        plan,
        provider=provider,
        provider_capabilities=provider_capabilities,
        compare_root=compare_root,
        mutable_fields=mutable_fields,
        override=override,
    )
    strict_bytes = override.get("strict_bytes")
    if not isinstance(strict_bytes, bool):
        strict_bytes = bool(plan.strict_bytes and not byte_mutable_fields)

    return {
        "provider": provider,
        "compare_root": compare_root,
        "strict_bytes": strict_bytes,
        "mutable_fields": mutable_fields,
        "byte_mutable_fields": byte_mutable_fields,
        "transit_mutations": _policy_transit_mutations(
            plan,
            provider=provider,
            provider_capabilities=provider_capabilities,
            compare_root=compare_root,
            override=override,
        ),
    }


def wire_compare_root(plan: PacketPlan) -> str | None:
    """Return the canonical wire comparison root for a packet."""

    root = _packet_root(plan)
    if root is not None:
        return WIRE_COMPARE_ROOT_ALIASES.get(root)
    if _requires_ipv4(plan):
        return "l3:ipv4"
    if _requires_ipv6(plan):
        return "l3:ipv6"
    return None


def _policy_compare_root(
    plan: PacketPlan,
    override: Mapping[str, object],
) -> str | None:
    value = override.get("compare_root")
    if isinstance(value, str):
        return WIRE_COMPARE_ROOT_ALIASES.get(value, value)
    return wire_compare_root(plan)


def _policy_mutable_fields(
    plan: PacketPlan,
    *,
    provider: str,
    provider_capabilities: Mapping[str, object] | None,
    compare_root: str | None,
    override: Mapping[str, object],
) -> list[str]:
    explicit = _optional_string_list(override.get("mutable_fields"))
    if explicit is not None:
        return _unique_strings(explicit)

    fields: list[str] = []
    if _provider_policy_flag(
        provider,
        provider_capabilities,
        "ipv4_header_mutable",
    ) and "ipv4" in plan.stack:
        fields.extend(["ipv4.ttl", "ipv4.checksum"])
    if _provider_policy_flag(
        provider,
        provider_capabilities,
        "l3_send_adds_link_layer_metadata",
    ) and (compare_root or "").startswith("l3:"):
        fields.extend(["ethernet.src", "ethernet.dst", "ethernet.ethertype"])
    return _unique_strings(fields)


def _policy_transit_mutations(
    plan: PacketPlan,
    *,
    provider: str,
    provider_capabilities: Mapping[str, object] | None,
    compare_root: str | None,
    override: Mapping[str, object],
) -> list[JSONObject]:
    explicit = _optional_json_object_list(override.get("transit_mutations"))
    if explicit is not None:
        return explicit

    mutations: list[JSONObject] = []
    if _provider_policy_flag(
        provider,
        provider_capabilities,
        "transit_decrements_ipv4_ttl",
    ) and "ipv4" in plan.stack:
        mutations.extend(
            [
                {
                    "field": "ipv4.ttl",
                    "reason": "provider live transit may decrement TTL before capture",
                },
                {
                    "field": "ipv4.checksum",
                    "reason": "IPv4 header checksum follows provider TTL mutation",
                },
            ]
        )
    if _provider_policy_flag(
        provider,
        provider_capabilities,
        "l3_send_adds_link_layer_metadata",
    ) and (compare_root or "").startswith("l3:"):
        mutations.append(
            {
                "field": "ethernet.*",
                "reason": "provider capture may expose Ethernet metadata around an L3 send",
                "covered_fields": ["ethernet.src", "ethernet.dst", "ethernet.ethertype"],
            }
        )
    return mutations


def _policy_byte_mutable_fields(
    plan: PacketPlan,
    *,
    provider: str,
    provider_capabilities: Mapping[str, object] | None,
    compare_root: str | None,
    mutable_fields: Sequence[str],
    override: Mapping[str, object],
) -> list[str]:
    explicit = _optional_string_list(override.get("byte_mutable_fields"))
    if explicit is not None:
        return _unique_strings(explicit)
    root = compare_root or ""
    return [
        field
        for field in mutable_fields
        if _wire_mutable_field_affects_compare_bytes(field, root)
    ]


def _provider_policy_flag(
    provider: str,
    provider_capabilities: Mapping[str, object] | None,
    key: str,
) -> bool:
    override = _wire_policy_override(provider_capabilities)
    value = override.get(key)
    if isinstance(value, bool):
        return value
    profile = _WIRE_PROVIDER_POLICY_PROFILES.get(provider, {})
    return bool(profile.get(key, False))


def _wire_policy_override(
    provider_capabilities: Mapping[str, object] | None,
) -> JSONObject:
    if provider_capabilities is None:
        return {}
    for key in ("wire_policy", "mutation_policy"):
        raw = provider_capabilities.get(key)
        if isinstance(raw, Mapping):
            return json_object(raw, f"provider_capabilities.{key}")
    return {}


def _wire_mutable_field_affects_compare_bytes(field: str, compare_root: str) -> bool:
    layer = field.split(".", 1)[0]
    if compare_root.startswith("l3:"):
        return layer not in {"ethernet", "linux_cooked", "null_loopback"}
    if compare_root.startswith("link:"):
        return True
    return True


def _packet_root(plan: PacketPlan) -> str | None:
    root = plan.metadata.get("root_decoder", plan.metadata.get("root"))
    return root if isinstance(root, str) and root else None


def _requires_ipv4(plan: PacketPlan) -> bool:
    root = _packet_root(plan)
    return root == "l3:ipv4" or plan.family == "ipv4" or "ipv4" in plan.stack


def _requires_ipv6(plan: PacketPlan) -> bool:
    root = _packet_root(plan)
    return root == "l3:ipv6" or plan.family == "ipv6" or bool(
        set(plan.stack).intersection({"ipv6", "icmpv6", "ipv6_fragment", "ipv6_routing"})
    )


def _optional_string_list(value: object) -> list[str] | None:
    if value is None:
        return None
    return string_list(value, "wire_policy.mutable_fields")


def _optional_json_object_list(value: object) -> list[JSONObject] | None:
    if value is None:
        return None
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    output: list[JSONObject] = []
    for index, item in enumerate(value):
        if isinstance(item, Mapping):
            output.append(json_object(item, f"wire_policy.transit_mutations[{index}]"))
    return output


def _unique_strings(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(values))
