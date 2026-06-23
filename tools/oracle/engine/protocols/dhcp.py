"""Generator-stage sampler plugin for the DHCP layer.

Moves the ``_sample_dhcp_field`` sampler and the ``dhcp_behavior`` feature
behavior (``_apply_dhcp_behavior``) out of :mod:`generator` and registers them
through the uniform :class:`~.base.ProtocolSampler` contract. The sampling and
behavior logic is moved verbatim (behavior must stay byte-identical); only the
dispatch moves from the generator's legacy if/elif into this self-contained
module, which self-registers on import.

DHCP carries a feature behavior like IPv4/UDP/DNS: ``apply_behavior`` reproduces
the legacy ``dhcp_behavior`` branch of ``_apply_feature_behavior`` and
``handles_feature`` claims ownership of the ``"dhcp_behavior"`` feature name, so
the generator's registry-first feature loop runs it exactly once. The legacy
branch gated on ``"dhcp" in fields`` and mutated ``fields["dhcp"]`` in place;
that guard is reproduced here.

``DHCP_OPTION_MATRIX_TOKENS`` stays generator-visible because
``tools/oracle/tests/test_dhcp_oracle.py`` imports it from ``generator``. It is
defined here (the owning module) and re-imported back into ``generator`` so the
test's import keeps working — the same co-locate-and-re-import pattern as the DNS
``_dns_behavior_emits_raw`` helper.

This step is generator-stage only: the Scapy ``dhcp`` encoder (``_dhcp`` plus the
option helpers) and the Scapy/Wireshark decoders stay on their legacy backend
paths (registered fallbacks) until the next step migrates them. Relative imports
only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import (
    _SamplingContext,
    _is_ipv4_root_dhcp_stack,
    bounded_int,
)
from .base import ProtocolSampler, register


# DHCP fields the generator samples, mirroring the former
# ``generator._SUPPORTED_FIELDS["dhcp"]`` entry.
_SUPPORTED_FIELDS = frozenset(
    {
        "op",
        "hardware_type",
        "hardware_length",
        "transaction_id",
        "flags",
        "client_ip",
        "your_ip",
        "client_hardware_address",
        "options",
    }
)


def _sample_dhcp_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "op":
        return domain
    if field_name == "hardware_type":
        return "ethernet"
    if field_name == "hardware_length":
        return 6
    if field_name == "transaction_id":
        return bounded_int(ctx.rng, 0, (1 << 32) - 1)
    if field_name == "flags":
        if domain == "broadcast" and _is_ipv4_root_dhcp_stack(ctx.stack):
            return "none"
        return domain
    if field_name == "client_ip":
        return "0.0.0.0" if domain == "zero" else ctx.src_ipv4
    if field_name == "your_ip":
        return "0.0.0.0" if domain == "zero" else ctx.dst_ipv4
    if field_name == "client_hardware_address":
        return ctx.src_mac
    if field_name == "options":
        return _dhcp_option_domains(ctx, domain)
    raise ValueError(f"spec error: unsupported dhcp field sampler: {field_name}")


def _dhcp_option_domains(ctx: _SamplingContext, domain: object) -> list[object]:
    options: list[object] = ["message-type=discover"]
    boundary = ctx.profile in {"boundary", "fuzz"}
    if domain == "hostname" and ctx.profile != "smoke":
        options.append("hostname=libcrafter-oracle")
    elif domain == "domain_name" and boundary:
        options.append("domain=example.com")
    elif domain == "requested_ip" and boundary:
        options.append(f"requested_addr={ctx.dst_ipv4}")
    elif domain == "server_id" and boundary:
        options.append(f"server_id={ctx.src_ipv4}")
    elif domain == "lease_time" and boundary:
        options.append(("lease_time", 3600))
    elif domain == "router" and boundary:
        options.append(f"router={ctx.src_ipv4}")
    elif domain == "dns_server" and boundary:
        options.append(f"name_server={ctx.dst_ipv4}")
    elif domain == "vendor_class" and boundary:
        options.append(["vendor_class_id", "6c6962637261667465722d6f7261636c65"])
    elif domain == "client_identifier" and boundary:
        options.append(["client_id", "01" + ctx.src_mac.replace(":", "")])
    elif domain == "classless_static_route" and boundary:
        options.append(["classless_static_routes", [f"192.0.2.0/24:{ctx.src_ipv4}"]])
    elif domain == "relay_agent" and boundary:
        options.append(["relay_agent_information", "0103616263"])
    elif domain == "parameter_request_list" and boundary:
        options.append(["param_req_list", [1, 3, 6]])
    options.append("end")
    return options


# Backend-neutral DHCP option kinds that materialize byte-for-byte through both
# the Scapy reference backend and the libcrafter adapter, in fixed option order.
# Kinds the dhcp_behavior option_matrix lists that Scapy cannot encode
# byte-for-byte (parameter_request_list, vendor_class, client_identifier,
# classless_static_route, relay_agent, generic) are covered by native libcrafter
# fixtures rather than this cross-backend matrix; see
# tools/oracle/specs/layers/dhcp.yaml and features/dhcp-behavior.yaml.
DHCP_OPTION_MATRIX_TOKENS: tuple[str, ...] = (
    "message-type=discover",
    "hostname=libcrafter-oracle",
    "domain_name=example.com",
    "requested_ip=192.0.2.100",
    "server_id=192.0.2.1",
    "router=192.0.2.1",
    "domain_name_server=192.0.2.53",
    "lease_time=3600",
    "end",
)


def _dhcp_option_matrix() -> list[object]:
    """Return the deterministic byte-safe DHCP option matrix in option order.

    The matrix spans every cross-backend option kind the dhcp_behavior
    option_matrix lists as Scapy-byte-safe, in a fixed order, so a single
    generated plan exercises the whole matrix and the kinds are deterministic
    for both directions and both DHCP roots.
    """

    return list(DHCP_OPTION_MATRIX_TOKENS)


def _apply_dhcp_behavior(fields: JSONObject, *, case: str, behavior: str) -> None:
    key = f"{case} {behavior}".replace("_", "-")
    if "option-matrix" in key:
        fields["options"] = _dhcp_option_matrix()
        return
    if "offer" in key or "ack" in key:
        fields["op"] = "bootreply"
        fields["your_ip"] = "192.0.2.100"
        message = "ack" if "ack" in key else "offer"
        fields["options"] = [f"message-type={message}", "server_id=192.0.2.1", "end"]
    elif "nak" in key:
        fields["op"] = "bootreply"
        fields["options"] = ["message-type=nak", "server_id=192.0.2.1", "end"]
    elif "request" in key:
        fields["options"] = ["message-type=request", "requested_addr=192.0.2.100", "end"]
    elif "decline" in key:
        fields["options"] = ["message-type=decline", "requested_addr=192.0.2.100", "end"]
    elif "inform" in key:
        fields["options"] = ["message-type=inform", "hostname=libcrafter-oracle", "end"]
    elif "release" in key:
        fields["options"] = ["message-type=release", "server_id=192.0.2.1", "end"]
    elif "force-renew" in key:
        fields["op"] = "bootreply"
        fields["options"] = ["message-type=force_renew", "server_id=192.0.2.1", "end"]
    elif "lease-query" in key:
        fields["options"] = ["message-type=lease_query", "end"]


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter: DHCP uses only ``ctx``/``field_name``/``domain``."""

    return _sample_dhcp_field(ctx, field_name, domain)


def _apply_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None = None,
) -> None:
    """Apply the ``dhcp_behavior`` feature behavior to the sampled DHCP fields.

    Byte-identical to the legacy ``dhcp_behavior`` branch of
    ``generator._apply_feature_behavior``: it gated on ``"dhcp" in fields`` and ran
    ``_apply_dhcp_behavior(fields["dhcp"], ...)``, mutating the DHCP-layer dict in
    place per the selected case/behavior. ``grammar`` is part of the uniform
    ``apply_behavior`` call path (the TCP ``tcp_header`` behavior reads it); DHCP
    does not consult it.
    """

    if "dhcp" in fields:
        _apply_dhcp_behavior(fields["dhcp"], case=case, behavior=behavior)


def _handles_feature(feature: str) -> bool:
    return feature == "dhcp_behavior"


register(
    ProtocolSampler(
        layer="dhcp",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_behavior,
        handles_feature=_handles_feature,
    )
)
