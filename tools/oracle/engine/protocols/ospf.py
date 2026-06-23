"""Generator-stage sampler plugin for the OSPF layer.

Moves the ``_sample_ospf_field`` sampler, the ``_ospf_packet_type_for_case`` case
mapper, the ``_apply_ospf_behavior`` smoke-body injector, and the
``_ospf_smoke_lsa_header`` / ``_int_or`` helpers verbatim out of :mod:`generator`
and registers them through the uniform :class:`~.base.ProtocolSampler` contract.
The sampling and behavior logic is moved unchanged (behavior must stay
byte-identical); only the dispatch moves from the generator's legacy if/elif into
this self-contained module, which self-registers on import.

OSPF has NO feature behavior: it is materialized only through the focused
``ospf-smoke`` profile path, which calls ``_apply_ospf_behavior`` directly (with
``behavior=""``) outside the registry feature loop. The plugin therefore registers
only ``sample`` (no ``apply_behavior``/``handles_feature``). ``_apply_ospf_behavior``
keeps its original ``(fields, *, stack, case, behavior)`` signature and is
re-imported into :mod:`generator` so the smoke path keeps working unchanged — the
same co-locate-and-re-import pattern as the BGP/RIP body injectors.

The sampler only seeds the eight OSPFv2 common-header fields; the per-type body
(Hello neighbor list, DD/LSAck LSA headers, LSR requests, LSU LSAs) is attached by
``_apply_ospf_behavior`` during the smoke-case pass, mirroring the BGP body path.

Shared primitives (``_SamplingContext``, ``_SKIP_FIELD``, ``documentation_ipv4``)
live in :mod:`..sampling`; they are imported here rather than duplicated. The
``_int_or`` helper is OSPF-only, so it moves here with the sampler. Relative imports
only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import _SKIP_FIELD, _SamplingContext, documentation_ipv4
from .base import ProtocolSampler, register


# OSPFv2 common-header fields declared in specs/layers/ospf.yaml. The per-type body
# (Hello/DD/LSR/LSU/LSAck neighbor and LSA lists) is injected by
# ``_apply_ospf_behavior`` AFTER field sampling, mirroring the BGP body path, so
# only the common-header fields appear here. Mirrors the former
# ``generator._SUPPORTED_FIELDS["ospf"]`` entry.
_SUPPORTED_FIELDS = frozenset(
    {
        "version",
        "type",
        "packet_length",
        "router_id",
        "area_id",
        "checksum",
        "autype",
        "authentication",
    }
)


def _sample_ospf_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    """Sample one OSPFv2 common-header field for the ipv4/ospf/payload stack.

    Only the eight common-header fields are sampled here; the per-type body
    (Hello neighbor list, DD/LSAck LSA headers, LSR requests, LSU LSAs) is
    injected by ``_apply_ospf_behavior`` after sampling, mirroring the BGP body
    path. ``packet_length`` and ``checksum`` are left unset (skipped) so both the
    Scapy reference backend and the libcrafter adapter derive them, keeping the
    offline byte comparison on the parts each backend fills identically.

    ``autype`` is pinned to the null type and ``authentication`` to eight zero
    octets for the smoke path: AuType 2 (cryptographic) needs the keyed-MD5 /
    HMAC-SHA trailer split that ``scapy.contrib.ospf`` does not expose for an
    offline byte-for-byte build, so it is covered by the crate's own auth
    fixtures rather than this cross-backend smoke profile.
    """

    if field_name == "version":
        return _int_or(domain, 2)
    if field_name == "type":
        return _ospf_packet_type_for_case(ctx.case)
    if field_name in {"packet_length", "checksum"}:
        return _SKIP_FIELD
    if field_name == "router_id":
        return documentation_ipv4(ctx.rng)
    if field_name == "area_id":
        # The backbone area (0.0.0.0) is the deterministic documentation area for
        # the smoke path; OSPF documentation examples use the backbone.
        return "0.0.0.0"
    if field_name == "autype":
        return "null"
    if field_name == "authentication":
        return {"hex": "00" * 8}
    raise ValueError(f"spec error: unsupported ospf field sampler: {field_name}")


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter: OSPF only needs ``ctx``, ``field_name``, ``domain``."""

    return _sample_ospf_field(ctx, field_name, domain)


def _int_or(domain: object, default: int) -> object:
    """Return ``domain`` when it is a concrete int, otherwise ``default``."""

    if isinstance(domain, bool):
        return int(domain)
    if isinstance(domain, int):
        return domain
    return default


def _apply_ospf_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    case: str,
    behavior: str,
) -> None:
    """Inject the per-type OSPFv2 body for a smoke case.

    The body field names match the Scapy reference builder
    (``tools/oracle/engine/backends/scapy/protocols/ospf.py`` ``_ospf*``) so the
    reference vector materializes a real Hello/DD/LSR/LSU/LSAck packet, and the
    field shapes round-trip through the libcrafter typed OSPFv2 layer. Documentation
    router IDs / area identifiers and a backbone area keep the packet in
    documentation address space. ``packet_length`` and ``checksum`` stay unset so
    both backends derive them.
    """

    del behavior  # Smoke cases carry no per-behavior variation.
    ospf = fields["ospf"]
    packet_type = _ospf_packet_type_for_case(case)
    ospf["type"] = packet_type

    if "payload" in fields:
        fields["payload"] = {"hex": "", "length": 0}

    # Drop any stray body fields so each case starts from the common header.
    for key in (
        "neighbors",
        "network_mask",
        "designated_router",
        "backup_designated_router",
        "interface_mtu",
        "options",
        "dd_flags",
        "dd_sequence_number",
        "lsa_headers",
        "requests",
        "lsas",
        "num_lsas",
        "body",
    ):
        ospf.pop(key, None)

    if packet_type == "hello":
        ospf["network_mask"] = "255.255.255.0"
        ospf["hello_interval"] = 10
        ospf["options"] = 0x02
        ospf["router_priority"] = 1
        ospf["router_dead_interval"] = 40
        ospf["designated_router"] = "192.0.2.1"
        ospf["backup_designated_router"] = "192.0.2.2"
        ospf["neighbors"] = ["192.0.2.3"]
        return

    if packet_type == "database_description":
        ospf["interface_mtu"] = 1500
        ospf["options"] = 0x02
        ospf["dd_flags"] = 0x07
        ospf["dd_sequence_number"] = 0x1A2B
        ospf["lsa_headers"] = [_ospf_smoke_lsa_header(0x99)]
        return

    if packet_type == "link_state_request":
        ospf["requests"] = [
            {
                "ls_type": 1,
                "link_state_id": "192.0.2.10",
                "advertising_router": "192.0.2.1",
            }
        ]
        return

    if packet_type == "link_state_update":
        ospf["num_lsas"] = 1
        ospf["lsas"] = [
            {
                **_ospf_smoke_lsa_header(0x99),
                "body": {"hex": "deadbeef"},
            }
        ]
        return

    if packet_type == "link_state_ack":
        ospf["lsa_headers"] = [_ospf_smoke_lsa_header(0x99)]
        return


def _ospf_smoke_lsa_header(ls_type: int) -> dict[str, object]:
    """Return a deterministic LSA header dict for the OSPF smoke cases.

    An unknown LSA type (default 0x99) keeps the body raw so both the Scapy
    reference backend and the libcrafter typed layer preserve it verbatim rather
    than re-interpreting it as a typed LSA, which keeps the decoded models equal.
    """

    return {
        "ls_age": 1,
        "options": 0x02,
        "ls_type": ls_type,
        "link_state_id": "192.0.2.20",
        "advertising_router": "192.0.2.1",
        "ls_sequence_number": 0x80000001,
    }


def _ospf_packet_type_for_case(case: str) -> str:
    """Map an ospf-* coverage case to the oracle-neutral OSPFv2 packet type."""

    normalized = case.replace("_", "-")
    if "database-description" in normalized:
        return "database_description"
    if "link-state-request" in normalized:
        return "link_state_request"
    if "link-state-update" in normalized:
        return "link_state_update"
    if "link-state-ack" in normalized:
        return "link_state_ack"
    return "hello"


register(
    ProtocolSampler(
        layer="ospf",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
    )
)
