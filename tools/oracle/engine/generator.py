"""Deterministic packet plan generation primitives for oracle."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import random
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from .model import JSONObject, PacketPlan
from .sampling import (
    EPHEMERAL_PORT_MAX,
    EPHEMERAL_PORT_MIN,
    T,
    _SKIP_FIELD,
    _SamplingContext,
    _SkipField,
    _declared_ethertype_for_stack,
    _dot11_is_management,
    _different_ipv4,
    _different_ipv6,
    _different_mac,
    _different_port,
    _field_bits,
    _identifier_part,
    _integer_domain_value,
    _IPV4_DOCUMENTATION_NETWORKS,
    _IPV6_DOCUMENTATION_NETWORK,
    _ipv6_next_header_for_stack,
    _is_ipv4_root_dhcp_stack,
    _mac_for_domain,
    _next_layer_after,
    bounded_int,
    byte_payload,
    documentation_ipv4,
    documentation_ipv6,
    documentation_mac,
    ephemeral_port,
    plan_identifier,
    weighted_choice,
)
from .spec_loader import load_oracle_specs
# Importing the protocols package runs its ``autodiscover`` so every per-protocol
# sampler module self-registers; ``SAMPLER_REGISTRY`` is then consulted before the
# legacy sampling/feature branches below. No protocol is migrated yet, so the
# registry is empty and every layer falls through to the legacy code.
from .protocols import SAMPLER_REGISTRY


SUPPORTED_LAYER_BACKEND = "libcrafter"

_DERIVED_DOMAINS = {"derived"}
_IGMP_DOC_GROUP = "233.252.0.17"
_IGMP_DOC_GROUP_ALT = "233.252.0.61"
_IGMP_SSM_DOC_GROUP = "232.0.0.17"
_IGMP_DOC_SOURCE = "192.0.2.44"
_IGMP_BYTES_EMPTY: JSONObject = {"hex": ""}
_IGMP_BYTES_RAW: JSONObject = {"hex": "deadbeef"}
_IGMP_BYTES_PADDED_WORD: JSONObject = {"hex": "aabbccdd"}
_IGMP_BYTES_UNKNOWN_TYPE: JSONObject = {"hex": "756e6b6e"}
_IGMP_BYTES_UNSUPPORTED_ASSIGNED_TYPE: JSONObject = {"hex": "64766d72"}
_IGMP_BYTES_IGNORED_EXTRA: JSONObject = {"hex": "aabbccdd"}
_IGMP_BYTES_E_FLAG_CLEAR_EXTENSION: JSONObject = {"hex": "00000000"}

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
_SUPPORTED_FIELDS: dict[str, set[str]] = {
    "dhcp": {
        "op",
        "hardware_type",
        "hardware_length",
        "transaction_id",
        "flags",
        "client_ip",
        "your_ip",
        "client_hardware_address",
        "options",
    },
    "dot11": {
        "addr1",
        "addr2",
        "addr3",
        "addr4",
        "duration_id",
        "frame_control",
        "frame_type",
        "from_ds",
        "ht_control",
        "management_fixed_fields",
        "more_data",
        "more_fragments",
        "order",
        "payload",
        "power_management",
        "protected",
        "protocol_version",
        "qos_control",
        "retry",
        "sequence_control",
        "subtype",
        "tagged_parameters",
        "to_ds",
    },
    "dns": {
        "transaction_id",
        "is_response",
        "opcode",
        "flags",
        "response_code",
        "questions",
    },
    # IEEE 802.15.4 MAC frame fields the scapy Dot15d4FCS/Dot15d4Data
    # materializer and the libcrafter Dot15d4 decoder both round-trip. The MAC
    # carries an addressed data frame so scapy dispatches the payload into the
    # Zigbee NWK/APS sublayers (conf.dot15d4_protocol="zigbee"), matching the
    # libcrafter decode layer structure.
    "dot15d4": {
        "frame_type",
        "pan_id_compression",
        "dest_addr_mode",
        "src_addr_mode",
        "seq",
        "dest_pan",
        "dest_addr",
        "src_addr",
    },
    # The IEEE 802.15.4 TAP (DLT 283) pseudo-header carries no strict-byte
    # descriptor fields through the scapy reference path; libcrafter owns the
    # TAP decode, so no fields are sampled.
    "dot15d4_radio": set(),
    "zigbee_nwk": {
        "frame_type",
        "protocol_version",
        "dest",
        "src",
        "radius",
        "seq",
    },
    "zigbee_aps": {
        "frame_type",
        "delivery_mode",
        "dest_endpoint",
        "cluster",
        "profile",
        "src_endpoint",
        "counter",
    },
    "eapol": {
        "body_length",
        "descriptor_type",
        "key_data",
        "key_data_length",
        "key_id",
        "key_information",
        "key_iv",
        "key_length",
        "key_mic",
        "key_nonce",
        "key_rsc",
        "packet_type",
        "replay_counter",
        "version",
    },
    "ah": {
        "next_header",
        "payload_len",
        "reserved",
        "spi",
        "sequence",
        "icv",
    },
    "esp": {
        "spi",
        "sequence",
        "next_header",
        "pad_length",
        "iv",
        "icv",
    },
    "bgp": {"marker", "length", "type"},
    "rip": {"command", "version", "reserved"},
    "ripng": {"command", "version", "reserved"},
    "icmp": {
        "type",
        "code",
        "checksum",
        "identifier",
        "sequence",
        "rest_of_header",
        "gateway",
        "pointer",
        "next_hop_mtu",
        "originate_timestamp",
        "receive_timestamp",
        "transmit_timestamp",
        "address_mask",
        "router_addresses",
        "router_address_entry_size",
        "router_lifetime",
        "extension_bytes",
        "embedded_header",
    },
    "icmpv6": {"type", "code", "identifier", "sequence"},
    "ikev2": {
        "initiator_spi",
        "responder_spi",
        "next_payload",
        "version",
        "exchange_type",
        "flags",
        "message_id",
        "length",
    },
    # OSPFv2 common-header fields declared in specs/layers/ospf.yaml. The
    # per-type body (Hello/DD/LSR/LSU/LSAck neighbor and LSA lists) is injected
    # by _apply_ospf_behavior AFTER field sampling, mirroring the BGP body path,
    # so only the common-header fields appear here.
    "ospf": {
        "version",
        "type",
        "packet_length",
        "router_id",
        "area_id",
        "checksum",
        "autype",
        "authentication",
    },
    "radiotap": {
        "antenna",
        "channel_flags",
        "channel_frequency",
        "dbm_antenna_signal",
        "fcs_status",
        "flags",
        "length",
        "pad",
        "present_words",
        "rate",
        "rx_flags",
        "tx_flags",
        "unknown_fields",
        "version",
    },
    "rsn": {
        "akm_suites",
        "capabilities",
        "element_id",
        "group_cipher_suite",
        "group_management_cipher_suite",
        "length",
        "pairwise_cipher_suites",
        "pmkid_list",
        "trailing_bytes",
        "version",
    },
    "tcp": {
        "src_port",
        "dst_port",
        "sequence",
        "acknowledgement",
        "reserved",
        "flags",
        "window",
        "urgent_pointer",
        "options",
    },
    "udp": {"src_port", "dst_port", "checksum", "options"},
}


def _supported_fields(layer: str) -> frozenset[str] | set[str]:
    """Return the fields the generator samples for ``layer``.

    A migrated layer declares its field allowlist on its registered
    :class:`~.protocols.base.ProtocolSampler`; an unmigrated layer keeps it in the
    legacy ``_SUPPORTED_FIELDS`` table. Consulting the registry first lets the two
    coexist during the migration without changing which fields get sampled.
    """

    plugin = SAMPLER_REGISTRY.get(layer)
    if plugin is not None:
        return plugin.supported_fields
    return _SUPPORTED_FIELDS.get(layer, set())


_SUPPORTED_FIELD_DOMAINS: dict[tuple[str, str], set[object]] = {
    ("dns", "answers"): set(),
    ("icmp", "type"): {"echo_reply", "echo_request"},
    ("icmpv6", "type"): {"echo_reply", "echo_request"},
    ("ipv4", "options"): {
        "eol",
        "nop",
        "record_route",
        "loose_source_route",
        "timestamp",
        "traceroute",
        "generic",
    },
    ("tcp", "options"): {
        "eol",
        "nop",
        "mss",
        "window_scale",
        "sack_permitted",
        "sack_blocks",
        "timestamp",
        "mptcp",
        "fast_open",
        "edo",
        "generic",
    },
    ("udp", "checksum"): {"zero_ipv4"},
    ("udp", "options"): {
        "known",
        "ocs",
        "apc",
        "unknown_safe",
        "unknown_unsafe",
        "unsupported_frag",
        "surplus_application_boundary",
    },
}
# ICMP rest-of-header and type-specific body fields. The base layer sampler
# leaves these unset (echo query default); the live-matrix sampler fills exactly
# the fields a given ICMP behavior needs.
_ICMP_BODY_FIELDS = {
    "checksum",
    "rest_of_header",
    "gateway",
    "pointer",
    "next_hop_mtu",
    "originate_timestamp",
    "receive_timestamp",
    "transmit_timestamp",
    "address_mask",
    "router_addresses",
    "router_address_entry_size",
    "router_lifetime",
    "extension_bytes",
    "embedded_header",
}
_SCAPY_MATERIALIZED_LAYERS = {
    "arp",
    "dhcp",
    "dot11",
    "dot15d4",
    "dot15d4_radio",
    "eapol",
    "dns",
    "ethernet",
    "icmp",
    "icmpv6",
    "ipv4",
    "ipv6",
    "llc_snap",
    "ospf",
    "payload",
    "radiotap",
    "rsn",
    "tcp",
    "udp",
    "vlan",
    "bgp",
    "zigbee_aps",
    "zigbee_nwk",
}


def load_stack_grammar(path: str | Path | None = None) -> JSONObject:
    """Load the executable YAML specs as generator grammar."""

    spec_root = None if path is None else Path(path)
    specs = load_oracle_specs(spec_root)
    return {
        "version": 1,
        "roots": {
            root.name: {
                "layers": list(root.layers),
                "families": list(root.families),
            }
            for root in specs.roots.values()
        },
        "families": {
            family.name: {
                "stack": list(family.default_stack),
                "feature_tags": list(family.feature_tags),
            }
            for family in specs.families.values()
        },
        "stacks": {
            stack.name: {
                "name": stack.name,
                "root": stack.root,
                "layers": list(stack.layers),
                "coverage_cases": list(stack.coverage_cases),
                "families": _stack_families(stack.layers, specs.roots[stack.root].families),
            }
            for stack in specs.stacks.values()
        },
        "profiles": {
            profile.name: {
                "default_count": profile.default_count,
                "family_weights": [
                    {"name": weight.name, "weight": weight.weight}
                    for weight in profile.family_weights
                ],
                "payload_length": profile.payload_length.as_pair(),
                "feature_weights": dict(profile.feature_weights),
            }
            for profile in specs.profiles.values()
        },
        "layers": {
            layer.name: {
                "name": layer.name,
                "fields": [
                    _layer_field_grammar(layer.raw, field.name, field.field_type, field.required, field.domains)
                    for field in layer.fields
                ],
                "coverage_cases": list(layer.coverage_cases),
                "backend_support": {
                    name: {
                        "status": support.status,
                        "encode": support.encode,
                        "decode": support.decode,
                    }
                    for name, support in layer.backend_support.items()
                },
            }
            for layer in specs.layers.values()
        },
        "features": {
            feature.name: {
                "name": feature.name,
                "layers": list(feature.layers),
                "directions": list(feature.directions),
                "strict_bytes": feature.strict_bytes,
                "malformed": feature.malformed,
                "coverage_cases": list(feature.coverage_cases),
                "behaviors": list(_object_list(feature.raw.get("behaviors", []), "feature.behaviors")),
                "supported_cases": list(
                    _object_list(feature.raw.get("supported_cases", []), "feature.supported_cases")
                ),
                "live_matrix": list(_object_list(feature.raw.get("live_matrix", []), "feature.live_matrix")),
                "categories": _feature_categories(
                    feature.name,
                    feature.directions,
                    feature.malformed,
                    feature.coverage_cases,
                ),
            }
            for feature in specs.features.values()
        },
    }


def case_byte_policy_index(path: str | Path | None = None) -> dict[str, str]:
    """Map each declared supported case to its byte policy.

    Built from every feature's ``supported_cases`` block so other oracle modes
    (pcap eligibility in particular) can honor the same per-case byte policy the
    generator reads. Cases without a ``supported_cases`` entry are absent from
    the map; cases that declare no ``byte_policy`` are absent as well. The result
    is data-driven from the specs, never a hardcoded case list.
    """

    grammar = load_stack_grammar(path)
    features = grammar.get("features", {})
    index: dict[str, str] = {}
    if not isinstance(features, Mapping):
        return index
    for raw_feature in features.values():
        if not isinstance(raw_feature, Mapping):
            continue
        supported = raw_feature.get("supported_cases", [])
        if not isinstance(supported, Sequence) or isinstance(supported, (str, bytes)):
            continue
        for raw_case in supported:
            if not isinstance(raw_case, Mapping):
                continue
            name = raw_case.get("name")
            byte_policy = raw_case.get("byte_policy")
            if isinstance(name, str) and isinstance(byte_policy, str):
                index[name] = byte_policy
    return index


def _igmp_behavior_for_case(feature: str, case: str) -> str | None:
    cases = {
        "igmp_header": {
            "igmp-membership-query": "v1-query",
            "igmp-v2-membership-query": "v2-query",
            "igmp-v1-membership-report": "v1-membership-report",
            "igmp-v2-membership-report": "v2-membership-report",
            "igmp-v2-leave-group": "v2-leave-group",
            "igmp-checksum-explicit-invalid": "checksum-explicit",
            "igmp-unknown-type-raw": "unknown-type-raw",
            "igmp-unsupported-assigned-type-raw": "unsupported-assigned-type-raw",
        },
        "igmp_v3_query": {
            "igmp-v3-query-general": "general-query",
            "igmp-v3-query-group-specific": "group-specific-query",
            "igmp-v3-query-group-and-source-specific": "group-and-source-specific-query",
            "igmp-v3-query-source-count-override": "query-source-count-override",
            "igmp-v3-query-checksum-explicit-invalid": "checksum-explicit",
            "igmp-v3-query-ignored-extra-octets": "ignored-extra-query-octets",
        },
        "igmp_v3_report": {
            "igmp-v3-report-empty": "empty-report",
            "igmp-v3-report-include-record": "include-record",
            "igmp-v3-report-exclude-record": "exclude-record",
            "igmp-v3-report-source-list-change-records": "source-list-change-records",
            "igmp-v3-report-auxiliary-data-record": "auxiliary-data-record",
            "igmp-v3-report-unknown-record-type": "unknown-record-type",
            "igmp-v3-report-count-override": "report-count-override",
            "igmp-v3-report-checksum-explicit-invalid": "checksum-explicit",
        },
        "igmp_extensions": {
            "igmp-extension-query-noop": "query-noop-extension",
            "igmp-extension-report-noop-zero-length": "report-noop-extension",
            "igmp-extension-unassigned-type": "unassigned-extension-type",
            "igmp-extension-experimental-type": "experimental-extension-type",
            "igmp-extension-ordered-tlvs": "ordered-extension-tlvs",
            "igmp-extension-e-flag-clear-raw-tail": "e-flag-clear-extension-looking-bytes",
        },
        "igmp_mrd": {
            "igmp-mrd-advertisement": "multicast-router-advertisement",
            "igmp-mrd-solicitation": "multicast-router-solicitation",
            "igmp-mrd-termination": "multicast-router-termination",
            "igmp-mrd-explicit-checksum-invalid": "mrd-explicit-checksum",
            "igmp-mrd-reserved-override": "mrd-reserved-override",
        },
    }
    return cases.get(feature, {}).get(case)


def _igmp_feature_for_case(case: str) -> str | None:
    for feature in (
        "igmp_header",
        "igmp_v3_query",
        "igmp_v3_report",
        "igmp_extensions",
        "igmp_mrd",
    ):
        if _igmp_behavior_for_case(feature, case) is not None:
            return feature
    return None


def _layer_field_grammar(
    layer_raw: JSONObject,
    name: str,
    field_type: str,
    required: bool,
    domains: Sequence[object],
) -> JSONObject:
    output: JSONObject = {
        "name": name,
        "type": field_type,
        "required": required,
        "domains": list(domains),  # type: ignore[list-item]
    }
    raw_fields = layer_raw.get("fields", [])
    if isinstance(raw_fields, list):
        for raw_field in raw_fields:
            if not isinstance(raw_field, Mapping) or raw_field.get("name") != name:
                continue
            for key in ("profile_domains", "profiles", "sampling"):
                if key in raw_field:
                    output[key] = raw_field[key]  # type: ignore[assignment]
            break
    return output


class PacketGenerator:
    """Seeded packet plan generator independent of any backend."""

    def __init__(
        self,
        *,
        seed: int,
        profile: str,
        backend: str = "scapy",
        grammar: Mapping[str, object] | None = None,
    ) -> None:
        self.grammar = _json_object(load_stack_grammar() if grammar is None else grammar)
        profiles = _object(self.grammar.get("profiles"), "profiles")
        if profile not in profiles:
            raise ValueError(f"unsupported profile: {profile}")
        self.seed = seed
        self.profile = profile
        self.backend = backend

    def generate(
        self,
        *,
        index: int,
        root: str | None = None,
        family: str | None = None,
        case: str | None = None,
        feature: str | None = None,
        direction: str = "reference_to_libcrafter",
    ) -> PacketPlan:
        if index < 0:
            raise ValueError(f"index must be non-negative: {index}")

        rng = random.Random(
            _derive_seed(
                self.seed,
                self.profile,
                index,
                root,
                family,
                case,
                feature,
                direction,
            )
        )
        selected_stack = self._choose_stack(
            index=index,
            root=root,
            family=family,
            case=case,
            feature=feature,
            direction=direction,
        )
        stack_name = _string(selected_stack.get("name"), "stack.name")
        selected_root = _string(selected_stack.get("root"), f"stacks.{stack_name}.root")
        stack = _string_list(selected_stack.get("layers"), f"stacks.{stack_name}.layers")
        stack_families = _string_list(
            selected_stack.get("families", []),
            f"stacks.{stack_name}.families",
        )
        selected_family = self._selected_family(stack_families, family, stack)
        selected_case = case or self._choose_case(
            rng,
            selected_stack,
            feature,
            family=selected_family,
            direction=direction,
        )
        selected_feature = self._choose_feature(
            rng,
            stack=stack,
            case=selected_case,
            feature=feature,
            direction=direction,
        )
        if selected_feature is None:
            selected_feature = _igmp_feature_for_case(selected_case)
        strict_bytes = self._strict_bytes(selected_feature)
        feature_tags = self._feature_tags(
            stack=stack,
            family=selected_family,
            feature=selected_feature,
        )

        fields = self._fields(
            rng,
            stack,
            feature=selected_feature,
            case=selected_case,
        )
        behavior = self._feature_behavior(
            rng,
            feature=selected_feature,
            case=selected_case,
        )
        if behavior is not None:
            self._apply_feature_behavior(
                fields,
                stack=stack,
                feature=selected_feature,
                case=selected_case,
                behavior=behavior,
            )
        elif _is_bgp_smoke_case(selected_case) and "bgp" in fields:
            _apply_bgp_behavior(fields, stack=stack, case=selected_case, behavior="")
        elif _is_rip_smoke_case(selected_case) and "rip" in fields:
            _apply_rip_behavior(fields, stack=stack, case=selected_case, behavior="")
        elif _is_rip_smoke_case(selected_case) and "ripng" in fields:
            _apply_ripng_behavior(fields, stack=stack, case=selected_case, behavior="")
        elif _is_ospf_smoke_case(selected_case) and "ospf" in fields:
            _apply_ospf_behavior(fields, stack=stack, case=selected_case, behavior="")
        live_behavior = self._apply_icmp_live_fields(
            rng,
            fields,
            feature=selected_feature,
            case=selected_case,
        )
        if live_behavior is not None:
            behavior = live_behavior
        feature_tags = self._augment_feature_tags(
            feature_tags,
            feature=selected_feature,
            case=selected_case,
            behavior=behavior,
        )
        feature_metadata = self._feature_metadata(
            fields,
            stack=stack,
            feature=selected_feature,
            case=selected_case,
            behavior=behavior,
        )
        malformed = self._is_malformed_case(selected_feature, selected_case)
        if malformed:
            strict_bytes = False
            feature_tags = list(dict.fromkeys([*feature_tags, "malformed", "non_strict_reencode"]))
        plan_id = plan_identifier(
            seed=self.seed,
            profile=self.profile,
            index=index,
            root=selected_root,
            stack_name=stack_name,
            family=selected_family,
            case=selected_case,
            feature=selected_feature,
        )
        reproduction = {
            "seed": self.seed,
            "profile": self.profile,
            "index": index,
            "count": 1,
            "root": selected_root,
            "family": selected_family,
            "case": selected_case,
            "feature": selected_feature,
            "direction": direction,
        }

        selected_specs = [
            "tools/oracle/specs/stacks.yaml",
            "tools/oracle/specs/profiles.yaml",
            f"root:{selected_root}",
            f"stack:{stack_name}",
            f"case:{selected_case}",
        ]
        if selected_feature is not None:
            selected_specs.append(f"feature:{selected_feature}")

        return PacketPlan(
            stack=stack,
            fields=fields,
            profile=self.profile,
            seed=self.seed,
            index=index,
            direction=direction,
            family=selected_family,
            feature_tags=feature_tags,
            case=selected_case,
            strict_bytes=strict_bytes,
            metadata={
                "plan_id": plan_id,
                "generator": "oracle.seeded.v1",
                "root": selected_root,
                "root_decoder": selected_root,
                "stack_name": stack_name,
                "stack_families": stack_families,
                "feature": selected_feature,
                "feature_behavior": behavior,
                "malformed": malformed,
                **feature_metadata,
                "selected_specs": selected_specs,
                "strict_bytes": strict_bytes,
                "comparison_policy": "non_strict_reencode" if malformed else "strict_reencode",
                "reproduction": reproduction,
            },
        )

    def _choose_stack(
        self,
        *,
        index: int,
        root: str | None,
        family: str | None,
        case: str | None,
        feature: str | None,
        direction: str,
    ) -> JSONObject:
        candidates = self._stack_candidates(
            root=root,
            family=family,
            case=case,
            feature=feature,
            direction=direction,
        )
        if not candidates:
            detail = []
            if root is not None:
                detail.append(f"root={root!r}")
            if family is not None:
                detail.append(f"family={family!r}")
            if case is not None:
                detail.append(f"case={case!r}")
            if feature is not None:
                detail.append(f"feature={feature!r}")
            joined = " ".join(detail) or "current filters"
            raise ValueError(f"no stack specs match {joined}")

        deck = self._stack_deck(candidates)
        if not deck:
            raise ValueError("no stack specs have positive sampling weight")
        return deck[index % len(deck)]

    def _stack_candidates(
        self,
        *,
        root: str | None,
        family: str | None,
        case: str | None,
        feature: str | None,
        direction: str,
    ) -> list[JSONObject]:
        roots = _object(self.grammar.get("roots"), "roots")
        if root is not None and root not in roots:
            raise ValueError(f"unsupported root: {root}")

        families = _object(self.grammar.get("families"), "families")
        profile_family_names = set(self._family_weights())
        if family is not None and family not in families and family not in profile_family_names:
            all_families = {
                item
                for stack in _object(self.grammar.get("stacks"), "stacks").values()
                for item in _string_list(
                    _object(stack, "stack").get("families", []),
                    "stack.families",
                )
            }
            if family not in all_families:
                raise ValueError(f"unsupported family: {family}")

        feature_spec = self._feature_spec(feature) if feature is not None else None
        stacks = _object(self.grammar.get("stacks"), "stacks")
        candidates: list[JSONObject] = []
        for raw_stack in stacks.values():
            stack = _object(raw_stack, "stack")
            stack_layers = _string_list(stack.get("layers"), "stack.layers")
            stack_root = _string(stack.get("root"), "stack.root")
            stack_families = _string_list(stack.get("families", []), "stack.families")
            coverage_cases = _string_list(
                stack.get("coverage_cases", []),
                "stack.coverage_cases",
            )

            if root is not None and stack_root != root:
                continue
            if family is not None and family not in stack_families:
                continue
            if case is not None and case not in coverage_cases:
                continue
            if feature_spec is not None:
                feature_layers = _string_list(feature_spec.get("layers"), "feature.layers")
                feature_directions = _string_list(
                    feature_spec.get("directions"),
                    "feature.directions",
                )
                if not _layers_cover_feature(stack_layers, feature_layers):
                    continue
                if direction not in feature_directions and "roundtrip" not in feature_directions:
                    continue
            if (
                feature is None
                and case is None
                and root is None
                and family is None
                and self.profile == "smoke"
            ):
                if stack_layers not in (
                    ["ipv4", "udp", "payload"],
                    ["ipv6", "udp", "payload"],
                    ["ble_radio", "ble_adv"],
                ):
                    continue
            if (
                feature is None
                and case is None
                and root is None
                and family is None
                and self.profile in {
                    "dot11-smoke",
                    "radiotap-smoke",
                    "dot11-pcap",
                    "eapol-smoke",
                    "rsn-smoke",
                    "bgp-smoke",
                    "ospf-smoke",
                    *_IPSEC_SMOKE_PROFILES,
                }
            ):
                profile_families = set(profile_family_names)
                if not profile_families.intersection(stack_families):
                    continue
            if feature is None and case is None and self.profile == "smoke" and "dhcp" in stack_layers:
                continue
            if (
                feature is None
                and case is None
                and self.profile == "tcp-header"
                and not _has_tcp_header_case(coverage_cases)
            ):
                continue
            if (
                feature is None
                and case is None
                and self.profile == "tcp-options"
                and not _has_tcp_options_case(coverage_cases)
            ):
                continue
            if (
                feature is None
                and case is None
                and self.profile == "tcp-smoke"
                and not _has_tcp_smoke_case(coverage_cases)
            ):
                continue
            if (
                feature is None
                and case is None
                and self.profile == "bgp-smoke"
                and not _has_bgp_smoke_case(coverage_cases)
            ):
                continue
            if (
                feature is None
                and case is None
                and self.profile == "rip-smoke"
                and not _has_rip_smoke_case(coverage_cases)
            ):
                continue
            if (
                feature is None
                and case is None
                and self.profile == "ospf-smoke"
                and not _has_ospf_smoke_case(coverage_cases)
            ):
                continue
            if (
                feature is None
                and case is None
                and self.profile == "ipv4-enrichment"
                and not _has_ipv4_enrichment_case(coverage_cases, self.grammar)
            ):
                continue
            if (
                feature is None
                and case is None
                and self.profile == "ipv6-enrichment"
                and not _has_ipv6_enrichment_case(coverage_cases)
            ):
                continue
            if (
                feature is None
                and case is None
                and self.profile in _IP_FRAGMENT_SMOKE_PROFILES
                and not _has_ip_fragment_smoke_case(coverage_cases)
            ):
                continue
            candidates.append(stack)
        return candidates

    def _stack_deck(self, stacks: Sequence[JSONObject]) -> list[JSONObject]:
        if self.profile == "ipv6-enrichment":
            deck: list[JSONObject] = []
            for stack in stacks:
                coverage_cases = _string_list(
                    stack.get("coverage_cases", []),
                    "stack.coverage_cases",
                )
                for case in coverage_cases:
                    if not _is_ipv6_enrichment_case(case):
                        continue
                    deck.append({**stack, "coverage_cases": [case]})
            if deck:
                return deck
        if self.profile in _IP_FRAGMENT_SMOKE_PROFILES:
            deck = []
            for stack in stacks:
                coverage_cases = _string_list(
                    stack.get("coverage_cases", []),
                    "stack.coverage_cases",
                )
                for case in coverage_cases:
                    if not _is_ip_fragment_smoke_case(case):
                        continue
                    deck.append({**stack, "coverage_cases": [case]})
            if deck:
                return deck

        weighted: list[JSONObject] = []
        for stack in stacks:
            weight = self._stack_weight(stack)
            weighted.extend([stack] * weight)

        seed = _derive_deck_seed(
            self.seed,
            self.profile,
            [_string(stack.get("name"), "stack.name") for stack in stacks],
        )
        rng = random.Random(seed)
        rng.shuffle(weighted)
        return weighted

    def _stack_weight(self, stack: JSONObject) -> int:
        family_weights = self._family_weights()
        feature_weights = self._profile_feature_weights()
        stack_families = _string_list(stack.get("families", []), "stack.families")
        coverage_cases = _string_list(stack.get("coverage_cases", []), "stack.coverage_cases")
        weight = sum(family_weights.get(family, 0) for family in stack_families)
        if weight <= 0:
            weight = 1

        categories = _case_categories(coverage_cases)
        category_weight = max((feature_weights.get(category, 0) for category in categories), default=1)
        return max(1, weight * max(1, category_weight))

    def _family_weights(self) -> dict[str, int]:
        profiles = _object(self.grammar.get("profiles"), "profiles")
        profile_spec = _object(profiles.get(self.profile), f"profiles.{self.profile}")
        raw_weights = profile_spec.get("family_weights")
        if raw_weights is None:
            raise ValueError(f"profiles.{self.profile}.family_weights is required")

        weights: dict[str, int] = {}
        if not isinstance(raw_weights, Sequence) or isinstance(raw_weights, (str, bytes)):
            raise ValueError("family_weights must be a list")
        for item in raw_weights:
            item_obj = _object(item, "family_weights item")
            name = item_obj.get("name")
            weight = item_obj.get("weight")
            if not isinstance(name, str) or not isinstance(weight, int):
                raise ValueError("family_weights entries require string name and integer weight")
            weights[name] = weight
        return weights

    def _profile_feature_weights(self) -> dict[str, int]:
        profiles = _object(self.grammar.get("profiles"), "profiles")
        profile_spec = _object(profiles.get(self.profile), f"profiles.{self.profile}")
        raw_weights = _object(profile_spec.get("feature_weights"), "feature_weights")
        weights: dict[str, int] = {}
        for name, weight in raw_weights.items():
            if not isinstance(weight, int):
                raise ValueError("feature_weights entries must be integers")
            weights[name] = weight
        return weights

    def _selected_family(
        self,
        stack_families: Sequence[str],
        requested_family: str | None,
        stack: Sequence[str],
    ) -> str:
        if requested_family is not None:
            return requested_family
        family_weights = self._family_weights()
        for family in family_weights:
            if family in stack_families:
                return family
        if stack_families:
            return stack_families[0]
        for layer in stack:
            if layer in {"ipv4", "ipv6", "arp", "dns", "dhcp"}:
                return layer
        return "link"

    def _feature_tags(
        self,
        *,
        stack: Sequence[str],
        family: str,
        feature: str | None,
    ) -> list[str]:
        tags = ["baseline", family, *stack]
        if feature is not None:
            tags.append(feature)
            tags.extend(self._feature_categories(feature))
        return list(dict.fromkeys(tags))

    def _augment_feature_tags(
        self,
        tags: Sequence[str],
        *,
        feature: str | None,
        case: str,
        behavior: str | None,
    ) -> list[str]:
        output = list(tags)
        if feature == "udp_options":
            output.extend(_udp_option_feature_tags(case, behavior))
        return list(dict.fromkeys(output))

    def _feature_metadata(
        self,
        fields: Mapping[str, JSONObject],
        *,
        stack: Sequence[str],
        feature: str | None,
        case: str,
        behavior: str | None,
    ) -> JSONObject:
        if feature == "udp_options":
            return {
                "udp_options": _udp_options_metadata(
                    fields,
                    stack=stack,
                    case=case,
                    behavior=behavior,
                )
            }
        return {}

    def _choose_case(
        self,
        rng: random.Random,
        stack: JSONObject,
        feature: str | None,
        *,
        family: str | None,
        direction: str,
    ) -> str:
        coverage_cases = _string_list(stack.get("coverage_cases", []), "stack.coverage_cases")
        if feature is None and self.profile == "ipv4-enrichment":
            # Focused IPv4 profile: restrict to the IPv4 layer's declared
            # enrichment cases so the run stays data-driven from layers/ipv4.yaml.
            coverage_cases = _ipv4_enrichment_cases(coverage_cases, self.grammar)
        if feature is None and self.profile == "tcp-header":
            # Focused profile: restrict the stack's own coverage cases to the
            # tcp_header set so case selection never falls through to the other
            # cases (ipv4-tcp-syn, tcp-options*) the IPv4/IPv6 TCP stacks declare.
            coverage_cases = [case for case in coverage_cases if _has_tcp_header_case([case])]
        if feature is None and self.profile == "tcp-options":
            # Focused profile: restrict to the tcp-option-* single-option cases so
            # case selection never falls through to the broad option-list cases
            # (ipv4-tcp-syn, tcp-options, tcp-header-*) the TCP stacks declare.
            coverage_cases = [case for case in coverage_cases if _has_tcp_options_case([case])]
        if feature is None and self.profile == "tcp-smoke":
            # Representative TCP smoke set: restrict to the union of the focused
            # tcp-header-* and tcp-option-* cases so case selection stays on TCP
            # behavior and never falls through to unrelated cases.
            coverage_cases = [case for case in coverage_cases if _has_tcp_smoke_case([case])]
        if feature is None and self.profile == "bgp-smoke":
            # Focused BGP smoke set: keep case selection on BGP message cases so
            # a default/raw payload case is never paired with a BGP stack.
            coverage_cases = [case for case in coverage_cases if _is_bgp_smoke_case(case)]
        if feature is None and self.profile == "rip-smoke":
            # Focused RIP/RIPng smoke set: keep case selection on the RIP and
            # RIPng message cases so a default/raw payload case is never paired
            # with a RIP/RIPng stack.
            coverage_cases = [case for case in coverage_cases if _is_rip_smoke_case(case)]
        if feature is None and self.profile == "ospf-smoke":
            # Focused OSPF smoke set: keep case selection on the five OSPFv2
            # packet-type cases so a default/raw payload case is never paired
            # with the ipv4/ospf stack.
            coverage_cases = [case for case in coverage_cases if _is_ospf_smoke_case(case)]
        if feature is None and self.profile == "ipv6-enrichment":
            # Focused IPv6 enrichment profile: restrict to stack-declared
            # base/unknown-next-header and strict-byte extension cases. This
            # avoids the generic feature expansion below, which is too broad for
            # extension chains because any ipv6_routing stack can otherwise draw
            # cases whose terminal layer belongs to a different stack.
            coverage_cases = [case for case in coverage_cases if _is_ipv6_enrichment_case(case)]
        if feature is None and self.profile in _IP_FRAGMENT_SMOKE_PROFILES:
            # Focused fragmentation profile: keep case selection on the stack's
            # own pcap-eligible fragment cases. Transform feature contract cases
            # are many-record stream cases and must not be paired with unrelated
            # packet stacks by the generic feature expansion below.
            coverage_cases = [case for case in coverage_cases if _is_ip_fragment_smoke_case(case)]
        if feature is not None:
            feature_spec = self._feature_spec(feature)
            feature_cases = _string_list(feature_spec.get("coverage_cases"), "feature.coverage_cases")
            matching = [
                case
                for case in coverage_cases
                if case in feature_cases and self._case_supported_in_direction(case, direction)
            ]
            if matching:
                return weighted_choice(rng, tuple((case, 1) for case in matching))
            compatible = self._compatible_feature_cases(
                stack=_string_list(stack.get("layers"), "stack.layers"),
                feature=feature,
                direction=direction,
            )
            if compatible:
                return weighted_choice(rng, tuple((case, 1) for case in compatible))
        if not coverage_cases:
            coverage_cases = []

        choices: list[tuple[str, int]] = []
        for stack_case in coverage_cases:
            if not self._case_supported_in_direction(stack_case, direction):
                continue
            weight = self._case_weight(stack_case, categories=_case_categories([stack_case]))
            if weight > 0:
                choices.append((stack_case, weight))
        stack_layers = _string_list(stack.get("layers"), "stack.layers")
        # Focused tcp-header profile: select only from the stack's declared
        # tcp-header coverage cases (filtered above) so an IPv4-checksum case is
        # never drawn for the IPv6 stack and vice versa. The cross-feature case
        # expansion below is intentionally skipped for this profile.
        if feature is None and self.profile == "tcp-header":
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        # Focused tcp-options profile: same discipline for the tcp-option-* cases.
        # The cross-feature case expansion below is skipped so only the focused
        # single-option cases are drawn.
        if feature is None and self.profile == "tcp-options":
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        # tcp-smoke profile: select only from the union of the tcp-header-* and
        # tcp-option-* coverage cases (filtered above) so the smoke run stays on
        # TCP behavior. The cross-feature case expansion below is skipped.
        if feature is None and self.profile == "tcp-smoke":
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        # bgp-smoke profile: select only from stack-declared BGP message cases
        # and skip the generic cross-feature expansion below.
        if feature is None and self.profile == "bgp-smoke":
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        # rip-smoke profile: select only from stack-declared RIP/RIPng message
        # cases and skip the generic cross-feature expansion below.
        if feature is None and self.profile == "rip-smoke":
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        # ospf-smoke profile: select only from the stack-declared OSPFv2 packet
        # cases and skip the generic cross-feature expansion below so an
        # unrelated case is never paired with the ipv4/ospf stack.
        if feature is None and self.profile == "ospf-smoke":
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        # ipv4-enrichment profile: the stack was pre-filtered to IPv4 layer
        # enrichment cases, and cross-feature expansion is skipped so unrelated
        # features that happen to ride IPv4 stacks cannot enter the sample.
        if feature is None and self.profile == "ipv4-enrichment":
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        # Focused IPv6 enrichment profile: select only from the stack's declared
        # enrichment cases. The cross-feature case expansion below intentionally
        # stays disabled so routing/TCP/ICMPv6 terminal chains remain aligned
        # with their declared stack shapes.
        if feature is None and self.profile == "ipv6-enrichment":
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        # Focused fragmentation smoke profile: select only stack-declared
        # fragment cases so dry-run plans stay packet-shape consistent.
        if feature is None and self.profile in _IP_FRAGMENT_SMOKE_PROFILES:
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        if (
            feature is None
            and self.profile == "smoke"
            and stack_layers == ["ble_radio", "ble_adv"]
        ):
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        if feature is None and self.profile in {
            "dot11-smoke",
            "radiotap-smoke",
            "dot11-pcap",
            "eapol-smoke",
            "rsn-smoke",
        }:
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        # Focused IPSec smoke profiles: select only from the stack's own declared
        # ESP/AH/IKEv2 coverage cases. The cross-feature case expansion below is
        # skipped so an unrelated case (DNS, fragment, pcap, ...) is never paired
        # with an ESP/AH/IKEv2 stack.
        if feature is None and self.profile in _IPSEC_SMOKE_PROFILES:
            if not choices:
                return "default"
            return weighted_choice(rng, choices)
        for feature_name, feature_spec in self._matching_features_for_stack(
            stack=stack_layers,
            direction=direction,
        ):
            if family == "udp" and feature_name != "udp_options":
                continue
            categories = _string_list(feature_spec.get("categories", []), "feature.categories")
            for feature_case in self._compatible_feature_cases(
                stack=stack_layers,
                feature=feature_name,
                direction=direction,
            ):
                if feature_case in coverage_cases:
                    continue
                if not self._case_supported_in_direction(feature_case, direction):
                    continue
                weight = self._case_weight(
                    feature_case,
                    categories=[*categories, *_case_categories([feature_case])],
                )
                if weight > 0:
                    choices.append((feature_case, weight))
        if not choices:
            return "default"
        return weighted_choice(rng, choices)

    def _choose_feature(
        self,
        rng: random.Random,
        *,
        stack: Sequence[str],
        case: str,
        feature: str | None,
        direction: str,
    ) -> str | None:
        if feature is not None:
            return feature

        matches = self._matching_features(stack=stack, case=case, direction=direction)
        if not matches:
            return None
        feature_weights = self._profile_feature_weights()
        choices: list[tuple[str, int]] = []
        for name, spec in matches:
            categories = _string_list(spec.get("categories", []), "feature.categories")
            weight = max((feature_weights.get(category, 0) for category in categories), default=0)
            if weight > 0:
                choices.append((name, weight))
        if not choices:
            return None
        return weighted_choice(rng, choices)

    def _matching_features(
        self,
        *,
        stack: Sequence[str],
        case: str,
        direction: str,
    ) -> list[tuple[str, JSONObject]]:
        features = _object(self.grammar.get("features", {}), "features")
        output: list[tuple[str, JSONObject]] = []
        for name, feature in self._matching_features_for_stack(stack=stack, direction=direction):
            cases = _string_list(
                feature.get("coverage_cases", []),
                f"features.{name}.coverage_cases",
            )
            if case not in cases:
                continue
            output.append((name, feature))
        return output

    def _matching_features_for_stack(
        self,
        *,
        stack: Sequence[str],
        direction: str,
    ) -> list[tuple[str, JSONObject]]:
        features = _object(self.grammar.get("features", {}), "features")
        output: list[tuple[str, JSONObject]] = []
        for name, raw_feature in features.items():
            if not _auto_sample_feature(name):
                continue
            # The tcp-header profile is a focused offline run: only the
            # tcp_header feature is auto-sampled so the seeded selection stays on
            # the TCP header cases instead of mixing in tcp_options or other
            # features that also ride the IPv4/IPv6 TCP stacks.
            if self.profile == "tcp-header" and name != "tcp_header":
                continue
            # The tcp-options profile is the analogous focused run: only the
            # tcp_options feature is auto-sampled so the seeded selection stays on
            # the focused single-option cases.
            if self.profile == "tcp-options" and name != "tcp_options":
                continue
            # The tcp-smoke profile is the representative TCP smoke run: both the
            # tcp_header and tcp_options features are auto-sampled so the seeded
            # selection materializes a mix of TCP header and TCP option cases
            # without mixing in unrelated features.
            if self.profile == "tcp-smoke" and name not in ("tcp_header", "tcp_options"):
                continue
            # The BGP smoke profile auto-samples only BGP feature specs, keeping
            # pcap/IPsec/fragment features off the BGP TCP stacks.
            if self.profile == "bgp-smoke" and not name.startswith("bgp_"):
                continue
            # The RIP smoke profile auto-samples only RIP/RIPng feature specs
            # (rip_header, rip_entries, rip_auth, ripng_header, ripng_rtes),
            # keeping pcap/IPsec/fragment features off the RIP/RIPng UDP stacks.
            if self.profile == "rip-smoke" and not name.startswith("rip"):
                continue
            # The OSPF smoke profile materializes the OSPFv2 body through the
            # smoke-case path (_apply_ospf_behavior), not the feature path: the
            # Scapy reference backend builds the body from the ospf body fields,
            # not from an ospf_* feature materialization. Keep every feature out
            # of the automatic sampler so the case stays feature-less and the
            # smoke body injection drives the packet.
            if self.profile == "ospf-smoke":
                continue
            # IGMP profiles are IPv4-only packet-layer runs. Keep the automatic
            # feature sampler on IGMP specs so unrelated IPv4 features never
            # attach to the ipv4/igmp stack.
            if self.profile.startswith("igmp-") and not name.startswith("igmp_"):
                continue
            # The IPv4 enrichment profile auto-samples only the IPv4 option
            # feature; all non-option IPv4 layer cases remain plain header cases.
            if self.profile == "ipv4-enrichment" and name != "ipv4_options":
                continue
            # The ipv6-enrichment profile is a focused offline run over the
            # IPv6 fragment/routing feature plus plain IPv6 base-header cases.
            # Keep other IPv6-adjacent features (UDP/TCP/pcap/live) out of the
            # automatic feature sampler for reproducibility.
            if self.profile == "ipv6-enrichment" and name != "ipv6_fragment_routing":
                continue
            # The fragmentation smoke profile keeps generated packet cases on
            # IP fragment behavior; pcap itself is selected by pcap mode later.
            if self.profile in _IP_FRAGMENT_SMOKE_PROFILES and name not in (
                "ip_fragment_transforms",
                "ipv6_fragment_routing",
            ):
                continue
            feature = _object(raw_feature, f"features.{name}")
            layers = _string_list(feature.get("layers"), f"features.{name}.layers")
            directions = _string_list(feature.get("directions"), f"features.{name}.directions")
            if not _layers_cover_feature(stack, layers):
                continue
            if direction not in directions and "roundtrip" not in directions:
                continue
            output.append((name, feature))
        return output

    def _compatible_feature_cases(
        self,
        *,
        stack: Sequence[str],
        feature: str,
        direction: str,
    ) -> list[str]:
        feature_spec = self._feature_spec(feature)
        layers = _string_list(feature_spec.get("layers"), "feature.layers")
        directions = _string_list(feature_spec.get("directions"), "feature.directions")
        if not _layers_cover_feature(stack, layers):
            return []
        if direction not in directions and "roundtrip" not in directions:
            return []
        cases = _string_list(feature_spec.get("coverage_cases", []), "feature.coverage_cases")
        if feature == "ipv6_fragment_routing":
            return _ipv6_extension_cases_for_stack(stack, cases)
        if feature == "udp_options":
            return _udp_option_cases_for_stack(stack, cases)
        return cases

    def _case_weight(self, case: str, *, categories: Sequence[str]) -> int:
        weights = self._profile_feature_weights()
        normalized = [*categories]
        if _is_malformed_case_name(case):
            normalized.append("malformed")
        return max((weights.get(category, 0) for category in normalized), default=0)

    def _strict_bytes(self, feature: str | None) -> bool:
        if feature is None:
            return True
        feature_spec = self._feature_spec(feature)
        strict_bytes = feature_spec.get("strict_bytes")
        if not isinstance(strict_bytes, bool):
            raise ValueError(f"features.{feature}.strict_bytes must be a boolean")
        return strict_bytes

    def _feature_spec(self, feature: str | None) -> JSONObject:
        if feature is None:
            raise ValueError("feature is required")
        features = _object(self.grammar.get("features"), "features")
        if feature not in features:
            raise ValueError(f"unsupported feature: {feature}")
        return _object(features[feature], f"features.{feature}")

    def _feature_categories(self, feature: str) -> list[str]:
        feature_spec = self._feature_spec(feature)
        return _string_list(feature_spec.get("categories", []), f"features.{feature}.categories")

    def _supported_case_index(self) -> dict[str, JSONObject]:
        """Map each declared supported case to its directions and byte policy.

        Built from every feature's ``supported_cases`` block so case selection
        can honor the per-case ``directions`` and ``byte_policy`` contract that
        the feature specs declare. Cases without a ``supported_cases`` entry are
        absent from the map and keep the historical sampling behavior.
        """

        cached = getattr(self, "_supported_case_index_cache", None)
        if cached is not None:
            return cached
        index: dict[str, JSONObject] = {}
        features = _object(self.grammar.get("features", {}), "features")
        for feature_name, raw_feature in features.items():
            feature_spec = _object(raw_feature, f"features.{feature_name}")
            supported = _object_list(
                feature_spec.get("supported_cases", []),
                f"features.{feature_name}.supported_cases",
            )
            for raw_case in supported:
                if not isinstance(raw_case, Mapping):
                    continue
                name = raw_case.get("name")
                if not isinstance(name, str):
                    continue
                directions = _string_list(
                    raw_case.get("directions", []),
                    f"features.{feature_name}.supported_cases.{name}.directions",
                )
                byte_policy = raw_case.get("byte_policy")
                index[name] = {
                    "directions": list(directions),
                    "byte_policy": byte_policy if isinstance(byte_policy, str) else None,
                }
        self._supported_case_index_cache = index  # type: ignore[attr-defined]
        return index

    def _case_supported_in_direction(self, case: str, direction: str) -> bool:
        """Return whether ``case`` may be generated for ``direction``.

        A case that declares ``supported_cases`` directions is excluded from a
        direction it does not list, and any ``structured_error`` case is excluded
        from offline encode/decode sampling entirely (the oracle has no offline
        malformed comparison pathway). Undeclared cases keep the prior behavior.
        """

        entry = self._supported_case_index().get(case)
        if entry is None:
            return True
        if entry.get("byte_policy") == "structured_error":
            return False
        directions = entry.get("directions") or []
        if not directions:
            return True
        return direction in directions or "roundtrip" in directions

    def _family_spec(self, family: str) -> JSONObject:
        families = _object(self.grammar.get("families"), "families")
        return _object(families.get(family), f"families.{family}")

    def _payload_bounds(self) -> tuple[int, int]:
        profiles = _object(self.grammar.get("profiles"), "profiles")
        profile_spec = _object(profiles.get(self.profile), f"profiles.{self.profile}")
        value = profile_spec.get("payload_length")
        if value is None:
            raise ValueError(f"profiles.{self.profile}.payload_length is required")
        if (
            not isinstance(value, Sequence)
            or isinstance(value, (str, bytes))
            or len(value) != 2
            or not isinstance(value[0], int)
            or not isinstance(value[1], int)
        ):
            raise ValueError("payload_length must be a two-integer list")
        return value[0], value[1]

    def _layer_spec(self, layer: str) -> JSONObject:
        layers = _object(self.grammar.get("layers"), "layers")
        if layer not in layers:
            raise ValueError(f"spec error: no layer spec declares {layer}")
        return _object(layers[layer], f"layers.{layer}")

    def _fields(
        self,
        rng: random.Random,
        stack: Sequence[str],
        *,
        feature: str | None,
        case: str,
    ) -> dict[str, JSONObject]:
        payload_min, payload_max = self._payload_bounds()
        ctx = _SamplingContext(
            rng=rng,
            profile=self.profile,
            feature_weights=self._profile_feature_weights(),
            stack=list(stack),
            payload_min=payload_min,
            payload_max=payload_max,
            feature=feature,
            case=case,
        )

        fields: dict[str, JSONObject] = {}
        for layer in stack:
            if layer == "ipv6_fragment":
                sampled = {
                    "next_header": _ipv6_next_header_for_stack(stack, "ipv6_fragment"),
                    "fragment_offset": 0,
                    "more_fragments": False,
                    "identification": bounded_int(rng, 0, (1 << 32) - 1),
                }
            elif layer == "ipv6_hop_by_hop":
                sampled = {
                    "next_header": _ipv6_next_header_for_stack(stack, "ipv6_hop_by_hop"),
                    "options": _ipv6_extension_options_for_case(layer, case),
                }
            elif layer == "ipv6_destination_options":
                sampled = {
                    "next_header": _ipv6_next_header_for_stack(stack, "ipv6_destination_options"),
                    "options": _ipv6_extension_options_for_case(layer, case),
                }
            elif layer == "ipv6_routing":
                sampled = {
                    "next_header": _ipv6_next_header_for_stack(stack, "ipv6_routing"),
                    "type": 0,
                    "segments_left": 0,
                }
            elif layer == "payload" and ("bgp" in stack or "ospf" in stack):
                sampled = {"hex": "", "length": 0}
            else:
                spec = self._layer_spec(layer)
                self._validate_layer_backend_support(layer, spec)
                sampled = self._sample_layer_fields(ctx, layer, spec)
                self._validate_sampled_fields(layer, spec, sampled)
                if layer in _IPSEC_CRYPTO_LAYERS:
                    # Attach the pinned key/salt/IV crypto material AFTER field
                    # validation (it is not a declared layer field). This is the
                    # determinism seam: both backends seal ESP/AH and the IKEv2
                    # SK payload with these identical inputs so ciphertext and ICV
                    # are byte-reproducible. The block also guarantees the
                    # esp/ah/ikev2 layer is always present in the plan even when
                    # every sampled field is derived/skipped.
                    sampled = dict(sampled)
                    sampled["crypto"] = _ipsec_pinned_crypto()
            if sampled:
                fields[layer] = sampled
                ctx.sampled_layers[layer] = sampled

        # Post-sample hook: after every layer is sampled, give each stack layer's
        # plugin a chance to run an ordered post-sampling step (this will host the
        # IPsec pinned-crypto injection above once esp/ah/ikev2 migrate, preserving
        # its "after field sampling" ordering). Iterating in stack order keeps any
        # cross-layer ordering stable. The registry is empty today, so this is a
        # no-op and the legacy in-loop IPsec injection above still runs.
        for layer in stack:
            plugin = SAMPLER_REGISTRY.get(layer)
            if plugin is not None and plugin.post_sample is not None:
                plugin.post_sample(fields, stack=stack, case=case)

        return fields

    def _feature_behavior(
        self,
        rng: random.Random,
        *,
        feature: str | None,
        case: str,
    ) -> str | None:
        if feature is None:
            return None
        feature_spec = self._feature_spec(feature)
        behaviors = _object_list(feature_spec.get("behaviors", []), f"features.{feature}.behaviors")
        names = [
            _string(behavior.get("name"), f"features.{feature}.behaviors.name")
            for behavior in behaviors
            if isinstance(behavior, Mapping) and isinstance(behavior.get("name"), str)
        ]
        if not names:
            return None
        if feature.startswith("igmp_"):
            mapped = _igmp_behavior_for_case(feature, case)
            if mapped in names:
                return mapped
        case_id = _identifier_part(case)
        case_key = f"-{case_id}-"
        if feature == "tcp_header":
            # tcp_header cases are named tcp-header-<behavior>; match the behavior
            # whose id is the exact case suffix so tcp-header-syn-ack selects the
            # syn-ack behavior rather than the shorter syn substring match.
            suffix = case_id[len("tcp-header-"):] if case_id.startswith("tcp-header-") else case_id
            for name in names:
                if _identifier_part(name) == suffix:
                    return name
        if feature == "tcp_options":
            # Focused single-option cases are named tcp-option-<behavior>; match
            # the behavior whose id is the exact case suffix so tcp-option-sack
            # selects the sack behavior rather than the longer sack-permitted /
            # advanced-generic substring matches. Broad option-list cases
            # (tcp-options*, tcp-all-flags-reserved-offset) keep the existing
            # substring matching below and never select a focused behavior.
            if case_id.startswith("tcp-option-"):
                suffix = case_id[len("tcp-option-"):]
                for name in names:
                    if _identifier_part(name) == suffix:
                        return name
            else:
                names = [name for name in names if not _is_focused_tcp_option_behavior(name)]
        for name in names:
            name_id = _identifier_part(name)
            if feature == "udp_options":
                if f"-{name_id}-" in case_key:
                    return name
            elif name_id in case_id:
                return name
        # No behavior identifier is a substring of the case id, so fall back to a
        # deterministic weighted pick. Drop any DNS behavior that would emit a raw
        # compressed-bytes spec the libcrafter materializer cannot encode, unless
        # the case id itself opts into the raw path. This keeps a typed case such
        # as dns-record-txt from being materialized through the name-records
        # compressed raw builder in the libcrafter_to_reference direction.
        if feature == "dns_behavior":
            typed = [name for name in names if not _dns_behavior_emits_raw(case, name)]
            if typed:
                names = typed
        return weighted_choice(rng, tuple((name, 1) for name in names))

    def _apply_feature_behavior(
        self,
        fields: dict[str, JSONObject],
        *,
        stack: Sequence[str],
        feature: str | None,
        case: str,
        behavior: str,
    ) -> None:
        # Consult registered plugins first: the owning plugin (if any) handles the
        # feature exactly once and we return before the legacy branches. A plugin
        # owns the feature when its handles_feature matches, it carries an
        # apply_behavior, and its layer is present in the sampled fields or the
        # stack (igmp gates on the stack). The registry is empty until protocols are
        # migrated, so this loop is a no-op today and every feature falls through.
        if feature is not None:
            for plugin in SAMPLER_REGISTRY.values():
                if (
                    plugin.handles_feature is None
                    or plugin.apply_behavior is None
                    or not plugin.handles_feature(feature)
                ):
                    continue
                if plugin.layer not in fields and plugin.layer not in stack:
                    continue
                plugin.apply_behavior(
                    fields,
                    stack=stack,
                    feature=feature,
                    case=case,
                    behavior=behavior,
                )
                return
        if feature == "tcp_options" and "tcp" in fields:
            self._apply_tcp_options_behavior(
                fields,
                case=case,
                behavior=behavior,
            )
        elif feature == "tcp_header" and "tcp" in fields:
            self._apply_tcp_header_behavior(
                fields,
                feature=feature,
                case=case,
                behavior=behavior,
            )
        elif feature is not None and feature.startswith("bgp_") and "bgp" in fields:
            _apply_bgp_behavior(fields, stack=stack, case=case, behavior=behavior)
        elif feature is not None and feature.startswith("ripng_") and "ripng" in fields:
            _apply_ripng_behavior(fields, stack=stack, case=case, behavior=behavior)
        elif feature is not None and feature.startswith("rip_") and "rip" in fields:
            _apply_rip_behavior(fields, stack=stack, case=case, behavior=behavior)
        elif feature == "icmpv4_errors" and "icmp" in fields:
            self._apply_icmpv4_error_behavior(
                fields,
                feature=feature,
                case=case,
                behavior=behavior,
            )
        elif feature == "icmpv6_errors" and "icmpv6" in fields:
            fields["icmpv6"]["type"] = _icmp_error_type_for_case(case, behavior, ipv6=True)
            fields["icmpv6"]["code"] = 0
        elif feature == "dns_behavior" and "dns" in fields:
            _apply_dns_behavior(fields["dns"], case=case, behavior=behavior)
        elif feature == "dhcp_behavior" and "dhcp" in fields:
            _apply_dhcp_behavior(fields["dhcp"], case=case, behavior=behavior)
        elif feature == "udp_options" and "udp" in fields:
            _apply_udp_options_behavior(fields, case=case, behavior=behavior)
        elif feature is not None and feature.startswith("igmp_") and "igmp" in stack:
            self._apply_igmp_behavior(fields, feature=feature, case=case, behavior=behavior)

    def _apply_igmp_behavior(
        self,
        fields: dict[str, JSONObject],
        *,
        feature: str,
        case: str,
        behavior: str,
    ) -> None:
        ipv4 = fields.setdefault("ipv4", {})
        ipv4["protocol"] = "igmp"
        ipv4["flags"] = "none"
        ipv4["fragment_offset"] = 0

        igmp = fields.setdefault("igmp", {})
        if feature == "igmp_header":
            self._apply_igmp_header_behavior(igmp, behavior=behavior)
        elif feature == "igmp_v3_query":
            self._apply_igmp_v3_query_behavior(igmp, behavior=behavior)
        elif feature == "igmp_v3_report":
            self._apply_igmp_v3_report_behavior(igmp, behavior=behavior)
        elif feature == "igmp_extensions":
            self._apply_igmp_extension_behavior(igmp, behavior=behavior)
        elif feature == "igmp_mrd":
            self._apply_igmp_mrd_behavior(ipv4, igmp, behavior=behavior)

    def _apply_igmp_header_behavior(self, igmp: JSONObject, *, behavior: str) -> None:
        igmp.update({"type": "membership_query", "code": 0, "group_address": "0.0.0.0"})
        if behavior == "v2-query":
            igmp.update({"code": 100, "group_address": _IGMP_DOC_GROUP})
        elif behavior == "v1-membership-report":
            igmp.update({"type": "v1_membership_report", "group_address": _IGMP_DOC_GROUP})
        elif behavior == "v2-membership-report":
            igmp.update({"type": "v2_membership_report", "group_address": _IGMP_DOC_GROUP})
        elif behavior == "v2-leave-group":
            igmp.update({"type": "v2_leave_group", "group_address": _IGMP_DOC_GROUP})
        elif behavior == "checksum-explicit":
            igmp["checksum"] = "explicit_invalid"
        elif behavior == "unknown-type-raw":
            igmp.update({"type": "unassigned", "raw_tail": _IGMP_BYTES_UNKNOWN_TYPE})
        elif behavior == "unsupported-assigned-type-raw":
            igmp.update(
                {
                    "type": "dvmrp_unsupported_assigned",
                    "raw_tail": _IGMP_BYTES_UNSUPPORTED_ASSIGNED_TYPE,
                }
            )

    def _apply_igmp_v3_query_behavior(self, igmp: JSONObject, *, behavior: str) -> None:
        igmp.update(
            {
                "type": "membership_query",
                "code": 100,
                "group_address": "0.0.0.0",
                "query_flags": 0,
                "qqic": 10,
                "source_addresses": [],
            }
        )
        if behavior == "group-specific-query":
            igmp.update({"group_address": _IGMP_DOC_GROUP_ALT, "query_flags": 0x08, "qqic": 0x81})
        elif behavior == "group-and-source-specific-query":
            igmp.update(
                {
                    "group_address": _IGMP_SSM_DOC_GROUP,
                    "query_flags": 0x02,
                    "source_addresses": [_IGMP_DOC_SOURCE],
                }
            )
        elif behavior == "query-source-count-override":
            igmp.update(
                {
                    "group_address": _IGMP_SSM_DOC_GROUP,
                    "number_of_sources": 0,
                    "source_addresses": [_IGMP_DOC_SOURCE],
                }
            )
        elif behavior == "checksum-explicit":
            igmp["checksum"] = "explicit_invalid"
        elif behavior == "ignored-extra-query-octets":
            igmp["raw_tail"] = _IGMP_BYTES_IGNORED_EXTRA

    def _apply_igmp_v3_report_behavior(self, igmp: JSONObject, *, behavior: str) -> None:
        igmp.update({"type": "v3_membership_report", "report_flags": 0, "group_records": []})
        if behavior == "include-record":
            igmp["group_records"] = [self._igmp_group_record("mode_is_include")]
        elif behavior == "exclude-record":
            igmp["group_records"] = [self._igmp_group_record("mode_is_exclude")]
        elif behavior == "source-list-change-records":
            igmp["group_records"] = [
                self._igmp_group_record("allow_new_sources", group=_IGMP_SSM_DOC_GROUP),
                self._igmp_group_record("block_old_sources", group=_IGMP_DOC_GROUP_ALT),
            ]
        elif behavior == "auxiliary-data-record":
            igmp["group_records"] = [
                self._igmp_group_record(
                    "change_to_exclude_mode", auxiliary_data=_IGMP_BYTES_PADDED_WORD
                )
            ]
        elif behavior == "unknown-record-type":
            igmp["group_records"] = [self._igmp_group_record("unknown", auxiliary_data=_IGMP_BYTES_RAW)]
        elif behavior == "report-count-override":
            igmp.update(
                {
                    "number_of_group_records": 0,
                    "group_records": [self._igmp_group_record("mode_is_include")],
                }
            )
        elif behavior == "checksum-explicit":
            igmp["checksum"] = "explicit_invalid"

    def _apply_igmp_extension_behavior(self, igmp: JSONObject, *, behavior: str) -> None:
        if behavior in {
            "query-noop-extension",
            "unassigned-extension-type",
            "ordered-extension-tlvs",
            "e-flag-clear-extension-looking-bytes",
        }:
            self._apply_igmp_v3_query_behavior(igmp, behavior="general-query")
        else:
            self._apply_igmp_v3_report_behavior(igmp, behavior="empty-report")

        if behavior == "query-noop-extension":
            igmp.update(
                {
                    "query_flags": 0x10,
                    "extension_tlvs": [
                        {"extension_type": "noop", "extension_value": _IGMP_BYTES_RAW}
                    ],
                }
            )
        elif behavior == "report-noop-extension":
            igmp.update(
                {
                    "report_flags": 0x8000,
                    "extension_tlvs": [
                        {
                            "extension_type": "noop",
                            "extension_length": 0,
                            "extension_value": _IGMP_BYTES_EMPTY,
                        }
                    ],
                }
            )
        elif behavior == "unassigned-extension-type":
            igmp.update(
                {
                    "query_flags": 0x10,
                    "extension_tlvs": [
                        {"extension_type": "unassigned", "extension_value": _IGMP_BYTES_RAW}
                    ],
                }
            )
        elif behavior == "experimental-extension-type":
            igmp.update(
                {
                    "report_flags": 0x8000,
                    "extension_tlvs": [
                        {"extension_type": "experimental", "extension_value": _IGMP_BYTES_RAW}
                    ],
                }
            )
        elif behavior == "ordered-extension-tlvs":
            igmp.update(
                {
                    "query_flags": 0x10,
                    "extension_tlvs": [
                        {
                            "extension_type": "noop",
                            "extension_length": 0,
                            "extension_value": _IGMP_BYTES_EMPTY,
                        },
                        {"extension_type": "unassigned", "extension_value": _IGMP_BYTES_RAW},
                        {"extension_type": "experimental", "extension_value": _IGMP_BYTES_RAW},
                    ],
                }
            )
        elif behavior == "e-flag-clear-extension-looking-bytes":
            igmp.update({"query_flags": 0, "raw_tail": _IGMP_BYTES_E_FLAG_CLEAR_EXTENSION})

    def _apply_igmp_mrd_behavior(
        self, ipv4: JSONObject, igmp: JSONObject, *, behavior: str
    ) -> None:
        ipv4["ttl"] = 1
        ipv4["dst"] = "224.0.0.106"
        igmp.update({"type": "multicast_router_solicitation", "code": 0})
        if behavior == "multicast-router-advertisement":
            igmp.update(
                {
                    "type": "multicast_router_advertisement",
                    "code": 20,
                    "mrd_query_interval": 125,
                    "mrd_robustness_variable": 2,
                }
            )
        elif behavior == "multicast-router-termination":
            igmp["type"] = "multicast_router_termination"
        elif behavior == "mrd-explicit-checksum":
            igmp.update(
                {
                    "type": "multicast_router_advertisement",
                    "code": 20,
                    "mrd_query_interval": 125,
                    "mrd_robustness_variable": 2,
                    "checksum": "explicit_invalid",
                }
            )
        elif behavior == "mrd-reserved-override":
            igmp["code"] = 7

    def _igmp_group_record(
        self,
        record_type: str,
        *,
        group: str = _IGMP_DOC_GROUP,
        auxiliary_data: object = _IGMP_BYTES_EMPTY,
    ) -> JSONObject:
        return {
            "record_type": record_type,
            "multicast_address": group,
            "source_addresses": [_IGMP_DOC_SOURCE],
            "auxiliary_data": auxiliary_data,
        }

    def _apply_tcp_header_behavior(
        self,
        fields: dict[str, JSONObject],
        *,
        feature: str,
        case: str,
        behavior: str,
    ) -> None:
        """Populate one TCP header behavior for the tcp_header feature.

        The control-bit set comes from the behavior's declared ``flags`` list so
        SYN, SYN-ACK, RST-ACK, and payload/raw ACK cases set exactly the bits the
        spec names. Per-case overrides fill the remaining header behaviors: an
        explicit checksum override that compile() must honor, a deliberately
        out-of-range data offset that decode preserves rather than rewriting, and
        a deterministic application payload for the raw-payload-preservation
        cases. Every value uses documentation-safe, seed-independent bytes so the
        comparison stays deterministic.
        """

        tcp = fields["tcp"]
        flags = self._tcp_header_behavior_flags(feature, behavior)
        if flags:
            tcp["flags"] = list(flags)

        key = case.replace("_", "-")
        if "explicit-checksum" in key:
            # Honored override: fix the TCP checksum to a constant so both
            # backends emit it verbatim instead of deriving from the pseudo
            # header. Exercises the protocol-correct-defaults / honored-override
            # contract for an intentionally non-derived value.
            tcp["checksum"] = 0xBEEF
        if "invalid-data-offset" in key:
            # Deliberately malformed: a data offset of 15 (60 bytes) with no
            # option space. compile() preserves the explicit value rather than
            # rewriting it; compared non-strict (see supported_cases byte_policy).
            tcp["data_offset"] = 15
        if "payload-ack" in key or "raw-payload" in key:
            # Raw payload preservation: a fixed application payload that must
            # round-trip as a trailing Raw layer after the TCP header.
            payload_hex = "7261772d7463702d7061796c6f6164"  # b"raw-tcp-payload"
            fields["payload"] = {
                "hex": payload_hex,
                "length": len(payload_hex) // 2,
            }

    def _tcp_header_behavior_flags(self, feature: str, behavior: str) -> list[str]:
        feature_spec = self._feature_spec(feature)
        behaviors = _object_list(
            feature_spec.get("behaviors", []), f"features.{feature}.behaviors"
        )
        for raw_behavior in behaviors:
            if not isinstance(raw_behavior, Mapping):
                continue
            if raw_behavior.get("name") != behavior:
                continue
            return _string_list(
                raw_behavior.get("flags", []),
                f"features.{feature}.behaviors.{behavior}.flags",
            )
        return []

    def _apply_tcp_options_behavior(
        self,
        fields: dict[str, JSONObject],
        *,
        case: str,
        behavior: str,
    ) -> None:
        """Populate one TCP option behavior for the tcp_options feature.

        Broad option-list cases (tcp-options*, tcp-all-flags-reserved-offset)
        keep their existing combined option region via ``_tcp_options_hex``. The
        focused single-option cases (tcp-option-*) materialize exactly one option
        kind via ``_tcp_option_case_hex``: the comparable kinds (MSS, Window
        Scale, SACK Permitted, SACK, Timestamp, Fast Open, MPTCP generic, and an
        unknown valid generic) emit a self-consistent option both backends build
        byte-identically. The preserved-only kinds (User Timeout, TCP-AO,
        TCP-ENO, Accurate ECN, experimental ExID) and the malformed-length case
        carry byte_policy: structured_error and are excluded from offline
        sampling (see _case_supported_in_direction), so they never reach this
        materialization in an offline run; the option bytes are still defined
        here so the spec's declared coverage stays reproducible and so the
        libcrafter_to_reference and dry-plan paths can render them determinist
        ically. Every value uses fixed, seed-independent bytes.
        """

        tcp = fields["tcp"]
        case_id = _identifier_part(case)
        if case_id.startswith("tcp-option-"):
            tcp["options"] = {"hex": _tcp_option_case_hex(behavior)}
            return
        tcp["options"] = {"hex": _tcp_options_hex(case, behavior)}
        if case == "tcp-all-flags-reserved-offset":
            tcp["flags"] = "all"
            tcp["reserved"] = 7

    def _apply_icmpv4_error_behavior(
        self,
        fields: dict[str, JSONObject],
        *,
        feature: str,
        case: str,
        behavior: str,
    ) -> None:
        """Populate one structured ICMPv4 error behavior.

        Structured error behaviors (destination unreachable, time exceeded,
        parameter problem, redirect, fragmentation-needed) carry an outer IPv4
        header, the ICMP error header, and a quoted (embedded) IPv4 datagram
        prefix with deterministic payload bytes. The quoted datagram is emitted
        as the ``embedded_header`` field so both backends materialize the same
        bytes after the ICMP rest-of-header.

        Extension-framing behaviors marked raw-compatible (RFC 4884/4950 MPLS,
        RFC 5837 interface information) still include the quoted datagram before
        their deterministic ``extension_bytes`` body. The reference model keeps
        this as a flat trailing payload for backend-neutral comparison.
        """

        icmp = fields["icmp"]
        spec = self._icmpv4_error_behavior_spec(feature, behavior)
        icmp_type = _string_or_none(spec.get("icmp_type")) if spec is not None else None
        if icmp_type is None:
            icmp_type = _icmp_error_type_for_case(case, behavior, ipv6=False)
        icmp["type"] = icmp_type
        icmp["code"] = 0

        embeds = _icmp_behavior_embeds(spec)

        # Extension error behaviors keep backend-neutral flat payload bytes, but
        # the ICMP error body still starts with a quoted datagram.
        if "icmp_extension_mpls" in embeds:
            icmp["embedded_header"] = {"hex": _ICMP_QUOTED_IPV4_DATAGRAM}
            icmp["extension_bytes"] = {"hex": _ICMP_MPLS_EXTENSION_BYTES}
            return
        if embeds.intersection({"icmp_extension_header", "icmp_extension_object"}):
            icmp["extension_bytes"] = {"hex": _ICMP_EXTENSION_BYTES}
            if "quoted_ipv4" in embeds or "ipv4" in embeds:
                icmp["embedded_header"] = {"hex": _ICMP_QUOTED_IPV4_DATAGRAM}
            return

        # Structured quoted-datagram error behaviors: outer IPv4 header, ICMP
        # error header, quoted IPv4 prefix, and deterministic quoted payload.
        if "ipv4" in embeds or "payload_prefix" in embeds:
            icmp["embedded_header"] = {"hex": _ICMP_QUOTED_IPV4_DATAGRAM}
            if behavior == "redirect" or icmp_type == "redirect":
                icmp["gateway"] = "192.0.2.1"
            elif behavior == "parameter_problem" or icmp_type == "parameter_problem":
                icmp["pointer"] = 20
            elif behavior == "frag_needed_next_hop_mtu":
                icmp["next_hop_mtu"] = 1280

    def _icmpv4_error_behavior_spec(
        self, feature: str, behavior: str
    ) -> JSONObject | None:
        feature_spec = self._feature_spec(feature)
        behaviors = _object_list(
            feature_spec.get("behaviors", []), f"features.{feature}.behaviors"
        )
        for raw_behavior in behaviors:
            if not isinstance(raw_behavior, Mapping):
                continue
            entry = _json_object(raw_behavior)
            if entry.get("name") == behavior:
                return entry
        return None

    def _apply_icmp_live_fields(
        self,
        rng: random.Random,
        fields: dict[str, JSONObject],
        *,
        feature: str | None,
        case: str,
    ) -> str | None:
        """Fill ICMP rest-of-header and type-specific body fields per behavior.

        Driven by the live coverage matrix in the feature spec rather than by
        backend-specific special cases: each matrix entry names a coverage case,
        its ICMP type, the representative code or pair, and (via the behavior
        name) which rest-of-header body the live exchange exercises. Only the
        fields a given behavior needs are added, and only deterministic, well
        formed bytes both backends can emit and parse are sampled.
        """

        if feature is None or "icmp" not in fields:
            return None
        feature_spec = self._feature_spec(feature)
        matrix = _object_list(
            feature_spec.get("live_matrix", []),
            f"features.{feature}.live_matrix",
        )
        if not matrix:
            return None
        entry = _icmp_live_matrix_entry(matrix, case)
        if entry is None:
            return None
        icmp = fields["icmp"]
        return _apply_icmp_live_entry(rng, icmp, case=case, entry=entry)

    def _is_malformed_case(self, feature: str | None, case: str) -> bool:
        if _is_malformed_case_name(case):
            return True
        if feature is None:
            return False
        feature_spec = self._feature_spec(feature)
        malformed = feature_spec.get("malformed")
        if not isinstance(malformed, bool):
            raise ValueError(f"features.{feature}.malformed must be a boolean")
        return malformed

    def _validate_layer_backend_support(self, layer: str, spec: JSONObject) -> None:
        support = _object(spec.get("backend_support"), f"layers.{layer}.backend_support")
        for backend_name in (self.backend, SUPPORTED_LAYER_BACKEND):
            if backend_name not in support:
                raise ValueError(
                    f"spec error: layer {layer} has no backend_support for {backend_name}"
                )
            entry = _object(
                support[backend_name],
                f"layers.{layer}.backend_support.{backend_name}",
            )
            status = _string(entry.get("status"), f"layers.{layer}.backend_support.{backend_name}.status")
            if status == "planned":
                raise ValueError(
                    f"spec error: layer {layer} is planned, not supported, for {backend_name}"
                )
            if layer in _SCAPY_MATERIALIZED_LAYERS and backend_name == self.backend:
                if entry.get("encode") is not True:
                    raise ValueError(
                        f"spec error: layer {layer} cannot be encoded by backend {backend_name}"
                    )

    def _sample_layer_fields(
        self,
        ctx: "_SamplingContext",
        layer: str,
        spec: JSONObject,
    ) -> JSONObject:
        output: JSONObject = {}
        for raw_field in _field_specs(spec, layer):
            field_name = _string(raw_field.get("name"), f"layers.{layer}.fields.name")
            if field_name not in _supported_fields(layer):
                continue
            sampled = self._sample_field_value(ctx, layer, raw_field, output)
            if sampled is _SKIP_FIELD:
                continue
            output[field_name] = sampled  # type: ignore[assignment]
        return output

    def _validate_sampled_fields(
        self,
        layer: str,
        spec: JSONObject,
        sampled: Mapping[str, object],
    ) -> None:
        declared = {
            _string(field.get("name"), f"layers.{layer}.fields.name")
            for field in _field_specs(spec, layer)
        }
        supported = _supported_fields(layer)
        for field_name in sampled:
            if field_name not in declared:
                raise ValueError(
                    f"spec error: sampler emitted undeclared field {layer}.{field_name}"
                )
            if field_name not in supported:
                supported_list = ", ".join(sorted(supported)) or "<none>"
                raise ValueError(
                    f"spec error: sampler emitted unsupported field {layer}.{field_name}; "
                    f"{self.backend}/{SUPPORTED_LAYER_BACKEND} supports {supported_list}"
                )

    def _sample_field_value(
        self,
        ctx: "_SamplingContext",
        layer: str,
        field_spec: JSONObject,
        current_fields: Mapping[str, object],
    ) -> object:
        field_name = _string(field_spec.get("name"), f"layers.{layer}.fields.name")
        domains = self._field_domains(layer, field_name, field_spec)
        domain = self._choose_domain(ctx, layer, field_name, domains)

        if domain is _SKIP_FIELD:
            return _SKIP_FIELD
        plugin = SAMPLER_REGISTRY.get(layer)
        if plugin is not None:
            return plugin.sample(
                ctx,
                field_name,
                domain,
                field_spec=field_spec,
                current_fields=current_fields,
            )
        if layer == "udp":
            return _sample_udp_field(ctx, field_name, domain)
        if layer == "tcp":
            return _sample_tcp_field(ctx, field_name, domain, field_spec)
        if layer == "bgp":
            return _sample_bgp_field(ctx, field_name, domain)
        if layer == "rip":
            return _sample_rip_field(ctx, field_name, domain)
        if layer == "ripng":
            return _sample_ripng_field(ctx, field_name, domain)
        if layer == "ospf":
            return _sample_ospf_field(ctx, field_name, domain)
        if layer == "icmp":
            return _sample_icmp_field(ctx, field_name, domain)
        if layer == "icmpv6":
            return _sample_icmp_field(ctx, field_name, domain)
        if layer == "esp":
            return _sample_esp_field(ctx, field_name, domain, field_spec)
        if layer == "ah":
            return _sample_ah_field(ctx, field_name, domain, field_spec)
        if layer == "ikev2":
            return _sample_ikev2_field(ctx, field_name, domain, field_spec)
        if layer == "dns":
            return _sample_dns_field(ctx, field_name, domain)
        if layer == "dhcp":
            return _sample_dhcp_field(ctx, field_name, domain)
        if layer == "radiotap":
            return _sample_radiotap_field(ctx, field_name, domain)
        if layer == "dot11":
            return _sample_dot11_field(ctx, field_name, domain, current_fields)
        if layer == "eapol":
            return _sample_eapol_field(ctx, field_name, domain)
        if layer == "rsn":
            return _sample_rsn_field(ctx, field_name, domain)

        raise ValueError(f"spec error: unsupported layer sampler: {layer}")

    def _field_domains(
        self,
        layer: str,
        field_name: str,
        field_spec: JSONObject,
    ) -> list[object]:
        default_domains = _object_list(field_spec.get("domains"), f"layers.{layer}.{field_name}.domains")
        profile_domains = field_spec.get("profile_domains")
        if isinstance(profile_domains, Mapping) and self.profile in profile_domains:
            return _object_list(
                profile_domains[self.profile],
                f"layers.{layer}.{field_name}.profile_domains.{self.profile}",
            )
        profiles = field_spec.get("profiles")
        if isinstance(profiles, Mapping) and self.profile in profiles:
            profile_entry = profiles[self.profile]
            if isinstance(profile_entry, Mapping) and "domains" in profile_entry:
                return _object_list(
                    profile_entry["domains"],
                    f"layers.{layer}.{field_name}.profiles.{self.profile}.domains",
                )
            if isinstance(profile_entry, list):
                return list(profile_entry)
        sampling = field_spec.get("sampling")
        if isinstance(sampling, Mapping):
            profiles_obj = sampling.get("profiles")
            if isinstance(profiles_obj, Mapping) and self.profile in profiles_obj:
                profile_entry = profiles_obj[self.profile]
                if isinstance(profile_entry, Mapping) and "domains" in profile_entry:
                    return _object_list(
                        profile_entry["domains"],
                        f"layers.{layer}.{field_name}.sampling.profiles.{self.profile}.domains",
                    )
        return default_domains

    def _choose_domain(
        self,
        ctx: "_SamplingContext",
        layer: str,
        field_name: str,
        domains: Sequence[object],
    ) -> object:
        supported_domains = _SUPPORTED_FIELD_DOMAINS.get((layer, field_name))
        choices: list[tuple[object, int]] = []
        for domain in domains:
            if isinstance(domain, str) and domain in _DERIVED_DOMAINS:
                continue
            if supported_domains is not None and domain not in supported_domains:
                continue
            weight = _domain_weight(ctx, layer, field_name, domain)
            if weight > 0:
                choices.append((domain, weight))
        if not choices:
            return _SKIP_FIELD
        return weighted_choice(ctx.rng, choices)


def _field_specs(spec: JSONObject, layer: str) -> list[JSONObject]:
    raw_fields = spec.get("fields")
    if not isinstance(raw_fields, Sequence) or isinstance(raw_fields, (str, bytes)):
        raise ValueError(f"layers.{layer}.fields must be a list")
    return [_object(field, f"layers.{layer}.fields item") for field in raw_fields]


def _object_list(value: object, name: str) -> list[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{name} must be a list")
    return list(value)


def _domain_weight(ctx: _SamplingContext, layer: str, field_name: str, domain: object) -> int:
    if field_name == "options" and layer == "ipv4":
        if ctx.feature == "ipv4_options" or "ipv4-options" in ctx.case:
            return max(1, ctx.feature_weights.get("boundary", 1))
        return 0
    if field_name == "options" and layer == "tcp":
        if ctx.feature == "tcp_options" or "tcp-options" in ctx.case or ctx.case == "tcp-all-flags-reserved-offset":
            return max(1, ctx.feature_weights.get("boundary", 1))
        return 0
    if field_name == "options" and layer == "udp":
        if ctx.feature == "udp_options" or "udp-options" in ctx.case:
            return max(1, ctx.feature_weights.get("boundary", 1))
        return 0
    if field_name == "answers" and layer == "dns":
        if ctx.feature == "dns_behavior" and "response" in ctx.case:
            return max(1, ctx.feature_weights.get("boundary", 1))
        return 0
    if ctx.profile == "smoke" and _is_boundary_domain(domain):
        return 0
    if ctx.profile == "smoke" and layer in {"dns", "dhcp"}:
        smoke_domains = {
            False,
            0,
            6,
            "a_in",
            "bootrequest",
            "deterministic",
            "documentation_ipv4",
            "documentation_mac_padded",
            "ethernet",
            "message_type",
            "none",
            "query",
            "zero",
        }
        return 0 if domain not in smoke_domains else 10
    if _is_boundary_domain(domain):
        return max(0, ctx.feature_weights.get("boundary", 0))
    return max(1, ctx.feature_weights.get("baseline", 1))


def _is_boundary_domain(domain: object) -> bool:
    if isinstance(domain, bool):
        return domain is True
    if isinstance(domain, int):
        return domain in {0, 1, 255, 4094, 65535}
    if not isinstance(domain, str):
        return False
    return domain in {
        "all",
        "boundary",
        "broadcast",
        "mf",
        "packet_too_big",
        "parameter_problem",
        "time_exceeded",
        "truncated",
        "zero",
        "zero_ipv4",
    }


def _ipv6_extension_options_for_case(layer: str, case: str) -> list[JSONObject]:
    normalized = case.replace("_", "-")
    if "option-metadata" in normalized:
        return [
            {
                "kind": "unknown",
                "option_type": 0x22,
                "data": {"hex": "aabbccdd"},
            }
        ]
    if layer == "ipv6_hop_by_hop":
        return [
            {"kind": "router_alert", "value": 0},
            {"kind": "padn", "total_length": 2},
        ]
    return [
        {"kind": "home_address", "address": "2001:db8::42"},
        {"kind": "padn", "total_length": 4},
    ]


def _sample_udp_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "src_port":
        if "dhcp" in ctx.stack:
            return 68
        if "dns" in ctx.stack:
            return ephemeral_port(ctx.rng)
        # RIP (UDP/520, RFC 1058 §3.4) and RIPng (UDP/521, RFC 2080 §2) are
        # exchanged from the well-known port, not an ephemeral one.
        if "rip" in ctx.stack:
            return 520
        if "ripng" in ctx.stack:
            return 521
        if domain in {"bootpc", "dns_client", "dynamic"}:
            return _integer_domain_value(ctx, domain, field_name, bits=16)
        return ctx.src_port
    if field_name == "dst_port":
        if "dhcp" in ctx.stack:
            return 67
        if "dns" in ctx.stack:
            return 53
        if "rip" in ctx.stack:
            return 520
        if "ripng" in ctx.stack:
            return 521
        if domain in {"bootps", "dns_server"}:
            return ctx.dst_port
        if domain == "dynamic":
            return _integer_domain_value(ctx, domain, field_name, bits=16)
        return ctx.dst_port
    if field_name == "checksum" and domain == "zero_ipv4" and "ipv4" in ctx.stack:
        return 0
    if field_name == "options":
        payload_hex = ctx.payload.hex() if "payload" in ctx.stack else None
        return _udp_options_field(
            f"{ctx.case} {domain}".replace("_", "-"),
            payload_hex=payload_hex,
        ) or _SKIP_FIELD
    return _SKIP_FIELD


def _sample_tcp_field(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    field_spec: JSONObject,
) -> object:
    if field_name == "src_port":
        return _integer_domain_value(ctx, domain, field_name, bits=16)
    if field_name == "dst_port":
        return _integer_domain_value(ctx, domain, field_name, bits=16)
    if field_name in {"sequence", "acknowledgement", "urgent_pointer"}:
        return _integer_domain_value(ctx, domain, field_name, bits=_field_bits(field_spec))
    if field_name == "reserved":
        return _integer_domain_value(ctx, domain, field_name, bits=3)
    if field_name == "flags":
        return domain
    if field_name == "window":
        return _integer_domain_value(ctx, domain, field_name, bits=16)
    if field_name == "options":
        return {"hex": _tcp_options_hex(ctx.case, str(domain))}
    raise ValueError(f"spec error: unsupported tcp field sampler: {field_name}")


def _sample_bgp_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "marker":
        return {"hex": "ff" * 16}
    if field_name == "length":
        return _SKIP_FIELD
    if field_name == "type":
        return _bgp_message_type_for_case(ctx.case)
    raise ValueError(f"spec error: unsupported bgp field sampler: {field_name}")


def _sample_rip_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    # The RIP header scalars (command/version/reserved) seed the layer so it
    # survives the empty-dict drop in _fields; the per-case entries/auth values
    # are attached by _apply_rip_behavior, mirroring how BGP body bytes attach.
    if field_name == "command":
        return _rip_command_for_case(ctx.case)
    if field_name == "version":
        return _rip_version_for_case(ctx.case)
    if field_name == "reserved":
        return 0
    raise ValueError(f"spec error: unsupported rip field sampler: {field_name}")


def _sample_ripng_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "command":
        return _rip_command_for_case(ctx.case)
    if field_name == "version":
        return 1
    if field_name == "reserved":
        return 0
    raise ValueError(f"spec error: unsupported ripng field sampler: {field_name}")


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


def _int_or(domain: object, default: int) -> object:
    """Return ``domain`` when it is a concrete int, otherwise ``default``."""

    if isinstance(domain, bool):
        return int(domain)
    if isinstance(domain, int):
        return domain
    return default


def _sample_icmp_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "type":
        return str(domain).replace("_", "-") if domain in {"echo_reply", "echo_request"} else domain
    if field_name == "code":
        return 0
    if field_name in {"identifier", "sequence"}:
        return bounded_int(ctx.rng, 0, 65535)
    # Rest-of-header, gateway, pointer, MTU, timestamp, address-mask, router
    # discovery, and extension-byte fields are populated per ICMP behavior by the
    # live-matrix sampler so the base path stays an echo query. Emitting them
    # unconditionally here would attach body bytes to plain echo cases.
    if field_name in _ICMP_BODY_FIELDS:
        return _SKIP_FIELD
    raise ValueError(f"spec error: unsupported icmp field sampler: {field_name}")


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


def _sample_dns_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "transaction_id":
        return _integer_domain_value(ctx, domain, field_name, bits=16)
    if field_name == "is_response":
        return False
    if field_name == "opcode":
        return "query"
    if field_name == "flags":
        return ["recursion_desired"]
    if field_name == "response_code":
        return "no_error"
    if field_name == "questions":
        question_count = 2 if domain == "multiple_questions" and ctx.profile in {"boundary", "fuzz"} else 1
        names = ("example.com.", "example.net.", "libcrafter.test.")
        questions: list[JSONObject] = []
        for index in range(question_count):
            questions.append(
                {
                    "qname": names[index % len(names)],
                    "qtype": weighted_choice(ctx.rng, (("A", 3), ("AAAA", 1))),
                }
            )
        return questions
    if field_name == "answers":
        return _dns_answers_for_domain(ctx, domain)
    raise ValueError(f"spec error: unsupported dns field sampler: {field_name}")


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


def _tcp_options_hex(case: str, behavior: str) -> str:
    key = f"{case} {behavior}".replace("_", "-")
    if "sack" in key:
        return "0402050a0000000100000002"
    if any(token in key for token in ("mptcp", "fast-open", "edo", "generic", "advanced")):
        return "1e04000122040102fd040000fe040102"
    if "header-boundary" in key or "all-flags" in key:
        return "01010101"
    return "020405b4010303070402080a0102030405060708"


# Per-behavior option region for the focused single-option tcp_options cases.
# Each entry carries exactly one TCP option whose declared length byte matches
# its data so the Scapy reference backend emits it verbatim (comparable cases)
# or so libcrafter preserves the documented wire form (preserved-only cases).
# Sources: RFC 9293 (base options/EOL/NOP), RFC 793/879 (MSS kind 2),
# RFC 7323 (Window Scale kind 3, Timestamps kind 8), RFC 2018 (SACK Permitted
# kind 4, SACK kind 5), RFC 7413 (Fast Open kind 34), RFC 8684 (MPTCP kind 30),
# RFC 5482 (User Timeout kind 28), RFC 5925 (TCP-AO kind 29), RFC 8547
# (TCP-ENO kind 69), RFC 9768 (Accurate ECN kinds 172/174), and RFC 6994
# (experimental ExID kinds 253/254). See docs/guide/tcp.md.
_TCP_OPTION_CASE_HEX: dict[str, str] = {
    # Comparable kinds: Scapy builds these byte-identically to libcrafter.
    "mss": "020405b4",  # kind 2, len 4: MSS 1460
    "window-scale": "030307",  # kind 3, len 3: shift 7
    "sack-permitted": "0402",  # kind 4, len 2
    "sack": "050a0000000100000002",  # kind 5, len 10: one SACK block
    "timestamp": "080a0102030405060708",  # kind 8, len 10: TSval/TSecr
    "fast-open": "2202",  # kind 34, len 2: Fast Open cookie request
    "mptcp-generic": "1e040001",  # kind 30, len 4: MPTCP generic subtype
    "unknown-generic": "c804aabb",  # kind 200, len 4: unknown valid generic
    # Preserved-only kinds: declared coverage, byte_policy structured_error.
    # Scapy has no faithful native build/compare path; libcrafter preserves
    # these bytes verbatim (asserted by the crate suites).
    "user-timeout": "1c0480e8",  # kind 28, len 4: G=1, value 0x00e8 (RFC 5482)
    "tcp-ao": "1d0c01020304050607080910",  # kind 29, len 12: KeyID/RNext/MAC
    "tcp-eno": "4504aabb",  # kind 69, len 4: ENO suboptions (RFC 8547)
    "accurate-ecn": "ac0601020304",  # kind 172, len 6: AccECN order-0 counters
    "experimental": "fd06f0010203",  # kind 253, len 6: ExID 0xf001 + data
    # Malformed: a length byte below the two-octet minimum (kind 2, len 1).
    # No offline malformed comparison pathway; the crate suites assert the error.
    "malformed-length": "0201",
}


def _tcp_option_case_hex(behavior: str) -> str:
    """Return the option region hex for one focused tcp_options behavior."""

    key = _identifier_part(behavior)
    if key not in _TCP_OPTION_CASE_HEX:
        raise ValueError(f"spec error: no tcp option hex for behavior {behavior!r}")
    return _TCP_OPTION_CASE_HEX[key]


def _icmp_error_type_for_case(case: str, behavior: str, *, ipv6: bool) -> str:
    key = f"{case} {behavior}".replace("_", "-")
    if "packet-too-big" in key:
        return "packet_too_big" if ipv6 else "destination_unreachable"
    if "time-exceeded" in key:
        return "time_exceeded"
    if "parameter-problem" in key:
        return "parameter_problem"
    if "redirect" in key and not ipv6:
        return "redirect"
    return "destination_unreachable"


def _dns_behavior_emits_raw(case: str, behavior: str) -> bool:
    """Whether applying ``behavior`` to ``case`` emits a Scapy-owned raw spec.

    Mirrors the ``dns_raw`` branches in ``_apply_dns_behavior`` so case/behavior
    selection can avoid pairing a typed case with a compressed raw-byte builder
    that only the reference backend can encode.
    """

    key = f"{case} {behavior}".replace("_", "-")
    return "compressed-names" in key or "name-records-compressed" in key


# Stable per-code mapping for the representative ICMP destination-unreachable
# codes named by the live matrix. Each behavior names at most one code so the
# generated plan exercises a deterministic code byte rather than a random one.
_ICMP_DEST_UNREACHABLE_CODES: dict[str, int] = {
    "net_unreachable": 0,
    "host_unreachable": 1,
    "protocol_unreachable": 2,
    "port_unreachable": 3,
    "fragmentation_needed": 4,
}
# Raw rest-of-header bytes for legacy/raw-compatible types whose four reserved
# bytes both backends emit and parse identically. Deterministic and well formed.
_ICMP_LEGACY_REST_OF_HEADER = "00000000"
# Deterministic RFC 4884 extension blob (extension header version 2 plus one
# generic object) shared by the extension-framing live behaviors as
# raw-compatible bytes.
_ICMP_EXTENSION_BYTES = "20000000000800010102030405060708"
# Deterministic RFC 4950 MPLS extension blob (extension header plus one MPLS
# object carrying a single label stack entry).
_ICMP_MPLS_EXTENSION_BYTES = "2000000000080100000010ff"
# Deterministic quoted (embedded) original IPv4 datagram carried inside an
# ICMPv4 error message per RFC 792: a documentation-address UDP/53 query with a
# well-formed IPv4 header (correct length and checksum) plus eight bytes of UDP
# header and a short payload. Both backends emit and decode these bytes
# identically; the normalized model collapses them into a single trailing
# payload after the ICMP rest-of-header.
_ICMP_QUOTED_IPV4_DATAGRAM = (
    "45000028424200004011b464c000020ac00002149c4000350014000071756f7465642d7175657279"
)


def _icmp_behavior_embeds(spec: JSONObject | None) -> set[str]:
    """Return the set of layer names a behavior's ``embeds`` declaration lists."""

    if spec is None:
        return set()
    embeds = spec.get("embeds")
    if not isinstance(embeds, Sequence) or isinstance(embeds, (str, bytes)):
        return set()
    return {value for value in embeds if isinstance(value, str)}


def _icmp_live_matrix_entry(
    matrix: Sequence[object],
    case: str,
) -> JSONObject | None:
    """Return the live-matrix entry whose coverage case matches ``case``."""

    for raw_entry in matrix:
        if not isinstance(raw_entry, Mapping):
            continue
        entry = _json_object(raw_entry)
        coverage_case = entry.get("coverage_case")
        if isinstance(coverage_case, str) and coverage_case == case:
            return entry
    return None


def _icmp_live_pick(rng: random.Random, values: Sequence[object]) -> object | None:
    """Deterministically pick one value from a non-empty matrix list."""

    options = [value for value in values if isinstance(value, str)]
    if not options:
        return None
    return weighted_choice(rng, tuple((value, 1) for value in options))


def _apply_icmp_live_entry(
    rng: random.Random,
    icmp: JSONObject,
    *,
    case: str,
    entry: JSONObject,
) -> str:
    """Apply one ICMP live-matrix entry's type, code, and body fields in place.

    Returns the resolved behavior name recorded in plan metadata.
    """

    behavior = _string_or_none(entry.get("behavior")) or case
    icmp_type = _string_or_none(entry.get("icmp_type"))

    # Request/reply pairs alternate deterministically by plan rng so both members
    # of the pair appear across a seeded run.
    pairs = entry.get("pairs")
    if isinstance(pairs, Sequence) and not isinstance(pairs, (str, bytes)):
        picked = _icmp_live_pick(rng, pairs)
        if picked is not None:
            icmp_type = str(picked)

    # Representative legacy/raw-compatible types likewise rotate over the named
    # representative set.
    representative = entry.get("representative_types")
    if isinstance(representative, Sequence) and not isinstance(representative, (str, bytes)):
        picked = _icmp_live_pick(rng, representative)
        if picked is not None:
            icmp_type = str(picked)

    if icmp_type is None:
        # An entry without a concrete ICMP type (e.g. a pure pair/representative
        # listing handled above) leaves the base echo type untouched.
        return behavior

    icmp["type"] = icmp_type

    # Representative code for the destination-unreachable family.
    codes = entry.get("codes")
    if isinstance(codes, Sequence) and not isinstance(codes, (str, bytes)):
        picked_code = _icmp_live_pick(rng, codes)
        if isinstance(picked_code, str) and picked_code in _ICMP_DEST_UNREACHABLE_CODES:
            icmp["code"] = _ICMP_DEST_UNREACHABLE_CODES[picked_code]

    _apply_icmp_live_body(rng, icmp, behavior=behavior, icmp_type=icmp_type, entry=entry)
    return behavior


def _apply_icmp_live_body(
    rng: random.Random,
    icmp: JSONObject,
    *,
    behavior: str,
    icmp_type: str,
    entry: JSONObject,
) -> None:
    """Populate the type-specific rest-of-header body for one ICMP behavior."""

    # RFC 4884/4950 extension framing: ICMP error packets carry a quoted
    # datagram before deterministic, raw-compatible extension bytes. Extended
    # echo uses the same extension byte field without an embedded datagram.
    embeds = entry.get("embeds")
    if isinstance(embeds, Sequence) and not isinstance(embeds, (str, bytes)):
        embed_names = {value for value in embeds if isinstance(value, str)}
        is_error_type = icmp_type in {
            "destination_unreachable",
            "time_exceeded",
            "parameter_problem",
        }
        if "icmp_extension_mpls" in embed_names:
            if is_error_type:
                icmp["embedded_header"] = {"hex": _ICMP_QUOTED_IPV4_DATAGRAM}
            icmp["extension_bytes"] = {"hex": _ICMP_MPLS_EXTENSION_BYTES}
        elif embed_names.intersection(
            {"icmp_extension_header", "icmp_extension_object"}
        ):
            if is_error_type:
                icmp["embedded_header"] = {"hex": _ICMP_QUOTED_IPV4_DATAGRAM}
            icmp["extension_bytes"] = {"hex": _ICMP_EXTENSION_BYTES}

    if behavior == "redirect" or icmp_type == "redirect":
        icmp["gateway"] = "192.0.2.1"
    elif behavior == "parameter_problem" or icmp_type == "parameter_problem":
        icmp["pointer"] = 20
    elif behavior == "frag_needed_next_hop_mtu":
        icmp["next_hop_mtu"] = 1280
    elif icmp_type in {"timestamp", "timestamp_reply"}:
        icmp["originate_timestamp"] = bounded_int(rng, 0, (1 << 31) - 1)
        icmp["receive_timestamp"] = bounded_int(rng, 0, (1 << 31) - 1)
        icmp["transmit_timestamp"] = bounded_int(rng, 0, (1 << 31) - 1)
    elif icmp_type in {"address_mask_request", "address_mask_reply"}:
        icmp["address_mask"] = "255.255.255.0"
    elif icmp_type == "router_advertisement":
        icmp["router_address_entry_size"] = 2
        icmp["router_lifetime"] = 1800
        icmp["router_addresses"] = [
            {"address": "192.0.2.1", "preference": 0},
            {"address": "192.0.2.2", "preference": 0},
        ]
    elif icmp_type == "router_solicitation":
        icmp["rest_of_header"] = {"hex": _ICMP_LEGACY_REST_OF_HEADER}
    elif icmp_type in {"extended_echo_request", "extended_echo_reply"}:
        # Scapy has no typed extended-echo class; emit a deterministic rest of
        # header plus a generic extension object both sides parse identically.
        icmp["rest_of_header"] = {"hex": "00000100"}
        icmp.setdefault("extension_bytes", {"hex": _ICMP_EXTENSION_BYTES})
    elif behavior == "legacy_raw_compatible_types" or icmp_type in {
        "source_quench",
        "traceroute",
        "mobile_host_redirect",
        "domain_name_request",
        "photuris",
    }:
        icmp["rest_of_header"] = {"hex": _ICMP_LEGACY_REST_OF_HEADER}


def _apply_dns_behavior(fields: JSONObject, *, case: str, behavior: str) -> None:
    key = f"{case} {behavior}".replace("_", "-")
    if "compressed-names" in key:
        fields.clear()
        fields["dns_raw"] = _dns_compressed_names_raw_spec()
        return
    if "name-records-compressed" in key:
        # Compressed NS/CNAME/PTR input: the Scapy reference owns hand-built
        # bytes whose owner and RDATA names are compression pointers, and
        # libcrafter normalizes to the same uncompressed DnsRecordData::Name
        # model on decode. Checked before the uncompressed name-records branch
        # because that token is a substring of this one.
        fields.clear()
        fields["dns_raw"] = _dns_name_records_compressed_raw_spec()
        return
    if "raw-unknown-records" in key:
        # A response carrying record types this crate intentionally keeps as
        # DnsRecordData::Raw: an unknown private-use numeric TYPE plus the
        # deferred NSEC3PARAM (51), TLSA (52), KEY (25), and NAPTR (35) types
        # from docs/guide/dns.md. Each RDATA is a deterministic opaque blob carried as
        # hex so neither backend reinterprets it, and the TYPE is given as a
        # numeric IANA codepoint so both the Scapy DNSRR(type=N) reference and the
        # libcrafter DnsRecordData::Raw materializer agree byte-for-byte. The
        # owner names, TTLs, and IN class are stable. libcrafter must decode every
        # answer to DnsRecordData::Raw (never a mis-typed record) and recompile the
        # same RDATA bytes. (raw-unknown-records is not a substring of any other
        # case id, so the matcher resolves this branch unambiguously.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": 65280}]
        fields["answers"] = [
            {
                # Private-use unknown TYPE 65280 (RFC 6895 Section 3.1): no named
                # mapping on either backend; preserved as a numeric codepoint.
                "name": "unknown.example.com.",
                "type": 65280,
                "ttl": 3600,
                "data": {"hex": "deadbeef"},
            },
            {
                # NSEC3PARAM (51): deferred to Raw (docs/guide/dns.md). Bytes look like a
                # plausible NSEC3PARAM RDATA but are never parsed into typed fields.
                "name": "example.com.",
                "type": 51,
                "ttl": 300,
                "data": {"hex": "0100000a04aabbccdd"},
            },
            {
                # TLSA (52): deferred certificate-association record, kept Raw.
                "name": "_443._tcp.example.com.",
                "type": 52,
                "ttl": 300,
                "data": {"hex": "030101a1b2c3d4e5f6"},
            },
            {
                # KEY (25): cryptographic-key transport type, kept Raw.
                "name": "example.com.",
                "type": 25,
                "ttl": 300,
                "data": {"hex": "010003080a0b0c0d"},
            },
            {
                # NAPTR (35): deferred naming-authority-pointer record, kept Raw.
                "name": "example.com.",
                "type": 35,
                "ttl": 300,
                "data": {"hex": "0064000a0153000455524c00"},
            },
        ]
        return
    if "dnssec-ds-dnskey-rrsig" in key:
        # An authoritative response carrying the three core DNSSEC delegation and
        # signature records (RFC 4034) with raw numeric fields and opaque
        # key/digest/signature material that neither backend interprets
        # cryptographically. The DS RDATA is Key Tag, Algorithm, Digest Type, and
        # Digest (Section 5.1); the DNSKEY RDATA is Flags, Protocol, Algorithm,
        # and Public Key (Section 2.1); the RRSIG RDATA is Type Covered,
        # Algorithm, Labels, Original TTL, Signature Expiration, Signature
        # Inception, Key Tag, the uncompressed Signer's Name, and the Signature
        # (Section 3.1). Every name is uncompressed and the records use stable
        # values, so both backends agree byte-for-byte in both directions.
        # (dnssec-ds-dnskey-rrsig is not a substring of any other case id, so the
        # dispatcher resolves this branch unambiguously.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "DS"}]
        fields["answers"] = [
            {
                # DS: Key Tag 12345, Algorithm 8 (RSASHA256), Digest Type 2
                # (SHA-256), and a 32-octet opaque digest.
                "name": "example.com.",
                "type": "DS",
                "class": "IN",
                "ttl": 3600,
                "key_tag": 12345,
                "algorithm": 8,
                "digest_type": 2,
                "digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            },
            {
                # DNSKEY: Flags 257 (Zone Key + SEP), Protocol 3, Algorithm 8, and
                # an opaque public-key blob.
                "name": "example.com.",
                "type": "DNSKEY",
                "class": "IN",
                "ttl": 3600,
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "public_key": "03010001deadbeefcafebabe",
            },
            {
                # RRSIG over the DS RRset: every fixed field carries a stable raw
                # value, the Signer's Name is uncompressed example.com., and the
                # signature is opaque bytes.
                "name": "example.com.",
                "type": "RRSIG",
                "class": "IN",
                "ttl": 3600,
                "type_covered": "DS",
                "algorithm": 8,
                "labels": 2,
                "original_ttl": 3600,
                "signature_expiration": 0x65005D00,
                "signature_inception": 0x645E0B80,
                "key_tag": 12345,
                "signer_name": "example.com.",
                "signature": "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            },
        ]
        return
    if "dnssec-nsec-bitmaps" in key:
        # An authoritative response carrying two NSEC (type 47) answers whose
        # Type Bit Maps (RFC 4034 Section 4.1.2) exercise the full encoder:
        #
        #   * the first answer mirrors the RFC 4034 Section 4.3 example owner
        #     alfa.example.com. with next name host.example.com. and the present
        #     types A (1), MX (15), RRSIG (46), NSEC (47), and the unknown
        #     codepoint TYPE1234, which spans window block 0 and window block 4;
        #   * the second answer feeds an UNSORTED list with a DUPLICATE entry
        #     spanning three window blocks so that the libcrafter
        #     DnsTypeBitmaps::from_types sort/de-dup and the Scapy DNSRRNSEC
        #     RRlist2bitmap normalization both collapse to the same minimal,
        #     window-ordered encoding.
        #
        # Both backends sort, de-duplicate, and emit minimal windows, so the
        # decoded type set agrees in both directions even though the second
        # answer's source order is deliberately scrambled. The reference-built
        # bytes therefore match the RFC-style minimal encoding, and the
        # libcrafter-built bytes verify the sorted output. (dnssec-nsec-bitmaps
        # is dispatched here before the shorter dnssec-nsec / dnssec-nsec-bitmap
        # substrings, so resolution stays deterministic.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "alfa.example.com.", "qtype": "NSEC"}]
        fields["answers"] = [
            {
                # RFC 4034 Section 4.3 NSEC example: window 0 (A, MX, RRSIG,
                # NSEC) plus window 4 (the unknown codepoint TYPE1234). The
                # neutral type names and the bare numeric codepoint map to the
                # same RR-type values on both backends.
                "name": "alfa.example.com.",
                "type": "NSEC",
                "class": "IN",
                "ttl": 86400,
                "next_name": "host.example.com.",
                "type_bitmaps": ["A", "MX", "RRSIG", "NSEC", 1234],
            },
            {
                # Unsorted input with a duplicate A (1) entry spanning window
                # blocks 0, 1, and 255 (codepoints 0xff01). libcrafter sorts and
                # de-duplicates on construction and Scapy normalizes identically,
                # so the minimal, window-ordered encoding is deterministic.
                "name": "host.example.com.",
                "type": "NSEC",
                "class": "IN",
                "ttl": 86400,
                "next_name": "alfa.example.com.",
                "type_bitmaps": [47, 1, 300, 1, 0xFF01, 15],
            },
        ]
        return
    if "dnssec-nsec3" in key:
        # An authoritative response carrying three NSEC3 (type 50) answers whose
        # RDATA exercises the full RFC 5155 Section 3.2 wire layout: Hash
        # Algorithm, Flags, Iterations, Salt Length + Salt, Hash Length + next
        # hashed owner name, then Type Bit Maps. NSEC3 hash, salt, and next
        # hashed owner material is wire data only; libcrafter preserves the bytes
        # and never validates DNSSEC cryptography.
        #
        #   * answer 1 uses a NON-EMPTY salt, a non-empty next hashed owner name,
        #     and MULTIPLE type bitmap entries (A, NS, SOA, RRSIG, DNSKEY) in a
        #     single window block;
        #   * answer 2 uses an EMPTY salt (Salt Length 0 omits the Salt field)
        #     with a different next hashed owner name and a small bitmap;
        #   * answer 3 uses an UNKNOWN hash algorithm value (0xfe) and an UNKNOWN
        #     high type bitmap codepoint (TYPE65280) spanning a later window block,
        #     proving the numeric fields and minimal window encoding survive.
        #
        # Salt and next hashed owner are carried as hex blobs so both backends
        # preserve the exact octets as bytes, not text. The Scapy DNSRRNSEC3
        # reference and the libcrafter DnsRecord::nsec3 materializer produce the
        # same uncompressed bytes, so the case is strict-byte in both directions.
        # (dnssec-nsec3 is dispatched here, after dnssec-nsec-bitmaps and before
        # any shorter dnssec-nsec substring branch, so resolution is
        # deterministic.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "NSEC3"}]
        fields["answers"] = [
            {
                # Non-empty salt, non-empty next hashed owner name, and multiple
                # type bitmap entries in a single window block.
                "name": "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.com.",
                "type": "NSEC3",
                "class": "IN",
                "ttl": 86400,
                "hash_algorithm": 1,  # SHA-1
                "flags": 1,  # Opt-Out
                "iterations": 12,
                "salt": {"hex": "aabbccdd"},
                "next_hashed_owner": {
                    "hex": "1112131415161718191a1b1c1d1e1f2021222324"
                },
                "type_bitmaps": ["A", "NS", "SOA", "RRSIG", "DNSKEY"],
            },
            {
                # Empty salt: Salt Length 0 omits the Salt field entirely.
                "name": "2vptu5timamqttgl4luu9kg21e0aor3s.example.com.",
                "type": "NSEC3",
                "class": "IN",
                "ttl": 86400,
                "hash_algorithm": 1,
                "flags": 0,
                "iterations": 0,
                "salt": {"hex": ""},
                "next_hashed_owner": {
                    "hex": "25262728292a2b2c2d2e2f30313233343536373839"
                },
                "type_bitmaps": ["A", "RRSIG"],
            },
            {
                # Unknown hash algorithm value and an unknown high type bitmap
                # codepoint spanning a later window block; both stay raw numeric
                # wire data.
                "name": "th1q5pl8ku5b8c98er8gj7p9hf2d8jcm.example.com.",
                "type": "NSEC3",
                "class": "IN",
                "ttl": 86400,
                "hash_algorithm": 0xFE,  # unassigned hash algorithm
                "flags": 0,
                "iterations": 2500,
                "salt": {"hex": "deadbeef"},
                "next_hashed_owner": {
                    "hex": "393a3b3c3d3e3f404142434445464748494a4b4c"
                },
                "type_bitmaps": ["A", "RRSIG", 65280],
            },
        ]
        return
    if "svcb-https" in key:
        # An authoritative response carrying one answer per SVCB/HTTPS
        # service-binding shape (RFC 9460 / RFC 9461). Every SvcParamValue is
        # opaque wire data carried verbatim through both backends; the Scapy
        # reference owns the exact RDATA bytes and libcrafter materializes the
        # same bytes through DnsRecord::svcb / ::https and SvcParams, so the case
        # is strict-byte in both directions. The third answer feeds params in a
        # deliberately scrambled key order; both the libcrafter SvcParams
        # constructor and the reference RDATA builder sort the params into
        # strictly increasing SvcParamKey order, so the encoded output is
        # deterministic regardless of source order. Values:
        #   * mandatory (0): the two-octet SvcParamKey list [alpn(1), port(3)];
        #   * alpn (1): the length-prefixed ALPN id list "h2"/"h3-29";
        #   * no-default-alpn (2): an empty value;
        #   * port (3): the 16-bit port in network byte order;
        #   * ipv4hint (4): two concatenated documentation IPv4 addresses;
        #   * ipv6hint (6): one documentation IPv6 address;
        #   * dohpath (7): the RFC 9461 DoH URI template as UTF-8 octets;
        #   * an unknown SvcParamKey (65280): opaque bytes preserved verbatim.
        # (svcb-https is dispatched here before any shorter dns-svcb / dns-https
        # substring branch, so resolution stays deterministic.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "HTTPS"}]
        fields["answers"] = [
            {
                # SVCB AliasMode: SvcPriority 0 with a real (non-root) target and
                # an empty SvcParams list (RFC 9460 Section 2.4.2).
                "name": "example.com.",
                "type": "SVCB",
                "class": "IN",
                "ttl": 3600,
                "priority": 0,
                "target": "foo.example.com.",
                "params": [],
            },
            {
                # HTTPS ServiceMode: non-zero SvcPriority with a root target and
                # the full named SvcParam set, listed out of key order to prove
                # the deterministic sort. mandatory lists alpn(1) and port(3).
                "name": "example.com.",
                "type": "HTTPS",
                "class": "IN",
                "ttl": 7200,
                "priority": 1,
                "target": ".",
                "params": [
                    {"key": "ipv6hint", "value": {"hex": "20010db8000000000000000000000001"}},
                    {"key": "port", "value": {"hex": "01bb"}},
                    {"key": "alpn", "value": {"hex": "0268320568332d3239"}},
                    {"key": "mandatory", "value": {"hex": "00010003"}},
                    {"key": "no-default-alpn", "value": {"hex": ""}},
                    {"key": "dohpath", "value": {"hex": "2f646e732d71756572797b3f646e737d"}},
                    {"key": "ipv4hint", "value": {"hex": "c0000201c000020a"}},
                ],
            },
            {
                # SVCB ServiceMode with a non-root target carrying an unknown
                # SvcParamKey (65280, RFC 6895 private use) plus a named param, so
                # an unrecognized key still round trips byte-for-byte as opaque
                # bytes alongside a known key.
                "name": "svc.example.com.",
                "type": "SVCB",
                "class": "IN",
                "ttl": 60,
                "priority": 16,
                "target": "svc.example.net.",
                "params": [
                    {"key": 65280, "value": {"hex": "deadbeef"}},
                    {"key": "no-default-alpn", "value": {"hex": ""}},
                ],
            },
        ]
        return
    if "section-placement" in key:
        # A single authoritative response whose records each land in their own
        # DNS section (RFC 1035 Section 4.1.1): one question (QDCOUNT), one A
        # answer (ANCOUNT), one NS authority record (NSCOUNT), and two additional
        # records (ARCOUNT) -- an EDNS(0) OPT pseudo-record (RFC 6891) plus a
        # non-OPT A record. Both backends materialize the answer, authority, and
        # additional sections from independent plan keys, so the case proves that
        # placement and counts survive decode and recompile and that no record
        # migrates between sections. Every value is stable and uncompressed, so
        # the encoded bytes agree in both directions. ("section-placement" is a
        # substring only of this case id, so the dispatcher resolves this branch
        # unambiguously.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields["answers"] = [
            {
                # Answer section: the requested A record.
                "name": "example.com.",
                "type": "A",
                "class": "IN",
                "ttl": 3600,
                "address": "192.0.2.10",
            },
        ]
        fields["authority"] = [
            {
                # Authority section: an NS record delegating the zone.
                "name": "example.com.",
                "type": "NS",
                "class": "IN",
                "ttl": 3600,
                "target": "ns1.example.com.",
            },
        ]
        fields["additional"] = [
            {
                # Additional section: the glue A record for the authority NS.
                "name": "ns1.example.com.",
                "type": "A",
                "class": "IN",
                "ttl": 3600,
                "address": "192.0.2.53",
            },
            {
                # Additional section: an EDNS(0) OPT pseudo-record (RFC 6891) with
                # a root owner name, a non-default UDP payload size, and an empty
                # option list.
                "name": ".",
                "type": "OPT",
                "udp_payload_size": 1232,
                "extended_rcode": 0,
                "version": 0,
                "dnssec_ok": False,
                "options": [],
            },
        ]
        fields.pop("authorities", None)
        fields.pop("additionals", None)
        return
    if "header-flags-opcodes" in key:
        fields["is_response"] = True
        fields["opcode"] = "status"
        fields["response_code"] = "refused"
        fields["flags"] = [
            "authoritative",
            "truncated",
            "recursion_available",
            "authentic_data",
            "checking_disabled",
        ]
        fields.pop("answers", None)
        return
    if "header-empty-sections" in key:
        # Empty answer/authority/additional sections so the auto-filled counts
        # stay zero while the single question keeps QDCOUNT at one.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        fields.pop("authority", None)
        fields.pop("authorities", None)
        fields.pop("additional", None)
        fields.pop("additionals", None)
        return
    if "header-counts" in key:
        # One record in each of the three response sections so the encoder
        # auto-fills ANCOUNT/NSCOUNT/ARCOUNT to nonzero values from the typed
        # vectors rather than from any user-set count field.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative", "recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields["answers"] = [
            {"name": "example.com.", "type": "A", "ttl": 60, "address": "192.0.2.10"}
        ]
        fields["authority"] = [
            {"name": "example.com.", "type": "NS", "ttl": 300, "target": "ns1.example.com."}
        ]
        fields["additional"] = [
            {"name": "ns1.example.com.", "type": "A", "ttl": 300, "address": "192.0.2.53"}
        ]
        return
    if "header-raw-flags" in key:
        # Reserved Z header bit set through the raw-flags escape hatch; the
        # encoder must preserve a bit that has no named setter.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["reserved_z"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        return
    if "header-opcode" in key:
        # A non-default named opcode on a plain query; STATUS keeps the message
        # otherwise minimal so the four opcode bits are the load-bearing field.
        fields["is_response"] = False
        fields["opcode"] = "status"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_desired"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        return
    if "header-rcode" in key:
        # A named rcode on a response; REFUSED is representable in both
        # materializers and exercises the low four flag-word bits.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "refused"
        fields["flags"] = ["recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        return
    if "header-flags" in key:
        # Every named header flag bit set on a recursive query so each flag is
        # exercised independently of opcode/rcode.
        fields["is_response"] = False
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = [
            "authoritative",
            "truncated",
            "recursion_desired",
            "recursion_available",
            "authentic_data",
            "checking_disabled",
        ]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        return
    if "header-qr" in key:
        # Response-bit set with recursion-available, the canonical server reply
        # header shape, paired with the matching query via the QR bit.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        return
    if "header-id" in key:
        # Nonzero transaction ID on an otherwise plain query so the 16-bit ID
        # field is the load-bearing header value.
        fields["is_response"] = False
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_desired"]
        fields["transaction_id"] = 0x1A2B
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        return
    if "name-root-escaped" in key:
        # Byte-preserving name shapes in one message: the root name as the
        # question owner, a trailing-dot text answer name, a CNAME target that
        # carries literal dot and backslash octets via the RFC 1035 Section 5.1
        # \DDD escape, and a PTR target whose label is a non-UTF-8 byte run
        # (\000 and \255). The libcrafter materializer parses these presentation
        # strings back into the exact wire octets, so the decoded header/section
        # model agrees in both directions. The compared subset is header plus
        # section counts, so the special label octets never need a lossless
        # Scapy high-level encode; the faithful byte-preserving assertions live
        # in the crate name tests.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_available"]
        fields["questions"] = [{"qname": ".", "qtype": "A"}]
        fields["answers"] = [
            {"name": "example.com.", "type": "A", "ttl": 60, "address": "192.0.2.10"},
            {
                "name": "trailing.example.com.",
                "type": "CNAME",
                "ttl": 300,
                # Literal '.' (\046) and '\' (\092) inside a single label.
                "target": "lit\\046dot\\092slash.example.com.",
            },
            {
                "name": "ptr.example.com.",
                "type": "PTR",
                "ttl": 300,
                # Non-UTF-8 label: NUL (\000) and 0xff (\255) octets.
                "target": "\\000\\255.example.com.",
            },
        ]
        return
    if "record-soa" in key:
        # Focused single-SOA response so a SOA decode failure reproduces without
        # the SRV answer in the message. Every fixed SOA field carries a distinct
        # nonzero value (SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM) and both nested
        # names (MNAME, RNAME) are documentation names, so the strict byte encode
        # pins each field against the Scapy reference. Checked before the combined
        # soa-srv-records branch; the focused id never contains that token.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "SOA"}]
        fields["answers"] = [
            {
                "name": "example.com.",
                "type": "SOA",
                "ttl": 300,
                "primary_name": "ns1.example.com.",
                "responsible_name": "hostmaster.example.com.",
                "serial": 2024010101,
                "refresh": 7200,
                "retry": 3600,
                "expire": 1209600,
                "minimum": 300,
            }
        ]
        return
    if "record-srv" in key:
        # Focused single-SRV response so an SRV decode failure reproduces without
        # the SOA answer. The three fixed 16-bit fields (priority, weight, port)
        # are distinct nonzero values and the target is a documentation name, so
        # the strict byte encode pins every SRV field against the Scapy reference.
        # Checked before the combined soa-srv-records branch; the focused id never
        # contains that token.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "_sip._tcp.example.com.", "qtype": "SRV"}]
        fields["answers"] = [
            {
                "name": "_sip._tcp.example.com.",
                "type": "SRV",
                "ttl": 60,
                "priority": 10,
                "weight": 60,
                "port": 5060,
                "target": "sip.example.com.",
            }
        ]
        return
    if "soa-srv-records" in key:
        # A response carrying one SOA authority-style answer and one SRV answer
        # so the libcrafter materializer exercises both typed record builders in
        # a single message and compares against the Scapy reference.
        fields["is_response"] = True
        fields["questions"] = [{"qname": "example.com.", "qtype": "SOA"}]
        fields["answers"] = [
            {
                "name": "example.com.",
                "type": "SOA",
                "ttl": 300,
                "primary_name": "ns1.example.com.",
                "responsible_name": "hostmaster.example.com.",
                "serial": 2024010101,
                "refresh": 7200,
                "retry": 3600,
                "expire": 1209600,
                "minimum": 300,
            },
            {
                "name": "_sip._tcp.example.com.",
                "type": "SRV",
                "ttl": 60,
                "priority": 10,
                "weight": 60,
                "port": 5060,
                "target": "sip.example.com.",
            },
        ]
        return
    if "a-aaaa-records" in key:
        # An authoritative response carrying A and AAAA answers for the same
        # owner name, with stable TTLs and documentation IPv4/IPv6 addresses.
        # The two answers are ordered AAAA before A so the case also exercises a
        # non-canonical answer ordering; both materializers must preserve the
        # supplied order and emit identical uncompressed names so the encode is
        # byte-exact in both directions.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative", "recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields["answers"] = [
            {
                "name": "host.example.com.",
                "type": "AAAA",
                "ttl": 3600,
                "address": "2001:db8:1::10",
            },
            {
                "name": "host.example.com.",
                "type": "A",
                "ttl": 3600,
                "address": "192.0.2.10",
            },
            {
                "name": "alt.example.net.",
                "type": "A",
                "ttl": 300,
                "address": "198.51.100.20",
            },
            {
                "name": "alt.example.net.",
                "type": "AAAA",
                "ttl": 300,
                "address": "2001:db8:2::20",
            },
        ]
        return
    if "name-records" in key:
        # An authoritative response carrying NS, CNAME, and PTR answers. NS,
        # CNAME, and PTR all carry their RDATA as a single nested <domain-name>,
        # so all three map to DnsRecordData::Name and must match Scapy in both
        # the record owner and the RDATA name. The CNAME target is root-adjacent
        # (a single label directly under the root) and the PTR owner is a
        # reverse-DNS name, so the case spans ordinary and boundary name shapes.
        # Both materializers emit every name uncompressed, so the encode is
        # byte-exact in both directions. The compressed companion is the separate
        # dns-name-records-compressed case. (Checked after name-records-compressed,
        # which returns early at the top of this dispatcher.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "NS"}]
        fields["answers"] = [
            {
                "name": "example.com.",
                "type": "NS",
                "ttl": 3600,
                "target": "ns1.example.com.",
            },
            {
                "name": "www.example.com.",
                "type": "CNAME",
                "ttl": 300,
                # Root-adjacent target: a single label directly under the root.
                "target": "host.example.",
            },
            {
                "name": "20.113.0.203.in-addr.arpa.",
                "type": "PTR",
                "ttl": 300,
                "target": "host.example.com.",
            },
        ]
        return
    if "mx-txt-records" in key:
        # A response carrying one MX answer and a sequence of TXT answers so a
        # single message exercises the MX preference + nested exchange name plus
        # every TXT character-string shape libcrafter must preserve: one string,
        # multiple strings, an empty string, a non-UTF-8 binary string (carried
        # as hex so neither materializer mangles the octets), and a single
        # string at the 255-octet length boundary. Both materializers emit
        # uncompressed names and exact-length character-strings, so the encode is
        # byte-exact in both directions.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative", "recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "MX"}]
        fields["answers"] = [
            {
                "name": "example.com.",
                "type": "MX",
                "ttl": 3600,
                "preference": 10,
                "exchange": "mail.example.com.",
            },
            {
                "name": "example.com.",
                "type": "TXT",
                "ttl": 300,
                "strings": ["v=spf1 -all"],
            },
            {
                "name": "example.com.",
                "type": "TXT",
                "ttl": 300,
                "strings": ["first chunk", "second chunk"],
            },
            {
                "name": "empty.example.com.",
                "type": "TXT",
                "ttl": 300,
                "strings": [""],
            },
            {
                "name": "bin.example.com.",
                "type": "TXT",
                "ttl": 300,
                # Non-UTF-8 octets (NUL, 0xfe, 0xff, DEL) carried as hex so the
                # character-string bytes survive both materializers verbatim.
                "strings": [{"hex": "000a1ffeff617f"}],
            },
            {
                "name": "max.example.com.",
                "type": "TXT",
                "ttl": 300,
                # A single character-string at the 255-octet length boundary.
                "strings": [{"hex": "78" * 255}],
            },
        ]
        return
    if "multi-question-classes" in key:
        # A single query carrying several questions in a deterministic order that
        # exercise the QTYPE and QCLASS axes together: named QTYPEs (A, AAAA, MX,
        # TXT, ANY) and a private unknown numeric QTYPE, paired with every named
        # QCLASS (IN, CH, HS, NONE, ANY) and a private unknown numeric QCLASS.
        # Section counts must auto-fill QDCOUNT from this questions vector, and
        # both materializers must preserve the unknown numeric codepoints.
        fields["is_response"] = False
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_desired"]
        fields["questions"] = [
            {"qname": "example.com.", "qtype": "A", "qclass": "IN"},
            {"qname": "example.net.", "qtype": "AAAA", "qclass": "CH"},
            {"qname": "mail.example.com.", "qtype": "MX", "qclass": "HS"},
            {"qname": "txt.example.com.", "qtype": "TXT", "qclass": "NONE"},
            {"qname": "any.example.com.", "qtype": "ANY", "qclass": "ANY"},
            # Private-use QTYPE 65280 (RFC 6895 Section 3.1) and QCLASS 65280
            # (RFC 6895 Section 3.2) as raw numeric codepoints neither backend
            # maps to a named type or class.
            {"qname": "unknown.example.com.", "qtype": 65280, "qclass": 65280},
        ]
        fields.pop("answers", None)
        return
    if "edns-options" in key:
        # A response carrying a single EDNS(0) OPT pseudo-record (RFC 6891
        # Section 6.1) whose RDATA holds an ordered list of option TLVs
        # (Section 6.1.2). The matrix spans the three source-backed options with
        # named constructors (NSID RFC 5001, COOKIE RFC 7873, Padding RFC 7830),
        # one option that has a registry mnemonic but no named constructor (DAU
        # RFC 6975, code 5), and one unknown option code (65534) that has no
        # mnemonic at all. The option order is fixed so the encoded byte stream
        # is deterministic, and every OPTION-DATA payload is carried as raw hex
        # so neither backend reinterprets the per-option bit field: Scapy emits
        # each as a generic EDNS0TLV(optcode=N, optdata=...) and libcrafter
        # carries each as an EdnsOption preserving the exact code and data bytes.
        # ("edns-options" is a substring only of this case id, never of
        # dns-edns-opt-basic, so the dispatcher resolves this branch
        # unambiguously and before the edns-opt-basic branch below.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        fields["additional"] = [
            {
                "name": ".",
                "type": "OPT",
                "udp_payload_size": 4096,
                "extended_rcode": 0,
                "version": 0,
                "dnssec_ok": True,
                "options": [
                    # NSID (code 3): opaque name-server identifier bytes.
                    {"option_code": 3, "option_data": "6e733031"},
                    # COOKIE (code 10): an 8-octet client cookie.
                    {"option_code": 10, "option_data": "0102030405060708"},
                    # Padding (code 12): zero octets used only for size padding.
                    {"option_code": 12, "option_data": "0000000000000000"},
                    # DAU (code 5): a registered option with a mnemonic but no
                    # named libcrafter constructor; raw algorithm-list bytes.
                    {"option_code": 5, "option_data": "0501080a"},
                    # Unknown option code 65534: no IANA mnemonic, preserved as
                    # opaque bytes.
                    {"option_code": 65534, "option_data": "cafe"},
                ],
            },
        ]
        return
    if "edns-opt-basic" in key:
        # A response carrying several EDNS(0) OPT pseudo-records in the additional
        # section (RFC 6891 Section 6.1). Each OPT exercises a different basic
        # field combination so a regression in any one packed field reproduces in
        # isolation: the UDP payload size lives in the OPT CLASS, while the
        # extended RCODE, EDNS version, and DO flag are packed into the OPT TTL.
        # The owner name is always root ("."), the option list is empty (the
        # option-TLV matrix is the separate dns-edns-options-* cases), and every
        # value round trips byte-for-byte because both the Scapy DNSRROPT
        # reference and the libcrafter DnsRecord::opt builder pack the same wire
        # fields. (edns-opt-basic is a substring only of this case id, so the
        # dispatcher resolves this branch unambiguously.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        fields["additional"] = [
            {
                # Bare OPT: default UDP payload size, no extended RCODE/version,
                # DO clear, empty option list.
                "name": ".",
                "type": "OPT",
                "udp_payload_size": 4096,
                "extended_rcode": 0,
                "version": 0,
                "dnssec_ok": False,
                "options": [],
            },
            {
                # Non-default small UDP payload size with the DO flag set.
                "name": ".",
                "type": "OPT",
                "udp_payload_size": 512,
                "extended_rcode": 0,
                "version": 0,
                "dnssec_ok": True,
                "options": [],
            },
            {
                # Non-zero extended RCODE (upper 8 bits of the 12-bit RCODE) on a
                # 1232-octet payload size, DO clear.
                "name": ".",
                "type": "OPT",
                "udp_payload_size": 1232,
                "extended_rcode": 0x12,
                "version": 0,
                "dnssec_ok": False,
                "options": [],
            },
            {
                # Maximum UDP payload size, a non-default EDNS version, DO set.
                "name": ".",
                "type": "OPT",
                "udp_payload_size": 65535,
                "extended_rcode": 0,
                "version": 1,
                "dnssec_ok": True,
                "options": [],
            },
        ]
        return
    if "response" in key:
        fields["is_response"] = True
        fields.pop("answers", None)
    if "multiple-questions" in key:
        fields["questions"] = [
            {"qname": "example.com.", "qtype": "A"},
            {"qname": "example.net.", "qtype": "AAAA"},
        ]
    if "truncated" in key:
        fields["flags"] = ["recursion_desired", "truncated"]
        fields["response_code"] = "server_failure"


def _dns_compressed_names_raw_spec() -> JSONObject:
    """Raw DNS spec with explicit compression pointers for the raw helper.

    The question name ``example.com.`` lands at the fixed offset 12 (right after
    the 12-octet header), so every compressed name in the message points back to
    offset 12. The case exercises a compressed question owner name (re-used as the
    first answer owner via a bare pointer) and a compression pointer in the
    embedded <domain-name> of each byte-preserving record type libcrafter
    decodes: CNAME/NS/PTR (name at RDATA start), MX (after the 2-octet
    preference), SOA (compressed MNAME and RNAME before the 20 fixed octets), SRV
    (after priority/weight/port), RRSIG signer (after the 18 fixed octets), NSEC
    next-domain (before the type bitmap), and SVCB/HTTPS target (after the 2-octet
    priority). Scapy's high-level fields will not emit these pointers, so the
    bytes are built by hand while staying under the Scapy reference backend.
    libcrafter re-encodes every name uncompressed, so this case is normalized: the
    decoded DNS name model agrees while the recompiled bytes differ from the
    pointer input (see specs/features/dns-behavior.yaml byte_policy).
    """

    ptr = 12  # The question name example.com. is at the fixed 12-octet offset.
    # The 20 fixed SOA octets after MNAME/RNAME: serial, refresh, retry, expire,
    # minimum (all 32-bit). The 18 fixed RRSIG octets: type covered (A=0x0001),
    # algorithm, labels, original TTL, expiration, inception, key tag. The NSEC
    # type bitmap is window 0, a 6-octet bitmap, with the A (1), RRSIG (46), and
    # NSEC (47) bits set.
    soa_fixed = "0000000100000e1000000708001baf8000000384"
    rrsig_fixed = "0001050200000e10655f5d00655e0b800539"
    nsec_bitmap = "0006400000000003"
    return {
        "transaction_id": 0x1234,
        "is_response": True,
        "flags": ["recursion_desired", "recursion_available"],
        "response_code": "no_error",
        "questions": [
            {"name": "example.com.", "type": "A", "class": "IN"},
        ],
        "answers": [
            # CNAME owner is a bare pointer to the question name; the RDATA target
            # is the label "alias" plus a pointer back to example.com.
            {
                "name_with_pointer": {"prefix": None, "pointer_offset": ptr},
                "type": "CNAME",
                "class": "IN",
                "ttl": 300,
                "target_with_pointer": {"prefix": "alias", "pointer_offset": ptr},
            },
            # NS RDATA is a bare pointer to the question name.
            {
                "name": "example.com.",
                "type": "NS",
                "class": "IN",
                "ttl": 300,
                "target_with_pointer": {"prefix": "ns1", "pointer_offset": ptr},
            },
            # PTR RDATA is a compressed name.
            {
                "name": "1.2.0.192.in-addr.arpa.",
                "type": "PTR",
                "class": "IN",
                "ttl": 300,
                "target_with_pointer": {"prefix": "host", "pointer_offset": ptr},
            },
            # MX exchange is a compressed name after the 2-octet preference (10).
            {
                "name": "example.com.",
                "type": "MX",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "prefix_hex": "000a",
                    "pointers": [{"prefix": "mail", "pointer_offset": ptr}],
                },
            },
            # SOA MNAME and RNAME are both compression pointers before 20 fixed
            # octets.
            {
                "name": "example.com.",
                "type": "SOA",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "pointers": [
                        {"prefix": "ns1", "pointer_offset": ptr},
                        {"prefix": "hostmaster", "pointer_offset": ptr},
                    ],
                    "suffix_hex": soa_fixed,
                },
            },
            # SRV target is a compressed name after priority/weight/port.
            {
                "name": "_sip._tcp.example.com.",
                "type": "SRV",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "prefix_hex": "000a0005162c",
                    "pointers": [{"prefix": "sip", "pointer_offset": ptr}],
                },
            },
            # RRSIG signer name is a compression pointer after the 18 fixed
            # octets; the remaining bytes are an opaque signature blob.
            {
                "name": "example.com.",
                "type": "RRSIG",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "prefix_hex": rrsig_fixed,
                    "pointers": [{"prefix": None, "pointer_offset": ptr}],
                    "suffix_hex": "abcdef0123456789",
                },
            },
            # NSEC next-domain name is a compression pointer before the type
            # bitmap window.
            {
                "name": "example.com.",
                "type": "NSEC",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "pointers": [{"prefix": "next", "pointer_offset": ptr}],
                    "suffix_hex": nsec_bitmap,
                },
            },
            # SVCB target is a compression pointer after the 2-octet priority.
            {
                "name": "_dns.example.com.",
                "type": "SVCB",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "prefix_hex": "0001",
                    "pointers": [{"prefix": "svc", "pointer_offset": ptr}],
                },
            },
            # HTTPS target is a compression pointer after the 2-octet priority.
            {
                "name": "example.com.",
                "type": "HTTPS",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "prefix_hex": "0001",
                    "pointers": [{"prefix": None, "pointer_offset": ptr}],
                },
            },
        ],
    }


def _dns_name_records_compressed_raw_spec() -> JSONObject:
    """Raw DNS spec for the compressed NS/CNAME/PTR name-records case.

    The question name ``example.com.`` is at the fixed 12-octet offset, so every
    owner and embedded RDATA name in this message is a compression pointer back
    to offset 12. NS, CNAME, and PTR all carry their RDATA as a single nested
    <domain-name> at the start of the RDATA, so each answer's target is a label
    prefix plus a pointer to the question name. Scapy's high-level fields will not
    emit these pointers, so the bytes are built by hand under the Scapy reference
    backend; libcrafter follows each pointer on decode and re-encodes every name
    uncompressed, so this case is normalized and matches the uncompressed
    ``dns-name-records`` decoded DnsRecordData::Name model.
    """

    ptr = 12  # The question name example.com. is at the fixed 12-octet offset.
    return {
        "transaction_id": 0x4E43,
        "is_response": True,
        "flags": ["authoritative"],
        "response_code": "no_error",
        "questions": [
            {"name": "example.com.", "type": "NS", "class": "IN"},
        ],
        "answers": [
            # NS owner is a bare pointer to the question name; the RDATA target is
            # the label "ns1" plus a pointer back to example.com.
            {
                "name": "example.com.",
                "type": "NS",
                "class": "IN",
                "ttl": 3600,
                "target_with_pointer": {"prefix": "ns1", "pointer_offset": ptr},
            },
            # CNAME owner is "www" plus a pointer; the RDATA target is "host"
            # plus a pointer back to example.com.
            {
                "name_with_pointer": {"prefix": "www", "pointer_offset": ptr},
                "type": "CNAME",
                "class": "IN",
                "ttl": 300,
                "target_with_pointer": {"prefix": "host", "pointer_offset": ptr},
            },
            # PTR owner is "ptr" plus a pointer; the RDATA target is "host" plus a
            # pointer back to example.com.
            {
                "name_with_pointer": {"prefix": "ptr", "pointer_offset": ptr},
                "type": "PTR",
                "class": "IN",
                "ttl": 300,
                "target_with_pointer": {"prefix": "host", "pointer_offset": ptr},
            },
        ],
    }


def _dns_answers_for_domain(ctx: _SamplingContext, domain: object) -> list[JSONObject]:
    if domain == "aaaa":
        return [{"name": "example.net.", "type": "AAAA", "ttl": 60, "address": ctx.dst_ipv6}]
    if domain == "cname":
        return [{"name": "example.org.", "type": "CNAME", "ttl": 60, "target": "alias.example.org."}]
    return [{"name": "example.com.", "type": "A", "ttl": 60, "address": ctx.dst_ipv4}]


def _apply_bgp_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    case: str,
    behavior: str,
) -> None:
    bgp = fields["bgp"]
    bgp["marker"] = {"hex": "ff" * 16}
    bgp["type"] = _bgp_message_type_for_case(case)
    bgp["message_type"] = bgp["type"]

    if "tcp" in fields:
        fields["tcp"]["dst_port"] = 179
    if "payload" in fields:
        fields["payload"] = {"hex": "", "length": 0}

    if bgp["type"] == "keepalive":
        bgp.pop("body", None)
        return

    if bgp["type"] == "open":
        bgp["body"] = {"hex": _bgp_open_body_hex(case)}
        return

    if bgp["type"] == "notification":
        bgp["body"] = {"hex": "0203deadbeef"}
        return

    if bgp["type"] == "route_refresh":
        bgp["body"] = {"hex": "00010001"}
        return

    if bgp["type"] == "update":
        bgp["body"] = {"hex": _bgp_update_body_hex(stack=stack, case=case, behavior=behavior)}


def _apply_ospf_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    case: str,
    behavior: str,
) -> None:
    """Inject the per-type OSPFv2 body for a smoke case.

    The body field names match the Scapy reference builder
    (``tools/oracle/engine/backends/scapy/packets.py`` ``_ospf*``) so the
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


def _is_ospf_smoke_case(case: str) -> bool:
    """Whether ``case`` is sampled by the focused ospf-smoke profile."""

    return case.replace("_", "-").startswith("ospf-")


def _bgp_message_type_for_case(case: str) -> str:
    normalized = case.replace("_", "-")
    if "keepalive" in normalized:
        return "keepalive"
    if "notification" in normalized:
        return "notification"
    if "route-refresh" in normalized:
        return "route_refresh"
    if "open" in normalized:
        return "open"
    return "update"


def _bgp_open_body_hex(case: str) -> str:
    base = "04fc00005ac0000201"
    if "capabilities" not in case.replace("_", "-"):
        return base + "00"
    capabilities = (
        "010400010001"  # Multiprotocol IPv4 unicast.
        "010400020001"  # Multiprotocol IPv6 unicast.
        "41040000fc00"  # Four-octet AS 64512.
        "0200"          # Route refresh.
    )
    optional_parameters = "02" + f"{len(bytes.fromhex(capabilities)):02x}" + capabilities
    return base + f"{len(bytes.fromhex(optional_parameters)):02x}" + optional_parameters


def _bgp_update_body_hex(*, stack: Sequence[str], case: str, behavior: str) -> str:
    normalized = f"{case} {behavior}".replace("_", "-")
    if "withdraw" in normalized:
        return "000418c000020000"
    if "mp-reach" in normalized:
        mp_reach_value = "00020110" + "20010db8000000000000000000000001" + "00" + "2020010db8"
        attrs = "800e" + f"{len(bytes.fromhex(mp_reach_value)):02x}" + mp_reach_value
        return "0000" + len(bytes.fromhex(attrs)).to_bytes(2, "big").hex() + attrs
    if "extended-communities" in normalized:
        attrs = "c01010" + "0002fc0000000064" + "0002fc00000000c8"
        return "0000" + len(bytes.fromhex(attrs)).to_bytes(2, "big").hex() + attrs
    if "large-communities" in normalized:
        attrs = (
            "c02018"
            "0000fc000000006400000001"
            "0000fc000000006400000002"
        )
        return "0000" + len(bytes.fromhex(attrs)).to_bytes(2, "big").hex() + attrs
    if "communities" in normalized:
        attrs = "c00808ffffff0100fc0064"
        return "0000" + len(bytes.fromhex(attrs)).to_bytes(2, "big").hex() + attrs
    attrs = "40010100" + "4002040201fc00" + "400304c0000201"
    nlri = "18c63364"
    if "announce" not in normalized and "ipv6" in stack:
        nlri = ""
    return "0000" + len(bytes.fromhex(attrs)).to_bytes(2, "big").hex() + attrs + nlri


# --------------------------------------------------------------------------
# RIP / RIPng behavior enrichment.
#
# Like BGP, the RIP/RIPng header scalars are seeded by the field sampler and the
# per-case message body (route entries, the AFI 0xFFFF authentication entry, and
# the RIPng RTEs) is attached here. The libcrafter adapter and the Scapy
# reference backend read the same plan field names (command/version/reserved,
# entries[*].{address_family,route_tag,address,subnet_mask,next_hop,metric},
# auth.{type,simple_password}, rtes[*].{prefix,route_tag,prefix_len,metric,
# next_hop}), so a single field block materializes byte-identically on both
# backends. Every address lives in documentation space (RFC 5737 / RFC 3849).
# The authentication case uses simple-password (RFC 2453 §4.1) because that is
# the byte-safe form the Scapy RIPAuth reference can reproduce; keyed message
# digest is covered by the feature-spec / native-fixture path, not the smoke
# cross-backend run.


def _rip_command_for_case(case: str) -> str:
    """RIP/RIPng command for a coverage case: request vs response (RFC 1058 §4)."""

    if "request" in case.replace("_", "-"):
        return "request"
    return "response"


def _rip_version_for_case(case: str) -> int:
    """RIP version for a coverage case: v1 only for the explicit v1 cases."""

    return 1 if "v1" in case.replace("_", "-") else 2


def _apply_rip_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    case: str,
    behavior: str,
) -> None:
    rip = fields["rip"]
    rip["command"] = _rip_command_for_case(case)
    rip["version"] = _rip_version_for_case(case)
    rip.setdefault("reserved", 0)
    rip.pop("auth", None)
    rip.pop("entries", None)

    if "udp" in fields:
        fields["udp"]["src_port"] = 520
        fields["udp"]["dst_port"] = 520
    if "payload" in fields:
        fields["payload"] = {"hex": "", "length": 0}

    normalized = case.replace("_", "-")

    if rip["command"] == "request":
        # Request-whole-table sentinel (RFC 2453 §3.4.1 / RFC 1058 §3.4.1):
        # one AFI 0 entry with metric 16 (infinity).
        rip["entries"] = [
            {
                "address_family": 0,
                "route_tag": 0,
                "address": "0.0.0.0",
                "subnet_mask": "0.0.0.0",
                "next_hop": "0.0.0.0",
                "metric": 16,
            }
        ]
        return

    if "auth" in normalized:
        # Simple-password authenticated response (RFC 2453 §4.1): the AFI 0xFFFF
        # leading entry carries a 16-octet cleartext password, followed by a
        # single v2 route entry.
        rip["auth"] = {"type": 2, "simple_password": "oraclesecret"}
        rip["entries"] = [_rip_v2_entry()]
        return

    if rip["version"] == 1:
        # RFC 1058 v1 route entry: AFI IP, address + metric only (route tag,
        # subnet mask, and next hop are reserved-zero on the wire).
        rip["entries"] = [
            {
                "address_family": 2,
                "route_tag": 0,
                "address": "192.0.2.0",
                "subnet_mask": "0.0.0.0",
                "next_hop": "0.0.0.0",
                "metric": 1,
            }
        ]
        return

    # RFC 2453 v2 response: a route entry carrying route tag, subnet mask, and
    # next hop. The matrix case adds a second entry so a multi-entry message is
    # exercised by the smoke run.
    entries = [_rip_v2_entry()]
    if "matrix" in normalized:
        entries.append(
            {
                "address_family": 2,
                "route_tag": 64512,
                "address": "198.51.100.0",
                "subnet_mask": "255.255.255.0",
                "next_hop": "192.0.2.1",
                "metric": 2,
            }
        )
    rip["entries"] = entries


def _rip_v2_entry() -> dict[str, object]:
    """A canonical RFC 2453 v2 route entry in documentation address space."""

    return {
        "address_family": 2,
        "route_tag": 0,
        "address": "192.0.2.0",
        "subnet_mask": "255.255.255.0",
        "next_hop": "0.0.0.0",
        "metric": 1,
    }


def _apply_ripng_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    case: str,
    behavior: str,
) -> None:
    ripng = fields["ripng"]
    ripng["command"] = _rip_command_for_case(case)
    ripng["version"] = 1
    ripng.setdefault("reserved", 0)
    ripng.pop("rtes", None)
    ripng.pop("entries", None)

    if "udp" in fields:
        fields["udp"]["src_port"] = 521
        fields["udp"]["dst_port"] = 521
    if "payload" in fields:
        fields["payload"] = {"hex": "", "length": 0}

    normalized = case.replace("_", "-")

    if ripng["command"] == "request":
        # Request-whole-table sentinel (RFC 2080 §2.4.1): one RTE with prefix ::,
        # prefix length 0, metric 16 (infinity).
        ripng["rtes"] = [
            {
                "prefix": "::",
                "route_tag": 0,
                "prefix_len": 0,
                "metric": 16,
            }
        ]
        return

    route_rte = {
        "prefix": "2001:db8::",
        "route_tag": 0,
        "prefix_len": 64,
        "metric": 1,
    }

    if "next-hop" in normalized:
        # Next-hop RTE (RFC 2080 §2.1.1): metric 0xFF, route tag and prefix
        # length zero, immediately followed by the route RTEs it applies to.
        ripng["rtes"] = [
            {
                "prefix": "fe80::1",
                "route_tag": 0,
                "prefix_len": 0,
                "metric": 255,
                "next_hop": True,
            },
            route_rte,
        ]
        return

    rtes = [route_rte]
    if "matrix" in normalized:
        rtes.append(
            {
                "prefix": "2001:db8:1::",
                "route_tag": 64512,
                "prefix_len": 48,
                "metric": 2,
            }
        )
    ripng["rtes"] = rtes


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


def _apply_udp_options_behavior(
    fields: dict[str, JSONObject],
    *,
    case: str,
    behavior: str,
) -> None:
    key = f"{case} {behavior}".replace("_", "-")
    udp_fields = fields.setdefault("udp", {})
    if "ipv4-zero-checksum" in key or "ipv6-zero-checksum" in key:
        udp_fields["checksum"] = 0
    payload_hex = _payload_hex_from_fields(fields.get("payload", {})) if "payload" in fields else None
    options = _udp_options_field(key, payload_hex=payload_hex)
    if options is None:
        udp_fields.pop("options", None)
    else:
        udp_fields["options"] = options


def _udp_option_feature_tags(case: str, behavior: str | None) -> list[str]:
    key = f"{case} {behavior or ''}".replace("_", "-")
    tags = ["udp_options"]
    if "udp-options" in key:
        tags.append("udp_surplus")
    if "ocs" in key:
        tags.extend(["udp_ocs", "udp_option_checksum"])
    if "apc" in key:
        tags.extend(["udp_apc", "udp_additional_payload_checksum"])
    if "unknown-safe" in key:
        tags.append("udp_unknown_safe")
    if "unknown-unsafe" in key:
        tags.append("udp_unknown_unsafe")
    if "unsupported-frag" in key:
        tags.extend(["udp_frag", "udp_unsupported_frag"])
    if "ipv4-zero-checksum" in key:
        tags.extend(["udp_checksum_status", "udp_ipv4_zero_checksum"])
    if "ipv6-zero-checksum" in key:
        tags.extend(["udp_checksum_status", "udp_ipv6_zero_checksum"])
    if "surplus-application-boundary" in key:
        tags.extend(["udp_application_boundary", "udp_surplus_application_boundary"])
    return list(dict.fromkeys(tags))


def _udp_options_metadata(
    fields: Mapping[str, JSONObject],
    *,
    stack: Sequence[str],
    case: str,
    behavior: str | None,
) -> JSONObject:
    key = f"{case} {behavior or ''}".replace("_", "-")
    payload_hex = _payload_hex_from_fields(fields.get("payload", {})) if "payload" in fields else None
    checksum_status = "generated"
    if "ipv4-zero-checksum" in key:
        checksum_status = "ipv4_no_checksum"
    elif "ipv6-zero-checksum" in key:
        checksum_status = "ipv6_zero_checksum_exception_required"

    options_field = _udp_options_field(key, payload_hex=payload_hex)
    options = _udp_options_items(options_field)
    surplus = options_field is not None
    return {
        "intent": "logical_plan_fields",
        "requires_backend_materialization": True,
        "stack": list(stack),
        "case": case,
        "behavior": behavior,
        "checksum_status": checksum_status,
        "udp_length_scope": "header_and_application_payload",
        "application_payload_hex": payload_hex,
        "surplus_area": {
            "present": surplus,
            "placement": "after_udp_length",
            "option_checksum": _udp_option_checksum_intent(key, surplus),
            "options": options,
        },
        "application_boundary": {
            "payload_excludes_surplus": surplus,
            "surplus_excluded_from_udp_checksum": surplus,
        },
        "logical_fields": {
            "application_payload": "fields.payload.hex"
            if payload_hex is not None
            else "materialized_udp_payload",
            "udp_options": "fields.udp.options",
        },
    }


def _payload_hex_from_fields(payload: object) -> str:
    if not isinstance(payload, Mapping):
        return ""
    payload_hex = payload.get("hex", "")
    return payload_hex if isinstance(payload_hex, str) else ""


def _payload_hex_length(payload_hex: str) -> int:
    try:
        return len(bytes.fromhex(payload_hex))
    except ValueError:
        return 0


def _udp_options_field(key: str, *, payload_hex: str | None) -> JSONObject | None:
    options = _udp_option_intent(key)
    if not options:
        return None
    field: JSONObject = {
        "format": "udp_surplus_options",
        "placement": "after_udp_length",
        "udp_length_scope": "header_and_application_payload",
        "surplus_excluded_from_udp_checksum": True,
        "option_checksum": _udp_option_checksum_intent(key, True),
        "items": options,
    }
    if payload_hex is not None:
        field["application_payload"] = {
            "layer": "payload",
            "hex": payload_hex,
            "length": _payload_hex_length(payload_hex),
        }
    return field


def _udp_options_items(options_field: JSONObject | None) -> list[JSONObject]:
    if options_field is None:
        return []
    items = options_field.get("items")
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
        return []
    return [dict(item) for item in items if isinstance(item, Mapping)]


def _udp_option_checksum_intent(key: str, surplus: bool) -> JSONObject:
    if not surplus:
        return {"mode": "absent"}
    if "ipv4-zero-checksum" in key:
        return {"mode": "zero_allowed_when_udp_checksum_zero"}
    return {"mode": "auto_internet_checksum"}


def _udp_option_intent(key: str) -> list[JSONObject]:
    if "ipv4-zero-checksum" in key or "ipv6-zero-checksum" in key:
        return []
    if "apc" in key:
        return [
            {
                "kind": 2,
                "name": "apc",
                "length": 6,
                "checksum": "auto_crc32c_application_payload",
            }
        ]
    if "unknown-safe" in key:
        return [
            {
                "kind": 10,
                "name": "unassigned_safe",
                "length": 4,
                "data_hex": "aabb",
                "safety": "safe",
                "expected_status": "unknown_safe",
            }
        ]
    if "unknown-unsafe" in key:
        return [
            {
                "kind": 194,
                "name": "unassigned_unsafe",
                "length": 4,
                "data_hex": "dead",
                "safety": "unsafe",
                "expected_status": "unknown_unsafe",
            }
        ]
    if "unsupported-frag" in key:
        return [
            {
                "kind": 3,
                "name": "frag",
                "length": 10,
                "data_hex": "00010003aabbccdd",
                "expected_status": "unsupported_fragmentation",
            }
        ]
    if "surplus-application-boundary" in key:
        return [
            {"kind": 1, "name": "nop", "length": 1},
            {"kind": 0, "name": "eol", "length": 1},
        ]
    return [
        {"kind": 1, "name": "nop", "length": 1},
        {"kind": 4, "name": "mds", "length": 4, "max_datagram_size": 1440},
        {
            "kind": 5,
            "name": "mrds",
            "length": 5,
            "max_reassembled_size": 1500,
            "segment_count": 2,
        },
        {"kind": 6, "name": "req", "length": 6, "token": 16909060},
        {"kind": 7, "name": "res", "length": 6, "token": 168496141},
        {"kind": 8, "name": "time", "length": 10, "tsval": 16909060, "tsecr": 168496141},
    ]


def _is_malformed_case_name(case: str) -> bool:
    return "malformed" in case.replace("_", "-")


def _has_tcp_header_case(cases: Sequence[str]) -> bool:
    """Whether ``cases`` contains a tcp_header coverage case.

    Used by the focused tcp-header profile to keep stack and case selection on
    the ``tcp-header-*`` cases declared by the IPv4/IPv6 TCP stacks.
    """

    return any(case.replace("_", "-").startswith("tcp-header-") for case in cases)


def _has_tcp_options_case(cases: Sequence[str]) -> bool:
    """Whether ``cases`` contains a focused tcp_options coverage case.

    Used by the focused tcp-options profile to keep stack and case selection on
    the ``tcp-option-*`` single-option cases declared by the IPv4/IPv6 TCP
    stacks, rather than the broad ``tcp-options*`` option-list cases that ride
    the wild/ci/boundary profiles.
    """

    return any(case.replace("_", "-").startswith("tcp-option-") for case in cases)


def _has_tcp_smoke_case(cases: Sequence[str]) -> bool:
    """Whether ``cases`` contains a TCP smoke coverage case.

    The tcp-smoke profile is the representative TCP smoke set used by
    provider-backed dry-run validation. It keeps stack and case selection on the
    union of the focused ``tcp-header-*`` and ``tcp-option-*`` cases declared by
    the IPv4/IPv6 TCP stacks, so a single small run materializes a mix of TCP
    header and TCP option cases without falling through to unrelated stacks.
    """

    return _has_tcp_header_case(cases) or _has_tcp_options_case(cases)


def _is_bgp_smoke_case(case: str) -> bool:
    """Whether ``case`` is sampled by the focused bgp-smoke profile."""

    return case.replace("_", "-").startswith("bgp-")


def _has_bgp_smoke_case(cases: Sequence[str]) -> bool:
    """Whether ``cases`` contains a BGP smoke coverage case."""

    return any(_is_bgp_smoke_case(case) for case in cases)


def _is_rip_smoke_case(case: str) -> bool:
    """Whether ``case`` is sampled by the focused rip-smoke profile.

    Covers the RIP (UDP/520) and RIPng (UDP/521) coverage cases declared on the
    ``ipv4_udp_rip`` / ``ipv6_udp_ripng`` stacks and the ``rip-`` / ``ripng-``
    feature cases, including the ``crafter-rip-*`` / ``crafter-ripng-*`` matrix
    cases. The ``crafter-`` materialize/decode prefix is stripped first so those
    matrix cases match the same ``rip-`` / ``ripng-`` prefixes.
    """

    normalized = case.replace("_", "-")
    if normalized.startswith("crafter-"):
        normalized = normalized[len("crafter-") :]
    return normalized.startswith("rip-") or normalized.startswith("ripng-")


def _has_rip_smoke_case(cases: Sequence[str]) -> bool:
    """Whether ``cases`` contains a RIP/RIPng smoke coverage case."""

    return any(_is_rip_smoke_case(case) for case in cases)


def _has_ospf_smoke_case(cases: Sequence[str]) -> bool:
    """Whether ``cases`` contains an OSPF smoke coverage case."""

    return any(_is_ospf_smoke_case(case) for case in cases)


def _ipv4_enrichment_cases(cases: Sequence[str], grammar: Mapping[str, object]) -> list[str]:
    declared = _layer_coverage_cases(grammar, "ipv4")
    return [case for case in cases if case in declared]


def _has_ipv4_enrichment_case(cases: Sequence[str], grammar: Mapping[str, object]) -> bool:
    return bool(_ipv4_enrichment_cases(cases, grammar))


def _layer_coverage_cases(grammar: Mapping[str, object], layer: str) -> set[str]:
    layers = _object(grammar.get("layers"), "layers")
    layer_spec = _object(layers.get(layer), f"layers.{layer}")
    return set(_string_list(layer_spec.get("coverage_cases", []), f"layers.{layer}.coverage_cases"))


_IPV6_ENRICHMENT_CASES = frozenset(
    {
        "crafter-ipv6-boundary-fields",
        "crafter-ipv6-fragment-udp",
        "crafter-ipv6-routing-generic",
        "crafter-ipv6-routing-icmpv6",
        "crafter-ipv6-routing-tcp-raw",
        "crafter-ipv6-segment-routing-udp",
        "crafter-ipv6-unknown-next-header-raw",
        "ipv6-boundary-fields",
        "ipv6-destination-options",
        "ipv6-extension-chain-tcp-raw",
        "ipv6-fragment-udp",
        "ipv6-hop-by-hop-options",
        "ipv6-mobile-routing",
        "ipv6-option-metadata",
        "ipv6-routing-generic",
        "ipv6-routing-icmpv6",
        "ipv6-segment-routing-udp",
        "ipv6-unknown-next-header-raw",
    }
)


def _is_ipv6_enrichment_case(case: str) -> bool:
    """Whether ``case`` is sampled by the focused ipv6-enrichment profile."""

    return case.replace("_", "-") in _IPV6_ENRICHMENT_CASES


def _has_ipv6_enrichment_case(cases: Sequence[str]) -> bool:
    """Whether ``cases`` contains an ipv6-enrichment coverage case."""

    return any(_is_ipv6_enrichment_case(case) for case in cases)


_IP_FRAGMENT_SMOKE_PROFILES = frozenset(
    {
        "fragmentation-smoke",
        "ip-fragment-smoke",
    }
)
# Focused IPSec offline profiles. Like the dot11/rsn smoke profiles they keep the
# stack and case selection on their own IPSec families (esp/ah/ikev2) rather than
# letting the generic cross-feature case expansion draw unrelated cases onto the
# ESP/AH/IKEv2 stacks.
_IPSEC_SMOKE_PROFILES = frozenset(
    {
        "ipsec-smoke",
        "esp",
        "ah",
        "ikev2",
    }
)


def _has_ip_fragment_smoke_case(cases: Sequence[str]) -> bool:
    """Whether ``cases`` contains an IP fragmentation smoke coverage case."""

    return any(_is_ip_fragment_smoke_case(case) for case in cases)


def _is_ip_fragment_smoke_case(case: str) -> bool:
    return "fragment" in case.replace("_", "-")


# Behavior names of the focused single-option tcp_options cases (tcp-option-*).
# These select exactly one option kind so they must not be matched against the
# broad option-list cases (tcp-options*, tcp-all-flags-reserved-offset), which
# keep their own common_options / sack_blocks / advanced_generic_options /
# header_boundary behaviors.
_FOCUSED_TCP_OPTION_BEHAVIORS = frozenset(
    {
        "mss",
        "window-scale",
        "sack-permitted",
        "sack",
        "timestamp",
        "fast-open",
        "mptcp-generic",
        "unknown-generic",
        "user-timeout",
        "tcp-ao",
        "tcp-eno",
        "accurate-ecn",
        "experimental",
        "malformed-length",
    }
)


def _is_focused_tcp_option_behavior(name: str) -> bool:
    """Whether ``name`` is a focused single-option tcp_options behavior."""

    return _identifier_part(name) in _FOCUSED_TCP_OPTION_BEHAVIORS


def _auto_sample_feature(feature: str) -> bool:
    return feature != "icmpv4_errors"


def _sample_radiotap_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "version":
        return 0 if domain != "explicit_nonzero" else 1
    if field_name == "pad":
        return 0
    if field_name == "length":
        return 0
    if field_name == "present_words":
        return [0]
    if field_name == "flags":
        if domain == "absent":
            return _SKIP_FIELD
        if domain in {"fcs_present", "fcs_present_failed"}:
            return "fcs_present"
        if domain == "failed_fcs":
            return "failed_fcs"
        return "none"
    if field_name == "rate":
        return _SKIP_FIELD if domain == "absent" else (2 if domain == "2" else _integer_domain_value(ctx, domain, field_name, bits=8))
    if field_name == "channel_frequency":
        return _SKIP_FIELD if domain == "absent" else _integer_domain_value(ctx, domain, field_name, bits=16)
    if field_name == "channel_flags":
        if domain == "absent":
            return _SKIP_FIELD
        return domain
    if field_name == "dbm_antenna_signal":
        if domain == "absent":
            return _SKIP_FIELD
        if domain == "boundary":
            return -128
        return -42 if domain == "synthetic_signal" else _integer_domain_value(ctx, domain, field_name, bits=8)
    if field_name == "antenna":
        return _SKIP_FIELD if domain == "absent" else _integer_domain_value(ctx, domain, field_name, bits=8)
    if field_name == "rx_flags":
        if domain == "absent":
            return _SKIP_FIELD
        return 0x0001 if domain == "failed_fcs" else 0
    if field_name == "tx_flags":
        if domain == "absent":
            return _SKIP_FIELD
        return 0x0008 if domain == "no_ack" else 0
    if field_name == "unknown_fields":
        return _SKIP_FIELD if domain == "absent" else {"hex": "aabbccdd"}
    if field_name == "fcs_status":
        return _SKIP_FIELD if domain == "absent" else domain
    raise ValueError(f"spec error: unsupported radiotap field sampler: {field_name}")


def _sample_dot11_field(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    current_fields: Mapping[str, object],
) -> object:
    frame_control = _dot11_frame_control_for_case(ctx.case, ctx.stack)
    if field_name == "frame_control":
        return frame_control
    if field_name == "protocol_version":
        return frame_control & 0x3
    if field_name == "frame_type":
        return (frame_control >> 2) & 0x3
    if field_name == "subtype":
        return (frame_control >> 4) & 0xF
    if field_name == "to_ds":
        return 1 if frame_control & 0x0100 else 0
    if field_name == "from_ds":
        return 1 if frame_control & 0x0200 else 0
    if field_name == "more_fragments":
        return 0
    if field_name == "retry":
        return 0
    if field_name == "power_management":
        return 0
    if field_name == "more_data":
        return 0
    if field_name == "protected":
        return 1 if frame_control & 0x4000 else 0
    if field_name == "order":
        return 0
    if field_name == "duration_id":
        if domain == "nav":
            return 314
        if domain == "association_id":
            return 0xC001
        if domain == "boundary":
            return 0xFFFF
        return 0
    if field_name == "addr1":
        return _mac_for_domain(ctx, domain, ctx.dst_mac)
    if field_name == "addr2":
        if domain == "absent" and _dot11_control_address_count(frame_control) < 2:
            return _SKIP_FIELD
        return _mac_for_domain(ctx, domain, ctx.src_mac)
    if field_name == "addr3":
        if domain == "absent" and _dot11_header_has_three_addresses(frame_control):
            return ctx.dst_mac
        if domain == "absent":
            return _SKIP_FIELD
        return _mac_for_domain(ctx, domain, "00:00:5e:00:53:03")
    if field_name == "addr4":
        if not _dot11_has_addr4(current_fields):
            return _SKIP_FIELD
        return _mac_for_domain(ctx, domain, "00:00:5e:00:53:04")
    if field_name == "sequence_control":
        if not _dot11_header_has_sequence_control(frame_control):
            return _SKIP_FIELD
        if _dot11_is_data(frame_control) and "llc_snap" in ctx.stack:
            if domain == "sequence":
                return 0x1230
            if domain == "boundary":
                return 0xFFF0
            return 0x1000
        if domain == "absent":
            return 0x1000
        if domain == "fragment_zero":
            return 0x1000
        if domain == "sequence":
            return 0x1230
        if domain == "boundary":
            return 0xFFFF
        return 0x1000
    if field_name == "qos_control":
        if not _dot11_has_qos_control(frame_control):
            return _SKIP_FIELD
        if domain == "ack_policy":
            return 0x0020
        if domain == "boundary":
            return 0xFFFF
        return 0
    if field_name == "ht_control":
        return _SKIP_FIELD
    if field_name == "management_fixed_fields":
        if not _dot11_is_management(frame_control):
            return _SKIP_FIELD
        return {"hex": _dot11_management_fixed_hex(frame_control, str(domain))}
    if field_name == "tagged_parameters":
        subtype = (frame_control >> 4) & 0x0F
        if not _dot11_is_management(frame_control) or not _dot11_management_subtype_has_tags(subtype):
            return _SKIP_FIELD
        return _dot11_management_tags(ctx.case, str(domain))
    if field_name == "payload":
        return _SKIP_FIELD
    raise ValueError(f"spec error: unsupported dot11 field sampler: {field_name}")


def _dot11_management_fixed_hex(frame_control: int, domain: str) -> str:
    subtype = (frame_control >> 4) & 0x0F
    if subtype in {5, 8}:  # probe response, beacon
        return "000000000000000064000100"
    if subtype == 0:  # association request
        return "31040000"
    if subtype in {1, 3}:  # association/reassociation response
        return "310400000100"
    if subtype == 2:  # reassociation request
        return "3104000000005e005301"
    if subtype == 11:  # authentication
        return "000001000000"
    if subtype in {10, 12}:  # disassociation/deauthentication
        return "0100"
    if subtype in {13, 14}:  # action/action-no-ack category
        return "00"
    if domain == "association_fixed":
        return "31040000"
    if domain == "authentication_fixed":
        return "000001000000"
    return ""


def _dot11_management_tags(case: str, domain: str) -> list[JSONObject]:
    if domain == "absent":
        return []
    if domain == "rsn" or "rsn" in case.replace("_", "-"):
        return [{"id": 48, "value": {"hex": _rsn_information_value_hex()}}]
    if domain == "supported_rates":
        return [{"id": 1, "value": {"hex": "82848b96"}}]
    if domain == "unknown":
        return [{"id": 221, "value": {"hex": "0050f20101"}}]
    return [
        {"id": 0, "value": {"hex": "6c696263726166746572"}},
        {"id": 1, "value": {"hex": "82848b96"}},
        {"id": 221, "value": {"hex": "0050f20101"}},
    ]


def _dot11_management_subtype_has_tags(subtype: int) -> bool:
    return subtype in {0, 2, 4, 5, 8}


def _sample_eapol_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    is_key = "key" in ctx.case.replace("_", "-")
    if field_name == "version":
        return 2 if domain in {1, 2, 3, "explicit"} else 2
    if field_name == "packet_type":
        case = ctx.case.replace("_", "-")
        if "logoff" in case:
            return "logoff"
        if is_key:
            return "key"
        if "eap-packet" in case:
            return "eap_packet"
        return "start"
    if field_name == "body_length":
        return 0
    if not is_key:
        return _SKIP_FIELD
    if field_name == "descriptor_type":
        return "rsn_key"
    if field_name == "key_information":
        return 0x008A if "key-data" not in ctx.case else 0x010A
    if field_name == "key_length":
        return 16
    if field_name == "replay_counter":
        return 1
    if field_name == "key_nonce":
        return {"hex": "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f"}
    if field_name == "key_iv":
        return {"hex": "00000000000000000000000000000000"}
    if field_name == "key_rsc":
        return {"hex": "0000000000000000"}
    if field_name == "key_id":
        return {"hex": "0000000000000000"}
    if field_name == "key_mic":
        return {"hex": "00000000000000000000000000000000"}
    if field_name == "key_data_length":
        return 0
    if field_name == "key_data":
        return {"hex": _rsn_information_value_hex()} if "key-data" in ctx.case else _SKIP_FIELD
    raise ValueError(f"spec error: unsupported eapol field sampler: {field_name}")


def _sample_rsn_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "element_id":
        return 48
    if field_name == "length":
        return 0
    if field_name == "version":
        return 1
    if field_name == "group_cipher_suite":
        return "ccmp_128"
    if field_name == "pairwise_cipher_suites":
        return ["ccmp_128"]
    if field_name == "akm_suites":
        return ["sae"] if "sae" in ctx.case else ["psk"]
    if field_name == "capabilities":
        return 0x00C0 if "management-protection" in ctx.case else 0
    if field_name == "pmkid_list":
        return _SKIP_FIELD
    if field_name == "group_management_cipher_suite":
        return "bip_cmac_128" if "management-protection" in ctx.case else _SKIP_FIELD
    if field_name == "trailing_bytes":
        if domain in {"absent", "empty"} or "unknown-suite-raw" not in ctx.case:
            return _SKIP_FIELD
        return {"hex": "aabb"}
    raise ValueError(f"spec error: unsupported rsn field sampler: {field_name}")


def _rsn_information_value_hex() -> str:
    return "0100000fac040100000fac040100000fac020000"


def _dot11_frame_control_for_case(case: str, stack: Sequence[str]) -> int:
    key = case.replace("_", "-")
    if "llc_snap" in stack:
        return 2 << 2
    if "control" in key:
        return (1 << 2) | (11 << 4)
    if "management" in key or "rsn" in key:
        return (0 << 2) | (8 << 4)
    subtype = 8 if "qos" in key else 0
    flags = 0x4000 if "protected" in key else 0
    if "tods-fromds" in key:
        flags |= 0x0300
    return (2 << 2) | (subtype << 4) | flags


def _dot11_is_control(frame_control: int) -> bool:
    return ((frame_control >> 2) & 0x3) == 1


def _dot11_is_data(frame_control: int) -> bool:
    return ((frame_control >> 2) & 0x3) == 2


def _dot11_header_has_three_addresses(frame_control: int) -> bool:
    return not _dot11_is_control(frame_control)


def _dot11_header_has_sequence_control(frame_control: int) -> bool:
    return not _dot11_is_control(frame_control)


def _dot11_has_qos_control(frame_control: int) -> bool:
    return ((frame_control >> 2) & 0x3) == 2 and (((frame_control >> 4) & 0xF) & 0x8) != 0


def _dot11_has_addr4(fields: Mapping[str, object]) -> bool:
    return bool(fields.get("to_ds")) and bool(fields.get("from_ds"))


def _dot11_control_address_count(frame_control: int) -> int:
    if not _dot11_is_control(frame_control):
        return 3
    subtype = (frame_control >> 4) & 0xF
    return 1 if subtype in {12, 13} else 2


def generate_plans(
    *,
    seed: int,
    profile: str,
    count: int,
    backend: str = "scapy",
    root: str | None = None,
    family: str | None = None,
    case: str | None = None,
    feature: str | None = None,
    direction: str = "reference_to_libcrafter",
    index: int | None = None,
) -> list[PacketPlan]:
    """Generate a deterministic sequence, or one explicit index."""

    if count < 1:
        raise ValueError(f"count must be positive: {count}")
    generator = PacketGenerator(seed=seed, profile=profile, backend=backend)
    indices = [index] if index is not None else list(range(count))
    return [
        generator.generate(
            index=item,
            root=root,
            family=family,
            case=case,
            feature=feature,
            direction=direction,
        )
        for item in indices
    ]


def run_self_checks() -> None:
    """Run unit-style checks for the generator without importing any backend."""

    rng_a = random.Random(123)
    rng_b = random.Random(123)
    if [weighted_choice(rng_a, (("a", 1), ("b", 3))) for _ in range(5)] != [
        weighted_choice(rng_b, (("a", 1), ("b", 3))) for _ in range(5)
    ]:
        raise AssertionError("weighted choice is not deterministic")

    rng = random.Random(1)
    if not 10 <= bounded_int(rng, 10, 20) <= 20:
        raise AssertionError("bounded integer escaped its bounds")
    if len(byte_payload(random.Random(1), min_length=4, max_length=4)) != 4:
        raise AssertionError("byte payload did not honor fixed length")
    ipv4_address = ipaddress.IPv4Address(documentation_ipv4(random.Random(1)))
    if not any(ipv4_address in network for network in _IPV4_DOCUMENTATION_NETWORKS):
        raise AssertionError("IPv4 helper left documentation space")
    if ipaddress.IPv6Address(documentation_ipv6(random.Random(1))) not in _IPV6_DOCUMENTATION_NETWORK:
        raise AssertionError("IPv6 helper left documentation space")
    if not documentation_mac(random.Random(1)).startswith("00:00:5e:00:53:"):
        raise AssertionError("MAC helper left documentation block")
    if not EPHEMERAL_PORT_MIN <= ephemeral_port(random.Random(1)) <= EPHEMERAL_PORT_MAX:
        raise AssertionError("ephemeral port escaped dynamic/private range")

    first = PacketGenerator(seed=1, profile="smoke").generate(index=0).to_dict()
    second = PacketGenerator(seed=1, profile="smoke").generate(index=0).to_dict()
    third = PacketGenerator(seed=2, profile="smoke").generate(index=0).to_dict()
    if first != second:
        raise AssertionError("identical generator coordinates produced different plans")
    if first == third:
        raise AssertionError("different seeds produced identical plans")
    plan_id = first["metadata"]["plan_id"]
    if not isinstance(plan_id, str) or "seed-1/profile-smoke/index-000000/" not in plan_id:
        raise AssertionError("plan identifier is missing reproduction coordinates")
    ci_stacks = {
        PacketGenerator(seed=12345, profile="ci").generate(index=item).metadata["stack_name"]
        for item in range(200)
    }
    expected_stacks = {"ethernet_arp", "ipv4_tcp_payload", "ipv6_icmpv6", "vlan_ipv4_udp"}
    if not expected_stacks.intersection(ci_stacks):
        raise AssertionError("ci profile did not sample stack specs")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run oracle generator self checks.")
    parser.parse_args(argv)
    run_self_checks()
    sys.stdout.write("generator self-checks passed\n")
    return 0


def _derive_seed(
    seed: int,
    profile: str,
    index: int,
    root: str | None,
    family: str | None,
    case: str | None,
    feature: str | None,
    direction: str,
) -> int:
    material = "\0".join(
        (
            str(seed),
            profile,
            str(index),
            root or "",
            family or "",
            case or "",
            feature or "",
            direction,
        )
    ).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:16], byteorder="big")


def _derive_deck_seed(seed: int, profile: str, names: Sequence[str]) -> int:
    material = "\0".join((str(seed), profile, *names, "stack-deck")).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:16], byteorder="big")


def _json_object(value: object) -> JSONObject:
    if not isinstance(value, Mapping):
        raise ValueError("expected a JSON object")
    output: JSONObject = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError(f"JSON object key must be a string: {key!r}")
        output[key] = item  # type: ignore[assignment]
    return output


def _object(value: object, name: str) -> JSONObject:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return _json_object(value)


def _string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _string_list(value: object, name: str) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{name} must be a list of strings")
    if not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be a list of strings")
    return list(value)


def _string_or_none(value: object) -> str | None:
    if value is None or isinstance(value, str):
        return value
    raise ValueError(f"expected string or null: {value!r}")


def _stack_families(layers: Sequence[str], root_families: Sequence[str]) -> list[str]:
    families: list[str] = []
    layer_set = set(layers)
    for family in root_families:
        if family in layer_set:
            families.append(family)
    if "transport" in root_families and layer_set.intersection({"tcp", "udp"}):
        families.append("transport")
    if "icmp" in root_families and layer_set.intersection({"icmp", "icmpv6"}):
        families.append("icmp")
    if "link" in root_families and layer_set.intersection(
        {"ethernet", "vlan", "payload", "linux_cooked", "null_loopback"}
    ):
        families.append("link")
    if layer_set.intersection({"ipv4", "ipv6", "ipv6_fragment"}):
        families.append("ip")
    if not families:
        families.extend(root_families)
    return list(dict.fromkeys(families))


def _feature_categories(
    name: str,
    directions: Sequence[str],
    malformed: bool,
    cases: Sequence[str],
) -> list[str]:
    categories = ["malformed" if malformed else "baseline"]
    tokens = " ".join((name, *cases)).replace("_", "-")
    if any(direction.startswith("live") for direction in directions):
        categories.append("live")
    if "pcap" in tokens:
        categories.append("pcap")
    if any(token in tokens for token in ("boundary", "option", "fragment", "routing", "error")):
        categories.append("boundary")
    return list(dict.fromkeys(categories))


def _case_categories(cases: Sequence[str]) -> list[str]:
    if not cases:
        return ["baseline"]
    categories = ["baseline"]
    tokens = " ".join(cases)
    if "malformed" in tokens:
        categories.append("malformed")
    if "pcap" in tokens:
        categories.append("pcap")
    if "live" in tokens:
        categories.append("live")
    if any(token in tokens for token in ("boundary", "options", "fragment", "routing", "errors")):
        categories.append("boundary")
    return list(dict.fromkeys(categories))


def _layers_cover_feature(stack: Sequence[str], feature_layers: Sequence[str]) -> bool:
    stack_set = set(stack)
    feature_set = set(feature_layers)
    ipv6_extension_layers = {
        "ipv6_destination_options",
        "ipv6_fragment",
        "ipv6_hop_by_hop",
        "ipv6_routing",
    }
    if {"ipv4", "ipv6"}.issubset(feature_set):
        return bool(stack_set.intersection(feature_set))
    if "ipv6" in feature_set and feature_set.intersection(ipv6_extension_layers):
        return "ipv6" in stack_set and bool(stack_set.intersection(ipv6_extension_layers))
    return all(layer in stack_set for layer in feature_layers)


def _ipv6_extension_cases_for_stack(stack: Sequence[str], cases: Sequence[str]) -> list[str]:
    stack_set = set(stack)
    output: list[str] = []
    for case in cases:
        normalized = case.replace("_", "-")
        if (
            ("hop-by-hop" in normalized or "option-metadata" in normalized)
            and "ipv6_hop_by_hop" in stack_set
        ):
            output.append(case)
        elif (
            ("destination-options" in normalized or "option-metadata" in normalized)
            and "ipv6_destination_options" in stack_set
        ):
            output.append(case)
        elif "ipv6-fragment" in normalized and "ipv6_fragment" in stack_set:
            output.append(case)
        elif (
            any(token in normalized for token in ("routing", "segment", "mobile", "extension-chain"))
            and "ipv6_routing" in stack_set
        ):
            output.append(case)
    return output


def _udp_option_cases_for_stack(stack: Sequence[str], cases: Sequence[str]) -> list[str]:
    stack_set = set(stack)
    if "udp" not in stack_set or "payload" not in stack_set:
        return []
    # UDP surplus options model the application payload as the bytes UDP carries
    # directly, so they only apply when UDP terminates in a payload layer. When an
    # intermediate protocol (e.g. ESP) sits between UDP and payload, the declared
    # application payload no longer equals the materialized UDP payload, so skip
    # the pairing rather than emit a plan that cannot round-trip.
    if _next_layer_after(stack, "udp") != "payload":
        return []

    output: list[str] = []
    for case in cases:
        normalized = case.replace("_", "-")
        if "ipv4-zero-checksum" in normalized and "ipv4" not in stack_set:
            continue
        if "ipv6-zero-checksum" in normalized and "ipv6" not in stack_set:
            continue
        output.append(case)
    return output


if __name__ == "__main__":
    raise SystemExit(main())
