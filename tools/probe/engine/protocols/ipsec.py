"""IPSec probe protocol plugin: cases, plan builders, and planning surface.

This is the IPSec *planning half* migration (the last protocol to migrate). It
bundles IPSec's planning surface in one place:

* the four IPSec behavioral cases (``esp-transport-echo`` / ``esp-tunnel-echo`` /
  ``ah-transport-verify`` / ``ikev2-sa-init``), built through the
  ``_behavior_case`` factory, and their ``_IPSEC_ESP_CAPABILITIES`` /
  ``_IPSEC_AH_CAPABILITIES`` / ``_IKEV2_CAPABILITIES`` constants (plus the
  aggregate ``_IPSEC_CAPABILITIES`` alias) -- the catalog contribution,
* the planned-only ``_ipsec_probe_plan`` builder (one builder serving all four
  cases), the IPSec ESP/AH IP-protocol numbers and the IKEv2 UDP-port constant
  the plan references, and the planned-only set (all four cases are
  planned-only),
* and the IPSec stimulus-endpoint routing set (empty: the four IPSec cases are
  planned-only and were never stimulus-routed).

The plan builder is moved verbatim from :mod:`tools.probe.engine.planning`;
:mod:`planning` re-imports it so ``planning._ipsec_probe_plan`` and
``PLAN_BUILDERS[name] is _ipsec_probe_plan`` keep identical object identity for
the pinning tests.

The IPSec target-service half (this step) verified, against the actual code,
that IPSec contributes *no* target-service surface: there is no IPSec
``target_service_setup_plan`` service entry, no IPSec descriptor / case
frozenset / plan selector in :mod:`tools.probe.engine.target_services`, and no
inline IPSec setup-script block in ``target_service_setup_script`` (nor any
per-service shell assets under ``tools/probe/target_services/``). The four IPSec
cases are all planned-only and never reach the target-service path, so the
``target_service`` and ``setup_script`` hooks stay ``None`` and there is nothing
to move out of ``target_services.py``. This mirrors the ICMP / OSPF / IGMP
precedent (a protocol whose service concern simply does not exist), and keeping
both hooks ``None`` is byte-identical: the registry target-service partition
leaves the IPSec cases on the legacy path, which never built an IPSec service
either.

IPSec is the only protocol with a ``tools.oracle.engine.ipsec_interop``
cross-crypto dry-run hook (``cli._IPSEC_PROBE_CASES`` /
``_ipsec_interop_dry_run_metadata``). That interop hook -- and the IPSec
address-rewrite / failure-reason / lab-capability contributions -- are
deliberately *not* part of this step: there is no IPSec live-path rewrite branch
(the four cases are planned-only and never stimulus-routed), and no IPSec
``_failure_reasons_for_case`` branch (the cases fall through to the shared
default taxonomy). The IPSec lab-capability derivation (``ipsec_esp`` /
``ipsec_ah`` / ``ikev2``) and the interop hook land in step 35, so every
remaining optional hook -- including ``ipsec_interop`` -- stays ``None`` here.

IPSec's ``profile_counts`` is intentionally empty: the focused ``ipsec`` profile
rides the four cases in a fixed declaration order, and the registry-first profile
merge would move the registry contribution to the front of that profile, so the
legacy ordered profile name table in :mod:`tools.probe.engine.cases`
(``IPSEC_PROFILE_CASE_NAMES``, now sourced from the registered IPSec cases) keeps
owning IPSec's profile membership to preserve byte-identical selection order.

Imports are relative only so the module loads under both engine import roots
(``engine.protocols.ipsec`` for the CLI and ``tools.probe.engine.protocols.ipsec``
for the tests).
"""

from __future__ import annotations

from ..case_helpers import _behavior_case
from ..model import JSONObject, ProbeCase
from ..planning_helpers import deterministic_bytes, deterministic_ipv4_pair
from .base import ProtocolPlugin, register


# IPSec shared capability constants (moved verbatim from
# :mod:`tools.probe.engine.cases`). ESP and AH need a peer that holds the
# matching Security Association (the same SPI, mode, algorithms, and keys
# libcrafter seals/verifies with), so they carry ``ipsec_esp`` / ``ipsec_ah``
# beyond the unicast IPv4 substrate; IKEv2 only needs the peer to run an IKE
# responder on UDP/500, so it carries ``ikev2``. These capability names match the
# probe capability derivation in :mod:`tools.probe.engine.lab`, so providers
# without an IPSec-capable peer skip the cases with stable reasons rather than
# failing.
_IPSEC_ESP_CAPABILITIES = ["ipsec_esp"]
_IPSEC_AH_CAPABILITIES = ["ipsec_ah"]
_IKEV2_CAPABILITIES = ["ikev2"]
# Aggregate alias for callers that want the full IPSec capability surface.
_IPSEC_CAPABILITIES = [
    *_IPSEC_ESP_CAPABILITIES,
    *_IPSEC_AH_CAPABILITIES,
    *_IKEV2_CAPABILITIES,
]


# IPSec behavioral cases (RFC 4303 ESP, RFC 4302 AH, RFC 7296 IKEv2) against a
# controlled IPSec-capable peer that holds the matching Security Association.
# Each case is a stateful request/response exchange: libcrafter seals or
# authenticates a datagram (or builds an IKE_SA_INIT), the peer accepts it
# (decrypts/verifies the ICV, or parses the IKE header), and its protected reply
# or IKE_SA_INIT response is captured and decoded. The ``stateful`` metadata
# flag mirrors the DHCP precedent (an exchange whose response depends on shared
# per-exchange state -- here the SA / IKE SPI pair -- rather than a stateless
# echo); ``requires_tunnel`` marks the tunnel-mode ESP case the way NDP marks
# ``requires_router_target``, so a peer without tunnel-mode SAs can skip it
# cleanly while transport-mode cases still plan.
BEHAVIOR_IPSEC_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="esp-transport-echo",
        description=(
            "Send an ESP-protected (transport-mode) ICMP echo request to the "
            "peer and validate the peer's ESP-protected echo reply."
        ),
        stimulus="esp_transport_echo_request",
        expected_response="esp_transport_echo_reply",
        required_capabilities=_IPSEC_ESP_CAPABILITIES,
        protocol="ipsec",
        metadata={"ipsec_protocol": "esp", "mode": "transport", "stateful": True},
    ),
    _behavior_case(
        name="esp-tunnel-echo",
        description=(
            "Send a tunnel-mode ESP-encapsulated ICMP echo request (inner IP "
            "inside ESP) to the peer and validate the tunnel-mode ESP echo "
            "reply."
        ),
        # Tunnel mode needs the peer to hold a tunnel-mode SA (inner IP), which
        # not every IPSec-capable peer exposes; ``requires_tunnel`` lets such a
        # peer skip this case while the transport-mode ESP case still runs.
        stimulus="esp_tunnel_echo_request",
        expected_response="esp_tunnel_echo_reply",
        required_capabilities=_IPSEC_ESP_CAPABILITIES,
        protocol="ipsec",
        metadata={
            "ipsec_protocol": "esp",
            "mode": "tunnel",
            "stateful": True,
            "requires_tunnel": True,
            "notes": (
                "Needs the peer to hold a tunnel-mode ESP SA (inner IP); a "
                "transport-only peer skips this case. Live runners configure a "
                "tunnel-mode SA or skip."
            ),
        },
    ),
    _behavior_case(
        name="ah-transport-verify",
        description=(
            "Send an AH-protected (transport-mode) datagram to the peer and "
            "validate that the peer accepts it (the ICV verifies) and responds."
        ),
        stimulus="ah_transport_request",
        expected_response="ah_transport_response",
        required_capabilities=_IPSEC_AH_CAPABILITIES,
        protocol="ipsec",
        metadata={"ipsec_protocol": "ah", "mode": "transport", "stateful": True},
    ),
    _behavior_case(
        name="ikev2-sa-init",
        description=(
            "Send an IKE_SA_INIT request (header + SA + KE + Ni) over UDP/500 "
            "and validate a well-formed IKE_SA_INIT response from the peer's "
            "IKE responder."
        ),
        stimulus="ikev2_sa_init_request",
        expected_response="ikev2_sa_init_response",
        required_capabilities=_IKEV2_CAPABILITIES,
        protocol="ipsec",
        metadata={"ipsec_protocol": "ikev2", "exchange": "IKE_SA_INIT", "stateful": True},
    ),
)


# IPSec ESP/AH IP protocol numbers (RFC 4303 / RFC 4302) and the IKEv2 UDP port
# (RFC 7296). Recorded in the dry-run plan so an inspecting agent sees the wire
# protocol/port the exchange rides without consulting the crate. Moved verbatim
# from :mod:`tools.probe.engine.planning`.
_IPSEC_ESP_PROTOCOL = 50
_IPSEC_AH_PROTOCOL = 51
_IKEV2_UDP_PORT = 500


def _ipsec_probe_plan(
    *,
    case_name: str,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan an IPSec behavioral case (ESP transport/tunnel, AH, IKE_SA_INIT).

    The IPSec cases drive a controlled IPSec-capable peer (Linux xfrm /
    strongSwan / an oracle reference peer) and need libcrafter to seal/authenticate
    a datagram or build an IKE_SA_INIT against the Security Association the peer
    holds. The crate-side stimulus/response *builders* (and the cross-crypto
    parity assertion) land in the later probe steps; until then the dry-run plan
    is ``planned_only``: it records the case, the stimulus/expected-response
    packet shapes (ipsec protocol, mode, wire protocol number / UDP port, the
    deterministic SPI and peer addresses), and the live-path note, but builds no
    packet bytes. This keeps the dry-run plan well-formed and inspectable
    without requiring the crate stimulus builders or a live peer.
    """

    # Imported lazily so the plugin module loads during ``protocols`` package
    # auto-discovery without cycling through ``cases`` -> ``protocols`` ->
    # ``ipsec``. ``PROBE_CASE_BY_NAME`` is the assembled catalog index.
    from ..cases import PROBE_CASE_BY_NAME

    case = PROBE_CASE_BY_NAME[case_name]
    metadata = case.metadata or {}
    ipsec_protocol = str(metadata.get("ipsec_protocol", "ipsec"))
    mode = metadata.get("mode")
    exchange = metadata.get("exchange")
    requires_tunnel = bool(metadata.get("requires_tunnel", False))

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    # Deterministic, non-zero SPI (RFC 4303 reserves 0; the oracle SPI samplers
    # avoid it for the same NON_ESP heuristic reason). Kept in the dynamic
    # 0x1000..0xFFFFFFFF range so it never collides with the IKE/reserved low SPIs.
    spi = 0x1000 + int.from_bytes(digest[0:4], "big") % 0xFFFF_0000

    # The stimulus/response packet shape: the wire protocol the exchange rides
    # and, for ESP/AH, the mode and per-exchange SPI. This is the inspectable
    # contract the later crate stimulus builders will materialize.
    stimulus_shape: JSONObject = {
        "ipsec_protocol": ipsec_protocol,
        "stimulus": case.stimulus,
    }
    response_shape: JSONObject = {
        "ipsec_protocol": ipsec_protocol,
        "expected_response": case.expected_response,
    }
    if ipsec_protocol == "esp":
        stimulus_shape["ip_protocol"] = _IPSEC_ESP_PROTOCOL
        response_shape["ip_protocol"] = _IPSEC_ESP_PROTOCOL
        stimulus_shape["spi"] = spi
        response_shape["spi"] = spi
        if mode is not None:
            stimulus_shape["mode"] = mode
            response_shape["mode"] = mode
    elif ipsec_protocol == "ah":
        stimulus_shape["ip_protocol"] = _IPSEC_AH_PROTOCOL
        response_shape["ip_protocol"] = _IPSEC_AH_PROTOCOL
        stimulus_shape["spi"] = spi
        response_shape["spi"] = spi
        if mode is not None:
            stimulus_shape["mode"] = mode
            response_shape["mode"] = mode
    elif ipsec_protocol == "ikev2":
        stimulus_shape["udp_port"] = _IKEV2_UDP_PORT
        response_shape["udp_port"] = _IKEV2_UDP_PORT
        if exchange is not None:
            stimulus_shape["exchange"] = exchange
            response_shape["exchange"] = exchange

    plan: JSONObject = {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": case.stimulus,
        "expected_response": case.expected_response,
        # The IPSec stimulus/response builders and cross-crypto parity check land
        # in later probe steps; the dry-run plan is planned-only (no packet bytes
        # built) but still records the full exchange shape below.
        "planned_only": True,
        "ipsec_protocol": ipsec_protocol,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "stimulus_packet_shape": stimulus_shape,
        "expected_response_packet_shape": response_shape,
        # The peer that opens/answers the exchange. ESP/AH need it to hold the
        # matching SA; IKEv2 needs it to run an IKE responder. The peer is the
        # Linux xfrm / strongSwan stack or an oracle reference peer configured on
        # the controlled target endpoint -- provisioned only on the opt-in live
        # path (lab-session / providers), never for the dry-run.
        "ipsec_peer": {
            "required": True,
            "role": "ipsec_peer" if ipsec_protocol != "ikev2" else "ikev2_responder",
            "kind": (
                "ikev2-responder"
                if ipsec_protocol == "ikev2"
                else f"ipsec-{ipsec_protocol}-{mode or 'transport'}-peer"
            ),
            "peer_options": [
                "linux-xfrm",
                "strongswan",
                "oracle-reference-peer",
            ],
            "live_only": True,
        },
        "live_path": (
            "Opt-in via lab-session / providers: provision an IPSec-capable peer "
            "(Linux xfrm / strongSwan / an oracle reference peer) holding the "
            "matching SA (or running an IKE responder), run from there, collect "
            "artifacts, and tear it down. The dry-run plans this exchange without "
            "any live traffic."
        ),
        "digest_hex": digest.hex()[:16],
    }
    if mode is not None:
        plan["mode"] = mode
    if exchange is not None:
        plan["exchange"] = exchange
    if requires_tunnel:
        # Mirror the case metadata: tunnel-mode ESP needs a tunnel-mode SA on the
        # peer, so a transport-only peer skips this case while transport-mode
        # cases still plan. The shared capability is still ``ipsec_esp``.
        plan["requires_tunnel"] = True
    return plan


# Per-case plan-builder dispatch entries for the four IPSec cases (one builder
# serves them all). The registry merge in :mod:`tools.probe.engine.planning`
# exposes these through ``PLAN_BUILDERS`` (registry-first), and ``planning``
# re-imports ``_ipsec_probe_plan`` so ``planning._ipsec_probe_plan`` keeps
# identical object identity for the pinning tests.
_IPSEC_PLAN_BUILDERS: dict[str, object] = {
    "esp-transport-echo": _ipsec_probe_plan,
    "esp-tunnel-echo": _ipsec_probe_plan,
    "ah-transport-verify": _ipsec_probe_plan,
    "ikev2-sa-init": _ipsec_probe_plan,
}


# All four IPSec cases are planned-only: the builder records the exchange shape
# without building packet bytes. Moved verbatim from
# ``planning._LEGACY_PLANNED_ONLY_REGISTERED_CASES``.
_IPSEC_PLANNED_ONLY_CASES: frozenset[str] = frozenset(
    {
        "esp-transport-echo",
        "esp-tunnel-echo",
        "ah-transport-verify",
        "ikev2-sa-init",
    }
)


register(
    ProtocolPlugin(
        name="ipsec",
        cases=BEHAVIOR_IPSEC_CASES,
        plan_builders=_IPSEC_PLAN_BUILDERS,
        planned_only_cases=_IPSEC_PLANNED_ONLY_CASES,
        # IPSec's profile membership stays in the legacy ordered profile table in
        # ``cases.py`` (``IPSEC_PROFILE_CASE_NAMES``, sourced from the registered
        # IPSec cases) to preserve byte-identical selection order.
        profile_counts={},
        # All four IPSec cases are planned-only and were never stimulus-routed.
        stimulus_endpoint_cases=frozenset(),
        # IPSec produced no ``target_service_setup_plan`` service entry and no
        # inline setup-script block (verified in this target-service step against
        # the actual code), so ``target_service`` / ``setup_script`` stay ``None``
        # and nothing moved out of ``target_services.py``. The remaining hooks are
        # step 35: the four planned-only cases were never stimulus-routed, so there
        # is no live-path rewrite branch to reproduce
        # (``rewrite_endpoint_addresses``); the cases fall through to the shared
        # default failure taxonomy, so there is no IPSec
        # ``_failure_reasons_for_case`` branch (``failure_reasons``). The IPSec
        # lab-capability derivation (``ipsec_esp`` / ``ipsec_ah`` / ``ikev2``) and
        # the cross-crypto ``ipsec_interop`` hook (the only ``tools.oracle``
        # dependency) land in step 35.
        target_service=None,
        setup_script=None,
        rewrite_endpoint_addresses=None,
        failure_reasons=None,
        lab_capabilities=None,
        ipsec_interop=None,
    )
)
