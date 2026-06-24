"""RIP/RIPng probe protocol plugin: cases, plan builders, and live surface.

RIP (IPv4, UDP/520, RFC 2453) and RIPng (IPv6, UDP/521, RFC 2080) are related
distance-vector protocols that share the same probe-owned FRR runtime (the
``ripd`` / ``ripngd`` daemons), so they migrate together as a single small
plugin (``name="rip"``) owning both case families. The surface this module
bundles:

* the ``rip-update-v2`` and ``ripng-update`` cases (built through the
  ``_behavior_case`` factory) and their shared ``_RIP_CAPABILITIES`` constant
  (the catalog contribution),
* the ``_rip_update_probe_plan`` / ``_ripng_update_probe_plan`` plan builders,
  the planned-only set, the RIP/RIPng wire constants the plans reference, and
  the ``rip_peer_service_descriptor`` the IPv4 plan renders its target-service
  block from (moved verbatim from :mod:`tools.probe.engine.target_services`),
* the ``target_service`` hook (``None``: RIP/RIPng never produced a
  ``target_service_setup_plan`` service entry -- the legacy setup plan only built
  the BGP peer via the ``bgp-`` / ``frr-bgp-peer`` selector, which the RIP case
  names and ``frr-ripd`` / ``frr-ripngd`` kinds never matched -- so there is no
  setup-plan contribution to reproduce; the descriptor is a *plan-building*
  input, called by the IPv4 builder),
* the ``setup_script`` hook (``None``: RIP/RIPng had no inline setup-script
  block; the daemon is provision-script driven),
* the ``rewrite_endpoint_addresses`` hook (``None``: both RIP cases are
  planned-only and were never stimulus-routed, so the live-path rewrite never
  reached RIP -- there is no legacy RIP rewrite branch to reproduce),
* the ``failure_reasons`` hook (``None``: RIP/RIPng had no failure-reason branch
  in ``cli._failure_reasons_for_case`` and fell through to the shared default),
  and
* the ``lab_capabilities`` hook (the ``rip_peer`` derived capability).

The plan builders are moved verbatim from :mod:`tools.probe.engine.planning`;
``planning`` re-imports them so ``planning._rip_update_probe_plan`` /
``planning._ripng_update_probe_plan`` and ``PLAN_BUILDERS[name] is _<builder>``
keep identical object identity for the pinning tests. The
``rip_peer_service_descriptor`` is moved verbatim from
:mod:`tools.probe.engine.target_services`; that module no longer needs it (no
test or caller resolves ``target_services.rip_peer_service_descriptor``), and the
RIP plan builder calls it directly here.

RIP's ``profile_counts`` is intentionally empty: the ``rip-smoke`` profile rides
``rip-update-v2`` then ``ripng-update`` in a fixed position, and the
registry-first profile merge would move the registry contribution to the front
of that profile, so the legacy ordered profile name table in
:mod:`tools.probe.engine.cases` (``RIP_SMOKE_PROFILE_CASE_NAMES``, now sourced
from the registered RIP/RIPng cases) keeps owning RIP's profile membership to
preserve byte-identical selection order.

Imports are relative only so the module loads under both engine import roots
(``engine.protocols.rip`` for the CLI and ``tools.probe.engine.protocols.rip``
for the tests).
"""

from __future__ import annotations

from collections.abc import Mapping

from ..capability_derivation import capability, capability_default_true
from ..case_helpers import _behavior_case
from ..model import JSONObject, JSONValue, ProbeCase
from ..planning_helpers import (
    deterministic_bytes,
    deterministic_documentation_ipv6,
    deterministic_ipv4_pair,
)
from ..target_service_helpers import TargetServiceDescriptor
from .base import ProtocolPlugin, register


# RIP target-service constants (moved verbatim from
# :mod:`tools.probe.engine.target_services`). RIPv2 rides UDP/520 and advertises
# to the all-RIP-routers multicast group 224.0.0.9 (RFC 2453); the probe-owned
# RIP daemon is FRR ``ripd`` (the same FRR/vtysh runtime as the BGP target
# service), inspected with ``show ip rip``. The provision script and config
# template live under ``tools/probe/target_services/rip/`` (out of scope;
# referenced, not changed).
RIP_SERVICE_KIND = "frr-ripd"
RIP_SERVICE_PORTS = [520]
RIP_RUNTIME = "frr"
RIP_MULTICAST_GROUP = "224.0.0.9"
RIP_DOCUMENTATION_IPV4_PREFIX = "198.51.100.0/24"
RIP_PROVISION_SCRIPT = "tools/probe/target_services/rip/provision-daemon.sh"
RIP_CONFIG_TEMPLATE = "tools/probe/target_services/rip/ripd.conf.template"
RIP_RIB_COMMAND = "vtysh -c 'show ip rip'"


# RIPv2 plan constants (moved verbatim from
# :mod:`tools.probe.engine.planning`). These pull the wire port, multicast group,
# runtime, and RIB command from the target-service constants above so the plan
# matches the ``rip_peer_service_descriptor`` the live target setup renders.
_RIP_UDP_PORT = RIP_SERVICE_PORTS[0]
_RIP_MULTICAST_GROUP = RIP_MULTICAST_GROUP
_RIP_SERVICE_KIND = RIP_SERVICE_KIND
_RIP_RUNTIME = RIP_RUNTIME
_RIP_RIB_COMMAND = RIP_RIB_COMMAND


# RIPng (RFC 2080) plan constants (moved verbatim from
# :mod:`tools.probe.engine.planning`). RIPng rides UDP/521 and advertises to the
# all-RIPng-routers IPv6 multicast group ff02::9, reusing the same FRR runtime as
# the IPv4 RIP target service (FRR's ``ripngd`` daemon), inspected with
# ``show ipv6 ripng``. The documentation prefix stays in the RFC 3849 block
# (2001:db8::/32).
_RIPNG_UDP_PORT = 521
_RIPNG_MULTICAST_GROUP = "ff02::9"
_RIPNG_SERVICE_KIND = "frr-ripngd"
_RIPNG_RIB_COMMAND = "vtysh -c 'show ipv6 ripng'"
_RIPNG_DOCUMENTATION_IPV6_PREFIX = "2001:db8::/32"


# RIP/RIPng shared capability constant (moved verbatim from
# :mod:`tools.probe.engine.cases`). A controlled FRR ripd/ripngd peer needs the
# same IPv4-unicast + controlled-service substrate as the BGP target service,
# with an optional provider flag to deny RIP peer provisioning.
_RIP_CAPABILITIES = ["rip_peer"]


# RIP smoke cases (moved verbatim from ``cases.RIP_SMOKE_CASES``). Probe owns
# controlled target-service setup for the FRR ripd daemon; the current stimulus
# is planned-only until the endpoint driver executes the RIP stimulus example.
# The RIPng variant rides UDP/521 to the IPv6 all-RIPng-routers multicast group
# (ff02::9) and reuses the same FRR runtime (the ``ripngd`` daemon) so the live
# path covers IPv6 too.
RIP_SMOKE_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="rip-update-v2",
        description=(
            "Plan a RIPv2 update exchange against a probe-owned RIP daemon."
        ),
        stimulus="rip_request",
        expected_response="rip_peer_update",
        required_capabilities=_RIP_CAPABILITIES,
        protocol="rip",
        metadata={
            "service": "frr-ripd",
            "stateful": True,
            "planned_only": True,
        },
    ),
    _behavior_case(
        name="ripng-update",
        description=(
            "Plan a RIPng update exchange against a probe-owned RIPng daemon "
            "over UDP/521 to the ff02::9 multicast group."
        ),
        stimulus="ripng_request",
        expected_response="ripng_peer_update",
        required_capabilities=_RIP_CAPABILITIES,
        protocol="ripng",
        metadata={
            "service": "frr-ripngd",
            "stateful": True,
            "planned_only": True,
        },
    ),
)


def rip_peer_service_descriptor(
    *,
    bind_ipv4: str,
    source_ipv4: str,
) -> TargetServiceDescriptor:
    """Describe the probe-owned FRR ``ripd`` target service.

    Moved verbatim from :mod:`tools.probe.engine.target_services`. Mirrors
    ``frr_bgp_peer_descriptor`` for the RIP smoke profile: an FRR runtime serving
    RIPv2 on UDP/520, advertising documentation-range prefixes to the
    all-RIP-routers multicast group, provisioned from probe-owned assets and
    inspected through ``vtysh``. The IPv4 RIP plan builder calls it to render the
    plan's target-service block.
    """

    # Imported lazily so the plugin module loads during ``protocols`` package
    # auto-discovery without cycling through ``capabilities`` -> ``lab`` ->
    # ``protocols``. The constant is a plain skip-reason string.
    from ..capabilities import SKIP_REQUIRES_CONTROLLED_SERVICE

    return TargetServiceDescriptor(
        name=RIP_SERVICE_KIND,
        protocol="udp",
        purpose="rip-peer",
        bind_ipv4=bind_ipv4,
        source_ipv4=source_ipv4,
        port=RIP_SERVICE_PORTS[0],
        requires=[RIP_RUNTIME, SKIP_REQUIRES_CONTROLLED_SERVICE],
        setup_commands=[
            f"run {RIP_PROVISION_SCRIPT} with DRIVER_IP={source_ipv4}",
            f"inspect RIB with {RIP_RIB_COMMAND}",
        ],
        cleanup_commands=[
            "stop FRR ripd peer service through provider cleanup",
        ],
        artifacts=[
            "live-artifacts/probe/target-services/rip-provision.stdout.txt",
            "live-artifacts/probe/target-services/rip-provision.stderr.txt",
        ],
        metadata={
            "kind": RIP_SERVICE_KIND,
            "runtime": RIP_RUNTIME,
            "deterministic": True,
            "ports": list(RIP_SERVICE_PORTS),
            "multicast_group": RIP_MULTICAST_GROUP,
            "documentation_prefixes": [
                RIP_DOCUMENTATION_IPV4_PREFIX,
            ],
            "provision_script": RIP_PROVISION_SCRIPT,
            "config_template": RIP_CONFIG_TEMPLATE,
            "rib_command": RIP_RIB_COMMAND,
        },
    )


def _rip_update_probe_plan(
    *,
    case_name: str = "rip-update-v2",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a probe-owned RIPv2 update exchange against an FRR ``ripd`` service.

    The probe sends a RIPv2 request on UDP/520 to the documentation-range
    unicast target running the RIP daemon and expects the daemon's RIPv2
    response (advertised to the all-RIP-routers multicast group 224.0.0.9 per
    RFC 2453). The crate-side ``rip_request`` stimulus driver lands with the
    endpoint runner; until then the dry-run plan is ``planned_only`` -- it
    records the stimulus driver intent, the FRR ``ripd`` target-service setup,
    the UDP port, multicast group, and the ``show ip rip`` RIB command, but
    builds no packet bytes and sends nothing.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 42000 + int.from_bytes(digest[0:2], "big") % 10000
    documentation_prefixes = [
        RIP_DOCUMENTATION_IPV4_PREFIX,
    ]
    # The plan references the same probe-owned FRR ``ripd`` descriptor the live
    # target setup renders (mirroring how the BGP plan references its peer
    # descriptor), so the provision script and config template stay in sync.
    rip_service = rip_peer_service_descriptor(
        bind_ipv4=target_ipv4,
        source_ipv4=stimulus_ipv4,
    )
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "rip_request",
        "expected_response": "rip_peer_update",
        "planned_only": True,
        "protocol": "rip",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "multicast_group": _RIP_MULTICAST_GROUP,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": _RIP_UDP_PORT,
        "documentation_prefixes": documentation_prefixes,
        "stimulus_driver": {
            "name": "rip_request",
            "cargo_example": "rip_request",
            "driver_source": "crafter/examples/rip_request.rs",
            "state": "planned-only",
            "planned_only": True,
        },
        "target_service": {
            "required": True,
            "kind": _RIP_SERVICE_KIND,
            "protocol": "udp",
            "port": _RIP_UDP_PORT,
            "multicast_group": _RIP_MULTICAST_GROUP,
            "bind_ipv4": target_ipv4,
            "source_ipv4": stimulus_ipv4,
            "runtime": _RIP_RUNTIME,
            "documentation_prefixes": documentation_prefixes,
            "provision_script": rip_service.metadata["provision_script"],
            "config_template": rip_service.metadata["config_template"],
            "rib_command": _RIP_RIB_COMMAND,
            "deterministic": True,
        },
        "capture_filter": (
            f"udp and src host {target_ipv4} "
            f"and src port {_RIP_UDP_PORT} and dst port {_RIP_UDP_PORT}"
        ),
        "validation": {
            "planned_only": True,
            "driver": "rip_request",
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": _RIP_UDP_PORT,
            "destination_port": _RIP_UDP_PORT,
            "multicast_group": _RIP_MULTICAST_GROUP,
            "rib_command": _RIP_RIB_COMMAND,
        },
        "wire_requirements": {
            "requires_ipv4_unicast": True,
            "requires_controlled_service": True,
            "requires_rip_peer": True,
            "note": (
                "RIP smoke dry-run exposes the rip_request stimulus intent and "
                "probe-owned FRR ripd target-service setup without sending "
                "UDP/520 datagrams or installing FRR."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _ripng_update_probe_plan(
    *,
    case_name: str = "ripng-update",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a probe-owned RIPng update exchange against an FRR ``ripngd`` service.

    The IPv6 analog of :func:`_rip_update_probe_plan`: the probe sends a RIPng
    request on UDP/521 to the documentation-range unicast target running the
    RIPng daemon and expects the daemon's RIPng response (advertised to the
    all-RIPng-routers multicast group ``ff02::9`` per RFC 2080). The crate-side
    ``ripng_request`` stimulus driver lands with the endpoint runner; until then
    the dry-run plan is ``planned_only`` -- it records the stimulus driver
    intent, the FRR ``ripngd`` target-service setup, the UDP port, multicast
    group, and the ``show ipv6 ripng`` RIB command, but builds no packet bytes
    and sends nothing.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv6 = deterministic_documentation_ipv6(digest)
    target_ipv6 = deterministic_documentation_ipv6(digest[::-1])
    source_port = 42000 + int.from_bytes(digest[0:2], "big") % 10000
    documentation_prefixes = [
        _RIPNG_DOCUMENTATION_IPV6_PREFIX,
    ]
    # The RIPng path reuses the same probe-owned FRR runtime assets as the IPv4
    # RIP target service (FRR's ``ripngd`` daemon shares the ``ripd.conf``
    # runtime), so the provision script and config template stay in sync with
    # the IPv4 plan while the wire details (port, multicast group, RIB command)
    # are IPv6-specific.
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "ripng_request",
        "expected_response": "ripng_peer_update",
        "planned_only": True,
        "protocol": "ripng",
        "source_ipv6": stimulus_ipv6,
        "destination_ipv6": target_ipv6,
        "multicast_group": _RIPNG_MULTICAST_GROUP,
        "expected_reply_source_ipv6": target_ipv6,
        "expected_reply_destination_ipv6": stimulus_ipv6,
        "source_port": source_port,
        "destination_port": _RIPNG_UDP_PORT,
        "documentation_prefixes": documentation_prefixes,
        "stimulus_driver": {
            "name": "ripng_request",
            "cargo_example": "ripng_request",
            "driver_source": "crafter/examples/ripng_request.rs",
            "state": "planned-only",
            "planned_only": True,
        },
        "target_service": {
            "required": True,
            "kind": _RIPNG_SERVICE_KIND,
            "protocol": "udp",
            "port": _RIPNG_UDP_PORT,
            "multicast_group": _RIPNG_MULTICAST_GROUP,
            "bind_ipv6": target_ipv6,
            "source_ipv6": stimulus_ipv6,
            "runtime": _RIP_RUNTIME,
            "documentation_prefixes": documentation_prefixes,
            "provision_script": RIP_PROVISION_SCRIPT,
            "config_template": RIP_CONFIG_TEMPLATE,
            "rib_command": _RIPNG_RIB_COMMAND,
            "deterministic": True,
        },
        "capture_filter": (
            f"udp and src host {target_ipv6} "
            f"and src port {_RIPNG_UDP_PORT} and dst port {_RIPNG_UDP_PORT}"
        ),
        "validation": {
            "planned_only": True,
            "driver": "ripng_request",
            "source_ipv6": target_ipv6,
            "destination_ipv6": stimulus_ipv6,
            "source_port": _RIPNG_UDP_PORT,
            "destination_port": _RIPNG_UDP_PORT,
            "multicast_group": _RIPNG_MULTICAST_GROUP,
            "rib_command": _RIPNG_RIB_COMMAND,
        },
        "wire_requirements": {
            "requires_ipv6_unicast": True,
            "requires_controlled_service": True,
            "requires_rip_peer": True,
            "note": (
                "RIPng smoke dry-run exposes the ripng_request stimulus intent "
                "and probe-owned FRR ripngd target-service setup without sending "
                "UDP/521 datagrams or installing FRR."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


# Per-case plan-builder dispatch entries for the two RIP cases. The registry
# merge in :mod:`tools.probe.engine.planning` exposes these through
# ``PLAN_BUILDERS`` (registry-first), and ``planning`` re-imports the functions
# so ``planning._rip_update_probe_plan`` / ``planning._ripng_update_probe_plan``
# keep identical object identity for the pinning tests.
_RIP_PLAN_BUILDERS: dict[str, object] = {
    "rip-update-v2": _rip_update_probe_plan,
    "ripng-update": _ripng_update_probe_plan,
}


# Both RIP cases are planned-only: the builders record the exchange shape
# without building packet bytes.
_RIP_PLANNED_ONLY_CASES: frozenset[str] = frozenset(
    {"rip-update-v2", "ripng-update"}
)


def rip_lab_capabilities(substrate: Mapping[str, JSONValue]) -> Mapping[str, object]:
    """Return the RIP plugin's derived probe-capability contribution.

    Moved verbatim from the ``rip_peer`` derivation in
    ``lab.probe_capabilities_from_lab_capabilities``: RIP smoke drives a
    controlled FRR ripd peer on the target endpoint, so (like BGP) it needs the
    IPv4-unicast + controlled-service substrate, with an optional provider flag
    to deny RIP peer provisioning. The shared ``capability_names`` /
    ``capability_sources`` tables stay in ``lab``; this hook contributes only the
    derived ``rip_peer`` value, merged byte-identically over the legacy value.
    """

    ipv4_unicast = capability(substrate, "ipv4_unicast", "ipv4")
    controlled_services = capability(
        substrate,
        "controlled_services",
        "controlled_service",
    )
    return {
        "rip_peer": (
            ipv4_unicast
            and controlled_services
            and capability_default_true(substrate, "rip_peer")
        ),
    }


register(
    ProtocolPlugin(
        name="rip",
        cases=RIP_SMOKE_CASES,
        plan_builders=_RIP_PLAN_BUILDERS,
        planned_only_cases=_RIP_PLANNED_ONLY_CASES,
        # RIP's profile membership stays in the legacy ordered profile table in
        # ``cases.py`` (``RIP_SMOKE_PROFILE_CASE_NAMES``, sourced from the
        # registered RIP/RIPng cases) to preserve byte-identical selection order.
        profile_counts={},
        # Both RIP cases are planned-only and were never stimulus-routed.
        stimulus_endpoint_cases=frozenset(),
        # ``target_service`` / ``setup_script`` stay ``None``: RIP/RIPng produced
        # no ``target_service_setup_plan`` service entry and no inline
        # setup-script block (the daemon is provision-script driven). The
        # ``rip_peer_service_descriptor`` is a plan-building input, called by the
        # IPv4 builder above. ``rewrite_endpoint_addresses`` / ``failure_reasons``
        # stay ``None``: RIP has no live-path rewrite branch (it is not
        # stimulus-routed) and no failure-reason branch (it fell through to the
        # shared default). ``lab_capabilities`` contributes the ``rip_peer``
        # derived capability.
        target_service=None,
        setup_script=None,
        rewrite_endpoint_addresses=None,
        failure_reasons=None,
        lab_capabilities=rip_lab_capabilities,
    )
)
