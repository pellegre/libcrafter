"""Unit coverage for the probe boundary over lab providers."""

from __future__ import annotations

from dataclasses import dataclass
import unittest

from tools.lab.engine.model import LabEndpoint, LabRole, LabSession
from tools.lab.engine.providers.docker import DOCKER_LAB_PROVIDER_ADAPTER
from tools.probe.engine.lab import (
    LOCAL_DRY_RUN_PROVIDER,
    PROBE_CAPABILITY_NAMES,
    UnknownProbeLabProviderError,
    is_probe_lab_provider,
    probe_address_context_from_lab_session,
    probe_capabilities_for_provider,
    probe_capabilities_from_lab_capabilities,
    probe_lab_provider_names,
    probe_provider_names,
    resolve_probe_lab_provider,
)


@dataclass(frozen=True, slots=True)
class _ProviderCase:
    provider: str
    exposure: str
    stimulus_ipv4: str
    target_ipv4: str
    private_network: bool
    bridged_lan: bool
    private_group: str | None
    interface: str


PROVIDER_CASES = (
    _ProviderCase(
        provider="docker",
        exposure="private",
        stimulus_ipv4="10.79.0.10",
        target_ipv4="10.79.0.20",
        private_network=True,
        bridged_lan=False,
        private_group="probe-smoke-seed-1",
        interface="private",
    ),
    _ProviderCase(
        provider="hetzner",
        exposure="private",
        stimulus_ipv4="10.0.25.10",
        target_ipv4="10.0.25.20",
        private_network=True,
        bridged_lan=False,
        private_group="probe-smoke-seed-1",
        interface="private",
    ),
    _ProviderCase(
        provider="qemu",
        exposure="private",
        stimulus_ipv4="10.77.0.10",
        target_ipv4="10.77.0.20",
        private_network=True,
        bridged_lan=False,
        private_group="probe-smoke-seed-1",
        interface="private",
    ),
    _ProviderCase(
        provider="virtualbox",
        exposure="lan",
        stimulus_ipv4="192.0.2.10",
        target_ipv4="192.0.2.20",
        private_network=False,
        bridged_lan=True,
        private_group=None,
        interface="lan",
    ),
)


class ProbeLabProviderBoundaryTest(unittest.TestCase):
    def test_probe_provider_names_expose_local_and_lab_providers(self) -> None:
        self.assertEqual(
            probe_lab_provider_names(),
            ("docker", "hetzner", "qemu", "virtualbox"),
        )
        self.assertEqual(
            probe_provider_names(),
            ("docker", "hetzner", LOCAL_DRY_RUN_PROVIDER, "qemu", "virtualbox"),
        )
        self.assertIs(resolve_probe_lab_provider("docker"), DOCKER_LAB_PROVIDER_ADAPTER)

        for case in PROVIDER_CASES:
            with self.subTest(provider=case.provider):
                self.assertTrue(is_probe_lab_provider(case.provider))
                self.assertEqual(resolve_probe_lab_provider(case.provider).name, case.provider)

        self.assertFalse(is_probe_lab_provider(LOCAL_DRY_RUN_PROVIDER))
        with self.assertRaisesRegex(UnknownProbeLabProviderError, "probe-local"):
            resolve_probe_lab_provider(LOCAL_DRY_RUN_PROVIDER)

    def test_registered_lab_capabilities_derive_probe_capabilities(self) -> None:
        for case in PROVIDER_CASES:
            with self.subTest(provider=case.provider):
                capabilities = probe_capabilities_for_provider(case.provider, dry_run=True)

                self.assertEqual(capabilities["provider"], case.provider)
                self.assertEqual(capabilities["lab_provider"], case.provider)
                self.assertTrue(capabilities["dry_run"])
                self.assertTrue(capabilities["live_packet_exchange"])
                self.assertTrue(capabilities["icmp_echo"])
                self.assertTrue(capabilities["tcp_open_port"])
                self.assertTrue(capabilities["tcp_closed_port"])
                self.assertTrue(capabilities["dns_service"])
                self.assertFalse(capabilities["controlled_router"])
                self.assertEqual(
                    tuple(capabilities["capability_names"]),
                    PROBE_CAPABILITY_NAMES,
                )
                self.assertEqual(
                    capabilities["capability_sources"]["dns_service"],
                    ["ipv4_unicast", "controlled_services"],
                )
                lab_capabilities = capabilities["lab_capabilities"]
                self.assertEqual(lab_capabilities["provider"], case.provider)
                self.assertTrue(lab_capabilities["ipv4_unicast"])
                self.assertFalse(lab_capabilities["controlled_router"])

    def test_docker_private_lab_capabilities_drive_probe_cases(self) -> None:
        capabilities = probe_capabilities_for_provider("docker", dry_run=True)

        for key in (
            "ipv4_unicast",
            "controlled_services",
            "icmp_echo",
            "tcp_open_port",
            "tcp_closed_port",
            "dns_service",
            "link_layer_send",
            "link_layer_capture",
            "broadcast",
            "arp_resolution",
        ):
            with self.subTest(capability=key):
                self.assertTrue(capabilities[key])

        self.assertFalse(capabilities["controlled_router"])
        self.assertEqual(capabilities["lab_provider"], "docker")
        self.assertEqual(capabilities["lab_capabilities"]["provider"], "docker")
        self.assertTrue(capabilities["lab_capabilities"]["provider_mac_known"])
        self.assertTrue(capabilities["lab_capabilities"]["controlled_services"])
        self.assertNotIn("docker/lan", probe_provider_names())
        self.assertNotIn("docker/wan", probe_provider_names())
        self.assertNotIn("lan", capabilities["capability_names"])
        self.assertNotIn("wan", capabilities["capability_names"])

    def test_local_dry_run_capabilities_use_same_derivation(self) -> None:
        capabilities = probe_capabilities_for_provider(
            LOCAL_DRY_RUN_PROVIDER,
            dry_run=True,
        )

        self.assertEqual(capabilities["provider"], LOCAL_DRY_RUN_PROVIDER)
        self.assertTrue(capabilities["dry_run"])
        self.assertFalse(capabilities["live_packet_exchange"])
        self.assertTrue(capabilities["icmp_echo"])
        self.assertTrue(capabilities["tcp_open_port"])
        self.assertTrue(capabilities["tcp_closed_port"])
        self.assertTrue(capabilities["dns_service"])
        self.assertFalse(capabilities["controlled_router"])
        self.assertEqual(
            capabilities,
            probe_capabilities_from_lab_capabilities(
                LOCAL_DRY_RUN_PROVIDER,
                capabilities["lab_capabilities"],
                dry_run=True,
            ),
        )

    def test_lab_session_endpoints_convert_to_probe_address_context(self) -> None:
        for case in PROVIDER_CASES:
            with self.subTest(provider=case.provider):
                session = _fake_session(case)

                context = probe_address_context_from_lab_session(session)

                self.assertEqual(context["provider"], case.provider)
                self.assertEqual(context["wire_provider"], case.provider)
                self.assertEqual(context["wire_exposure"], case.exposure)
                self.assertTrue(context["dry_run"])
                self.assertEqual(context["stimulus_ipv4"], case.stimulus_ipv4)
                self.assertEqual(context["target_ipv4"], case.target_ipv4)
                self.assertEqual(context["endpoint_count"], 2)

                endpoints = context["endpoints"]
                stimulus = endpoints["stimulus"]
                target = endpoints["target"]
                self.assertEqual(stimulus["address"], case.stimulus_ipv4)
                self.assertEqual(stimulus["ipv4"], case.stimulus_ipv4)
                self.assertEqual(stimulus["peer_address"], case.target_ipv4)
                self.assertEqual(stimulus["peer_addresses"]["target"]["ipv4"], case.target_ipv4)
                self.assertEqual(stimulus["metadata"]["peer_role"], "target")
                self.assertEqual(
                    stimulus["metadata"]["lab_session_id"],
                    f"{case.provider}-probe-session",
                )
                self.assertEqual(stimulus["metadata"]["private_network"], case.private_network)
                self.assertEqual(
                    stimulus["metadata"].get("bridged_lan", False),
                    case.bridged_lan,
                )
                self.assertEqual(
                    stimulus["metadata"]["wire_endpoint_plan"]["endpoint_id"],
                    f"{case.provider}-stimulus",
                )
                self.assertEqual(target["peer_address"], case.stimulus_ipv4)

    def test_address_context_requires_stimulus_and_target(self) -> None:
        case = PROVIDER_CASES[0]
        session = LabSession(
            provider=case.provider,
            wire_provider=case.provider,
            wire_exposure=case.exposure,
            session_id="missing-target",
            roles=[LabRole(name="stimulus", planned_ipv4=case.stimulus_ipv4)],
            endpoints=[
                _endpoint(
                    case,
                    role="stimulus",
                    ipv4=case.stimulus_ipv4,
                    peer_role="target",
                    peer_ipv4=case.target_ipv4,
                )
            ],
        )

        with self.assertRaisesRegex(ValueError, "missing lab endpoint role 'target'"):
            probe_address_context_from_lab_session(session)


def _fake_session(case: _ProviderCase) -> LabSession:
    roles = [
        LabRole(
            name="stimulus",
            planned_ipv4=case.stimulus_ipv4,
            peer_roles=["target"],
        ),
        LabRole(
            name="target",
            planned_ipv4=case.target_ipv4,
            peer_roles=["stimulus"],
        ),
    ]
    endpoints = [
        _endpoint(
            case,
            role="stimulus",
            ipv4=case.stimulus_ipv4,
            peer_role="target",
            peer_ipv4=case.target_ipv4,
        ),
        _endpoint(
            case,
            role="target",
            ipv4=case.target_ipv4,
            peer_role="stimulus",
            peer_ipv4=case.stimulus_ipv4,
        ),
    ]
    return LabSession(
        provider=case.provider,
        wire_provider=case.provider,
        wire_exposure=case.exposure,
        session_id=f"{case.provider}-probe-session",
        roles=roles,
        endpoints=endpoints,
        provider_capabilities={
            "provider": case.provider,
            "dry_run": True,
            "live_packet_exchange": True,
            "ipv4_unicast": True,
            "controlled_services": True,
            "controlled_router": False,
        },
        infrastructure_metadata={
            "provider": case.provider,
            "wire_provider": case.provider,
            "wire_exposure": case.exposure,
            "dry_run": True,
            "creates_infrastructure": False,
            "would_create_infrastructure": True,
            "private_network": case.private_network,
            "bridged_lan": case.bridged_lan,
        },
        remote_dir="/root/libcrafter",
        remote_artifact_root=f"/root/libcrafter/artifacts/{case.provider}",
        dry_run=True,
        metadata={
            "provider": case.provider,
            "private_group": case.private_group,
            "private_network": case.private_network,
            "bridged_lan": case.bridged_lan,
        },
    )


def _endpoint(
    case: _ProviderCase,
    *,
    role: str,
    ipv4: str,
    peer_role: str,
    peer_ipv4: str,
) -> LabEndpoint:
    return LabEndpoint(
        endpoint_id=f"{case.provider}-{role}",
        role=role,
        interface=case.interface,
        ipv4=ipv4,
        ipv6="2001:db8:25::10" if role == "stimulus" else "2001:db8:25::20",
        mac="02:00:00:00:25:10" if role == "stimulus" else "02:00:00:00:25:20",
        peer_addresses={peer_role: {"ipv4": peer_ipv4}},
        wire_manifest={
            "endpoint_id": f"{case.provider}-{role}",
            "provider": case.provider,
            "exposure": case.exposure,
            "role": role,
            "artifact_dir": f"/tmp/libcrafter-lab/{case.provider}/{role}",
        },
        metadata={
            "provider": case.provider,
            "wire_provider": case.provider,
            "wire_exposure": case.exposure,
            "private_group": case.private_group,
            "private_network": case.private_network,
            "bridged_lan": case.bridged_lan,
            "address_source": "fake-lab-session",
        },
    )


if __name__ == "__main__":
    unittest.main()
