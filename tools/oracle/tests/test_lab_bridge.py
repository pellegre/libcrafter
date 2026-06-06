"""Unit coverage for converting lab sessions into oracle live report data."""

from __future__ import annotations

from dataclasses import dataclass
import unittest

from tools.lab.engine.model import LabCommandPlan, LabEndpoint, LabRole, LabSession
from tools.oracle.engine.live import (
    lab_session_oracle_report_metadata,
    live_endpoint_addresses,
    live_endpoint_from_lab_endpoint,
    live_endpoints_from_lab_session,
)


@dataclass(frozen=True, slots=True)
class _ProviderCase:
    provider: str
    exposure: str
    libcrafter_ipv4: str
    reference_ipv4: str
    private_network: bool
    bridged_lan: bool
    private_group: str | None
    interface: str


PROVIDER_CASES = (
    _ProviderCase(
        provider="hetzner",
        exposure="private",
        libcrafter_ipv4="10.42.19.10",
        reference_ipv4="10.42.19.20",
        private_network=True,
        bridged_lan=False,
        private_group="oracle-live-private",
        interface="oracle0",
    ),
    _ProviderCase(
        provider="qemu",
        exposure="private",
        libcrafter_ipv4="10.77.0.10",
        reference_ipv4="10.77.0.20",
        private_network=True,
        bridged_lan=False,
        private_group="oracle-live-private",
        interface="private",
    ),
    _ProviderCase(
        provider="virtualbox",
        exposure="lan",
        libcrafter_ipv4="192.0.2.110",
        reference_ipv4="192.0.2.120",
        private_network=False,
        bridged_lan=True,
        private_group=None,
        interface="lan",
    ),
)


class LabBridgeTest(unittest.TestCase):
    def test_lab_session_endpoints_convert_to_live_endpoints(self) -> None:
        for case in PROVIDER_CASES:
            with self.subTest(provider=case.provider):
                session = _fake_session(case)

                endpoints = live_endpoints_from_lab_session(session)

                self.assertEqual(list(endpoints), ["libcrafter", "reference_backend"])
                self.assertEqual(endpoints["libcrafter"].role, "libcrafter")
                self.assertEqual(endpoints["reference_backend"].role, "reference_backend")
                self.assertEqual(endpoints["libcrafter"].address, case.libcrafter_ipv4)
                self.assertEqual(endpoints["reference_backend"].address, case.reference_ipv4)
                self.assertEqual(endpoints["libcrafter"].interface, case.interface)
                self.assertEqual(
                    endpoints["libcrafter"].metadata["peer_role"],
                    "reference_backend",
                )
                self.assertEqual(
                    endpoints["libcrafter"].metadata["peer_address"],
                    case.reference_ipv4,
                )
                self.assertEqual(endpoints["libcrafter"].metadata["provider"], case.provider)
                self.assertEqual(
                    endpoints["libcrafter"].metadata["wire_exposure"],
                    case.exposure,
                )
                self.assertEqual(
                    endpoints["libcrafter"].metadata["lab_session_id"],
                    f"{case.provider}-oracle-session",
                )
                self.assertEqual(
                    endpoints["libcrafter"].metadata["private_network"],
                    case.private_network,
                )
                self.assertEqual(
                    endpoints["libcrafter"].metadata.get("bridged_lan", False),
                    case.bridged_lan,
                )
                self.assertEqual(
                    endpoints["libcrafter"].metadata["wire_endpoint_plan"]["endpoint_id"],
                    f"{case.provider}-libcrafter",
                )

    def test_lab_endpoint_conversion_preserves_addresses_and_mac(self) -> None:
        session = _fake_session(PROVIDER_CASES[2])
        endpoint = session.endpoints[0]

        live_endpoint = live_endpoint_from_lab_endpoint(endpoint, session=session)

        self.assertEqual(live_endpoint.role, endpoint.role)
        self.assertEqual(live_endpoint.address, endpoint.ipv4)
        self.assertEqual(live_endpoint.ipv6_address, endpoint.ipv6)
        self.assertEqual(live_endpoint.metadata["mac_address"], endpoint.mac)
        self.assertEqual(
            live_endpoint_addresses(live_endpoint),
            {
                "ipv4": endpoint.ipv4,
                "ipv6": endpoint.ipv6,
                "mac": endpoint.mac,
            },
        )

    def test_report_metadata_uses_existing_oracle_live_keys(self) -> None:
        for case in PROVIDER_CASES:
            with self.subTest(provider=case.provider):
                session = _fake_session(case)

                metadata = lab_session_oracle_report_metadata(session)

                self.assertEqual(metadata["provider"], case.provider)
                self.assertEqual(metadata["wire_provider"], case.provider)
                self.assertEqual(metadata["wire_exposure"], case.exposure)
                self.assertTrue(metadata["dry_run"])
                self.assertFalse(metadata["creates_infrastructure"])
                self.assertTrue(metadata["would_create_infrastructure"])
                self.assertEqual(metadata["endpoint_count"], 2)
                self.assertEqual(
                    metadata["planned_infrastructure"]["provider"],
                    case.provider,
                )
                self.assertEqual(
                    metadata["wire_endpoint_plan"]["endpoint_count"],
                    2,
                )
                self.assertNotIn("live_endpoints", metadata["wire_endpoint_plan"])
                self.assertEqual(
                    metadata["wire_endpoint_lifecycle"]["remote_dir"],
                    "/root/libcrafter",
                )
                self.assertEqual(
                    metadata["wire_endpoint_lifecycle"]["remote_artifact_root"],
                    f"/root/libcrafter/artifacts/{case.provider}",
                )
                self.assertEqual(
                    metadata["provider_workflow"][0]["operation"],
                    "endpoint.doctor",
                )
                self.assertEqual(
                    metadata["provider_commands"][0]["operation"],
                    "endpoint.create",
                )
                self.assertEqual(
                    metadata["endpoints"]["libcrafter"]["address"],
                    case.libcrafter_ipv4,
                )
                self.assertEqual(
                    metadata["lab_session"]["session_id"],
                    f"{case.provider}-oracle-session",
                )
                self.assertEqual(metadata.get("private_group"), case.private_group)
                self.assertEqual(metadata["private_network"], case.private_network)


def _fake_session(case: _ProviderCase) -> LabSession:
    roles = [
        LabRole(
            name="libcrafter",
            planned_ipv4=case.libcrafter_ipv4,
            peer_roles=["reference_backend"],
        ),
        LabRole(
            name="reference_backend",
            planned_ipv4=case.reference_ipv4,
            peer_roles=["libcrafter"],
        ),
    ]
    endpoints = [
        _endpoint(
            case,
            role="libcrafter",
            ipv4=case.libcrafter_ipv4,
            peer_role="reference_backend",
            peer_ipv4=case.reference_ipv4,
        ),
        _endpoint(
            case,
            role="reference_backend",
            ipv4=case.reference_ipv4,
            peer_role="libcrafter",
            peer_ipv4=case.libcrafter_ipv4,
        ),
    ]
    provider_workflow = [
        LabCommandPlan(
            purpose=f"check-{case.provider}-wire",
            role=None,
            argv=[
                "tools/endpoint/run",
                "doctor",
                "--provider",
                case.provider,
                "--exposure",
                case.exposure,
                "--dry-run",
                "--json",
            ],
            operation="endpoint.doctor",
            dry_run=True,
            live_mutation=False,
            metadata={
                "provider": case.provider,
                "exposure": case.exposure,
                "endpoint_command": True,
            },
        )
    ]
    command_records = [
        LabCommandPlan(
            purpose=f"create {endpoint.role} endpoint",
            role=endpoint.role,
            argv=[
                "tools/endpoint/run",
                "create",
                "--provider",
                case.provider,
                "--exposure",
                case.exposure,
                "--role",
                endpoint.role,
                "--dry-run",
                "--json",
            ],
            operation="endpoint.create",
            dry_run=True,
            live_mutation=False,
            metadata={
                "provider": case.provider,
                "exposure": case.exposure,
                "endpoint_command": True,
            },
        )
        for endpoint in endpoints
    ]
    return LabSession(
        provider=case.provider,
        wire_provider=case.provider,
        wire_exposure=case.exposure,
        session_id=f"{case.provider}-oracle-session",
        roles=roles,
        endpoints=endpoints,
        provider_capabilities={
            "provider": case.provider,
            "dry_run": True,
            "ipv4_unicast": True,
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
        provider_workflow=provider_workflow,
        command_records=command_records,
        remote_dir="/root/libcrafter",
        remote_artifact_root=f"/root/libcrafter/artifacts/{case.provider}",
        created_endpoint_ids=[],
        dry_run=True,
        cleanup_state={
            "status": "not_started",
            "artifact_collection_attempted": False,
            "teardown_attempted": False,
        },
        metadata={
            "provider": case.provider,
            "private_group": case.private_group,
            "private_network": case.private_network,
            "bridged_lan": case.bridged_lan,
            "endpoint_plan": {
                "provider": case.provider,
                "wire_provider": case.provider,
                "exposure": case.exposure,
                "dry_run": True,
                "endpoint_count": 2,
                "live_endpoints": {"legacy": "removed before reports"},
            },
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
        ipv6="2001:db8:16::10" if role == "libcrafter" else "2001:db8:16::20",
        mac="02:00:00:00:00:10" if role == "libcrafter" else "02:00:00:00:00:20",
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
