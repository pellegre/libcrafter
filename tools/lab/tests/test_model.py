"""Local contract coverage for lab JSON models."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.lab.engine.model import (
    LabCommandPlan,
    LabEndpoint,
    LabRequest,
    LabRole,
    LabSession,
    LabValidationCheck,
    read_json,
    write_json,
)


class LabModelSerializationTest(unittest.TestCase):
    def test_request_round_trip_preserves_roles_and_metadata(self) -> None:
        request = LabRequest(
            provider="hetzner",
            profile="smoke",
            seed=7,
            roles=[
                LabRole(
                    name="stimulus",
                    requested_private_ipv4="10.42.0.10",
                    planned_ipv4="192.0.2.10",
                    peer_roles=["target"],
                    capabilities=["raw-send"],
                    bootstrap_metadata={"script": "/opt/lab/bootstrap-stimulus.sh"},
                    workload_metadata={"workload": "probe"},
                ),
                LabRole(
                    name="target",
                    requested_private_ipv4="10.42.0.20",
                    planned_ipv4="192.0.2.20",
                    peer_roles=["stimulus"],
                ),
            ],
            dry_run=True,
            remote_dir="/opt/libcrafter-lab",
            workload_label="probe-smoke",
            metadata={"sequence": 1},
        )

        loaded = LabRequest.from_dict(request.to_dict())

        self.assertEqual(loaded.to_dict(), request.to_dict())
        self.assertEqual(loaded.roles[0].requested_private_ipv4, "10.42.0.10")
        self.assertTrue(loaded.dry_run)
        self.assertEqual(json.loads(request.to_json())["provider"], "hetzner")

    def test_session_round_trip_preserves_endpoints_commands_and_checks(self) -> None:
        session = _session()

        loaded = LabSession.from_dict(session.to_dict())

        self.assertEqual(loaded.to_dict(), session.to_dict())
        self.assertEqual(loaded.endpoints[0].mac, "02:00:00:00:00:10")
        self.assertEqual(loaded.provider_workflow[0].shell(), "tools/endpoint/run create-endpoint")
        self.assertEqual(loaded.validation_checks[0].name, "wire-mapping")

    def test_write_and_read_json_require_absolute_file_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "lab" / "session.json"
            write_json(output, _session())

            loaded = LabSession.from_dict(read_json(output))  # type: ignore[arg-type]

            self.assertEqual(loaded.session_id, "lab-smoke-0001")

        with self.assertRaisesRegex(ValueError, "JSON output path must be absolute"):
            write_json("relative/session.json", _session())
        with self.assertRaisesRegex(ValueError, "JSON input path must be absolute"):
            read_json("relative/session.json")


class LabModelValidationTest(unittest.TestCase):
    def test_identifiers_reject_unsafe_values(self) -> None:
        with self.assertRaisesRegex(ValueError, "role.name must be a role name"):
            LabRole(name="../sender")

        with self.assertRaisesRegex(ValueError, "request.provider must be a lower-case provider"):
            LabRequest(
                provider="Hetzner",
                profile="smoke",
                seed=1,
                roles=[LabRole(name="stimulus")],
            )

        with self.assertRaisesRegex(ValueError, "request.roles must contain at least one item"):
            LabRequest(
                provider="hetzner",
                profile="smoke",
                seed=1,
                roles=[],
            )

        with self.assertRaisesRegex(ValueError, "endpoint.endpoint_id"):
            LabEndpoint(
                endpoint_id="../endpoint",
                role="stimulus",
                interface="eth0",
                ipv4="192.0.2.10",
            )

    def test_absolute_session_and_command_paths_are_enforced(self) -> None:
        with self.assertRaisesRegex(ValueError, "request.remote_dir must be an absolute path"):
            LabRequest(
                provider="hetzner",
                profile="smoke",
                seed=1,
                roles=[LabRole(name="stimulus")],
                remote_dir="relative",
            )

        with self.assertRaisesRegex(ValueError, "command.artifacts\\[\\] must be an absolute path"):
            LabCommandPlan(
                purpose="collect stdout",
                role="stimulus",
                argv=["cat", "/tmp/stdout.log"],
                operation="collect",
                artifacts=["stdout.log"],
            )

    def test_endpoint_addresses_are_validated_and_normalized(self) -> None:
        endpoint = LabEndpoint(
            endpoint_id="endpoint-a",
            role="stimulus",
            interface="eth0",
            ipv4="192.0.2.10",
            ipv6="2001:0db8::0010",
            mac="02:AA:BB:CC:DD:EE",
            peer_addresses={"target": {"ipv4": "192.0.2.20"}},
        )

        self.assertEqual(endpoint.ipv4, "192.0.2.10")
        self.assertEqual(endpoint.ipv6, "2001:db8::10")
        self.assertEqual(endpoint.mac, "02:aa:bb:cc:dd:ee")

        with self.assertRaisesRegex(ValueError, "endpoint.ipv4 must be an IPv4 address"):
            LabEndpoint(
                endpoint_id="endpoint-a",
                role="stimulus",
                interface="eth0",
                ipv4="2001:db8::10",
            )
        with self.assertRaisesRegex(ValueError, "endpoint.peer_addresses key must be a role name"):
            LabEndpoint(
                endpoint_id="endpoint-a",
                role="stimulus",
                interface="eth0",
                ipv4="192.0.2.10",
                peer_addresses={"../target": {"ipv4": "192.0.2.20"}},
            )

    def test_session_rejects_duplicate_roles_and_unknown_endpoint_roles(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate role names"):
            LabSession(
                provider="qemu",
                wire_provider="qemu",
                wire_exposure="private",
                session_id="lab-smoke-0001",
                roles=[LabRole(name="stimulus"), LabRole(name="stimulus")],
            )

        with self.assertRaisesRegex(ValueError, "endpoint role not declared"):
            LabSession(
                provider="qemu",
                wire_provider="qemu",
                wire_exposure="private",
                session_id="lab-smoke-0001",
                roles=[LabRole(name="stimulus")],
                endpoints=[
                    LabEndpoint(
                        endpoint_id="endpoint-target",
                        role="target",
                        interface="eth0",
                        ipv4="192.0.2.20",
                    )
                ],
            )


def _session() -> LabSession:
    roles = [
        LabRole(name="stimulus", planned_ipv4="192.0.2.10", peer_roles=["target"]),
        LabRole(name="target", planned_ipv4="192.0.2.20", peer_roles=["stimulus"]),
    ]
    return LabSession(
        provider="qemu",
        wire_provider="qemu",
        wire_exposure="private",
        session_id="lab-smoke-0001",
        roles=roles,
        endpoints=[
            LabEndpoint(
                endpoint_id="qemu-private-stimulus",
                role="stimulus",
                interface="eth1",
                ipv4="192.0.2.10",
                ipv6="2001:db8::10",
                mac="02:00:00:00:00:10",
                peer_addresses={"target": {"ipv4": "192.0.2.20"}},
                wire_manifest={"endpoint_id": "qemu-private-stimulus"},
            ),
            LabEndpoint(
                endpoint_id="qemu-private-target",
                role="target",
                interface="eth1",
                ipv4="192.0.2.20",
                peer_addresses={"stimulus": {"ipv4": "192.0.2.10"}},
                wire_manifest={"endpoint_id": "qemu-private-target"},
            ),
        ],
        provider_capabilities={"private_network": True, "controlled_router": False},
        infrastructure_metadata={"private_group": "lab-smoke-0001"},
        provider_workflow=[
            LabCommandPlan(
                purpose="create endpoint",
                role="stimulus",
                argv=["tools/endpoint/run", "create-endpoint"],
                operation="wire.create",
                dry_run=True,
                live_mutation=True,
                artifacts=["/tmp/libcrafter-lab/stimulus/create.json"],
            )
        ],
        command_records=[
            LabCommandPlan(
                purpose="bootstrap role",
                role="target",
                argv=["/bin/sh", "-lc", "true"],
                operation="bootstrap",
                dry_run=True,
                artifacts=["/tmp/libcrafter-lab/target/bootstrap.log"],
            )
        ],
        remote_dir="/opt/libcrafter-lab/session",
        remote_artifact_root="/opt/libcrafter-lab/session/artifacts",
        created_endpoint_ids=["qemu-private-stimulus", "qemu-private-target"],
        dry_run=True,
        cleanup_state={"attempted": False},
        validation_checks=[
            LabValidationCheck(
                name="wire-mapping",
                passed=True,
                subject="qemu/private",
            )
        ],
        metadata={"workload": "probe"},
    )


if __name__ == "__main__":
    unittest.main()
