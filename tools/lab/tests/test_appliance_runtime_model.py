"""Coverage for appliance runtime fields in lab JSON models."""

from __future__ import annotations

import unittest

from tools.lab.engine.model import (
    LabApplianceRuntime,
    LabEndpoint,
    LabRole,
    LabSession,
)


class LabApplianceRuntimeSerializationTest(unittest.TestCase):
    def test_runtime_round_trip_on_session_and_endpoint(self) -> None:
        runtime = _runtime()
        session = _session(appliance_runtime=runtime)

        loaded = LabSession.from_dict(session.to_dict())

        self.assertEqual(loaded.to_dict(), session.to_dict())
        self.assertIsNotNone(loaded.appliance_runtime)
        self.assertIsNotNone(loaded.endpoints[0].appliance_runtime)
        self.assertEqual(loaded.appliance_runtime.profile, "lan-raw")
        self.assertEqual(
            loaded.appliance_runtime.image_tag,
            "registry.example.invalid/libcrafter/appliance:smoke",
        )
        self.assertEqual(
            loaded.appliance_runtime.container_policy["capabilities"],
            ["NET_RAW", "NET_ADMIN"],
        )
        self.assertEqual(
            loaded.endpoints[0].appliance_runtime.check_metadata["host_prepare"],
            {"passed": True},
        )

    def test_missing_runtime_field_loads_as_none(self) -> None:
        endpoint_data = {
            "endpoint_id": "endpoint-stimulus",
            "role": "stimulus",
            "interface": "eth0",
            "ipv4": "192.0.2.10",
        }
        session_data = {
            "provider": "qemu",
            "wire_provider": "qemu",
            "wire_exposure": "private",
            "session_id": "lab-smoke-0001",
            "roles": [{"name": "stimulus"}],
            "endpoints": [endpoint_data],
        }

        endpoint = LabEndpoint.from_dict(endpoint_data)
        session = LabSession.from_dict(session_data)

        self.assertIsNone(endpoint.appliance_runtime)
        self.assertIsNone(session.appliance_runtime)
        self.assertIsNone(session.endpoints[0].appliance_runtime)
        self.assertIsNone(session.to_dict()["appliance_runtime"])


class LabApplianceRuntimeValidationTest(unittest.TestCase):
    def test_profile_must_be_safe_path_component(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "appliance_runtime.profile must be a safe path component",
        ):
            LabApplianceRuntime(
                profile="../probe",
                image_tag="registry.example.invalid/libcrafter/appliance:smoke",
                remote_work_root="/srv/libcrafter/work",
                remote_artifact_root="/srv/libcrafter/artifacts",
            )

        with self.assertRaisesRegex(
            ValueError,
            "appliance_runtime.profile must be a safe path component",
        ):
            LabApplianceRuntime(
                profile="oracle/probe",
                image_tag="registry.example.invalid/libcrafter/appliance:smoke",
                remote_work_root="/srv/libcrafter/work",
                remote_artifact_root="/srv/libcrafter/artifacts",
            )

    def test_remote_roots_must_be_absolute_paths(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "appliance_runtime.remote_work_root must be an absolute path",
        ):
            LabApplianceRuntime(
                profile="lan-raw",
                image_tag="registry.example.invalid/libcrafter/appliance:smoke",
                remote_work_root="srv/libcrafter/work",
                remote_artifact_root="/srv/libcrafter/artifacts",
            )

        with self.assertRaisesRegex(
            ValueError,
            "appliance_runtime.remote_artifact_root must be an absolute path",
        ):
            LabApplianceRuntime(
                profile="lan-raw",
                image_tag="registry.example.invalid/libcrafter/appliance:smoke",
                remote_work_root="/srv/libcrafter/work",
                remote_artifact_root="srv/libcrafter/artifacts",
            )

    def test_json_fields_must_be_objects(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "appliance_runtime.container_policy must be an object",
        ):
            LabApplianceRuntime(
                profile="lan-raw",
                image_tag="registry.example.invalid/libcrafter/appliance:smoke",
                remote_work_root="/srv/libcrafter/work",
                remote_artifact_root="/srv/libcrafter/artifacts",
                container_policy=["NET_RAW"],  # type: ignore[arg-type]
            )


def _runtime() -> LabApplianceRuntime:
    return LabApplianceRuntime(
        profile="lan-raw",
        image_tag="registry.example.invalid/libcrafter/appliance:smoke",
        remote_work_root="/srv/libcrafter/work",
        remote_artifact_root="/srv/libcrafter/artifacts",
        container_policy={
            "runtime": "docker",
            "capabilities": ["NET_RAW", "NET_ADMIN"],
            "cap_drop_all": True,
        },
        check_metadata={"host_prepare": {"passed": True}},
        metadata={"substrate": "ssh-docker"},
    )


def _session(*, appliance_runtime: LabApplianceRuntime) -> LabSession:
    return LabSession(
        provider="qemu",
        wire_provider="qemu",
        wire_exposure="private",
        session_id="lab-smoke-0001",
        roles=[LabRole(name="stimulus")],
        endpoints=[
            LabEndpoint(
                endpoint_id="endpoint-stimulus",
                role="stimulus",
                interface="eth0",
                ipv4="192.0.2.10",
                appliance_runtime=appliance_runtime,
            )
        ],
        appliance_runtime=appliance_runtime,
    )


if __name__ == "__main__":
    unittest.main()
