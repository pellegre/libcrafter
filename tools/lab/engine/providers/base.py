"""Provider-neutral lab adapter contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol

from tools.endpoint.engine.model import EndpointManifest

from .. import endpoint_client
from ..model import (
    JSONObject,
    LabCommandPlan,
    LabEndpoint,
    LabRequest,
    LabRole,
    LabSession,
    LabValidationCheck,
)


class LabProviderAdapter(Protocol):
    """Substrate boundary for one lab provider implementation.

    Lab providers describe and operate endpoint infrastructure only. Oracle and
    probe own their workload semantics and pass role/bootstrap metadata through
    the neutral lab request/session models.
    """

    name: str
    wire_provider: str
    wire_exposure: str
    credential_label: str
    missing_credential_reason: str

    def credentials_available(self) -> bool:
        """Return whether live provider credentials or local prerequisites exist."""

    def default_provider_capabilities(
        self,
        *,
        dry_run: bool,
        source: str = "planned-defaults",
    ) -> JSONObject:
        """Return provider capability defaults before endpoint discovery."""

    def normalize_provider_capabilities(
        self,
        raw: JSONObject,
        *,
        dry_run: bool | None = None,
        source: str | None = None,
    ) -> JSONObject:
        """Normalize provider capability data into the lab session shape."""

    def plan_roles(self, request: LabRequest) -> list[LabRole]:
        """Return provider-normalized roles and address defaults for a request."""

    def private_group(self, request: LabRequest) -> str | None:
        """Return the private group to pass to wire, if this provider uses one."""

    def requested_private_ip(self, role: LabRole, request: LabRequest) -> str | None:
        """Return the requested private IPv4 address to pass to wire for a role."""

    def planned_infrastructure(self, request: LabRequest) -> JSONObject:
        """Return dry-run-safe infrastructure metadata for a lab request."""

    def provider_workflow(self, request: LabRequest) -> list[LabCommandPlan]:
        """Return planned provider lifecycle command records."""

    def wire_endpoint_plan(
        self,
        request: LabRequest,
        *,
        client: endpoint_client.EndpointClient | None = None,
        created_endpoint_ids: list[str] | None = None,
    ) -> JSONObject:
        """Plan or create provider-backed endpoints for all requested roles."""

    def normalize_endpoint(
        self,
        manifest: EndpointManifest | Mapping[str, object],
        *,
        role: LabRole,
        peer_roles: Sequence[LabRole] = (),
        request: LabRequest,
    ) -> LabEndpoint:
        """Convert an endpoint manifest into a provider-neutral lab endpoint."""

    def plan_session(
        self,
        request: LabRequest,
        *,
        client: endpoint_client.EndpointClient | None = None,
    ) -> LabSession:
        """Return a planned or live lab session for the request."""

    def validate_request(self, request: LabRequest) -> LabValidationCheck:
        """Validate provider-specific request invariants before planning."""

    def validate_provider_workflow(
        self,
        commands: list[LabCommandPlan],
        *,
        dry_run: bool,
    ) -> LabValidationCheck:
        """Validate provider lifecycle command invariants."""

    def validate_session(self, session: LabSession) -> list[LabValidationCheck]:
        """Validate provider-specific invariants on a planned or live session."""
