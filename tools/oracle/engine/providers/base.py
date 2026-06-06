"""Provider-backed oracle live adapter contracts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from tools.lab.engine import endpoint_client

from ..live import LiveCommandPlan, LiveEndpoint, LiveExchangePlan, LiveValidationCheck
from ..model import JSONObject, PacketPlan


class LiveProviderAdapter(Protocol):
    """Oracle-side boundary for one provider-backed live runner."""

    name: str
    wire_provider: str
    wire_exposure: str
    endpoint_roles: tuple[str, str]
    private_group: str | None
    endpoint_private_ips: Mapping[str, str]
    artifact_collection_purpose: str
    teardown_purpose: str
    credential_label: str
    missing_credential_reason: str

    def token_configured(self) -> bool:
        """Return whether real provider credentials are present."""

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
        """Normalize provider capability data for corpus filtering."""

    def planned_infrastructure(self, *, dry_run: bool) -> JSONObject:
        """Return report metadata for provider-backed infrastructure."""

    def packet_exchange_metadata(self, *, dry_run: bool) -> JSONObject:
        """Return provider-owned metadata for endpoint packet exchange."""

    def endpoints(self, *, dry_run: bool) -> dict[str, LiveEndpoint]:
        """Return planned endpoint roles for dry-run or skipped reports."""

    def wire_endpoint_plan(
        self,
        *,
        dry_run: bool,
        client: endpoint_client.EndpointClient | None = None,
        private_group: str | None = None,
        confirm_live_run: bool = False,
        created_endpoint_ids: list[str] | None = None,
    ) -> dict[str, object]:
        """Create or plan provider-backed endpoints."""

    def provider_workflow(self, *, dry_run: bool) -> list[LiveCommandPlan]:
        """Return provider lifecycle command plans."""

    def validate_provider_workflow(
        self,
        commands: list[LiveCommandPlan],
        *,
        dry_run: bool,
    ) -> LiveValidationCheck:
        """Validate provider lifecycle command invariants."""

    def validate_dry_run_exchange(
        self,
        exchange: LiveExchangePlan,
    ) -> LiveValidationCheck:
        """Validate provider-backed dry-run exchange invariants."""

    def remote_dir(self) -> str:
        """Return the absolute repository directory used on endpoints."""

    def endpoint_remote_command(
        self,
        *,
        endpoint_role: str,
        remote_dir: str,
        request_path: str,
        out_dir: str,
    ) -> list[str]:
        """Return the remote endpoint protocol command for one role."""

    def normalize_live_endpoints(
        self,
        endpoints: Mapping[str, LiveEndpoint],
    ) -> Mapping[str, LiveEndpoint]:
        """Normalize provider endpoint metadata before live request creation."""

    def apply_transit_plan(self, plan: PacketPlan) -> PacketPlan:
        """Apply provider transit rewrites before expected-model generation."""

    def wire_comparison_policy(self, plan: PacketPlan) -> JSONObject:
        """Return provider-specific wire comparison policy for one packet."""
