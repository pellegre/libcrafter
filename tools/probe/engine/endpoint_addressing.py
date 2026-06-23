"""Shared, protocol-agnostic live-path endpoint-addressing primitives.

The probe live path rewrites a dry-run plan (which carries deterministic
documentation addresses) onto the real lab-segment endpoint addresses before a
wire run. Most of that rewrite is per-protocol, but a handful of pieces are
shared across protocols and carry no protocol knowledge:

* deterministic lab-segment address derivation (an IPv4 alias host on the lab
  subnet, and the modified-EUI-64 link-local address for a MAC),
* the shared IPv4 validation/live-rewrite tail that runs for protocols whose
  rewrite is exhausted by the common transport-IPv4 overwrite (no per-protocol
  branch), and
* the shared failure-reason scaffolding (the failure-mode constants and the
  default empty reason list).

These live here so per-protocol plugins can import them without depending on the
CLI orchestrator module. This module must not import from ``cli`` (no cycle).
"""

from __future__ import annotations

import ipaddress

from .model import JSONObject, json_object

# Failure-mode reason constants shared by every protocol's failure-reason
# taxonomy. The per-protocol failure branches select from these; the default
# fall-through returns the empty reason list.
FAILURE_TIMEOUT = "timeout"
FAILURE_WRONG_PEER = "wrong_peer"
FAILURE_WRONG_PAYLOAD = "wrong_payload"
FAILURE_WRONG_FLAGS = "wrong_flags"
FAILURE_DECODE_FAILED = "decode_failed"
FAILURE_TARGET_SETUP_FAILED = "target_setup_failed"


def default_failure_reasons() -> list[str]:
    """Return the shared default failure-reason list (no protocol match)."""

    return []


def _lab_arp_alias_ipv4(target_ipv4: str, source_ipv4: str) -> str:
    """Derive a deterministic secondary IPv4 alias host on the lab segment.

    ``arp-alias-address-reply`` configures the target kernel to answer ARP for a
    *secondary* address added to the private interface, distinct from both the
    target endpoint's primary IPv4 (``target_ipv4``) and the stimulus endpoint
    (``source_ipv4``). The alias must therefore be a different host in the same
    /24 lab subnet as the target. The host octet is derived deterministically
    from the target's last octet and kept clear of the source/target hosts, the
    network (0), broadcast (255), and the conventional router (1).
    """

    octets = target_ipv4.split(".")
    if len(octets) != 4:
        raise ValueError(f"unexpected lab target IPv4 {target_ipv4!r}")
    prefix = ".".join(octets[:3])
    target_host = int(octets[3])
    source_host = int(source_ipv4.split(".")[3]) if source_ipv4.count(".") == 3 else -1
    reserved = {0, 1, 255, target_host, source_host}
    host = (target_host + 7) % 256
    while host in reserved:
        host = (host + 1) % 256
    return f"{prefix}.{host}"


def _eui64_link_local_ipv6(mac: str) -> str:
    """Return the modified-EUI-64 link-local address (``fe80::/64``) for a MAC.

    RFC 4291 Appendix A: an interface forms its link-local address by inserting
    ``ff:fe`` between the third and fourth octets of its 48-bit MAC and flipping
    the Universal/Local bit (bit 0x02 of the first octet) to produce a 64-bit
    interface identifier, prefixed with ``fe80::/64``. A Linux kernel always owns
    this address on every IPv6-enabled interface and auto-answers a Neighbor
    Solicitation for it (and defends it on Duplicate Address Detection), so it is
    the most robust live NDP target address — no separate address needs to be
    configured. The MAC is the real lab endpoint MAC threaded in from the
    provider manifest at live time.
    """

    octets = [int(part, 16) for part in mac.split(":")]
    if len(octets) != 6:
        raise ValueError(f"unexpected lab endpoint MAC {mac!r}")
    # Flip the Universal/Local bit of the first octet, then insert ff:fe.
    interface_id = bytes(
        [octets[0] ^ 0x02, octets[1], octets[2], 0xFF, 0xFE, octets[3], octets[4], octets[5]]
    )
    address = bytes(8) + interface_id
    link_local = bytearray(address)
    link_local[0] = 0xFE
    link_local[1] = 0x80
    return str(ipaddress.IPv6Address(bytes(link_local)))


def apply_shared_ipv4_rewrite_tail(
    updated: JSONObject,
    *,
    case_name: str,
    source_ipv4: str,
    target_ipv4: str,
    rewrite_source: str,
) -> JSONObject:
    """Apply the shared IPv4 validation/live-rewrite tail to ``updated``.

    This is the protocol-agnostic tail of
    ``_probe_plan_with_endpoint_addresses``: for a plan whose per-protocol
    rewrite is fully covered by the common transport-IPv4 overwrite (no
    early-returning per-protocol branch), the decoded reply is validated against
    the target IPv4 (or the controlled router IPv4 for ``ttl-expired``) and the
    live-rewrite record is stamped. Mutates and returns ``updated``.
    """

    validation = dict(json_object(updated.get("validation", {}), "probe_plan.validation"))
    validation["source_ipv4"] = (
        str(updated.get("controlled_router_ipv4"))
        if case_name == "ttl-expired" and updated.get("controlled_router_ipv4")
        else target_ipv4
    )
    validation["destination_ipv4"] = source_ipv4
    updated["validation"] = validation
    updated["live_address_rewrite"] = {
        "source": rewrite_source,
        "stimulus_ipv4": source_ipv4,
        "target_ipv4": target_ipv4,
    }
    return updated
