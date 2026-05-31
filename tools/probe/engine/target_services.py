"""Probe target service planning, setup scripts, and cleanup.

The probe target endpoint exposes controlled, disposable services and kernel
behavior the stimulus endpoint exercises. This module owns:

- the dry-run/live ``target_service_setup`` plan,
- typed service descriptors for the DNS responder, DHCP responder, UDP
  responder, ARP alias/sysctl setup, and closed UDP port validation,
- the deterministic, artifact-producing setup script for the live target,
- the cleanup script invocation that tears those services down.

Keeping the target-service surface here lets the behavior suite grow DNS, DHCP,
UDP, and ARP target setup in one place without enlarging the CLI orchestration
module. The lab-wire transport helpers stay in :mod:`cli`; the wire setup and
cleanup entry points accept them so this module has no import cycle with the
CLI.

The service descriptors are pure, deterministic data: each describes one
controlled service the live setup script must stand up (or one piece of kernel
state it must verify) and the cleanup commands that dispose of it. They make the
target contract inspectable from agent code and from dry-run reports without
running anything.
"""

from __future__ import annotations

import json
import posixpath
import shlex
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .capabilities import (
    SKIP_REQUIRES_CONTROLLED_ROUTER,
    SKIP_REQUIRES_CONTROLLED_SERVICE,
    SKIP_REQUIRES_LINK_LAYER,
)
from .lab import TARGET_ROLE
from .model import JSONObject, JSONValue, json_object


# A lab-wire helper that resolves an endpoint mapping to its endpoint ID.
EndpointIdResolver = Callable[..., str]
# A lab-wire helper that resolves an endpoint mapping to its bind IPv4 address.
EndpointIpv4Resolver = Callable[..., str]
# A lab-wire helper that runs a wire command response and records its artifacts.
WireCommandRunner = Callable[..., JSONObject]


# --------------------------------------------------------------------------- #
# Typed service descriptors
# --------------------------------------------------------------------------- #
#
# Each descriptor is a deterministic, inspectable plan for one controlled
# target service or one piece of verified kernel state. They are the typed
# contract the live setup script renders and the dry-run report advertises.


@dataclass(frozen=True, slots=True)
class TargetServiceDescriptor:
    """A controlled, disposable service the target endpoint stands up.

    ``setup_commands`` and ``cleanup_commands`` are deterministic shell
    fragments; ``artifacts`` lists the relative artifact paths the running
    service produces so the live path can collect inspectable evidence.
    """

    name: str
    protocol: str
    purpose: str
    bind_ipv4: str
    source_ipv4: str
    port: int | None = None
    requires: list[str] = field(default_factory=list)
    setup_commands: list[str] = field(default_factory=list)
    cleanup_commands: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class KernelStateDescriptor:
    """A piece of target kernel state the setup verifies or configures.

    Used for closed UDP/TCP port validation, ARP alias addresses, and ARP
    sysctl tuning. ``verify_commands`` assert preconditions; ``setup_commands``
    apply state; ``cleanup_commands`` restore it.
    """

    name: str
    purpose: str
    bind_ipv4: str
    source_ipv4: str
    port: int | None = None
    verify_commands: list[str] = field(default_factory=list)
    setup_commands: list[str] = field(default_factory=list)
    cleanup_commands: list[str] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)


def dns_responder_descriptor(
    *,
    bind_ipv4: str,
    source_ipv4: str,
    port: int,
    artifact_root: str,
) -> TargetServiceDescriptor:
    """Describe the controlled UDP DNS responder bound to the target address."""

    return TargetServiceDescriptor(
        name="dns-responder",
        protocol="udp",
        purpose="dns-query",
        bind_ipv4=bind_ipv4,
        source_ipv4=source_ipv4,
        port=port,
        requires=["python3", SKIP_REQUIRES_CONTROLLED_SERVICE],
        setup_commands=[
            f"check udp port {bind_ipv4}:{port} is free",
            f"start dns-responder.py on {bind_ipv4}:{port}",
        ],
        cleanup_commands=[
            f"kill dns-responder on {bind_ipv4}:{port}",
        ],
        artifacts=[
            posixpath.join(artifact_root, f"dns-responder-{port}.stdout.txt"),
            posixpath.join(artifact_root, f"dns-responder-{port}.stderr.txt"),
            posixpath.join(artifact_root, f"dns-responder-{port}.pid"),
        ],
        metadata={"runtime": "python3", "deterministic": True},
    )


def dhcp_responder_descriptor(
    *,
    bind_ipv4: str,
    source_ipv4: str,
    port: int,
    artifact_root: str,
) -> TargetServiceDescriptor:
    """Describe the controlled DHCP/BOOTP responder on a private L2 segment.

    DHCP requires link-layer broadcast on a private lab network, so the
    descriptor records the link-layer requirement that gates it.
    """

    return TargetServiceDescriptor(
        name="dhcp-responder",
        protocol="udp",
        purpose="dhcp",
        bind_ipv4=bind_ipv4,
        source_ipv4=source_ipv4,
        port=port,
        requires=["python3", SKIP_REQUIRES_LINK_LAYER, SKIP_REQUIRES_CONTROLLED_SERVICE],
        setup_commands=[
            f"check udp port {bind_ipv4}:{port} is free",
            f"start dhcp-responder.py on {bind_ipv4}:{port}",
        ],
        cleanup_commands=[
            f"kill dhcp-responder on {bind_ipv4}:{port}",
        ],
        artifacts=[
            posixpath.join(artifact_root, f"dhcp-responder-{port}.stdout.txt"),
            posixpath.join(artifact_root, f"dhcp-responder-{port}.stderr.txt"),
            posixpath.join(artifact_root, f"dhcp-responder-{port}.pid"),
        ],
        metadata={"runtime": "python3", "deterministic": True, "layer": "link"},
    )


def udp_responder_descriptor(
    *,
    bind_ipv4: str,
    source_ipv4: str,
    port: int,
    artifact_root: str,
) -> TargetServiceDescriptor:
    """Describe the controlled UDP echo/transform responder."""

    return TargetServiceDescriptor(
        name="udp-responder",
        protocol="udp",
        purpose="udp-echo",
        bind_ipv4=bind_ipv4,
        source_ipv4=source_ipv4,
        port=port,
        requires=["python3", SKIP_REQUIRES_CONTROLLED_SERVICE],
        setup_commands=[
            f"check udp port {bind_ipv4}:{port} is free",
            f"start udp-responder.py on {bind_ipv4}:{port}",
        ],
        cleanup_commands=[
            f"kill udp-responder on {bind_ipv4}:{port}",
        ],
        artifacts=[
            posixpath.join(artifact_root, f"udp-responder-{port}.stdout.txt"),
            posixpath.join(artifact_root, f"udp-responder-{port}.stderr.txt"),
            posixpath.join(artifact_root, f"udp-responder-{port}.pid"),
        ],
        metadata={"runtime": "python3", "deterministic": True},
    )


def closed_udp_port_descriptor(
    *,
    bind_ipv4: str,
    source_ipv4: str,
    port: int,
) -> KernelStateDescriptor:
    """Describe a closed UDP port whose kernel emits ICMP port-unreachable."""

    return KernelStateDescriptor(
        name="closed-udp-port",
        purpose="udp-port-unreachable",
        bind_ipv4=bind_ipv4,
        source_ipv4=source_ipv4,
        port=port,
        verify_commands=[
            f"check udp port {bind_ipv4}:{port} is free",
        ],
        metadata={"expects": "icmp_port_unreachable", "deterministic": True},
    )


def arp_alias_descriptor(
    *,
    bind_ipv4: str,
    source_ipv4: str,
    alias_ipv4: str,
    interface: str,
) -> KernelStateDescriptor:
    """Describe an ARP alias address added to the target interface."""

    quoted_alias = shlex.quote(f"{alias_ipv4}/32")
    quoted_iface = shlex.quote(interface)
    return KernelStateDescriptor(
        name="arp-alias",
        purpose="arp-alias-address",
        bind_ipv4=bind_ipv4,
        source_ipv4=source_ipv4,
        setup_commands=[
            f"ip addr add {quoted_alias} dev {quoted_iface}",
        ],
        cleanup_commands=[
            f"ip addr del {quoted_alias} dev {quoted_iface} || true",
        ],
        metadata={
            "alias_ipv4": alias_ipv4,
            "interface": interface,
            "layer": "link",
            "deterministic": True,
        },
    )


def arp_sysctl_descriptor(
    *,
    bind_ipv4: str,
    source_ipv4: str,
    interface: str,
) -> KernelStateDescriptor:
    """Describe ARP sysctl tuning and neighbor-cache flush for the target."""

    quoted_iface = shlex.quote(interface)
    arp_ignore = f"net.ipv4.conf.{interface}.arp_ignore"
    arp_announce = f"net.ipv4.conf.{interface}.arp_announce"
    return KernelStateDescriptor(
        name="arp-sysctl",
        purpose="arp-neighbor-setup",
        bind_ipv4=bind_ipv4,
        source_ipv4=source_ipv4,
        setup_commands=[
            f"sysctl -w {shlex.quote(arp_ignore + '=0')}",
            f"sysctl -w {shlex.quote(arp_announce + '=0')}",
            f"ip neigh flush dev {quoted_iface} || true",
        ],
        cleanup_commands=[
            f"ip neigh flush dev {quoted_iface} || true",
        ],
        metadata={"interface": interface, "layer": "link", "deterministic": True},
    )


# --------------------------------------------------------------------------- #
# Target service setup plan (dry-run + live shape)
# --------------------------------------------------------------------------- #


def target_service_setup_plan(
    *,
    probe_plans: Sequence[JSONObject],
    dry_run: bool,
) -> JSONObject:
    """Return the ``target_service_setup`` plan for a probe run.

    The shape is the stable contract consumed by the dry-run report and the
    live target setup. ``starts_services`` is only true on a live run that has
    at least one service to stand up; dry-run never starts services.
    """

    tcp_open_plans = plans_by_destination_port(
        plan for plan in probe_plans if plan.get("case") == "tcp-syn-open"
    )
    tcp_closed_plans = plans_by_destination_port(
        plan for plan in probe_plans if plan.get("case") == "tcp-syn-closed"
    )
    dns_plans = dns_probe_plans(probe_plans)
    dns_plans_by_port = plans_by_destination_port(dns_plans)
    return {
        "role": "target",
        "planned": True,
        "starts_services": not dry_run and bool(tcp_open_plans or dns_plans_by_port),
        "dry_run_starts_services": False,
        "services": [
            *[
                {
                    "name": "tcp-open-listener",
                    "protocol": "tcp",
                    "port": port,
                    "purpose": "tcp-syn-open",
                    "deterministic": True,
                    **target_service_address_fields(plan),
                }
                for port, plan in tcp_open_plans.items()
            ],
            *[
                {
                    "name": "dns-responder",
                    "protocol": "udp",
                    "port": port,
                    "purpose": "dns-query",
                    "deterministic": True,
                    "query_count": sum(
                        1
                        for plan in dns_plans
                        if int(plan.get("destination_port", 0)) == port
                    ),
                    **target_service_address_fields(plan),
                    "log_paths": [
                        f"live-artifacts/probe/target-services/dns-responder-{port}.stdout.txt",
                        f"live-artifacts/probe/target-services/dns-responder-{port}.stderr.txt",
                    ],
                }
                for port, plan in dns_plans_by_port.items()
            ],
        ],
        "closed_tcp_ports": [
            {
                "port": port,
                "state": "verified-unbound" if not dry_run else "planned-unbound",
                "purpose": "tcp-syn-closed",
                "deterministic": True,
                **target_service_address_fields(plan),
            }
            for port, plan in tcp_closed_plans.items()
        ],
        "controlled_router": {
            "available": False,
            "skip_reason": SKIP_REQUIRES_CONTROLLED_ROUTER,
        },
    }


def plans_by_destination_port(plans: Iterable[JSONObject]) -> dict[int, JSONObject]:
    """Map each plan's destination port to the first plan that used it."""

    by_port: dict[int, JSONObject] = {}
    for plan in plans:
        port = int(plan["destination_port"])
        by_port.setdefault(port, plan)
    return by_port


def target_service_address_fields(plan: Mapping[str, JSONValue]) -> JSONObject:
    """Return the bind/source IPv4 fields for a plan's target service."""

    target_service = _json_mapping(
        plan.get("target_service", {}),
        "probe_plan.target_service",
    )
    bind_ipv4 = _string_or(
        target_service.get("bind_ipv4"),
        _string_or(plan.get("destination_ipv4"), ""),
    )
    source_ipv4 = _string_or(
        target_service.get("source_ipv4"),
        _string_or(plan.get("source_ipv4"), ""),
    )
    fields: JSONObject = {}
    if bind_ipv4:
        fields["bind_ipv4"] = bind_ipv4
    if source_ipv4:
        fields["source_ipv4"] = source_ipv4
    return fields


# --------------------------------------------------------------------------- #
# Plan filters and small helpers
# --------------------------------------------------------------------------- #


def tcp_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return the TCP-SYN probe plans (open and closed) in order."""

    return [
        plan
        for plan in probe_plans
        if str(plan.get("case", "")).startswith("tcp-syn-")
    ]


# Probe cases that drive the controlled UDP DNS responder. ``dns-query`` is the
# legacy smoke case; ``dns-a-success``, ``dns-aaaa-success``, and the later DNS
# behavioral cases reuse the same responder descriptor and target setup.
_DNS_RESPONDER_CASES: frozenset[str] = frozenset(
    {
        "dns-query",
        "dns-a-success",
        "dns-aaaa-success",
        "dns-cname-chain",
        "dns-nxdomain",
        "dns-nodata",
        "dns-txt-answer",
        "dns-mx-answer",
        "dns-srv-answer",
        "dns-edns-opt",
        "dns-repeat-transaction",
    }
)


def dns_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return the DNS-query probe plans in order."""

    return [plan for plan in probe_plans if plan.get("case") in _DNS_RESPONDER_CASES]


# Probe cases that drive the controlled DHCP/BOOTP responder on a private L2
# segment. ``dhcp-discover-offer`` is the baseline Discover->Offer case; the
# later DHCP behavioral cases reuse the same responder descriptor and target
# setup. Providers without link-layer/broadcast capability skip these cases (the
# descriptor records the link-layer requirement that gates them).
_DHCP_RESPONDER_CASES: frozenset[str] = frozenset(
    {
        "dhcp-discover-offer",
        "dhcp-request-ack",
        "dhcp-client-identifier",
        "dhcp-hostname",
    }
)


def dhcp_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return the DHCP probe plans in order."""

    return [plan for plan in probe_plans if plan.get("case") in _DHCP_RESPONDER_CASES]


def dedupe_ints(values: Iterable[int]) -> list[int]:
    """Return the integer sequence with duplicates removed, order preserved."""

    return list(dict.fromkeys(values))


def _string_or(value: object, default: str) -> str:
    return value if isinstance(value, str) and value else default


def _json_mapping(value: object, name: str) -> JSONObject:
    if isinstance(value, Mapping):
        return json_object(value, name)
    return {}


# --------------------------------------------------------------------------- #
# Live target setup / cleanup over the lab-wire transport
# --------------------------------------------------------------------------- #


def prepare_wire_probe_target(
    *,
    wire: object,
    target_endpoint: Mapping[str, JSONValue],
    artifact_root: str,
    probe_plans: Sequence[JSONObject],
    output_dir: Path,
    endpoint_id_resolver: EndpointIdResolver,
    endpoint_ipv4_resolver: EndpointIpv4Resolver,
    run_wire_command: WireCommandRunner,
) -> JSONObject | None:
    """Stand up controlled target services for a live probe run.

    Returns ``None`` when no target service is required. The lab-wire transport
    helpers are injected so this module stays free of an import cycle with the
    CLI orchestration module.
    """

    tcp_plans = tcp_probe_plans(probe_plans)
    dns_plans = dns_probe_plans(probe_plans)
    if not tcp_plans and not dns_plans:
        return None
    endpoint_id = endpoint_id_resolver(target_endpoint, role=TARGET_ROLE)
    bind_ipv4 = endpoint_ipv4_resolver(target_endpoint, role=TARGET_ROLE)
    open_ports = dedupe_ints(
        int(plan["destination_port"])
        for plan in tcp_plans
        if plan.get("case") == "tcp-syn-open"
    )
    closed_ports = dedupe_ints(
        int(plan["destination_port"])
        for plan in tcp_plans
        if plan.get("case") == "tcp-syn-closed"
    )
    script = target_service_setup_script(
        artifact_root=artifact_root,
        bind_ipv4=bind_ipv4,
        open_ports=open_ports,
        closed_ports=closed_ports,
        dns_plans=dns_plans,
    )
    return run_wire_command(
        wire.exec(endpoint_id, ["bash", "-lc", script], timeout=60),
        output_dir=output_dir,
        label="probe-target-setup",
    )


def cleanup_wire_probe_target(
    *,
    wire: object,
    target_endpoint: Mapping[str, JSONValue],
    artifact_root: str,
    output_dir: Path,
    endpoint_id_resolver: EndpointIdResolver,
    run_wire_command: WireCommandRunner,
) -> JSONObject:
    """Run the disposable target cleanup script over the lab-wire transport."""

    endpoint_id = endpoint_id_resolver(target_endpoint, role=TARGET_ROLE)
    cleanup_script = posixpath.join(artifact_root, "cleanup.sh")
    script = "\n".join(
        [
            "set -euo pipefail",
            f"if [ -x {shlex.quote(cleanup_script)} ]; then {shlex.quote(cleanup_script)}; fi",
        ]
    )
    return run_wire_command(
        wire.exec(endpoint_id, ["bash", "-lc", script], timeout=60),
        output_dir=output_dir,
        label="probe-target-cleanup",
    )


# --------------------------------------------------------------------------- #
# Deterministic, artifact-producing setup script
# --------------------------------------------------------------------------- #


def target_service_setup_script(
    *,
    artifact_root: str,
    bind_ipv4: str,
    open_ports: Sequence[int],
    closed_ports: Sequence[int],
    dns_plans: Sequence[JSONObject],
) -> str:
    """Render the deterministic target setup script.

    The script verifies closed ports, starts TCP listeners and the DNS
    responder, records a cleanup script, and writes per-service artifacts so
    the live run is inspectable.
    """

    dns_plan_json = json.dumps(list(dns_plans), sort_keys=True)
    dns_ports = dedupe_ints(
        int(plan["destination_port"])
        for plan in dns_plans
        if isinstance(plan.get("destination_port"), int)
    )
    lines = [
        "set -euo pipefail",
        f"artifact_root={shlex.quote(artifact_root)}",
        f"tcp_bind_ipv4={shlex.quote(bind_ipv4)}",
        f"dns_bind_ipv4={shlex.quote(bind_ipv4)}",
        'mkdir -p "$artifact_root"',
        'cleanup="$artifact_root/cleanup.sh"',
        ': > "$cleanup"',
        'chmod 700 "$cleanup"',
        "check_port_free() {",
        "  python3 - \"$1\" \"$2\" <<'PY'",
        "import socket",
        "import sys",
        "bind_ip = sys.argv[1]",
        "port = int(sys.argv[2])",
        "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
        "try:",
        "    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)",
        "    sock.bind((bind_ip, port))",
        "except OSError as exc:",
        "    print(f'tcp port {bind_ip}:{port} is not free: {exc}', file=sys.stderr)",
        "    sys.exit(1)",
        "finally:",
        "    sock.close()",
        "PY",
        "}",
    ]
    for port in dns_ports:
        lines.extend(
            [
                "python3 - \"$dns_bind_ipv4\" \"$1\" <<'PY'".replace("$1", str(port)),
                "import socket",
                "import sys",
                "bind_ip = sys.argv[1]",
                "port = int(sys.argv[2])",
                "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
                "try:",
                "    sock.bind((bind_ip, port))",
                "except OSError as exc:",
                "    print(f'udp port {bind_ip}:{port} is not free: {exc}', file=sys.stderr)",
                "    sys.exit(1)",
                "finally:",
                "    sock.close()",
                "PY",
            ]
        )
    for port in closed_ports:
        lines.append(f"check_port_free \"$tcp_bind_ipv4\" {port}")
        lines.append(f"echo closed_port_{port}=free")
    for port in open_ports:
        listener_path = posixpath.join(artifact_root, f"tcp-listener-{port}.py")
        stdout_path = posixpath.join(artifact_root, f"tcp-listener-{port}.stdout.txt")
        stderr_path = posixpath.join(artifact_root, f"tcp-listener-{port}.stderr.txt")
        pid_path = posixpath.join(artifact_root, f"tcp-listener-{port}.pid")
        lines.extend(
            [
                f"check_port_free \"$tcp_bind_ipv4\" {port}",
                f"cat > {shlex.quote(listener_path)} <<'PY'",
                "import signal",
                "import socket",
                "import sys",
                "",
                "stop = False",
                "",
                "def handle_stop(_signum, _frame):",
                "    global stop",
                "    stop = True",
                "",
                "signal.signal(signal.SIGTERM, handle_stop)",
                "signal.signal(signal.SIGINT, handle_stop)",
                "bind_ip = sys.argv[1]",
                "port = int(sys.argv[2])",
                "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
                "sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)",
                "sock.bind((bind_ip, port))",
                "sock.listen(128)",
                "sock.settimeout(1.0)",
                "print(f'listening on {bind_ip}:{port}', flush=True)",
                "while not stop:",
                "    try:",
                "        conn, _addr = sock.accept()",
                "    except socket.timeout:",
                "        continue",
                "    conn.close()",
                "sock.close()",
                "PY",
                (
                    f"python3 {shlex.quote(listener_path)} \"$tcp_bind_ipv4\" {port} "
                    f">{shlex.quote(stdout_path)} 2>{shlex.quote(stderr_path)} &"
                ),
                "pid=$!",
                f"echo \"$pid\" > {shlex.quote(pid_path)}",
                "printf '%s\\n' \"kill $pid 2>/dev/null || true\" >> \"$cleanup\"",
                f"printf '%s\\n' \"rm -f {shlex.quote(pid_path)}\" >> \"$cleanup\"",
                "sleep 0.5",
                "if ! kill -0 \"$pid\" 2>/dev/null; then",
                f"  cat {shlex.quote(stderr_path)} >&2 || true",
                f"  echo listener_{port}=failed >&2",
                "  exit 73",
                "fi",
                f"echo listener_{port}=running",
            ]
        )
    if dns_ports:
        zone_path = posixpath.join(artifact_root, "dns-zone.json")
        service_path = posixpath.join(artifact_root, "dns-responder.py")
        lines.extend(
            [
                f"cat > {shlex.quote(zone_path)} <<'JSON'",
                dns_plan_json,
                "JSON",
                f"cat > {shlex.quote(service_path)} <<'PY'",
                "import ipaddress",
                "import json",
                "import signal",
                "import socket",
                "import struct",
                "import sys",
                "import time",
                "",
                "stop = False",
                "",
                "def handle_stop(_signum, _frame):",
                "    global stop",
                "    stop = True",
                "",
                "signal.signal(signal.SIGTERM, handle_stop)",
                "signal.signal(signal.SIGINT, handle_stop)",
                "",
                "zone_path, bind_ip, port_text = sys.argv[1:4]",
                "port = int(port_text)",
                "plans = json.load(open(zone_path, encoding='utf-8'))",
                "records = {}",
                "present_names = set()",
                "# repeat_overrides maps a client source port to the A answer that",
                "# port's send expects. The dns-repeat-transaction case reuses one",
                "# transaction id and query name across two sends distinguished only",
                "# by source port, so the responder serves each send its own planned",
                "# answer keyed by the client source port — that is what lets the",
                "# stimulus match each response back to its send without confusing",
                "# the two same-name responses.",
                "repeat_overrides = {}",
                "for plan in plans:",
                "    name = str(plan['query_name']).lower().rstrip('.') + '.'",
                "    qtype = int(plan['query_type_value'])",
                "    service = plan.get('target_service') or {}",
                "    # NXDOMAIN cases register no record: the name is deliberately",
                "    # absent so the responder returns rcode 3 with an empty answer",
                "    # section and the original question echoed.",
                "    if isinstance(service, dict) and service.get('absent'):",
                "        records.pop((name, qtype), None)",
                "        continue",
                "    # NODATA cases: the name EXISTS in the zone, but only under a",
                "    # different type (present_type), so the queried type has no",
                "    # record. Mark the name present (so the responder returns",
                "    # rcode 0 NODATA, not rcode 3 NXDOMAIN) without registering an",
                "    # answer record for the queried type.",
                "    if isinstance(service, dict) and service.get('nodata'):",
                "        present_names.add(name)",
                "        records.pop((name, qtype), None)",
                "        continue",
                "    present_names.add(name)",
                "    # TXT answers carry a list of character-strings instead of a",
                "    # single address/name answer_data. Each string is encoded on",
                "    # the wire as one length-prefixed DNS character-string.",
                "    if qtype == 16:",
                "        strings = service.get('txt_strings') if isinstance(service, dict) else None",
                "        if not strings:",
                "            strings = plan.get('expected_txt_strings') or []",
                "        records[(name, qtype)] = {",
                "            'txt_strings': [str(value) for value in strings],",
                "            'ttl': int(plan.get('answer_ttl', 60)),",
                "        }",
                "        continue",
                "    # MX answers carry structured RDATA: a 16-bit preference",
                "    # followed by the exchange <domain-name>, encoded uncompressed",
                "    # so the wire rdlength is 2 + encoded-name length.",
                "    if qtype == 15:",
                "        preference = service.get('mx_preference') if isinstance(service, dict) else None",
                "        exchange = service.get('mx_exchange') if isinstance(service, dict) else None",
                "        if preference is None:",
                "            preference = plan.get('expected_mx_preference')",
                "        if exchange is None:",
                "            exchange = plan.get('expected_mx_exchange')",
                "        records[(name, qtype)] = {",
                "            'mx_preference': int(preference),",
                "            'mx_exchange': str(exchange).lower().rstrip('.') + '.',",
                "            'ttl': int(plan.get('answer_ttl', 60)),",
                "        }",
                "        continue",
                "    # SRV answers carry structured RDATA: three 16-bit fields",
                "    # (priority, weight, port) followed by the target",
                "    # <domain-name>, encoded uncompressed so the wire rdlength is",
                "    # 6 + encoded-name length.",
                "    if qtype == 33:",
                "        priority = service.get('srv_priority') if isinstance(service, dict) else None",
                "        weight = service.get('srv_weight') if isinstance(service, dict) else None",
                "        srv_port = service.get('srv_port') if isinstance(service, dict) else None",
                "        target = service.get('srv_target') if isinstance(service, dict) else None",
                "        if priority is None:",
                "            priority = plan.get('expected_srv_priority')",
                "        if weight is None:",
                "            weight = plan.get('expected_srv_weight')",
                "        if srv_port is None:",
                "            srv_port = plan.get('expected_srv_port')",
                "        if target is None:",
                "            target = plan.get('expected_srv_target')",
                "        records[(name, qtype)] = {",
                "            'srv_priority': int(priority),",
                "            'srv_weight': int(weight),",
                "            'srv_port': int(srv_port),",
                "            'srv_target': str(target).lower().rstrip('.') + '.',",
                "            'ttl': int(plan.get('answer_ttl', 60)),",
                "        }",
                "        continue",
                "    record = {",
                "        'answer_data': str(plan['expected_answer_data']),",
                "        'ttl': int(plan.get('answer_ttl', 60)),",
                "    }",
                "    # EDNS(0) cases attach an OPT pseudo-record (RFC 6891) to the",
                "    # response's additional section. The responder echoes a planned",
                "    # OPT: UDP payload size in CLASS, extended rcode/version/DO flag",
                "    # packed into TTL, and an ordered {code,length,data} option list",
                "    # in the RDATA.",
                "    edns = service.get('edns') if isinstance(service, dict) else None",
                "    if isinstance(edns, dict):",
                "        record['edns'] = {",
                "            'udp_payload_size': int(edns.get('udp_payload_size', 4096)),",
                "            'version': int(edns.get('version', 0)),",
                "            'extended_rcode': int(edns.get('extended_rcode', 0)),",
                "            'do': bool(edns.get('do', False)),",
                "            'options': [",
                "                {",
                "                    'code': int(option['code']),",
                "                    'data': bytes.fromhex(str(option.get('data_hex', ''))),",
                "                }",
                "                for option in edns.get('options', [])",
                "            ],",
                "        }",
                "    # dns-repeat-transaction: register the per-source-port answer",
                "    # overrides so each send (same name/id, distinct source port)",
                "    # gets its own A answer.",
                "    repeat = service.get('repeat_transaction') if isinstance(service, dict) else None",
                "    if isinstance(repeat, dict):",
                "        for send in repeat.get('sends', []):",
                "            repeat_overrides[(name, qtype, int(send['source_port']))] = {",
                "                'answer_data': str(send['answer_data']),",
                "                'ttl': int(send.get('answer_ttl', record['ttl'])),",
                "            }",
                "    chain = service.get('cname_chain') if isinstance(service, dict) else None",
                "    if isinstance(chain, dict):",
                "        canonical = str(chain['canonical_name']).lower().rstrip('.') + '.'",
                "        record['cname'] = {",
                "            'canonical_name': canonical,",
                "            'cname_ttl': int(chain.get('cname_ttl', record['ttl'])),",
                "            'address_ttl': int(chain.get('address_ttl', record['ttl'])),",
                "        }",
                "    records[(name, qtype)] = record",
                "",
                "def read_name(message, offset):",
                "    labels = []",
                "    jumped = False",
                "    consumed = 0",
                "    seen = set()",
                "    while True:",
                "        if offset >= len(message):",
                "            raise ValueError('name offset out of range')",
                "        length = message[offset]",
                "        if length & 0xc0 == 0xc0:",
                "            if offset + 1 >= len(message):",
                "                raise ValueError('truncated compression pointer')",
                "            pointer = ((length & 0x3f) << 8) | message[offset + 1]",
                "            if pointer in seen:",
                "                raise ValueError('compression pointer loop')",
                "            seen.add(pointer)",
                "            if not jumped:",
                "                consumed += 2",
                "            offset = pointer",
                "            jumped = True",
                "            continue",
                "        offset += 1",
                "        if not jumped:",
                "            consumed += 1",
                "        if length == 0:",
                "            return '.'.join(labels).lower() + '.', consumed",
                "        if length & 0xc0:",
                "            raise ValueError('unsupported dns label kind')",
                "        label = message[offset:offset + length]",
                "        if len(label) != length:",
                "            raise ValueError('truncated dns label')",
                "        labels.append(label.decode('ascii'))",
                "        offset += length",
                "        if not jumped:",
                "            consumed += length",
                "",
                "def encode_name(name):",
                "    out = bytearray()",
                "    for label in name.rstrip('.').split('.'):",
                "        raw = label.encode('ascii')",
                "        out.append(len(raw))",
                "        out.extend(raw)",
                "    out.append(0)",
                "    return bytes(out)",
                "",
                "def encode_opt(edns):",
                "    # EDNS(0) OPT pseudo-record (RFC 6891 Section 6.1): root owner",
                "    # name, TYPE 41, CLASS = requestor UDP payload size, TTL packs",
                "    # extended-rcode(8) | version(8) | DO flag (bit 0 of the low 16),",
                "    # and RDATA is the ordered {code(u16), length(u16), data} options.",
                "    do_flag = 0x8000 if edns['do'] else 0",
                "    ttl = (",
                "        ((edns['extended_rcode'] & 0xff) << 24)",
                "        | ((edns['version'] & 0xff) << 16)",
                "        | do_flag",
                "    )",
                "    rdata = b''",
                "    for option in edns['options']:",
                "        data = option['data']",
                "        rdata += struct.pack('!HH', option['code'] & 0xffff, len(data)) + data",
                "    return (",
                "        b'\\x00'",
                "        + struct.pack('!HHIH', 41, edns['udp_payload_size'] & 0xffff, ttl, len(rdata))",
                "        + rdata",
                "    )",
                "",
                "def response_for(query, client_port=None):",
                "    if len(query) < 12:",
                "        raise ValueError('query shorter than dns header')",
                "    txid, flags, qdcount, _ancount, _nscount, _arcount = struct.unpack('!HHHHHH', query[:12])",
                "    if qdcount < 1:",
                "        raise ValueError('query has no question')",
                "    name, consumed = read_name(query, 12)",
                "    question_end = 12 + consumed + 4",
                "    if question_end > len(query):",
                "        raise ValueError('truncated dns question')",
                "    qtype, qclass = struct.unpack('!HH', query[12 + consumed:question_end])",
                "    question = query[12:question_end]",
                "    record = records.get((name, qtype))",
                "    rd = flags & 0x0100",
                "    if record is None or qclass != 1:",
                "        # NODATA: the name exists (under a different type), so the",
                "        # response is NOERROR (rcode 0) with the question echoed and",
                "        # an empty answer section. NXDOMAIN (rcode 3) is reserved for",
                "        # names absent from the zone.",
                "        if qclass == 1 and name in present_names:",
                "            header = struct.pack('!HHHHHH', txid, 0x8000 | rd | 0x0080, 1, 0, 0, 0)",
                "            return header + question, {'name': name, 'qtype': qtype, 'rcode': 0}",
                "        header = struct.pack('!HHHHHH', txid, 0x8000 | rd | 3, 1, 0, 0, 0)",
                "        return header + question, {'name': name, 'qtype': qtype, 'rcode': 3}",
                "    chain = record.get('cname')",
                "    if chain is not None:",
                "        if qtype != 1:",
                "            raise ValueError(f'cname chain only supports qtype 1, got {qtype}')",
                "        canonical = chain['canonical_name']",
                "        canonical_wire = encode_name(canonical)",
                "        cname_answer = (",
                "            b'\\xc0\\x0c'",
                "            + struct.pack('!HHIH', 5, 1, chain['cname_ttl'], len(canonical_wire))",
                "            + canonical_wire",
                "        )",
                "        address = ipaddress.IPv4Address(record['answer_data']).packed",
                "        a_answer = (",
                "            canonical_wire",
                "            + struct.pack('!HHIH', 1, 1, chain['address_ttl'], len(address))",
                "            + address",
                "        )",
                "        header = struct.pack('!HHHHHH', txid, 0x8000 | rd | 0x0400 | 0x0080, 1, 2, 0, 0)",
                "        meta = {",
                "            'name': name,",
                "            'qtype': qtype,",
                "            'rcode': 0,",
                "            'answer_count': 2,",
                "            'canonical_name': canonical,",
                "        }",
                "        return header + question + cname_answer + a_answer, meta",
                "    answer_data = record['answer_data']",
                "    answer_ttl = record['ttl']",
                "    # Per-source-port answer override (dns-repeat-transaction): pick",
                "    # the A answer planned for this client source port so each send's",
                "    # response carries its own answer.",
                "    override = repeat_overrides.get((name, qtype, client_port))",
                "    if override is not None:",
                "        answer_data = override['answer_data']",
                "        answer_ttl = override['ttl']",
                "    if qtype == 1:",
                "        rdata = ipaddress.IPv4Address(answer_data).packed",
                "    elif qtype == 28:",
                "        rdata = ipaddress.IPv6Address(answer_data).packed",
                "    elif qtype == 16:",
                "        # TXT RDATA: one or more DNS character-strings, each a",
                "        # single length octet followed by up to 255 content bytes.",
                "        rdata = b''",
                "        for value in record['txt_strings']:",
                "            raw = value.encode('utf-8')",
                "            if len(raw) > 255:",
                "                raise ValueError('txt character-string exceeds 255 bytes')",
                "            rdata += bytes([len(raw)]) + raw",
                "    elif qtype == 15:",
                "        # MX RDATA: 16-bit preference + exchange <domain-name>,",
                "        # encoded uncompressed so rdlength == 2 + name length.",
                "        rdata = struct.pack('!H', record['mx_preference'] & 0xffff)",
                "        rdata += encode_name(record['mx_exchange'])",
                "    elif qtype == 33:",
                "        # SRV RDATA: 16-bit priority + weight + port, then the",
                "        # target <domain-name>, encoded uncompressed so rdlength",
                "        # == 6 + name length.",
                "        rdata = struct.pack(",
                "            '!HHH',",
                "            record['srv_priority'] & 0xffff,",
                "            record['srv_weight'] & 0xffff,",
                "            record['srv_port'] & 0xffff,",
                "        )",
                "        rdata += encode_name(record['srv_target'])",
                "    else:",
                "        raise ValueError(f'unsupported qtype {qtype}')",
                "    answer = b'\\xc0\\x0c' + struct.pack('!HHIH', qtype, 1, answer_ttl, len(rdata)) + rdata",
                "    # EDNS(0) cases append an OPT pseudo-record to the additional",
                "    # section; arcount reflects it so the OPT decodes as an",
                "    # additional record rather than trailing bytes.",
                "    edns = record.get('edns')",
                "    additional = encode_opt(edns) if edns else b''",
                "    arcount = 1 if edns else 0",
                "    header = struct.pack(",
                "        '!HHHHHH', txid, 0x8000 | rd | 0x0400 | 0x0080, 1, 1, 0, arcount",
                "    )",
                "    meta = {'name': name, 'qtype': qtype, 'rcode': 0}",
                "    if edns:",
                "        meta['edns'] = True",
                "    return header + question + answer + additional, meta",
                "",
                "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
                "sock.bind((bind_ip, port))",
                "sock.settimeout(1.0)",
                "print(json.dumps({'event': 'listening', 'bind_ip': bind_ip, 'port': port}), flush=True)",
                "while not stop:",
                "    try:",
                "        data, addr = sock.recvfrom(4096)",
                "    except socket.timeout:",
                "        continue",
                "    try:",
                "        response, meta = response_for(data, addr[1])",
                "        sock.sendto(response, addr)",
                "        meta.update({'event': 'answered', 'client': addr[0], 'client_port': addr[1]})",
                "        print(json.dumps(meta, sort_keys=True), flush=True)",
                "    except Exception as exc:",
                "        print(json.dumps({'event': 'error', 'error': str(exc)}), file=sys.stderr, flush=True)",
                "sock.close()",
                "print(json.dumps({'event': 'stopped', 'ts': time.time()}), flush=True)",
                "PY",
            ]
        )
    for port in dns_ports:
        stdout_path = posixpath.join(artifact_root, f"dns-responder-{port}.stdout.txt")
        stderr_path = posixpath.join(artifact_root, f"dns-responder-{port}.stderr.txt")
        pid_path = posixpath.join(artifact_root, f"dns-responder-{port}.pid")
        lines.extend(
            [
                (
                    f"python3 {shlex.quote(posixpath.join(artifact_root, 'dns-responder.py'))} "
                    f"{shlex.quote(posixpath.join(artifact_root, 'dns-zone.json'))} "
                    f"\"$dns_bind_ipv4\" {port} "
                    f">{shlex.quote(stdout_path)} 2>{shlex.quote(stderr_path)} &"
                ),
                "pid=$!",
                f"echo \"$pid\" > {shlex.quote(pid_path)}",
                "printf '%s\\n' \"kill $pid 2>/dev/null || true\" >> \"$cleanup\"",
                f"printf '%s\\n' \"rm -f {shlex.quote(pid_path)}\" >> \"$cleanup\"",
                "sleep 0.5",
                "if ! kill -0 \"$pid\" 2>/dev/null; then",
                f"  cat {shlex.quote(stderr_path)} >&2 || true",
                f"  echo dns_responder_{port}=failed >&2",
                "  exit 73",
                "fi",
                f"echo dns_responder_{port}=running",
            ]
        )
    lines.append("echo target_service_setup=ok")
    return "\n".join(lines)


__all__ = [
    "KernelStateDescriptor",
    "TargetServiceDescriptor",
    "arp_alias_descriptor",
    "arp_sysctl_descriptor",
    "cleanup_wire_probe_target",
    "closed_udp_port_descriptor",
    "dedupe_ints",
    "dhcp_probe_plans",
    "dhcp_responder_descriptor",
    "dns_probe_plans",
    "dns_responder_descriptor",
    "plans_by_destination_port",
    "prepare_wire_probe_target",
    "target_service_address_fields",
    "target_service_setup_plan",
    "target_service_setup_script",
    "tcp_probe_plans",
    "udp_responder_descriptor",
]
