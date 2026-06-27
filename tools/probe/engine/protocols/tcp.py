"""TCP probe protocol plugin: cases, plan builders, and full live surface.

This is the TCP full migration (a single step, after the ARP vertical slice and
the DNS / DHCPv4 / UDP / NDP / ICMP migrations). TCP bundles its entire surface in
one place:

* the three inline TCP cases (``tcp-syn-open`` / ``tcp-syn-closed`` /
  ``tcp-syn-options``), carried directly in the legacy per-protocol aggregation
  rather than through the ``_behavior_case`` factory (the catalog contribution),
* the ``_tcp_syn_probe_plan`` and ``_tcp_syn_options_probe_plan`` plan builders
  (the plan-builder contribution),
* the TCP stimulus-endpoint routing set,
* the ``target_service`` hook (the controlled ``tcp-open-listener`` service for
  ``tcp-syn-open`` and the closed-port verification for ``tcp-syn-closed``,
  reusing the TCP equivalent of the UDP/closed-port machinery), with the
  co-located setup-script blocks (the closed-TCP-port free check and the
  open-listener heredoc + launch) called directly by
  ``target_services.target_service_setup_script`` because they need the planned
  TCP plans the ``setup_script`` hook is not handed,
* the ``rewrite_endpoint_addresses`` hook (the ``tcp-syn-`` name-prefix live-path
  rewrite, reproduced *exactly*),
* the ``failure_reasons`` hook (the ``tcp-syn-open`` / ``tcp-syn-closed``
  taxonomy; ``tcp-syn-options`` falls through to the shared default), and
* the ``lab_capabilities`` hook (the ``tcp_open_port`` / ``tcp_closed_port``
  derived capabilities).

The plan builders are moved verbatim from :mod:`tools.probe.engine.planning`;
:mod:`planning` re-imports both so ``planning._<builder>`` /
``planning.PLAN_BUILDERS[name]`` keep identical object identity for any pin. TCP
carries no ``planned_only`` cases (both builders materialize a plan), and its
``profile_counts`` is intentionally empty: ``tcp-syn-open`` / ``tcp-syn-closed``
sit in the ``smoke`` profile and all three sit in the ``tcp-smoke`` profile in a
fixed, order-sensitive position, and the registry-first profile merge would move
the registry contribution to the front of those profiles, so the legacy ordered
profile name tables in :mod:`tools.probe.engine.cases` keep owning TCP's profile
membership to preserve byte-identical selection order.

The ``rewrite_endpoint_addresses`` hook reproduces the ``tcp-syn-`` prefix branch
of ``cli._probe_plan_with_endpoint_addresses`` verbatim (the shared
transport-IPv4 pre-sets that ran before the per-protocol if/elif, the TCP capture
filter / ``target_service`` / ``stimulus_rst_guard`` rewrite, and the shared
IPv4-layer validation/live-rewrite tail). The ``tcp-syn-`` *name-prefix* dispatch
is preserved exactly: the hook keys on ``case_name.startswith("tcp-syn-")`` for
the TCP-specific rewrite, applying to all three TCP cases. The ``failure_reasons``
hook reproduces the ``tcp-syn-open`` / ``tcp-syn-closed`` taxonomy and returns
``None`` for ``tcp-syn-options`` (which fell through to the shared default) and
every non-TCP case. The ``lab_capabilities`` hook contributes the
``tcp_open_port`` (``ipv4_unicast`` + ``controlled_services``) and
``tcp_closed_port`` (``ipv4_unicast``) derived capabilities.

Imports are relative only so the module loads under both engine import roots
(``engine.protocols.tcp`` for the CLI and ``tools.probe.engine.protocols.tcp``
for the tests).
"""

from __future__ import annotations

import posixpath
import shlex
from collections.abc import Mapping, Sequence

from ..capability_derivation import capability
from ..endpoint_addressing import (
    FAILURE_DECODE_FAILED,
    FAILURE_TARGET_SETUP_FAILED,
    FAILURE_TIMEOUT,
    FAILURE_WRONG_FLAGS,
    FAILURE_WRONG_PEER,
    apply_shared_ipv4_rewrite_tail,
)
from ..model import JSONObject, JSONValue, ProbeCase, json_object
from ..planning_helpers import (
    deterministic_bytes,
    deterministic_ipv4_pair,
)
from ..target_service_helpers import (
    dedupe_ints,
    plans_by_destination_port,
    target_service_address_fields,
)
from .base import ProtocolPlugin, register


# The three inline TCP cases (the legacy per-protocol aggregation carried these
# directly rather than through the ``_behavior_case`` factory). ``tcp-syn-open``
# validates a SYN/ACK from a controlled listener; ``tcp-syn-closed`` validates a
# RST from a closed port (target kernel behavior); ``tcp-syn-options`` validates
# a SYN/ACK to a controlled listener while the stimulus carries a representative
# option set.
TCP_SYN_OPEN_CASE: ProbeCase = ProbeCase(
    name="tcp-syn-open",
    description="Send TCP SYN to controlled listener and validate SYN/ACK.",
    stimulus="tcp_syn",
    expected_response="tcp_syn_ack",
    required_capabilities=["tcp_open_port"],
    endpoint_roles=["stimulus", "target"],
    metadata={"protocol": "tcp", "service": "controlled_listener"},
)

TCP_SYN_CLOSED_CASE: ProbeCase = ProbeCase(
    name="tcp-syn-closed",
    description="Send TCP SYN to closed port and validate RST response.",
    stimulus="tcp_syn",
    expected_response="tcp_rst",
    required_capabilities=["tcp_closed_port"],
    endpoint_roles=["stimulus", "target"],
    metadata={"protocol": "tcp", "service": "kernel"},
)

TCP_SYN_OPTIONS_CASE: ProbeCase = ProbeCase(
    name="tcp-syn-options",
    description=(
        "Send a TCP SYN carrying a representative option set (MSS, Window "
        "Scale, SACK-Permitted, Timestamp, User Timeout) to a controlled "
        "listener and validate the SYN/ACK."
    ),
    stimulus="tcp_syn",
    expected_response="tcp_syn_ack",
    required_capabilities=["tcp_open_port"],
    endpoint_roles=["stimulus", "target"],
    metadata={"protocol": "tcp", "service": "controlled_listener"},
)


def _tcp_syn_probe_plan(
    *,
    case_name: str,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 61000 + int.from_bytes(digest[0:2], "big") % 4000
    destination_base = 18000 if case_name == "tcp-syn-open" else 22000
    destination_port = destination_base + int.from_bytes(digest[2:4], "big") % 3000
    sequence_number = int.from_bytes(digest[4:8], "big")
    expected_ack = (sequence_number + 1) & 0xFFFF_FFFF
    expected_response = "tcp_syn_ack" if case_name == "tcp-syn-open" else "tcp_rst"
    expected_flags = ["syn", "ack"] if case_name == "tcp-syn-open" else ["rst"]
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "tcp_syn",
        "expected_response": expected_response,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_sequence_number": sequence_number,
        "expected_acknowledgment_number": expected_ack,
        "window": 64240,
        "target_service": {
            "required": case_name == "tcp-syn-open",
            "kind": "tcp-listener" if case_name == "tcp-syn-open" else "closed-port",
            "port": destination_port,
        },
        "stimulus_rst_guard": {
            "required": True,
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": target_ipv4,
            "source_port": source_port,
            "destination_port": destination_port,
        },
        "capture_filter": (
            f"tcp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "flags": expected_flags,
            "acknowledgment_number": expected_ack,
            "allow_rst_ack": case_name == "tcp-syn-closed",
        },
    }


def _tcp_syn_options_probe_plan(
    *,
    case_name: str = "tcp-syn-options",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan the ``tcp-syn-options`` case.

    A TCP SYN to a controlled listener that carries a representative,
    deterministic option set so the dry-run materializes a TCP segment *with
    options* and reports the planned sends, captures, and matchers. The option
    list covers the currently deployed SYN options -- MSS, Window Scale,
    SACK-Permitted, and Timestamp (RFC 9293 / RFC 7323 / RFC 2018) -- plus one
    newer typed option, User Timeout (RFC 5482, kind 28), so the stimulus
    endpoint builds them through the crafter typed ``TcpOption`` API rather than
    raw bytes. The ``tcp_options`` descriptors are the stable spec the Rust
    adapter consumes; the wire option bytes are materialized by libcrafter at
    send time (and reported as ``sent_raw_hex`` in dry-run), never hand-rolled
    here. Expected SYN/ACK validation (peer, ports, flags, ack) mirrors
    ``tcp-syn-open``.
    """

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 61000 + int.from_bytes(digest[0:2], "big") % 4000
    destination_port = 18000 + int.from_bytes(digest[2:4], "big") % 3000
    sequence_number = int.from_bytes(digest[4:8], "big")
    expected_ack = (sequence_number + 1) & 0xFFFF_FFFF
    # Representative, deterministic SYN option set. Window-scale shift is kept in
    # the RFC 7323 valid range (0..=14); the MSS rides a documentation-friendly
    # 1460 typical value; the timestamp value is deterministic with a zero echo
    # reply (SYN has nothing to echo); user-timeout carries a granularity flag
    # and a 15-bit value (RFC 5482). The order matches a typical Linux SYN:
    # MSS, SACK-Permitted, Timestamp, NOP, Window Scale, then User Timeout.
    window_scale_shift = digest[8] % 15
    mss_value = 1460
    timestamp_value = int.from_bytes(digest[9:13], "big")
    user_timeout_value = 1 + int.from_bytes(digest[13:15], "big") % 0x7FFE
    tcp_options = [
        {"kind": "mss", "kind_value": 2, "mss": mss_value},
        {"kind": "sack_permitted", "kind_value": 4},
        {
            "kind": "timestamp",
            "kind_value": 8,
            "timestamp_value": timestamp_value,
            "timestamp_echo_reply": 0,
        },
        {"kind": "nop", "kind_value": 1},
        {
            "kind": "window_scale",
            "kind_value": 3,
            "window_scale_shift": window_scale_shift,
        },
        {
            "kind": "user_timeout",
            "kind_value": 28,
            "user_timeout_granularity": False,
            "user_timeout_value": user_timeout_value,
        },
    ]
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "tcp_syn",
        "expected_response": "tcp_syn_ack",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_sequence_number": sequence_number,
        "expected_acknowledgment_number": expected_ack,
        "window": 64240,
        # The representative typed option descriptors the stimulus endpoint
        # builds with the crafter TcpOption API. Materialized option bytes are
        # reported by libcrafter at send time; they are not hand-encoded here.
        "tcp_options": tcp_options,
        "target_service": {
            "required": True,
            "kind": "tcp-listener",
            "port": destination_port,
        },
        "stimulus_rst_guard": {
            "required": True,
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": target_ipv4,
            "source_port": source_port,
            "destination_port": destination_port,
        },
        "capture_filter": (
            f"tcp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "flags": ["syn", "ack"],
            "acknowledgment_number": expected_ack,
            "allow_rst_ack": False,
        },
    }


# Per-case plan-builder dispatch entries for the three TCP cases. The registry
# merge in :mod:`tools.probe.engine.planning` exposes these through
# ``PLAN_BUILDERS`` (registry-first), and ``planning`` re-imports each function so
# ``planning._<builder>`` keeps identical object identity for any pin. Both
# ``tcp-syn-open`` and ``tcp-syn-closed`` share ``_tcp_syn_probe_plan`` (the case
# name selects the open/closed shape), the way the legacy dispatch table did.
_TCP_PLAN_BUILDERS: dict[str, object] = {
    "tcp-syn-open": _tcp_syn_probe_plan,
    "tcp-syn-closed": _tcp_syn_probe_plan,
    "tcp-syn-options": _tcp_syn_options_probe_plan,
}


# All three TCP cases route through the stimulus endpoint adapter.
_TCP_STIMULUS_ENDPOINT_CASES: frozenset[str] = frozenset(
    {
        "tcp-syn-open",
        "tcp-syn-closed",
        "tcp-syn-options",
    }
)


# --------------------------------------------------------------------------- #
# Target-service plan selector (moved from target_services.py)
# --------------------------------------------------------------------------- #
#
# The ``tcp-syn-`` name-prefix selects the TCP probe plans (open and closed). The
# prefix dispatch is preserved exactly: ``live.py`` and the setup path call this
# to gate the stimulus RST guard and the open-listener / closed-port setup.


def tcp_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return the TCP-SYN probe plans (open and closed) in order."""

    return [
        plan
        for plan in probe_plans
        if str(plan.get("case", "")).startswith("tcp-syn-")
    ]


def tcp_target_service_contribution(
    probe_plans: Sequence[JSONObject],
    *,
    dry_run: bool,
) -> JSONObject:
    """Return the TCP plugin's ``target_service_setup_plan`` contribution.

    Moved verbatim from the ``tcp-open-listener`` ``services`` entries and the
    ``closed_tcp_ports`` entries of the central ``target_service_setup_plan``:
    one controlled ``tcp-open-listener`` service per distinct ``tcp-syn-open``
    destination port, one closed-TCP-port verification entry per distinct
    ``tcp-syn-closed`` destination, plus the ``starts_services`` flip on a live
    run that has at least one open listener to stand up. (``tcp-syn-options``
    rides the ``tcp-listener`` kind in its plan but, like the legacy body, does
    not contribute a separate setup-plan service entry: only ``tcp-syn-open``
    feeds the open-listener list.) The registry merge appends these ``services``
    / ``closed_tcp_ports`` to the central lists and OR-s ``starts_services``,
    byte-identical to the legacy per-protocol path (which included
    ``tcp_open_plans`` -- but not the closed-port plans -- in its
    ``starts_services`` OR).
    """

    tcp_open_plans = plans_by_destination_port(
        plan for plan in probe_plans if plan.get("case") == "tcp-syn-open"
    )
    tcp_closed_plans = plans_by_destination_port(
        plan for plan in probe_plans if plan.get("case") == "tcp-syn-closed"
    )
    services = [
        {
            "name": "tcp-open-listener",
            "protocol": "tcp",
            "port": port,
            "purpose": "tcp-syn-open",
            "deterministic": True,
            **target_service_address_fields(plan),
        }
        for port, plan in tcp_open_plans.items()
    ]
    closed_tcp_ports = [
        {
            "port": port,
            "state": "verified-unbound" if not dry_run else "planned-unbound",
            "purpose": "tcp-syn-closed",
            "deterministic": True,
            **target_service_address_fields(plan),
        }
        for port, plan in tcp_closed_plans.items()
    ]
    return {
        "services": services,
        "closed_tcp_ports": closed_tcp_ports,
        "starts_services": not dry_run and bool(tcp_open_plans),
    }


# --------------------------------------------------------------------------- #
# Target setup-script blocks (moved from target_services.target_service_setup_script)
# --------------------------------------------------------------------------- #
#
# The TCP setup-script contribution is split into two blocks that the legacy
# ``target_service_setup_script`` emitted at two distinct positions: a per-port
# closed-TCP-port free check (rendered after the DNS/DHCPv4 port checks, before the
# closed-UDP-port checks) and the open-listener heredoc + per-port launch loop
# (rendered after the closed-UDP-port checks, before the DNS responder block).
# They are co-located here and called *directly* by
# ``target_service_setup_script`` (the plugin ``setup_script`` hook receives no
# plan context), so the rendered bytes stay byte-identical to the legacy inline
# blocks.


def tcp_closed_port_check_lines(closed_ports: Sequence[int]) -> list[str]:
    """Render the closed-TCP-port free-check block for the setup script.

    Moved verbatim from the ``for port in closed_ports:`` loop that ran after the
    DNS/DHCPv4 port checks in ``target_service_setup_script``; binds
    ``$tcp_bind_ipv4:port`` to confirm the port stays free so the target kernel
    emits a RST for a SYN.
    """

    lines: list[str] = []
    for port in closed_ports:
        lines.append(f"check_port_free \"$tcp_bind_ipv4\" {port}")
        lines.append(f"echo closed_port_{port}=free")
    return lines


def tcp_open_listener_setup_lines(
    *,
    artifact_root: str,
    open_ports: Sequence[int],
) -> list[str]:
    """Render the TCP open-listener heredoc + launch block for the setup script.

    Moved verbatim from the ``for port in open_ports:`` loop of
    ``target_service_setup_script``; the orchestrator calls this with the
    ``tcp-syn-open`` destination ports so the rendered script bytes stay
    byte-identical.
    """

    lines: list[str] = []
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
    return lines


# --------------------------------------------------------------------------- #
# Live-path address rewrite (moved from cli._probe_plan_with_endpoint_addresses)
# --------------------------------------------------------------------------- #
#
# The legacy TCP rewrite branch matched on ``case_name.startswith("tcp-syn-")``,
# applying to all three TCP cases. The plugin reproduces that exact name-prefix
# dispatch plus the shared transport-IPv4 pre-sets and the shared IPv4-layer tail.


def tcp_rewrite_endpoint_addresses(
    plan: JSONObject,
    *,
    source_ipv4: str,
    target_ipv4: str,
    source_mac: str | None = None,
    target_mac: str | None = None,
    target_interface: str | None = None,
    rewrite_source: str = "wire_endpoint_plan",
) -> JSONObject:
    """Rewrite a TCP probe plan onto the live lab-segment addresses.

    Moved verbatim from the ``case_name.startswith("tcp-syn-")`` branch of
    ``cli._probe_plan_with_endpoint_addresses`` (including the shared
    transport-IPv4 pre-sets that ran before the per-protocol if/elif and the
    shared IPv4-layer validation/live-rewrite tail that ran after it). The
    ``tcp-syn-`` *name-prefix* dispatch is preserved exactly. The capture filter,
    ``target_service``, and ``stimulus_rst_guard`` are rewritten onto the lab
    segment; then the branch falls into the shared IPv4-layer
    validation/live-rewrite tail, applied here. TCP rides IPv4 with no link-layer
    rewrite, so the MAC / interface arguments are accepted and discarded.
    """

    updated = dict(plan)
    updated["source_ipv4"] = source_ipv4
    updated["destination_ipv4"] = target_ipv4
    updated["expected_reply_source_ipv4"] = target_ipv4
    updated["expected_reply_destination_ipv4"] = source_ipv4
    case_name = str(updated.get("case", ""))
    if case_name.startswith("tcp-syn-"):
        source_port = int(updated.get("source_port", 0))
        destination_port = int(updated.get("destination_port", 0))
        updated["capture_filter"] = (
            f"tcp and src host {target_ipv4} and dst host {source_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        )
        target_service = dict(
            json_object(updated.get("target_service", {}), "probe_plan.target_service")
        )
        target_service.update(
            {
                "bind_ipv4": target_ipv4,
                "source_ipv4": source_ipv4,
            }
        )
        updated["target_service"] = target_service
        rst_guard = dict(
            json_object(updated.get("stimulus_rst_guard", {}), "probe_plan.rst_guard")
        )
        rst_guard.update(
            {
                "source_ipv4": source_ipv4,
                "destination_ipv4": target_ipv4,
                "source_port": source_port,
                "destination_port": destination_port,
            }
        )
        updated["stimulus_rst_guard"] = rst_guard
    return apply_shared_ipv4_rewrite_tail(
        updated,
        case_name=case_name,
        source_ipv4=source_ipv4,
        target_ipv4=target_ipv4,
        rewrite_source=rewrite_source,
    )


# --------------------------------------------------------------------------- #
# Failure-reason taxonomy (moved from cli._failure_reasons_for_case)
# --------------------------------------------------------------------------- #


def tcp_failure_reasons(case_name: str) -> list[str] | None:
    """Return the ordered TCP failure-reason taxonomy for ``case_name``.

    Moved verbatim from the ``{"tcp-syn-open", "tcp-syn-closed"}`` branch of
    ``cli._failure_reasons_for_case``. ``tcp-syn-options`` is *not* covered (the
    legacy branch keyed only on the open/closed pair); it -- like every non-TCP
    case -- returns ``None`` so the central dispatcher falls through to the
    shared default taxonomy.
    """

    if case_name in {"tcp-syn-open", "tcp-syn-closed"}:
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_FLAGS,
            FAILURE_DECODE_FAILED,
            FAILURE_TARGET_SETUP_FAILED,
        ]
    return None


# --------------------------------------------------------------------------- #
# Lab-capability derivation (moved from lab.probe_capabilities_from_lab_capabilities)
# --------------------------------------------------------------------------- #


def tcp_lab_capabilities(substrate: Mapping[str, JSONValue]) -> Mapping[str, object]:
    """Return the TCP plugin's derived probe-capability contribution.

    Moved verbatim from the ``tcp_open_port`` / ``tcp_closed_port`` derivations in
    ``lab.probe_capabilities_from_lab_capabilities``: a controlled TCP listener
    needs an IPv4-unicast substrate that can host a controlled service
    (``tcp_open_port``); the closed-port RST behavior needs only IPv4-unicast
    reachability to the target kernel (``tcp_closed_port``). The shared
    ``capability_names`` / ``capability_sources`` tables stay in ``lab``; this
    hook contributes only the derived ``tcp_*`` values, merged byte-identically
    over the legacy values.
    """

    ipv4_unicast = capability(substrate, "ipv4_unicast", "ipv4")
    controlled_services = capability(
        substrate,
        "controlled_services",
        "controlled_service",
    )
    return {
        "tcp_open_port": ipv4_unicast and controlled_services,
        "tcp_closed_port": ipv4_unicast,
    }


register(
    ProtocolPlugin(
        name="tcp",
        # The three inline TCP cases in declaration order (``tcp-syn-open`` first,
        # to match the legacy aggregation where it led the catalog).
        cases=(TCP_SYN_OPEN_CASE, TCP_SYN_CLOSED_CASE, TCP_SYN_OPTIONS_CASE),
        plan_builders=_TCP_PLAN_BUILDERS,
        # TCP carries no planned-only cases (every builder materializes a plan).
        planned_only_cases=frozenset(),
        # TCP's profile membership stays in the legacy ordered profile tables in
        # ``cases.py`` to preserve byte-identical selection order (the registry-
        # first profile merge would otherwise move TCP to the front of the smoke
        # and tcp-smoke profiles). Contribute nothing here.
        profile_counts={},
        stimulus_endpoint_cases=_TCP_STIMULUS_ENDPOINT_CASES,
        # TCP's target service reuses the UDP/closed-port machinery: the
        # ``target_service`` hook contributes the ``tcp-open-listener`` services
        # entries (``tcp-syn-open``) and the ``closed_tcp_ports`` entries
        # (``tcp-syn-closed``), and diverts all three TCP cases off the legacy
        # target path. ``setup_script`` stays ``None``: TCP's setup-script blocks
        # (the closed-TCP-port free check and the open-listener heredoc + launch)
        # need the planned TCP ports, which the plugin ``setup_script`` hook does
        # not receive, so ``target_services.target_service_setup_script`` renders
        # them by calling :func:`tcp_closed_port_check_lines` /
        # :func:`tcp_open_listener_setup_lines` directly (byte-identically to the
        # legacy inline blocks). ``rewrite_endpoint_addresses`` reproduces the
        # ``tcp-syn-`` prefix rewrite; ``failure_reasons`` returns the TCP taxonomy
        # for the open/closed pair (``None`` otherwise); ``lab_capabilities``
        # contributes ``tcp_open_port`` / ``tcp_closed_port``.
        target_service=tcp_target_service_contribution,
        setup_script=None,
        rewrite_endpoint_addresses=tcp_rewrite_endpoint_addresses,
        failure_reasons=tcp_failure_reasons,
        lab_capabilities=tcp_lab_capabilities,
    )
)
