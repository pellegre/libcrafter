# TCP Flow Templates

The TCP flow templates model one userspace TCP connection as a bounded flow.
They are intended for neutral client/server interop and test harnesses built on
top of `crafter-flow`, not as a full TCP/IP stack.

All examples should use documentation address space such as `192.0.2.10` and
`198.51.100.20`. Live use remains explicit and should stay inside an isolated
lab or provider endpoint.

## Client Lifecycle

The client template performs an active open and carries the connection through
these states:

- `SynSent`: send the initial SYN with the local initial sequence number.
- `Established`: accept the peer SYN-ACK, acknowledge it, send configured data,
  and acknowledge peer data.
- `FinWait1`: send the active-close FIN and wait for the peer acknowledgement.
- `FinWait2`: wait for the peer FIN after the local FIN is acknowledged.
- `Closed`: send the final ACK and finish the flow report.

The client only advances when the received TCP segment belongs to the learned
four-tuple and acknowledges the current local send-next value. Peer data updates
the receive-next value before the next acknowledgement is emitted.

## Server Lifecycle

The server template performs a passive open and carries the connection through
these states:

- `Listen`: wait for a SYN on the configured local address and port.
- `SynReceived`: answer with SYN-ACK and wait for the final handshake ACK.
- `Established`: receive client data, acknowledge it, and optionally emit one
  configured response segment.
- `CloseWait`: acknowledge the peer FIN after the peer starts the close.
- `LastAck`: send the server FIN and wait for the peer ACK.
- `Closed`: finish after the server FIN is acknowledged.

The server learns the remote address and port from the SYN. Later segments must
match that connection tuple and the current sequence/acknowledgement state before
they can move the flow forward.

## Carried Connection State

Each flow keeps TCP state in `PacketContext` rather than hardcoding later
segments:

- local and remote IPv4 addresses and TCP ports;
- local initial sequence number and current send-next value;
- remote receive-next value derived from the peer sequence number and payload
  length;
- peer MSS and advertised window, used to cap the first data segment;
- received TCP payload bytes, surfaced through the flow report.

Outgoing ACK, data, and FIN segments are built from that carried state. Values
set explicitly by the flow remain visible in the emitted packets, while normal
packet compilation still fills lower-level lengths and checksums.

## First-Cut Scope

This is a small, single-connection TCP model:

- one IPv4/TCP connection at a time;
- in-order handshake, payload, and graceful close;
- a modest fixed window and one data segment sized by MSS/window state;
- no congestion control, no SACK/window scaling behavior, no simultaneous open,
  and no stream reassembly for large transfers.

The runner bound and timeout remain the guardrails for peers that never complete
the expected lifecycle. A stalled run should produce an inspectable partial
report instead of hanging.

## Live Kernel Suppression

Userspace-crafted TCP competes with the host kernel. During live runs, the kernel
can send a RST for SYNs or data segments that do not belong to a kernel socket,
which tears down the userspace connection before the flow can finish.

Live operation therefore requires scoped kernel RST suppression in the isolated
TCP lab. Keep the tracked flow documentation neutral and use the untracked lab
under `tools/flow/.scratch/lab/tcp/` for the concrete guard, verification, and
rollback commands. The guard must be limited to the lab ports and removed after
the run.
