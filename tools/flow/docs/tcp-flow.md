# TCP Flow Templates

The TCP flow templates model one userspace TCP connection as a bounded flow.
They are intended for neutral client/server interop and test harnesses built on
top of `crafter-flow`, not as a full TCP/IP stack.

All examples should use documentation address space such as `192.0.2.10` and
`198.51.100.20`. Live use remains explicit and should stay inside an isolated
lab or provider endpoint.

## Client Lifecycle

The client template performs an active open and carries the connection through
this state machine:

```text
SynSent
  entry: send SYN, store local ISS, local port, remote port, remote IPv4
  SYN|ACK with ack == snd_nxt -> store peer rcv_nxt, send ACK -> Established
  RST with ack == snd_nxt -> Closed

Established
  entry: optionally send one PSH|ACK data segment and advance snd_nxt
  ACK with payload, seq == rcv_nxt, ack == snd_nxt
    -> store payload, advance rcv_nxt, send ACK -> FinWait1
  no configured payload or zero send window -> FinWait1
  RST with ack == snd_nxt -> Closed

FinWait1
  entry: send FIN|ACK and advance snd_nxt
  ACK of local FIN -> FinWait2
  FIN|ACK from peer -> advance rcv_nxt, send final ACK -> Closed
  RST with ack == snd_nxt -> Closed

FinWait2
  FIN|ACK from peer -> advance rcv_nxt, send final ACK -> Closed
  RST with ack == snd_nxt -> Closed

Closed
  terminal report state
```

The client only advances when the received TCP segment belongs to the learned
four-tuple and acknowledges the current local send-next value. Peer data updates
the receive-next value before the next acknowledgement is emitted.

## Server Lifecycle

The server template performs a passive open and carries the connection through
this state machine:

```text
Listen
  SYN to local address and listen port
    -> store remote IPv4/port, peer rcv_nxt, local ISS, send SYN|ACK
    -> SynReceived

SynReceived
  ACK with seq == rcv_nxt and ack == snd_nxt -> Established

Established
  ACK with payload, seq == rcv_nxt, ack == snd_nxt
    -> store payload, advance rcv_nxt, send ACK or one PSH|ACK response
    -> Established
  FIN|ACK with seq == rcv_nxt, ack == snd_nxt
    -> store any FIN payload, advance rcv_nxt, send ACK -> CloseWait

CloseWait
  entry: send FIN|ACK and advance snd_nxt -> LastAck

LastAck
  ACK with seq == rcv_nxt, ack == snd_nxt, no payload, no FIN, no RST
    -> Closed

Closed
  terminal report state
```

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

The peer's initial sequence number is not assumed. Each acknowledgement is
derived from the latest accepted peer SYN, payload, or FIN, and every later
outgoing sequence number is derived from the local send-next carried across
earlier SYN, data, and FIN sends.

## Validation Status

The TCP client and TCP server were validated offline with scripted in-memory
packets, with the client and server flows driving each other without a network,
and live against real `netcat` peers in an isolated lab:

- `crafter-flow` TCP client to a `netcat` server: handshake, payload send,
  payload receive, and graceful close.
- `netcat` client to `crafter-flow` TCP server: passive handshake, payload
  receive, response send, and graceful close.

The live validation used isolated lab artifacts and scratch runners that are not
tracked. The tracked documentation keeps examples neutral and documentation-space
only.

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

Live operation therefore requires the scoped kernel RST-drop guard from the
isolated TCP lab. The concrete guard, verification, and rollback commands belong
to the untracked lab under `tools/flow/.scratch/lab/tcp/`, not tracked code. The
guard must be limited to the lab ports and removed after the run.
