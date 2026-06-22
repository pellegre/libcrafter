# WHAD 802.15.4 Protocol Manifest

Source-backed wire facts for the `crafter` WHAD `dot15d4` domain backend. The
live 802.15.4 backend (steps 40-51) speaks the WHAD protocol's 802.15.4 domain
over the existing `0xAC 0xBE` + u16-LE length + protobuf framing already used by
the BLE backend. Later vendored proto definitions, generated message types, and
the message builders/parsers should cite this manifest for the WHAD `dot15d4`
message names, field numbers, and command values below instead of relying on
model memory.

This manifest is pinned to the same WHAD release the BLE backend uses:
`whad-team/whad-protocol` `release/v3`, commit
`82dbbefe5c3a1b3bfa89f86829c8872985a7f27e` (protocol version 3), matching the
pin recorded in `crafter/src/wire/backend/whad/proto/{whad,device,ble,generic}.proto`,
`crafter/src/wire/backend/whad/proto/VERSION`, and
`crafter/src/wire/backend/whad/proto/LICENSE-NOTE.md`. The upstream definitions
live at `whad/protocol/dot15d4/dot15d4.proto`.

## Discovery Domain

| Fact | Citation |
| --- | --- |
| The 802.15.4 domain identifier is `discovery.Domain.Dot15d4 = 0x04000000`. | WHAD `whad/protocol/device.proto`, `Domain` enum (already vendored in `crafter/src/wire/backend/whad/proto/device.proto`). |
| A device advertises 802.15.4 support through `DeviceDomainInfoResp` with `domain = 0x04000000` and a `supported_commands` bitmap whose bits index the `Dot15d4Command` values below. | WHAD `whad/protocol/device.proto`, `DeviceDomainInfoQuery` / `DeviceDomainInfoResp` (vendored in `crafter/src/wire/backend/whad/proto/device.proto`). |

## Dot15d4Command Enum

The `Dot15d4Command` enum numbers index the device `supported_commands`
bitmap (bit N set means command value N is supported).

| Name | Value | Citation |
| --- | --- | --- |
| `SetNodeAddress` | 0 | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Dot15d4Command` enum. |
| `Sniff` | 1 | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Dot15d4Command` enum. |
| `Jam` | 2 | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Dot15d4Command` enum. |
| `EnergyDetection` | 3 | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Dot15d4Command` enum. |
| `Send` | 4 | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Dot15d4Command` enum. |
| `SendRaw` | 5 | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Dot15d4Command` enum. |
| `EndDeviceMode` | 6 | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Dot15d4Command` enum. |
| `CoordinatorMode` | 7 | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Dot15d4Command` enum. |
| `RouterMode` | 8 | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Dot15d4Command` enum. |
| `Start` | 9 | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Dot15d4Command` enum. |
| `Stop` | 10 | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Dot15d4Command` enum. |
| `ManInTheMiddle` | 11 | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Dot15d4Command` enum. |

The backend asserts `Domain::Dot15d4` plus the `Sniff` (1), `Send` (4), and
`SendRaw` (5) command bits for the sniff/inject surface. Upstream defines
additional command values beyond 11 (`ConfigureTSCH`, `SendInSlot`, `AddLink`,
`DeleteLink`, `UpdateSuperframe`, `DeleteSuperframe`, `SetChannelMap`) for TSCH;
those are out of scope for this plan (TSCH, energy-detection, jam, and MITM
workflows are non-goals) and are intentionally omitted from the vendored
scope-reduced proto.

## Command Messages

| Message | Fields (name = field number) | Citation |
| --- | --- | --- |
| `SniffCmd` | `channel = 1` | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `SniffCmd`. |
| `SendCmd` | `channel = 1`, `pdu = 2` | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `SendCmd`. |
| `SendRawCmd` | `channel = 1`, `pdu = 2`, `fcs = 3` | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `SendRawCmd`. |
| `StartCmd` | (no fields) | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `StartCmd`. |
| `StopCmd` | (no fields) | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `StopCmd`. |

`SniffCmd` selects the 802.15.4 channel to sniff. `SendCmd` injects a PDU and
lets the device compute the FCS; `SendRawCmd` injects a PDU with an explicit
`fcs` flag/value so a caller can transmit a frame with a deliberately wrong FCS
(malformed-on-purpose). `StartCmd`/`StopCmd` start and stop the selected mode.

## Notification Messages

| Message | Fields (name = field number) | Citation |
| --- | --- | --- |
| `RawPduReceived` | `channel = 1`, `rssi = 2`, `timestamp = 3`, `fcs_validity = 4`, `pdu = 5`, `fcs = 6`, `lqi = 7` | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `RawPduReceived`. |
| `PduReceived` | `channel = 1`, `rssi = 2`, `timestamp = 3`, `fcs_validity = 4`, `pdu = 5`, `lqi = 6` | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `PduReceived`. |

`RawPduReceived` carries the explicit trailing `fcs` and reports `fcs_validity`;
`PduReceived` omits the separate `fcs` field. Both map their `channel`, `rssi`,
`fcs_validity`, and `lqi` fields to the `Dot15d4Radio` descriptor and their
`pdu` bytes to the `Dot15d4` MAC frame. Upstream also defines later TSCH-related
fields on these messages (`asn`, `start_of_slot_timestamp`, `time_slot`,
`base_channel_frequency`, `number_of_channels`, `channel_spacing`); those are out
of scope and omitted from the vendored scope-reduced proto.

## dot15d4.Message Oneof

The `dot15d4` top-level `Message` wraps the domain messages in a `oneof msg`.
Only the field numbers used by this plan's sniff/inject surface are recorded;
the omitted arms correspond to the out-of-scope commands above.

| Oneof field | Field number | Message | Citation |
| --- | --- | --- | --- |
| `sniff` | 2 | `SniffCmd` | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Message` oneof. |
| `send` | 5 | `SendCmd` | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Message` oneof. |
| `send_raw` | 6 | `SendRawCmd` | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Message` oneof. |
| `start` | 10 | `StartCmd` | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Message` oneof. |
| `stop` | 11 | `StopCmd` | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Message` oneof. |
| `raw_pdu` | 15 | `RawPduReceived` | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Message` oneof. |
| `pdu` | 16 | `PduReceived` | WHAD `whad/protocol/dot15d4/dot15d4.proto`, `Message` oneof. |

## Top-Level whad.proto Envelope

| Fact | Citation |
| --- | --- |
| The top-level `whad.proto` `Message` `oneof msg` currently carries `generic = 1`, `discovery = 2`, and `ble = 3`; it must gain a `dot15d4` arm (mirroring the upstream envelope) so `dot15d4.Message` can be wrapped for the framing/transport layer. | `crafter/src/wire/backend/whad/proto/whad.proto` (vendored envelope); WHAD `whad/protocol/whad.proto`, top-level `Message` oneof. |
| The vendored `dot15d4.proto` is regenerated scope-reduced (not a verbatim copy of the upstream file), preserving only the package name, command/notification message names, field numbers, enum values, and oneof field numbers needed by the host-side sniff/inject backend, exactly as the BLE subset was regenerated. | `crafter/src/wire/backend/whad/proto/LICENSE-NOTE.md`; `crafter/src/wire/backend/whad/proto/VERSION`. |

## Licensing Caveat

The `whad-protocol` repository at the pinned commit does not contain an explicit
`LICENSE`, `COPYING`, or `NOTICE` file, and no SPDX/MIT license header was found
in the protocol sources. For that reason the vendored `dot15d4.proto` added in
step 40 must be a scope-reduced regenerated equivalent (not a verbatim vendored
copy), preserving the field numbers and names needed to generate host-side
message types and intentionally omitting unrelated WHAD domains and command
surfaces. This is the same licensing posture already recorded for the vendored
BLE/discovery/generic subsets in
`crafter/src/wire/backend/whad/proto/LICENSE-NOTE.md`.

## Sources

- WHAD protocol repository: <https://github.com/whad-team/whad-protocol>
- WHAD 802.15.4 protocol definition (pinned commit): <https://github.com/whad-team/whad-protocol/blob/82dbbefe5c3a1b3bfa89f86829c8872985a7f27e/whad/protocol/dot15d4/dot15d4.proto>
- WHAD device/discovery protocol definition (pinned commit): <https://github.com/whad-team/whad-protocol/blob/82dbbefe5c3a1b3bfa89f86829c8872985a7f27e/whad/protocol/device.proto>
- WHAD top-level protocol envelope (pinned commit): <https://github.com/whad-team/whad-protocol/blob/82dbbefe5c3a1b3bfa89f86829c8872985a7f27e/whad/protocol/whad.proto>
- Pinned ref: `whad-team/whad-protocol` `release/v3`, commit `82dbbefe5c3a1b3bfa89f86829c8872985a7f27e`, protocol version 3.
- Locally cloned upstream copy (disposable `.scratch` clone, not committed): `.scratch/whad-poc/whad-protocol/whad/protocol/dot15d4/dot15d4.proto`.
- Already-vendored WHAD subset (this repository): `crafter/src/wire/backend/whad/proto/{whad,device,ble,generic}.proto`, with the pin recorded in `crafter/src/wire/backend/whad/proto/VERSION` and `crafter/src/wire/backend/whad/proto/LICENSE-NOTE.md`.
