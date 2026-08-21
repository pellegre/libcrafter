# Crafter smoke protocol

`crafter-smoke` is a bounded, provider-neutral execution contract for checking
an exact libcrafter source tree outside the developer process. It knows nothing
about machines, placement, credentials, transports, interfaces, or resource
lifecycle. An external executor may build and run it wherever suitable compute
is available.

The process reads one JSON object from standard input, capped at 4 KiB:

```json
{"schema_version":1,"protocol":"crafter-smoke-v1","payload":"smoke"}
```

The payload is capped at 256 UTF-8 bytes. The workload constructs a deterministic
IPv4/UDP/Raw packet with documentation addresses, compiles it, decodes it from
layer 3, verifies its typed layers and payload, recompiles the decoded packet,
and requires byte-for-byte equality. It sends no packet and opens no capture.

On success it writes the same structured response to standard output and to
`result.json` in its working directory. The response reports only protocol
semantics and deterministic byte counts; execution receipts and cleanup
evidence belong to whichever external executor invoked it.

Run it locally:

```sh
printf '%s\n' '{"schema_version":1,"protocol":"crafter-smoke-v1","payload":"smoke"}' \
  | cargo run -q -p crafter-smoke
```
