# Libcrafter Wire

`tools/wire` is the shared endpoint layer for live provider work. It creates,
tracks, uses, and destroys one runnable endpoint at a time for callers such as
`tools/oracle`, `tools/probe`, and agents.

`tools/wire` owns only mechanical endpoint lifecycle:

- creating and destroying provider resources
- recording provider cleanup metadata
- executing commands over SSH
- uploading and downloading files
- collecting endpoint artifacts
- reporting SSH connection details for debugging

`tools/oracle` and `tools/probe` own workload semantics. Packet correctness,
backend comparison, Scapy behavior, probe case generation, expected responses,
reports, and reproduction coordinates must stay in those tools, not in
`tools/wire`.

## Terms

- Provider: the system that creates the endpoint, such as `hetzner`,
  `virtualbox`, or `qemu`.
- Exposure: where the endpoint is placed on the wire, such as `wan`, `lan`,
  `private`, or `wifi`.
- Endpoint: one runnable machine with SSH access, a manifest, local identity
  files, local state, artifacts, and enough provider metadata to destroy it
  after partial failures.
- Artifact: local diagnostic output produced while creating, using, or
  destroying an endpoint, such as logs, manifests, request files, response
  files, and collected remote files.

Every public request names a provider, exposure, and endpoint intent
explicitly. `tools/wire` does not select providers automatically and does not
hide the real machine behind a topology abstraction.

## Supported Pairs

The first concrete provider is `hetzner`.

| Provider | Exposure | Status |
| --- | --- | --- |
| `hetzner` | `wan` | Supported |
| `hetzner` | `private` | Supported for controlled oracle/probe endpoint exchange |
| `hetzner` | `lan` | Rejected with an explicit incompatibility error |
| `hetzner` | `wifi` | Rejected with an explicit incompatibility error |

For `private`, callers may pass a small private group string so separately
created endpoints attach to the same provider private network. The group is a
coordination key only; it is not a public topology or session object.

## Local State

Endpoint manifests must use absolute paths for identity files, state files,
artifact directories, and local request or response files. They must also carry
enough lifecycle metadata for idempotent destroy operations after failed or
partial creates.

Generated local files live below ignored paths:

```text
tools/wire/.state/
tools/wire/artifacts/
```

Do not put provider state, private keys, account identifiers, public host
identifiers, credentials, or personal defaults in tracked files or normal
documentation examples.
