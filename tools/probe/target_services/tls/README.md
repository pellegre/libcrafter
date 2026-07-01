# TLS Probe Target Service

TLS probe cases use a controlled TCP listener on a disposable provider target.
The service is a byte observer, not a TLS endpoint stack: it accepts a planned
TCP connection, records the TLS record bytes, writes capture artifacts, and
exits so provider cleanup can remove all state.

Dry-run output must show:

- service kind: `tls-controlled-service`
- protocol and port: TCP `4433`
- setup: scripted TLS byte observer bound to the target endpoint IPv4 address
- capture filter: `tcp and port 4433`
- expected records: the planned TLS content type and fragment bytes
- artifacts: `tls-listener.log`, `tls-capture.pcap`, and
  `tls-observed-records.json`
- cleanup: terminate the service, collect artifacts, and remove temporary state

The default probe path is dry-run only:

```sh
tools/probe/run --provider qemu --dry-run --profile tls-smoke --seed 8446 --count 3 --out target/probe/tls-smoke-dry-run
```

Live use requires a provider-backed disposable endpoint and explicit
`--confirm-live-run`. Do not run the listener on the repository host, and do not
commit provider IDs, public IPs, credentials, or packet captures from live
networks.
