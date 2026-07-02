# NTP Live Validation

NTP live validation is provider-backed packet validation for the `Ntp` packet
primitive. It is not an NTP client, server, pool probe, clock synchronization
workflow, or internet scan. The safe path is dry-run planning; real traffic is
allowed only through an explicitly selected disposable provider, bounded cases,
artifact collection, and teardown.

Do not send live NTP traffic from the developer machine. Do not commit provider
account data, endpoint IDs, public IPs, live host identifiers, credentials, or
packet captures from real networks.

## Dry-Run Planning

Run the planning commands before any live action. They create no provider
resources and send no packets.

```sh
tools/lab/run plan --provider qemu --dry-run --profile ntp-smoke --seed 5908 --role stimulus --role target --workload-label ntp-live-validation --json
tools/oracle/run live --backend scapy --provider local-dry-run --dry-run --family ntp --profile ntp-live-dry-run --seed 5908 --count 4 --direction live_exchange --out target/oracle/ntp-live-dry-run
tools/probe/run --provider qemu --dry-run --profile ntp-smoke --seed 5908 --count 4 --out target/probe/ntp-dry-run
tools/endpoint/run create --provider qemu --exposure private --private-group ntp-dry-run --dry-run --json
```

Inspect the reports before continuing. The expected dry-run state is no created
infrastructure, no live packet exchange, NTP capture filters such as UDP/123,
planned `stimulus` and `target` roles, provider capability metadata, artifact
paths below ignored `target/` roots, and teardown or cleanup plans.

## Live Gates

Every non-dry-run NTP validation run requires all of these gates:

- Select the provider explicitly with `LIBCRAFTER_NTP_LIVE_PROVIDER`; do not let
  scripts choose a live provider implicitly.
- Set `LIBCRAFTER_NTP_LIVE_CONFIRM=yes` for the protocol-specific confirmation.
- Pass the runner's `--confirm-live-run` flag.
- Provide provider credentials only through the environment when the selected
  provider requires them. The Hetzner provider reads `HETZNER_API_TOKEN` or
  `HCLOUD_TOKEN`; never place token values in tracked files or examples.
- Run provider doctor checks and the dry-run plan first.
- Bound the run with `--count`, `--case`, or an equivalent focused profile.
- Use only disposable provider-backed endpoints or lab sessions.
- Keep artifacts under ignored roots such as `target/oracle/ntp-*`,
  `target/probe/ntp-*`, and endpoint or lab artifact directories.
- Verify artifact collection and teardown records before treating the run as
  complete.

A guarded shell wrapper should fail closed when either NTP gate is missing:

```sh
if [ -n "${LIBCRAFTER_NTP_LIVE_PROVIDER:-}" ] &&
   [ "${LIBCRAFTER_NTP_LIVE_CONFIRM:-}" = "yes" ]; then
  tools/oracle/run live \
    --backend scapy \
    --provider "$LIBCRAFTER_NTP_LIVE_PROVIDER" \
    --family ntp \
    --profile ntp-live-dry-run \
    --seed 5908 \
    --count 4 \
    --direction live_exchange \
    --confirm-live-run \
    --out target/oracle/ntp-live
else
  tools/oracle/run live \
    --backend scapy \
    --provider local-dry-run \
    --dry-run \
    --family ntp \
    --profile ntp-live-dry-run \
    --seed 5908 \
    --count 4 \
    --direction live_exchange \
    --out target/oracle/ntp-live-dry-run
fi
```

Probe live validation uses the same gates and bounded case selection:

```sh
if [ -n "${LIBCRAFTER_NTP_LIVE_PROVIDER:-}" ] &&
   [ "${LIBCRAFTER_NTP_LIVE_CONFIRM:-}" = "yes" ]; then
  tools/probe/run \
    --provider "$LIBCRAFTER_NTP_LIVE_PROVIDER" \
    --profile ntp-smoke \
    --seed 5908 \
    --count 4 \
    --confirm-live-run \
    --out target/probe/ntp-live
else
  tools/probe/run \
    --provider qemu \
    --dry-run \
    --profile ntp-smoke \
    --seed 5908 \
    --count 4 \
    --out target/probe/ntp-dry-run
fi
```

## Captures And Artifacts

NTP live captures must be bounded by the selected oracle/probe case set and
runner capture filters. The artifact set should include the final report,
provider capability report, planned topology, command stdout and stderr, packet
bytes or decoded models, capture summaries or pcaps when produced, and teardown
records.

Keep live artifacts local unless they have been redacted or regenerated from
documentation-safe values. If a live capture is needed for a fixture or docs
example, rebuild the case offline with documentation address space instead of
copying provider traffic into the repository.

## Teardown

Oracle and probe live runners should tear down their lab sessions unless
`--keep-wire-endpoints` is used for an operator-approved debugging session. When
debugging keeps endpoints alive, record the endpoint or lab session IDs only in
ignored local notes, collect artifacts first, and destroy the resources before
declaring validation complete.

For direct endpoint work, collect and destroy explicitly:

```sh
tools/endpoint/run collect-artifacts ENDPOINT_ID
tools/endpoint/run destroy ENDPOINT_ID
```

For direct lab work, inspect and destroy the session explicitly:

```sh
tools/lab/run session-info SESSION_ID --json
tools/lab/run destroy SESSION_ID --json
```
