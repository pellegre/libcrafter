# Endpoint Rename Inventory

This inventory covers provider lifecycle references that currently use wire
terminology. The intended rename is endpoint terminology for lifecycle tooling,
while keeping wire for packet bytes, wire-format protocol facts, and the future
Rust `crafter::wire` packet I/O module.

## Tool Paths

Intended replacement: move the provider lifecycle package from `tools/endpoint` to
`tools/endpoint`; do not leave a `tools/endpoint` wrapper or second executable.

- `tools/endpoint/README.md` -> `tools/endpoint/README.md`
- `tools/endpoint/run` -> `tools/endpoint/run`
- `tools/endpoint/engine/*` -> `tools/endpoint/engine/*`
- `tools/endpoint/engine/providers/{docker,hetzner,qemu,virtualbox,vm}/*` -> `tools/endpoint/engine/providers/{docker,hetzner,qemu,virtualbox,vm}/*`
- `tools/endpoint/tests/*` -> `tools/endpoint/tests/*`
- `tools/endpoint/tests/providers/*` -> `tools/endpoint/tests/providers/*`
- `tools/endpoint/smoke/*` -> `tools/endpoint/smoke/*`
- `.gitignore` entries `tools/endpoint/.state/` and `tools/endpoint/artifacts/` -> `tools/endpoint/.state/` and `tools/endpoint/artifacts/`
- generated metadata string `created_by: tools/endpoint` -> `created_by: tools/endpoint`
- test metadata string `tools/endpoint-test` -> `tools/endpoint-test`

Current tool files found:

- `tools/endpoint/README.md`
- `tools/endpoint/run`
- `tools/endpoint/engine/__init__.py`
- `tools/endpoint/engine/cli.py`
- `tools/endpoint/engine/config.py`
- `tools/endpoint/engine/model.py`
- `tools/endpoint/engine/process.py`
- `tools/endpoint/engine/registry.py`
- `tools/endpoint/engine/ssh.py`
- `tools/endpoint/engine/state.py`
- `tools/endpoint/engine/providers/__init__.py`
- `tools/endpoint/engine/providers/docker/*`
- `tools/endpoint/engine/providers/hetzner/*`
- `tools/endpoint/engine/providers/qemu/*`
- `tools/endpoint/engine/providers/virtualbox/*`
- `tools/endpoint/engine/providers/vm/*`
- `tools/endpoint/tests/*.py`
- `tools/endpoint/tests/providers/*.py`
- `tools/endpoint/smoke/live_docker_lan_icmp.py`
- `tools/endpoint/smoke/live_docker_private_packet_exchange.py`
- `tools/endpoint/smoke/live_docker_wan_dns.py`
- `tools/endpoint/smoke/live_virtualbox_network_ping.py`

## Python Imports And Public Names

Intended replacement: imports use `tools.endpoint.engine.*`, and lab process
boundary names use endpoint terminology.

- `tools.endpoint.engine.*` -> `tools.endpoint.engine.*`
- `tools.lab.engine.wire_client` -> `tools.lab.engine.endpoint_client`
- `tools/lab/engine/wire_client.py` -> `tools/lab/engine/endpoint_client.py`
- `read_wire_json` / `write_wire_json` aliases -> `read_endpoint_json` / `write_endpoint_json`
- `WireClient` -> `EndpointClient`
- `WireClientError` -> `EndpointClientError`
- `WireCommandRecord` -> `EndpointCommandRecord`
- `WireCommandResponse` -> `EndpointCommandResponse`
- `wire_command` record field -> `endpoint_command`
- `_CreateTrackingWireClient`, `_OracleLabWireClient`, `_FakeWireClient` -> matching endpoint names
- `WireConfig` -> `EndpointConfig`
- `WIRE_ENTRYPOINT` -> `ENDPOINT_ENTRYPOINT`
- provider lifecycle constants such as `WIRE_PROVIDER`, `WIRE_EXPOSURE`, and provider metadata keys `wire_provider`, `wire_exposure` -> `ENDPOINT_PROVIDER`, `ENDPOINT_EXPOSURE`, `endpoint_provider`, `endpoint_exposure`

Import/update sites found:

- `tools/lab/engine/wire_client.py`
- `tools/lab/engine/cli.py`
- `tools/lab/engine/session.py`
- `tools/lab/engine/repo.py`
- `tools/lab/engine/providers/base.py`
- `tools/lab/engine/providers/common.py`
- `tools/lab/engine/providers/docker.py`
- `tools/lab/engine/providers/hetzner.py`
- `tools/lab/engine/providers/qemu.py`
- `tools/lab/engine/providers/virtualbox.py`
- `tools/oracle/engine/cli.py`
- `tools/oracle/engine/providers/base.py`
- `tools/oracle/engine/providers/docker.py`
- `tools/oracle/engine/providers/hetzner.py`
- `tools/oracle/engine/providers/qemu.py`
- `tools/oracle/engine/providers/virtualbox.py`
- `tools/probe/engine/live.py`
- all current `tools/endpoint/tests/**/*.py` imports when moved to `tools/endpoint/tests`
- lab/oracle/probe tests that import `tools.endpoint.engine.*`

Keep-review boundary: names that describe packet bytes or protocol comparison,
such as `metadata["wire"]`, `_live_endpoint_request_wire_metadata`,
`wire_eligible_count`, and byte-level `wire_policy` comparison data, may remain
wire if they are not lifecycle provider fields.

## Command Names

Current command path is `tools/endpoint/run`, and lifecycle subcommands use the
concise endpoint vocabulary.

- `tools/endpoint/run doctor`
- `tools/endpoint/run create`
- `tools/endpoint/run destroy`
- `tools/endpoint/run exec`
- `tools/endpoint/run upload`
- `tools/endpoint/run download`
- `tools/endpoint/run collect-artifacts`
- `tools/endpoint/run ssh-info`
- `tools/endpoint/run list`

Command-definition sites found:

- `tools/endpoint/engine/cli.py`
- `tools/endpoint/README.md`
- `docs/wire.md`
- `.github/workflows/wire.yml`
- `.agents/skills/endpoint-provider/SKILL.md`
- `tools/lab/engine/wire_client.py`
- `tools/lab/engine/session.py`
- `tools/lab/engine/providers/{docker,hetzner,qemu,virtualbox}.py`
- `tools/oracle/engine/cli.py`
- `tools/oracle/engine/providers/{docker,hetzner,qemu,virtualbox}.py`
- `tools/oracle/engine/live_provider_matrix.py`
- `tools/probe/engine/live.py`
- `tools/endpoint/smoke/*.py`
- lab/oracle/probe tests asserting command argv or operation names

## Environment Variables And State Roots

Endpoint lifecycle environment variables now use `ENDPOINT`, state and
artifact roots use endpoint names, and workflow target directories stop using
wire as lifecycle terminology.

- `LIBCRAFTER_ENDPOINT_STATE_ROOT`
- `LIBCRAFTER_ENDPOINT_ARTIFACT_ROOT`
- `LIBCRAFTER_ENDPOINT_STATE_DIR`
- `LIBCRAFTER_ENDPOINT_ARTIFACT_DIR`
- `LIBCRAFTER_ENDPOINT_UBUNTU_CLOUD_IMAGE_URL`
- `LIBCRAFTER_ENDPOINT_VM_DISK_SIZE`
- `LIBCRAFTER_ENDPOINT_REMOTE_DIR`
- disposable endpoint safety marker `LIBCRAFTER_ENDPOINT=1`
- `target/wire-state` -> `target/endpoint-state`
- `target/wire-artifacts` -> `target/endpoint-artifacts`
- `tools/endpoint/.state` -> `tools/endpoint/.state`
- `tools/endpoint/artifacts` -> `tools/endpoint/artifacts`

Environment variable sites found:

- `tools/endpoint/engine/config.py`
- `tools/endpoint/engine/providers/vm/images.py`
- `tools/endpoint/README.md`
- `.github/workflows/wire.yml`
- `tools/endpoint/tests/providers/test_{docker,hetzner_create,hetzner_destroy,qemu,virtualbox}_provider.py`
- `tools/endpoint/tests/test_cli_transfer.py`
- `tools/oracle/engine/providers/{docker,hetzner,qemu,virtualbox}.py`
- `tools/probe/engine/live.py`
- `tools/endpoint/smoke/live_virtualbox_network_ping.py`
- `crafter/examples/common/mod.rs`
- `crafter/examples/README.md`
- `CHANGELOG.md`

## Docs

Intended replacement: the current provider lifecycle guide becomes
`docs/endpoint.md`; a later step can create a new `docs/wire.md` for
`crafter::wire` packet I/O.

- `docs/wire.md` -> `docs/endpoint.md` for current provider lifecycle content
- references to `tools/endpoint` -> `tools/endpoint`
- provider lifecycle wording uses "endpoint provider"
- provider lifecycle resources use "endpoint" terminology
- command examples use `tools/endpoint/run create`, `destroy`, and `list`
- smoke script examples use `tools/endpoint/smoke/...`
- provider state text uses `tools/endpoint/.state` and `tools/endpoint/artifacts`

Doc files with lifecycle references:

- `README.md`
- `CHANGELOG.md`
- `AGENTS.md`
- `.github/SECURITY.md`
- `.github/ISSUE_TEMPLATE/bug_report.yml`
- `docs/wire.md`
- `docs/lab.md`
- `docs/probe.md`
- `docs/validation.md`
- `docs/examples.md`
- `docs/api.md`
- `tools/lab/README.md`
- `tools/oracle/README.md`
- `tools/oracle/LIVE.md`
- `tools/endpoint/README.md`
- `crafter/examples/README.md`

Keep-review boundary: documentation that intentionally discusses packet wire
formats or the new Rust `wire` module should keep wire terminology after the
provider lifecycle content is moved out.

## Skills

Intended replacement: repo-local skills describe endpoint provider lifecycle
without using wire as the lifecycle noun.

- `.agents/skills/endpoint-provider/SKILL.md`
- skill title/description use "endpoint provider"
- skill command examples `tools/endpoint/run ...` -> `tools/endpoint/run ...`
- skill command names use `create`, `destroy`
- teardown guidance uses `tools/endpoint/run destroy`
- `.agents/skills/lab-session/SKILL.md`: use "endpoint provider"
- `.agents/skills/lab-provider/SKILL.md`: use endpoint provider lifecycle terminology
- `.agents/skills/packet-validation/SKILL.md`: update any lab/provider lifecycle wording if found during the edit step
- `AGENTS.md` skill list should refer to the renamed endpoint skill after the skill path is changed

## Lab Integrations

Intended replacement: lab providers keep representing provider-backed endpoint
resources, but metadata and client names use endpoint terminology.

- `tools/lab/engine/wire_client.py` -> `tools/lab/engine/endpoint_client.py`
- imports of `tools.endpoint.engine.model` and provider constants -> `tools.endpoint.engine...`
- `WIRE_ENTRYPOINT = "tools/endpoint/run"` -> `ENDPOINT_ENTRYPOINT = "tools/endpoint/run"`
- `wire_provider` / `wire_exposure` / `wire_policy` lifecycle metadata -> `endpoint_provider` / `endpoint_exposure` / `endpoint_policy`
- `wire_manifest` fields on lab endpoint models -> `endpoint_manifest` unless they describe packet-level wire data
- `wire_endpoint_plan` / `wire_endpoint_lifecycle` metadata -> `endpoint_plan` / `endpoint_lifecycle`
- lab dry-run command records use `create`, `destroy`, and `list`
- repository excludes `tools/endpoint/.state` and `tools/endpoint/artifacts` -> endpoint paths

Lab files found:

- `tools/lab/engine/model.py`
- `tools/lab/engine/cli.py`
- `tools/lab/engine/session.py`
- `tools/lab/engine/repo.py`
- `tools/lab/engine/providers/base.py`
- `tools/lab/engine/providers/common.py`
- `tools/lab/engine/providers/docker.py`
- `tools/lab/engine/providers/hetzner.py`
- `tools/lab/engine/providers/qemu.py`
- `tools/lab/engine/providers/virtualbox.py`
- `tools/lab/tests/test_bootstrap.py`
- `tools/lab/tests/test_cleanup.py`
- `tools/lab/tests/test_cli_create_destroy.py`
- `tools/lab/tests/test_cli_dry_run.py`
- `tools/lab/tests/test_docker_provider.py`
- `tools/lab/tests/test_hetzner_provider.py`
- `tools/lab/tests/test_model.py`
- `tools/lab/tests/test_provider_common.py`
- `tools/lab/tests/test_provider_matrix.py`
- `tools/lab/tests/test_qemu_provider.py`
- `tools/lab/tests/test_repo_push.py`
- `tools/lab/tests/test_session.py`
- `tools/lab/tests/test_virtualbox_provider.py`
- `tools/lab/tests/test_wire_client.py` -> `tools/lab/tests/test_endpoint_client.py`

## Oracle Integrations

Intended replacement: oracle provider lifecycle bridges use endpoint client and
endpoint provider metadata; packet byte-policy names can remain wire.

- `tools.lab.engine.wire_client` imports -> `tools.lab.engine.endpoint_client`
- `WireClient`-typed parameters -> `EndpointClient`
- `WIRE_ENTRYPOINT` -> `ENDPOINT_ENTRYPOINT`
- command argv path `tools/endpoint/run` -> `tools/endpoint/run`
- lifecycle commands use `create` / `destroy` / `list`
- remote directory override uses `LIBCRAFTER_ENDPOINT_REMOTE_DIR`
- lifecycle metadata `wire_provider`, `wire_exposure`, `wire_endpoint_plan`, `wire_endpoint_lifecycle` -> endpoint equivalents
- CLI help text uses "provider endpoints"
- rsync excludes `tools/endpoint/.state` and `tools/endpoint/artifacts` -> endpoint paths

Oracle files found:

- `tools/oracle/engine/live.py`
- `tools/oracle/engine/live_provider_matrix.py`
- `tools/oracle/engine/cli.py`
- `tools/oracle/engine/providers/base.py`
- `tools/oracle/engine/providers/docker.py`
- `tools/oracle/engine/providers/hetzner.py`
- `tools/oracle/engine/providers/qemu.py`
- `tools/oracle/engine/providers/virtualbox.py`
- `tools/oracle/tests/test_lab_bridge.py`
- `tools/oracle/tests/test_live_provider_matrix.py`
- `tools/oracle/tests/test_live_provider_registry.py`
- `tools/oracle/tests/test_live_run_isolation.py`

Keep-review boundary: oracle functions and metadata that refer to wire-format
packet comparison, byte mutability, or packet eligibility should not be renamed
only because they contain the word wire.

## Probe Integrations

Intended replacement: probe live/lab transport helpers use endpoint client and
endpoint lifecycle metadata, while packet wire policy names remain unchanged if
they are byte-level policy.

- `tools.probe.engine.live` import `wire_client as lab_wire_client` -> `endpoint_client as lab_endpoint_client`
- local variable `wire = lab_wire_client.WireClient()` -> `endpoint = lab_endpoint_client.EndpointClient()`
- helper names `run_lab_wire_command`, `upload_wire_probe_request`, `download_wire_probe_artifacts`, `prepare_wire_probe_target`, `cleanup_wire_probe_target`, `run_wire_stimulus_endpoint`, `wire_command_failed` -> endpoint equivalents
- report metadata `wire_endpoint_plan` / `wire_endpoint_lifecycle` -> `endpoint_plan` / `endpoint_lifecycle`
- command records with `"wire_command": true` -> endpoint command marker
- remote directory override uses `LIBCRAFTER_ENDPOINT_REMOTE_DIR`
- `tools/probe/engine/lab.py` lifecycle fields `wire_provider`, `wire_exposure`, `wire_endpoint_plan` -> endpoint equivalents

Probe files found:

- `tools/probe/engine/lab.py`
- `tools/probe/engine/live.py`
- `tools/probe/engine/cli.py`
- `tools/probe/tests/test_bootstrap.py`
- `tools/probe/tests/test_lab_live_report.py`
- `tools/probe/tests/test_rst_guards.py`
- `tools/probe/tests/test_target_services.py`

Keep-review boundary: `wire_policy` in probe adapter request payloads may be a
packet transit/byte-policy concept and should be reviewed before renaming.

## Tests

Intended replacement: provider lifecycle unit tests move with the tool, imports
target `tools.endpoint`, and assertions use endpoint command vocabulary.

- `tools/endpoint/tests` -> `tools/endpoint/tests`
- `python3 -m unittest discover -s tools/endpoint/tests -p 'test_*.py'` -> `python3 -m unittest discover -s tools/endpoint/tests -p 'test_*.py'`
- patch targets `tools.endpoint.engine...` -> `tools.endpoint.engine...`
- test argv `tools/endpoint/run` -> `tools/endpoint/run`
- expected operations use `create`, `destroy`, `list`
- fake command response classes and fields use endpoint names
- lab test `test_wire_client.py` -> `test_endpoint_client.py`

Test groups with lifecycle references:

- `tools/endpoint/tests/**/*.py`
- `tools/lab/tests/*.py`
- `tools/oracle/tests/test_lab_bridge.py`
- `tools/oracle/tests/test_live_provider_matrix.py`
- `tools/oracle/tests/test_live_provider_registry.py`
- `tools/oracle/tests/test_live_run_isolation.py`
- `tools/probe/tests/test_bootstrap.py`
- `tools/probe/tests/test_lab_live_report.py`
- `tools/probe/tests/test_rst_guards.py`
- `tools/probe/tests/test_target_services.py`

## Smoke Scripts

Intended replacement: smoke scripts move under the endpoint tool path and use
endpoint command vocabulary.

- `tools/endpoint/smoke/live_virtualbox_network_ping.py` -> `tools/endpoint/smoke/live_virtualbox_network_ping.py`
- `tools/endpoint/smoke/live_docker_lan_icmp.py` -> `tools/endpoint/smoke/live_docker_lan_icmp.py`
- `tools/endpoint/smoke/live_docker_private_packet_exchange.py` -> `tools/endpoint/smoke/live_docker_private_packet_exchange.py`
- `tools/endpoint/smoke/live_docker_wan_dns.py` -> `tools/endpoint/smoke/live_docker_wan_dns.py`
- internal command path `tools/endpoint/run` -> `tools/endpoint/run`
- internal operations use `create` / `destroy`
- safety marker uses `LIBCRAFTER_ENDPOINT=1`
- artifact defaults `tools/endpoint/artifacts/...` -> `tools/endpoint/artifacts/...`

## CI And Repository Metadata

Intended replacement: CI provider lifecycle jobs and ignored/generated paths use
endpoint terminology. Workflow name can become endpoint-specific while the new
Rust packet I/O module owns wire terminology later.

- `.github/workflows/local-static.yml`: compile `tools/endpoint/engine` and `tools/endpoint/smoke`; run endpoint tests
- `.github/workflows/wire.yml` -> `.github/workflows/endpoint.yml`
- workflow names use endpoint provider wording
- workflow env `LIBCRAFTER_ENDPOINT_ARTIFACT_ROOT`, `LIBCRAFTER_ENDPOINT_STATE_ROOT` -> endpoint env vars
- workflow target dirs `target/wire-artifacts`, `target/wire-state` -> endpoint target dirs
- workflow cleanup commands `tools/endpoint/run list`, `destroy`, `collect-artifacts` -> endpoint path and command names
- `.gitignore` updates described in Tool Paths
