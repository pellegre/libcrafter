# Oracle Migration State

`tools/oracle/run` is the supported entrypoint for packet behavior validation.
The former standalone reference scripts have been removed; their offline, pcap,
fixture, dry-run, and live validation behavior now lives behind the oracle
runner.

Direct Scapy imports belong only in `tools/oracle/engine/backends/scapy/`.
Other scripts should call `tools/oracle/run` and select `--backend scapy` when
they need Scapy-backed validation.
