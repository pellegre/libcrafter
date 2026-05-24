---
name: oracle
description: Add oracle coverage for libcrafter packet behavior changes.
---

# Oracle Coverage

Use this skill when a change affects packet behavior, including:

- new protocol layer
- new option kind
- new ICMP or ICMPv6 message type
- new flag or field semantics
- checksum behavior
- extension header
- encapsulation path
- malformed decode behavior
- pcap link type behavior
- live exchange pattern

## Required Workflow

1. Update the relevant `tools/oracle` specs first so the expected behavior is
   data-driven before backend code changes.
2. Keep Scapy reference logic inside `tools/oracle/engine/backends/scapy`.
   Do not add ad hoc Scapy snippets elsewhere.
3. Update backend materialization and normalization as needed so emitted bytes
   and decoded summaries cover the new case or feature. Backend capability
   changes belong in the oracle backend registry and adapter code.
4. Run offline validation for the new case or feature, for example:
   `tools/oracle/run offline --backend scapy --profile <profile> --seed <seed> --count <count>`.
5. Run pcap validation when framing, capture/file IO, link type, or persisted
   packet representation is affected.
6. Treat Wireshark/tshark as parser-only. It may be used for decode and pcap
   read checks, but not for packet generation, pcap writing, or live endpoints.
7. Use live validation only through `tools/oracle/run live` and oracle
   providers. Start with local dry-run providers and preserve artifacts from any
   provider-backed run. Real Hetzner execution requires protected manual
   workflow dispatch.
8. Record any unsupported behavior, intentional mismatch, or required follow-up
   in the oracle artifacts or nearby docs.

Agents add packet behavior coverage through specs and backend adapters, not by
creating standalone Scapy code paths outside the Scapy backend.
