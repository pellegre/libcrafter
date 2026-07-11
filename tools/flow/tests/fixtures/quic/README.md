# Synthetic QUIC identity fixtures

Every asset in this directory is synthetic, self-signed, and restricted to
offline tests and examples. It is not a production credential or trust anchor.
The identity names only `quic.example`, carries no real account information,
and must never be used for a live endpoint.

DER bytes are stored as hexadecimal text so they remain reviewable source
fixtures. Tests decode them in memory without hidden file-system credential
lookup.
