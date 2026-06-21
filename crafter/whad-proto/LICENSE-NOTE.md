# WHAD Protocol License Note

Source inspected:

- `whad-team/whad-protocol` `release/v3`, commit `82dbbefe5c3a1b3bfa89f86829c8872985a7f27e`.
- `whad-team/whad-client` `v1.2.17`, commit `57f7370e58cc9d0d318f3986ac3808335251cea7`.
- `whad-team/butterfly` `v1.1.5`, commit `9518bffa19ad366cd8e511749d80ca93f5731206`.

The `whad-protocol` repository at the pinned commit does not contain an
explicit `LICENSE`, `COPYING`, or `NOTICE` file, and no SPDX or MIT license
header was found in the protocol sources. The related `whad-client` and
`butterfly` repositories carry MIT license files, but that does not by itself
establish an explicit license for `whad-protocol`.

For that reason, the files in this directory are not a verbatim vendored copy
of upstream `.proto` files. They are scope-reduced regenerated equivalents for
the BLE host backend only, preserving the protocol field numbers and names
needed to generate host-side message types. They intentionally omit unrelated
WHAD domains and command surfaces.

These files are used only to generate optional `whad` feature host-side message
types for libcrafter. If `whad-protocol` later publishes an explicit compatible
license, these regenerated definitions can be replaced by the corresponding
licensed upstream `.proto` files at a pinned tag or commit.
