# cotlme

A stupid-simple, extremely powerful CLI (Rust implementation) for working with **Concise Tag Lists
(CoTLs)** and **Concise Reference Integrity Manifests (CoRIMs)** as specified in
[draft-ietf-rats-corim-11](./draft-ietf-rats-corim-11.txt), built on the
[`corim-rs`](https://crates.io/crates/corim-rs) crate.

## What it does

| Capability | Detail |
|---|---|
| Create CoTL tags | `concise-tl-tag` (CBOR tag 508) with atomic tag activation lists and validity windows |
| Inspect / validate | Structural + temporal validation per Sections 6.1, 7.3, 8.2.3.4 of the draft |
| Wrap into CoRIM | Unsigned `#6.501` CoRIM maps, with optional profile identifiers |
| Sign / verify | `COSE_Sign1` (`#6.18`) signed CoRIMs — ES256/ES384/ES512 on P-256/P-384/P-521 |
| Key generation | PEM EC keypairs for COSE signing |
| Interactive mode | A wizard TUI when run without arguments |

## Install / build

```sh
cargo build --release
```

## Quick start

```sh
# 1. Generate a signing keypair
cotl keygen -c p256 --private-out signing-key.pem -P signing-pub.pem

# 2. Create a CoTL activating some tags (valid until 2100)
cotl cotl create -i my-cotl \
    -t 123e4567-e89b-12d3-a456-426614174000 \
    -t component-fw \
    --not-after "2100-01-01T00:00:00Z" \
    -o my.cotl

# 3. Check it
cotl cotl show my.cotl
cotl cotl validate my.cotl

# 4. Wrap it in an unsigned CoRIM
cotl rim wrap --cotl my.cotl -i rim-1 --profile "tag:example.com,2025/p" -o unsigned.corim

# 5. Sign it (COSE_Sign1)
cotl rim sign --input unsigned.corim --key signing-key.pem \
    -K kid1 -n "ACME Corp" --not-after "2100-01-01T00:00:00Z" -o signed.corim

# 6. Verify it
cotl rim verify signed.corim --key signing-pub.pem

# 7. Inspect anything
cotl rim show signed.corim
```

Or just run `cotl` with no arguments for the guided interactive mode.

### Timestamps

Everywhere a time is accepted (`--not-before`, `--not-after`, `--now`), both
Unix seconds (`1735689600`) and RFC 3339 (`2025-01-01T00:00:00Z`) work.

### Identifiers

CoTL ids, tag ids, and CoRIM ids accept either UUIDs or free text; UUIDs are
detected automatically and encoded as CBOR `uuid-type`.

## Library use

The binary is a thin shell over the [`cotlme`](src/lib.rs) library:

* [`cotl`] — build (`CotlSpec`), encode/decode, validate, summarize CoTL tags.
* [`rim`] — wrap unsigned CoRIMs, sign/verify signed CoRIMs.
* [`keys`] — EC keypair generation and correctly padded COSE key construction.

```rust
use cotlme::cotl::{CotlSpec, TagId};
use cotlme::rim;

let spec = CotlSpec {
    id: TagId::parse("my-list"),
    version: None,
    tags: vec![TagId::parse("123e4567-e89b-12d3-a456-426614174000")],
    not_before: None,
    not_after: rim::now_unix() + 86_400,
};
let cotl = spec.build()?;
let corim = rim::wrap_unsigned(&cotl, "corim-id", None)?;
```

> **Note on P-521:** this crate constructs COSE EC2 keys with explicitly
> zero-padded coordinates to work around an upstream `corim-rs` issue where
> unpadded big-endian integers break P-521 (and edge-case P-384) signatures.

## Testing

Exhaustively tested via unit tests (library semantics) and end-to-end CLI
integration tests:

```sh
cargo test          # 69 tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Coverage highlights: CBOR round-trips (tagged and untagged), all three curves'
sign→verify round-trips through the real CLI binary, tamper detection, wrong-key
rejection, expired/not-yet-valid validity windows, duplicate-tag warnings, UUID
round-trips, and graceful failures on garbage input.

Additional hardening:
* **Boundary semantics are pinned by tests**: validity windows are inclusive of
  `not-after` (RFC 5280 convention) and `not-before`; one-second boundaries are
  asserted on both sides.
* **Fuzz-lite tests**: deterministic pseudo-random byte streams are pushed
  through every decoder (`cotl::decode`, `rim::decode_signed`,
  `rim::decode_any`) — 4,000 malformed inputs — asserting Err, never panic.
* **Wrong CBOR tag numbers rejected** (e.g. a CoTL masquerading under tag 505),
  truncated inputs at multiple cut points, JSON human-readable round-trips,
  `urn:uuid:` id forms, unicode key-ids/signer names, empty-string CoRIM ids.
* **CLI failure paths**: missing files, non-CBOR garbage, already-signed input,
  missing keys, bad curves — all exit non-zero with a clean `error:` message.

A Go implementation of the same tool exists at [`../cotl-cli`](../cotl-cli); the two are
byte-compatible and continuously cross-verified by interop tests.

## Layout

```
src/
├── lib.rs         # library root
├── cotl.rs        # CoTL create/encode/decode/validate (+ unit tests)
├── rim.rs         # CoRIM wrap/sign/verify (+ unit tests)
├── keys.rs        # EC keygen & padded COSE keys (+ unit tests)
├── error.rs       # thiserror-based error type
├── main.rs        # clap CLI
└── interactive.rs # no-args wizard mode
tests/cli.rs       # end-to-end integration tests
```

## License

MIT
