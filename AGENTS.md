# rust-ma-core — Agent Notes

`ma-core` is the shared Rust library for all 間 endpoints. It compiles to
both native and `wasm32-unknown-unknown`. No binary is produced here.

---

## Agent rules

- **Never modify files in this repo without explicit user approval.**
  `ma-core` is a shared dependency used by multiple downstream crates
  (`ma-runtime`, `ma-agent`, etc.). Unannounced changes here break all
  consumers silently. Always ask before editing any file here.

---

## Crate structure

```text
src/
  lib.rs              — public API re-exports; feature-gated carefully
  acl/mod.rs          — AclMap, Permissions, check_op, normalize_principal
  config/
    mod.rs            — Config (native + wasm), BrowserIdentityExport
    cli.rs            — MaArgs (native only)
    logging.rs        — tracing-subscriber setup (native)
    logging_wasm.rs   — console logging (wasm)
    secrets.rs        — SecretBundle: keygen, encrypt/decrypt, build_document
  constants.rs        — shared string constants
  did.rs              — Did, DID_PREFIX
  doc.rs              — Document, MaExtension, Proof, VerificationMethod
  endpoint.rs         — MaEndpoint trait, DEFAULT_DELIVERY_PROTOCOL_ID
  error.rs            — Error, MaError, Result
  identity.rs         — GeneratedIdentity, generate_identity*, key file helpers
  inbox.rs            — Inbox<T>: bounded TTL-aware FIFO queue
  interfaces.rs       — DidPublisher, IpfsPublisher traits
  ipfs/
    mod.rs            — public re-exports for ipfs sub-modules
    gateway_resolver.rs — IpfsGatewayResolver, DidDocumentResolver trait
    publish.rs        — IdentityPublishRequest, IpfsStoreRequest, IpfsDidPublisher,
                        generate_identity_publish_request, generate_ipfs_store_request,
                        validate_identity_publish_request, validate_ipfs_request
  iroh/               — internal iroh QUIC backend (not public API)
  key.rs              — SigningKey, EncryptionKey
  kubo/               — internal Kubo RPC client (not public API)
  msg.rs              — Message, Envelope, ReplayGuard, Headers
  multiformat.rs      — codec constants (CODEC_*)
  outbox.rs           — Outbox (iroh feature)
  service.rs          — Service trait, protocol ID and message type constants
  transport.rs        — transport string parsing helpers
  ttl_queue.rs        — internal TTL queue backing Inbox
```

---

## Feature flags

| Feature  | Default | Description |
|----------|---------|-------------|
| `iroh`   | yes     | iroh QUIC transport backend |
| `gossip` | yes     | iroh-gossip broadcast (requires `iroh`) |
| `kubo`   | no      | Native Kubo RPC — publish/pin/add (non-wasm only) |
| `acl`    | no      | AclMap, check_op, Permissions, permission bits |
| `config` | no      | Config, SecretBundle, MaArgs, BrowserIdentityExport |

`kubo` and the `kubo` sub-module are **always** guarded by
`#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]`.

`acl` and `config` are both wasm-safe (no native-only code inside the feature).
The `config` CLI/filesystem helpers inside `config/cli.rs` and `config/logging.rs`
are additionally guarded by `#[cfg(not(target_arch = "wasm32"))]`.

---

## Key design rules

- **`#![forbid(unsafe_code)]`** — no unsafe anywhere.
- `pub use acl::…` re-exports in `lib.rs` **must** be wrapped in
  `#[cfg(feature = "acl")]` — the `acl` module itself is feature-gated and
  will not exist otherwise.
- `Message::new` and `Message::new_with_exp` take `content: &[u8]`.
  Call sites must pass a reference or byte literal, not `.to_vec()`.
- Do not re-export internal kubo helpers (`dag_put`, `import_key`, …) through
  the public API. They live in `src/kubo/` which is `pub(crate)`.
- `IpfsDidPublisher` (the public one) lives in `src/ipfs/publish.rs`, not
  `src/kubo/publish.rs`. The kubo version is a private implementation detail.
- Protocol IDs always include the leading `/`: `/ma/inbox/0.0.1`, etc.

---

## Build commands

```sh
make build    # cargo build --all-features
make check    # cargo check --all-features + --no-default-features + default
make test     # fmt-check + clippy (pedantic, -D warnings) + test + doc
make doc      # cargo doc --all-features --no-deps
make fmt      # cargo fmt
make lint     # clippy + mdl
```

`make test` runs clippy with `--all-targets --all-features -- -W clippy::pedantic -D warnings`.

Wasm profile check:

```sh
cargo check --target wasm32-unknown-unknown --no-default-features --features "iroh,config"
```

---

## ACL

Deny-wins semantics. A `null` value (or absent value) for a principal is an
explicit deny that overrides any wildcard allow.

Permission bits: `r`=4 read, `w`=2 write, `x`=1 execute.

`normalize_principal(did)` strips the fragment from DID-URLs before ACL lookup
so `did:ma:foo#bar` and `did:ma:foo` match the same entry.

---

## Message signing and validation

- Messages are created via `Message::new(from, to, type, content_type, &content, &signing_key)`.
- `new` defaults TTL to `DEFAULT_MESSAGE_TTL_SECS`; `new_with_exp` takes an
  explicit nanosecond expiry.
- `Envelope` wraps an encrypted `Message` for a specific recipient.
- `ReplayGuard` uses a sliding window (default `DEFAULT_REPLAY_WINDOW_SECS`) to
  reject duplicate envelope IDs.

---

## Common pitfalls

- `make test` only checks `--all-features`. Run `make check` separately to
  validate compilation without optional features.
- Doctests in `src/msg.rs` use `b"..."` byte literals (not `.to_vec()`).
- The `gossip` feature implicitly enables `iroh`.
- `Config::from_args` requires a `const MA_DEFAULT_SLUG: &str` in the caller's
  crate at compile time.
