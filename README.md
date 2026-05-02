# ma-core

A lean DIDComm service library for the ma ecosystem.

`ma-core` provides everything an ma endpoint needs: DID document publishing,
service inboxes, outbox delivery, and transport abstraction — without coupling
to any specific runtime or application.

## What it provides

### Messaging primitives

- **`Inbox`** — bounded, TTL-aware FIFO receive queue for service endpoints.
  Per-message TTL is computed from each message's `created_at + ttl`. Only
  endpoint implementations push to an inbox; consumers read via
  `pop`/`peek`/`drain`.
- **`Outbox`** — transport-agnostic write handle for fire-and-forget delivery.
  Takes a `Message`, validates, serializes to CBOR, and transmits.

### Service model

- **`Service` trait** — declares a protocol identifier and label.
- **`MaEndpoint` trait** — shared interface for all transport endpoints:
  register services, get inboxes, send messages.
- **`IrohEndpoint`** (behind `iroh` feature) — iroh QUIC-backed implementation
  of `MaEndpoint`.

Every endpoint must provide `ma/inbox/0.0.1`. Endpoints may optionally
provide `ma/ipfs/0.0.1` to publish DID documents on behalf of others.

### DID document publishing

- **`validate_ipfs_publish_request`** — decodes a signed CBOR message,
  enforces `application/x-ma-ipfs-request` content type, validates the document,
  verifies sender matches IPNS identity.
- **`KuboDidPublisher`** (non-WASM, `kubo` feature) — publishes validated
  documents to IPFS via Kubo RPC.
- **`publish_did_document_to_kubo`** / **`handle_ipfs_publish`** — lower-level
  publish helpers.

### Iroh startup metadata (`ma.iroh`)

When using iroh transport, update DID metadata from the live endpoint before
publishing at startup:

```rust
let mut endpoint = IrohEndpoint::new(secret_bytes).await?;

// Optional service registrations here.
let _inbox = endpoint.service("/ma/inbox/0.0.1");

if endpoint.reconcile_document_ma_iroh(&mut document)? {
    // Re-sign and publish only when metadata changed.
}
```

### DID resolution

- **`DidResolver` trait** — async DID-to-Document resolution.
- **`GatewayResolver`** — resolves via an IPFS/IPNS HTTP gateway.

### Transport parsing

Parses DID document service strings like `/iroh/<endpoint-id>/ma/inbox/0.0.1`:

- `endpoint_id_from_transport` / `protocol_from_transport`
- `resolve_endpoint_for_protocol` / `resolve_inbox_endpoint_id`
- `transport_string` — build service strings from parts.

### Identity bootstrap

- `generate_secret_key_file` / `load_secret_key_bytes` — secure 32-byte
  key persistence with OS-level permission hardening.

### Pinning

- `pin_update_add_rm` — pin new CID, unpin old, report unpin failures as
  metadata (not hard errors).

### Kubo RPC (non-WASM, `kubo` feature)

HTTP client for Kubo `/api/v0/` endpoints: add, cat, DAG put/get,
IPNS publish/resolve, key management, pinning.

## Feature flags

| Feature  | Default | Description |
|----------|---------|-------------|
| `kubo`   | no      | Kubo RPC client for IPFS publishing |
| `iroh`   | yes     | Iroh QUIC transport (`IrohEndpoint`, `Channel`, `Outbox`) |
| `gossip` | yes     | Iroh gossip helpers (`join_gossip_topic`, `gossip_send`, broadcast helpers) |
| `config` | no      | Daemon config: YAML, encrypted secret bundle, CLI args, logging init (native only) |

### `config` feature

The `config` feature is not available on `wasm32` targets.

It provides:

- **`Config`** — runtime configuration struct built from CLI args, environment
  variables (`MA_<SLUG>_*` then `MA_*`), a YAML file, and built-in defaults.
- **`MaArgs`** — a `#[derive(Args)]` struct you flatten into your own `Parser`.
- **`SecretBundle`** — four standard 32-byte keys (`iroh`, `ipns`,
  `did_signing`, `did_encryption`) plus any number of named extra keys,
  encrypted with Argon2id + ChaCha20-Poly1305 and stored on disk.
- **`Config::init_logging()`** — sets up `tracing-subscriber` with separate
  log levels for file and stdout.

Minimal usage:

```rust,ignore
use clap::Parser;
use ma_core::config::{Config, MaArgs};

const MA_DEFAULT_SLUG: &str = "myd";

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    ma: MaArgs,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::from_args(&cli.ma, MA_DEFAULT_SLUG)?;
    config.init_logging()?;
    Ok(())
}
```

Config file (`$XDG_CONFIG_HOME/ma/<slug>.yaml`) example:

```yaml
log_level: debug
kubo_rpc_url: http://127.0.0.1:5001
```

## Platform support

Core types (`Inbox`, `Service`, transport parsing, validation)
compile on all targets including `wasm32-unknown-unknown`.

- `kubo` APIs are native-only.
- `GatewayResolver` is native-only.
- `iroh` transport compiles on wasm and native.
- `gossip` is optional and can be enabled when needed.

## Quick usage

Consumers receive validated `Message` objects from an `Inbox` — the endpoint
handles deserialization and validation before messages enter the queue:

```rust,ignore
// Endpoint gives you an Inbox<Message> when you register a service
let mut inbox = endpoint.service("ma/inbox/0.0.1");

let now = current_time_secs();
while let Some(msg) = inbox.pop(now) {
    println!("from={} type={}", msg.from, msg.message_type);
}
```

Example: full publish flow against Kubo (non-WASM):

```rust
#[cfg(not(target_arch = "wasm32"))]
async fn publish(message_cbor: &[u8]) -> anyhow::Result<()> {
  let publisher = ma_core::KuboDidPublisher::new("http://127.0.0.1:5001/api/v0")?;
  let response = publisher.publish_signed_message(message_cbor).await?;
    println!("ok={} did={:?} cid={:?}", response.ok, response.did, response.cid);
    Ok(())
}
```

## End-to-end operational flow

This section shows a concrete non-WASM flow for publishing a DID document through Kubo.

### 1. Preconditions

- Kubo API is reachable at whichever base URL your environment uses.
- Create a publisher once with that URL and reuse the same instance.
- You have a signed CBOR `Message` payload where
  `content_type` is `application/x-ma-ipfs-request`,
  `from` is a DID whose IPNS id matches the DID document id,
  and `content` is JSON encoded `IpfsPublishDidRequest`.
- The DID document is valid and signature-verifiable.

### 2. Validate and publish

Use `KuboDidPublisher` when you want a persisted endpoint configuration:

```rust
#[cfg(not(target_arch = "wasm32"))]
pub async fn publish_from_wire(
  kubo_url: &str,
  message_cbor: &[u8],
) -> anyhow::Result<ma_core::IpfsPublishDidResponse> {
  let publisher = ma_core::KuboDidPublisher::new(kubo_url)?;
  publisher.publish_signed_message(message_cbor).await
}
```

What it does internally:

1. `validate_ipfs_publish_request` verifies message and document integrity.
1. Publisher imports the IPNS key under an ephemeral name, publishes, and
   removes the key immediately after.
1. Returns `IpfsPublishDidResponse` with `did` and `cid`.

### 3. Verify published target

After publish, resolve the IPNS name and compare to expected CID path:

```rust
#[cfg(not(target_arch = "wasm32"))]
pub async fn verify_publish(
  publisher: &ma_core::KuboDidPublisher,
  ipns_id: &str,
  expected_cid: &str,
) -> anyhow::Result<()> {
  let resolved = ma_core::kubo::name_resolve(publisher.kubo_url(), &format!("/ipns/{ipns_id}"), true).await?;
  let expected = format!("/ipfs/{expected_cid}");
  anyhow::ensure!(resolved == expected, "resolved target mismatch: {resolved} != {expected}");
  Ok(())
}
```

### 4. Production readiness pattern

Recommended startup/publish order:

1. create `KuboDidPublisher::new(kubo_url)` once
1. call `publisher.wait_until_ready(attempts)`
1. decode transport bytes
1. call `publisher.publish_signed_message(...)`
1. emit structured log with `did`, `cid`
1. optionally run a post-publish `name_resolve` check

Minimal orchestration example:

```rust
#[cfg(not(target_arch = "wasm32"))]
pub async fn publish_with_readiness(
  kubo_url: &str,
  message_cbor: &[u8],
) -> anyhow::Result<ma_core::IpfsPublishDidResponse> {
  let publisher = ma_core::KuboDidPublisher::new(kubo_url)?;
  publisher.wait_until_ready(5).await?;
  let response = publisher.publish_signed_message(message_cbor).await?;
  Ok(response)
}
```

### 5. Failure semantics you should rely on

- Invalid CBOR, content type, DID document, or signatures fail fast.
- Sender/document IPNS mismatch fails fast.
- Missing/import-mismatched key material fails fast.
- IPNS publish uses retry and may still be accepted if resolve confirms target.
- Unpin failures in pin rotation are returned as metadata (`PinUpdateOutcome`) and do not hide successful new pin operations.

## Build and test

```bash
cargo build
cargo test
```

Wasm, slim iroh-only profile:

```bash
cargo check --target wasm32-unknown-unknown --no-default-features --features iroh
```

Wasm, iroh + gossip profile (when you need broadcast):

```bash
cargo check --target wasm32-unknown-unknown --no-default-features --features "iroh gossip"
```

Run clippy when needed:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

## Design principles

- Strict input validation; never mutate malformed data.
- Small and clear building blocks, without unnecessary complexity.
- Shared types and contracts in the library; avoid duplication in consumers.
- Fail hard when identity, signature, or key mapping does not match.
