# ma-core

A lean DIDComm service library for the ma ecosystem.

`ma-core` provides everything an ma endpoint needs: DID document publishing,
service inboxes, outbox delivery, and transport abstraction — without coupling
to any specific runtime or application.

## What it provides

### Messaging primitives

- **`TtlQueue`** — bounded FIFO queue with per-item TTL and lazy eviction.
  Wasm-compatible (caller supplies `now`).
- **`Inbox`** — a `TtlQueue` wrapper with a configurable default TTL for
  service receive queues.
- **`Outbox`** — transport-agnostic write handle for fire-and-forget delivery
  to a remote service.

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
  enforces `application/x-ma-doc` content type, validates the document,
  verifies sender matches IPNS identity.
- **`KuboDidPublisher`** (non-WASM, `kubo` feature) — publishes validated
  documents to IPFS via Kubo RPC.
- **`publish_did_document_to_kubo`** / **`handle_ipfs_publish`** — lower-level
  publish helpers.

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

| Feature | Default | Description |
|---------|---------|-------------|
| `kubo`  | yes     | Kubo RPC client for IPFS publishing |
| `iroh`  | no      | Iroh QUIC transport (`IrohEndpoint`, `Channel`, `Outbox`) |

## Platform support

Core types (`Inbox`, `TtlQueue`, `Service`, transport parsing, validation)
compile on all targets including `wasm32-unknown-unknown`. Kubo, DID
resolution, and iroh require a native target.

## Quick usage

```rust
use ma_core::{Inbox, INBOX_PROTOCOL};

// Create an inbox with capacity 256 and 5-minute default TTL
let mut inbox: Inbox<Vec<u8>> = Inbox::new(256, 300);

let now = 1_000_000;
inbox.push(now, b"hello".to_vec());

if let Some(msg) = inbox.pop(now) {
    println!("got {} bytes", msg.len());
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
- You have a signed CBOR `Message` payload where:
  - `content_type` is `application/x-ma-doc`
  - `from` is a DID whose IPNS id matches the DID document id
  - `content` is JSON encoded `IpfsPublishDidRequest`
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
2. Publisher uses its persisted, normalized URL to write DAG and publish IPNS.
3. Returns `IpfsPublishDidResponse` with `did`, `key_name`, and `cid`.

### 3. Verify published target

After publish, resolve the IPNS name and compare to expected CID path:

```rust
#[cfg(not(target_arch = "wasm32"))]
pub async fn verify_publish(
  publisher: &ma_core::KuboDidPublisher,
  key_name: &str,
  expected_cid: &str,
) -> anyhow::Result<()> {
  let resolved = ma_core::kubo::name_resolve(publisher.kubo_url(), &format!("/ipns/{key_name}"), true).await?;
  let expected = format!("/ipfs/{expected_cid}");
  anyhow::ensure!(resolved == expected, "resolved target mismatch: {resolved} != {expected}");
  Ok(())
}
```

### 4. Production readiness pattern

Recommended startup/publish order:

1. create `KuboDidPublisher::new(kubo_url)` once
2. call `publisher.wait_until_ready(attempts)`
3. decode transport bytes
4. call `publisher.publish_signed_message(...)`
5. emit structured log with `did`, `key_name`, `cid`
6. optionally run a post-publish `name_resolve` check

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

Run clippy when needed:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

## Design principles

- Strict input validation; never mutate malformed data.
- Small and clear building blocks, without unnecessary complexity.
- Shared types and contracts in the library; avoid duplication in consumers.
- Fail hard when identity, signature, or key mapping does not match.
