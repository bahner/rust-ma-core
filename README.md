# ma-core

`ma-core` is a shared library for the ma ecosystem, focused on:

- publishing DID documents to IPFS/IPNS
- validating signed publish messages
- Kubo integration (non-WASM)
- pin lifecycle management when content changes
- small, stable trait interfaces for pluggable backends

The goal is to keep the core flow simple: validate input strictly, publish safely, and expose a compact API reusable by multiple binaries.

## What the library provides

### `interfaces`

Trait interfaces for dependency inversion:

- `DidPublisher`
- `IpfsPublisher`

This allows runtime layers to implement publishing without coupling domain logic to one specific transport or backend.

### `ipfs_publish`

Core logic for DID publishing:

- `validate_ipfs_publish_request(...)`
  - decodes a signed CBOR message
  - enforces the correct content type (`application/x-ma-doc`)
  - validates and verifies the DID document
  - verifies that the sender matches the document IPNS identity
- `publish_did_document_to_kubo(...)` (non-WASM only)
  - finds/validates a Kubo key
  - imports key material when needed
  - writes the document to DAG
  - publishes IPNS with retry
- `handle_ipfs_publish(...)` (non-WASM only)
  - orchestrates validation + publish
  - returns `IpfsPublishDidResponse`

Key types:

- `IpfsPublishDidRequest`
- `IpfsPublishDidResponse`
- `ValidatedIpfsPublish`

### `kubo` (non-WASM only)

HTTP client logic for the Kubo API (`/api/v0/...`), including:

- readiness: `wait_for_api`
- data: `ipfs_add`, `cat_bytes`, `cat_text`
- DAG: `dag_put`, `dag_get`
- naming/IPNS: `name_publish*`, `name_resolve`
- DID fetch: `fetch_did_document`
- pinning: `pin_add_named`, `pin_rm`
- key management: `generate_key`, `import_key`, `list_keys`

Constants and options:

- `DEFAULT_KUBO_API_URL`
- `IpnsPublishOptions`
- `KuboKey`

### `pinning`

Generic helper for safe pin updates:

- `pin_update_add_rm(...)`

Flow:

1. pin the new CID
2. attempt to unpin the old CID
3. return any unpin failure as metadata in `PinUpdateOutcome`

## Platform support

- WASM:
  - `interfaces`, `ipfs_publish` validation, and `pinning` are available
  - the Kubo module is not compiled in
- Non-WASM:
  - full functionality including Kubo integration

This is controlled via `#[cfg(not(target_arch = "wasm32"))]`.

## Public API (re-exports)

The crate re-exports core symbols from `lib.rs`, including:

- `DidPublisher`, `IpfsPublisher`
- `CONTENT_TYPE_DOC`
- `IpfsPublishDidRequest`, `IpfsPublishDidResponse`, `ValidatedIpfsPublish`
- `validate_ipfs_publish_request`
- `handle_ipfs_publish`, `publish_did_document_to_kubo` (non-WASM)
- `KuboKey` (non-WASM)
- `pin_update_add_rm`, `PinUpdateOutcome`

## Quick usage

Example: validating a signed IPFS publish message:

```rust
use ma_core::validate_ipfs_publish_request;

fn validate(bytes: &[u8]) -> anyhow::Result<()> {
    let validated = validate_ipfs_publish_request(bytes)?;
    println!("validated did: {}", validated.document_did.id());
    Ok(())
}
```

Example: full publish flow against Kubo (non-WASM):

```rust
#[cfg(not(target_arch = "wasm32"))]
async fn publish(message_cbor: &[u8]) -> anyhow::Result<()> {
    let response = ma_core::handle_ipfs_publish("http://127.0.0.1:5001", message_cbor).await?;
    println!("ok={} did={:?} cid={:?}", response.ok, response.did, response.cid);
    Ok(())
}
```

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
