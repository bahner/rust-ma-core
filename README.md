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

- `KuboDidPublisher` (non-WASM only)
  - created once with a `kubo_url`
  - stores that URL for the lifetime of the publisher instance
  - normalizes URL forms (for example trailing `/` or `/api/v0` suffix)
  - does not require one exact hardcoded Kubo URL string
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

- `KuboDidPublisher` (non-WASM)
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
- `KuboDidPublisher` (non-WASM)
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
