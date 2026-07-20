# Publishing a DID document from the browser

A 間 identity is anchored in IPFS. The DID — `did:ma:<ipns-id>` — resolves
through IPNS to a DAG-CBOR document that describes who the identity is, what
keys it uses for signing and encryption, and how to reach its iroh transport
endpoint. For an identity to be discoverable, that document must be published
to IPFS/IPNS.

This creates a problem for browser-based endpoints. Browsers cannot make
direct HTTP calls to a Kubo daemon on `localhost:5001` — the same-origin
policy blocks it. The solution in the 間 stack is to delegate publishing to a
`ma-runtime` instance running natively on the user's machine. The browser
builds a publish request, signs it with its own key, and sends it to the
runtime over iroh QUIC. The runtime validates the request, calls Kubo on the
browser's behalf, and the DID document lands on IPFS.

This delegation model has a useful security property: the runtime never
holds the user's IPNS key at rest. The key travels inside the encrypted
publish request, is decrypted and used once, and is immediately overwritten
in memory. The runtime cannot impersonate the user's identity.

## How it fits together

```text
ma-agent (wasm, browser tab)
    │
    │  1. builds a signed publish request (CBOR, encrypted envelope)
    │  2. sends it over iroh QUIC on /ma/ipfs/0.0.1
    ▼
ma-runtime (native daemon, user's machine)
    │
    │  3. validates the request: signature, DID match, replay guard, ACL
    │  4. DAG-puts the document bytes to Kubo → gets a CID
    │  5. calls name/publish with the sender's IPNS key → CID goes live
    │  6. zeroizes the IPNS key bytes
    ▼
Kubo (IPFS daemon, localhost:5001)
    │
    │  IPNS record propagates to the public network
    ▼
did:ma:<ipns-id>  now resolvable by anyone
```

## Prerequisites

Before any of this can work, three things need to be running on the user's
machine:

1. **IPFS Desktop (or Kubo directly).** This provides the Kubo daemon that
   `ma-runtime` speaks to. Without Kubo, there is nowhere to publish to.
2. **`ma-runtime`** itself. It is the bridge. Run it with `ma` and leave it
   running in the background. On first run, generate its config with
   `ma --gen-headless-config`.
3. **An active iroh connection** between the browser endpoint and the runtime.
   In `ma-agent`, the user establishes this by running `.my.間:discover` in
   the terminal, which reads `localhost:5003/status.json`, retrieves the
   runtime's `did` and `endpoint_id`, and connects.

Once connected, the browser can publish at any time. It does so automatically
whenever the user logs in, and again whenever the identity changes (language
preference, new service endpoints, etc.).

## Building the publish request (browser / wasm side)

The browser side of the publish flow lives in `ma-core::ipfs::publish`.
The key function is `generate_identity_publish_request`, which takes the user's
`SecretBundle` and the runtime's DID, and produces a signed `Message` ready
to send:

```rust,ignore
use ma_core::{generate_identity_publish_request, config::SecretBundle};
use ma_core::doc::MaExtension;

async fn publish_identity(
    bundle: &SecretBundle,
    runtime_did: &str,
) -> anyhow::Result<()> {
    // The MaExtension carries the type and language that go into the
    // DID document. build_document signs the document with did_signing_key.
    let ext = MaExtension::new().kind("agent").lang("nb");
    let document = bundle.build_document(ext)?;

    // generate_identity_publish_request builds a Message whose content contains:
    //   - the DAG-CBOR encoded document
    //   - the 32-byte IPNS secret key (the runtime will zeroize this)
    // The message is signed with the sender's did_signing_key and encrypted
    // for the runtime's did_encryption_key.
    let request = generate_identity_publish_request(bundle, runtime_did)?;

    // Send the signed CBOR bytes to the runtime over iroh on /ma/ipfs/0.0.1.
    send_on_ipfs_protocol(runtime_did, request.to_cbor()?).await?;

    Ok(())
}
```

A couple of things worth noting here. First, the IPNS secret key (`bundle.ipns_secret_key`)
is embedded in the request payload. This is intentional — the runtime needs
it to call `name/publish` on Kubo on your behalf. The key is protected in
transit by the iroh encryption layer, and the runtime zeroizes it the moment
Kubo returns. Second, the outer `Message` is signed with `did_signing_key`,
not the IPNS key. The runtime uses the signature to verify that the request
 genuinely came from the identity it claims to represent.

## Handling the request (runtime / native side)

On the runtime side, incoming messages on `/ma/ipfs/0.0.1` are passed to
`validate_identity_publish_request` before anything else happens. Validation is not
optional and cannot be skipped — `IpfsDidPublisher::publish_signed_message`
calls it internally:

```rust,ignore
use ma_core::IpfsDidPublisher;

// Create the publisher once at startup and reuse it.
// wait_until_ready polls Kubo's /api/v0/id until it responds,
// retrying up to the given number of times before giving up.
let publisher = IpfsDidPublisher::new(&config.kubo_rpc_url)?;
publisher.wait_until_ready(10).await?;

// In the incoming message handler:
match publisher.publish_signed_message(&raw_cbor_bytes).await {
    Ok(response) => {
        tracing::info!(
            did = %response.did.unwrap_or_default(),
            cid = %response.cid.unwrap_or_default(),
            "published DID document"
        );
    }
    Err(e) => {
        // Validation failures (bad signature, DID mismatch, replay, ACL deny)
        // all surface as errors here. Log and drop the message; do not crash.
        tracing::warn!(error = %e, "rejected publish request");
    }
}
```

What does validation actually check? It verifies the following in order:

- The bytes decode as valid CBOR and fit the expected message structure.
- The message content type is exactly `application/vnd.ma.identity.publish.request`.
- The outer message signature is valid, confirming the sender holds the
  private key corresponding to their DID document's signing verification
  method.
- The DID document embedded in the payload is internally consistent and
  its own proof signature verifies.
- The IPNS identity derived from the IPNS key in the payload matches the
  `id` field of the DID document — the sender cannot publish under
  someone else's DID.
- The message ID has not been seen before within the last 120 seconds
  (replay protection).
- The sender's DID has the `identity-publish` capability in the ACL. This is
  a separate capability from generic `ipfs` content storage (see below),
  since publishing identity documents transmits an IPNS secret key and may
  warrant tighter access control.

Only after all of these pass does the runtime call Kubo.

## What happens in Kubo

Once validation passes, `IpfsDidPublisher` does the following:

1. Calls `/api/v0/dag/put` with the document's DAG-CBOR bytes. Kubo stores
   the document and returns a CID.
2. Imports the IPNS key into Kubo's keystore under a deterministic alias
  derived from the document's `ma.type` plus a short blake3 hash of the IPNS
  identity. For example, an agent document uses `ma-agent-<hash>`, while a
  document without a usable `ma.type` falls back to `ma-unknown-<hash>`.
  Using a deterministic alias means that repeated publishes from the same
  identity always update the same keystore entry rather than accumulating new
  ones. Native runtimes may add local context such as a slug for their own
  Kubo keys; delegated agent publishes intentionally do not.
3. Calls `/api/v0/name/publish` to associate the CID with the IPNS identity.
   The IPNS record is what makes `did:ma:<ipns-id>` resolvable.
4. Calls `zeroize` on the raw key bytes in memory once the publish call
   returns.
5. Returns `IpfsPublishDidResponse` with the `did` and `cid` fields
   populated.

After step 3, the published DID is resolvable through any IPFS gateway.
`IpfsGatewayResolver` (which compiles on wasm) can fetch and verify it:

```rust,ignore
use ma_core::{IpfsGatewayResolver, ipfs::gateway_resolver::DidDocumentResolver};

let resolver = IpfsGatewayResolver::new("https://ipfs.io")?;
let document = resolver.resolve("did:ma:k51qzi5uqu5dgutdk9yovnzvqf7h0z3lfb2tl41ixitfmw4x8p2s0l3vul4ybz").await?;
println!("found: {}", document.id);
```

## Storing content on IPFS (a separate message type)

Publishing a DID document is not the only thing you can send to the runtime
on `/ma/ipfs/0.0.1`. The `generate_ipfs_store_request` function builds an
`application/vnd.ma.ipfs.request` request to store arbitrary content — a
document, a configuration blob, an entity definition — on IPFS without
touching IPNS. This is a distinct message type from identity-publish and is
gated by the plain `ipfs` capability (fire-and-forget content storage,
deliberately less sensitive than publishing an identity). The runtime stores
the bytes via `dag/put` and replies with the resulting CID. The browser can
then reference content by CID in its DID document or share it with other
identities.

```rust,ignore
use ma_core::generate_ipfs_store_request;

let content = b"# My document\n\nSome markdown content.";
let request = generate_ipfs_store_request(
    bundle,
    runtime_did,
    content,
    "text/markdown",
)?;
// Send and wait for the CID reply.
```

## A note on key lifetime

The IPNS key is the most sensitive piece of data in the entire publish flow.
Whoever holds it can publish arbitrary documents under that DID, effectively
replacing the identity. The design ensures it is in memory on the runtime for
the absolute minimum time: it arrives encrypted, is decrypted, used for one
Kubo call, and zeroized before the function returns. The runtime has no
reason to log it, cache it, or persist it, and the code is written to prevent
this by design.

If the Kubo call fails, the key is still zeroized before the error is
returned. A retry means the browser must send a new request — the runtime
never holds onto a key waiting for a retry opportunity.
