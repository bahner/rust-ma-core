# ma-core

`ma-core` is the shared Rust library for the 間 (ma) ecosystem — a distributed
actor system where each identity is a self-sovereign peer that can live in a
browser tab, a server daemon, or anywhere Rust compiles to.

## What is 間

間 (`ma`) is the protocol and runtime model for addressable actors. A `ma`
actor is an independently owned endpoint with a `did:ma:` identity, a DID
document, one or more protocol services, and an inbox for messages addressed to
those services. Actors do not share memory or reach into each other's state.
They send signed messages, optionally encrypted for the recipient, and the
receiver decides what to do from the message type, content type, and service
protocol it arrived on.

The unit of addressability is the DID. A bare DID such as `did:ma:<id>` names
an identity; a DID URL such as `did:ma:<id>#room` names an actor or entity
inside that identity's published document. Well-known services use `/ma/...`
protocol IDs: `/ma/inbox/0.0.1` for direct delivery, `/ma/rpc/0.0.1` for
request/reply style actor calls, `/ma/ipfs/0.0.1` for publishing support, and
`/ma/crud/0.0.1` for structured resource access. Those strings are the contract
between peers. The transport only carries bytes; `ma` defines what the bytes
mean.

This makes `ma` a small actor system rather than a single application. A
browser tab can be an interactive `ma-agent`; a server process can be a
`ma-runtime`; a wasm plugin can be one actor within that runtime. They all use
the same message envelope, identity model, service IDs, ACL checks, and DID
document fields. The implementation can vary, but the actor contract stays the
same.

The architecture is deliberately close to what Erlang/OTP does with processes,
but without one shared VM. The process boundary is the `ma` message boundary:
state stays local, communication is explicit, and every cross-actor interaction
is a message that can be signed, verified, routed, filtered, replay-checked,
and stored without special knowledge of the receiver's internals.

`ma-core` is the crate that makes that protocol composable. It handles
identity, documents, messages, envelopes, service inboxes, outbound delivery,
transport service strings, DID resolution, and access control in one place so
that `ma-agent` and `ma-runtime` can share a single implementation.

## Getting a feel for it

Create an identity and build a DID document in a few lines:

```rust,ignore
use ma_core::{MaExtension, SecretBundle};

let bundle = SecretBundle::generate();
println!("my DID: did:ma:{}", bundle.ipns_id()?);

let doc = bundle.build_document(MaExtension::new().kind("agent"))?;
let cbor = doc.encode()?; // ready for IPFS dag/put
```

Start an iroh endpoint, register a service, and receive messages:

```rust,ignore
use ma_core::{new_ma_endpoint, service::{INBOX_PROTOCOL_ID, RPC_PROTOCOL_ID}};
use web_time::{SystemTime, UNIX_EPOCH};

let mut endpoint = new_ma_endpoint(bundle.iroh_secret_key, true).await?;

let mut inbox  = endpoint.service(INBOX_PROTOCOL_ID);
let mut rpc_in = endpoint.service(RPC_PROTOCOL_ID);

// The service strings for the DID document are ready as soon as you register.
let services = endpoint.services(); // include in build_document's MaExtension

let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs();

// Drain everything currently queued and not expired.
for msg in inbox.drain(now) {
    println!("from {}: {}", msg.from, String::from_utf8_lossy(&msg.payload()));
}
```

Send an encrypted message to another actor — all you need is their DID:

```rust,ignore
use ma_core::{
    Envelope, IpfsGatewayResolver, Message,
    ipfs::gateway_resolver::DidDocumentResolver,
    service::MESSAGE_TYPE_MESSAGE,
};

// Resolve the recipient's DID document to get their encryption key.
let resolver = IpfsGatewayResolver::new("http://127.0.0.1:5001");
let their_doc = resolver.resolve("did:ma:k51qzi5uqu5d…").await?;

// Sign with your key, encrypt for them.
let msg = Message::new(
    bundle.did()?,
    their_doc.did.clone(),
    MESSAGE_TYPE_MESSAGE,
    "text/plain",
    b"hello from the other side",
    &bundle.signing_key()?,
)?;
let envelope = Envelope::encrypt(&msg, &their_doc)?;

// Send via iroh outbox.
let outbox = endpoint.outbox(&resolver, &their_doc.did, INBOX_PROTOCOL_ID).await?;
outbox.send(&envelope).await?;
```

Check whether a sender is allowed to call a service before processing their
message:

```rust,ignore
use ma_core::{check_cap, CAP_RPC};

// One call, deny-wins semantics, works identically on wasm and native.
check_cap(&acl, &msg.from, CAP_RPC)?;
```

## What the crate covers

`ma-core` covers four concerns and deliberately stays out of everything else:

- **Identity** — `SecretBundle` (four 32-byte keys), `Document`, `Proof`,
  verification methods. `build_document` signs the whole thing in one call.
- **Messaging** — `Message::new` signs and content-hashes. `Envelope` encrypts
  for a recipient with X25519 + XChaCha20-Poly1305. `ReplayGuard` rejects
  replayed envelopes using a sliding timestamp window.
- **Transport** — `new_ma_endpoint` starts an iroh QUIC endpoint. Register
  services by protocol ID string; each returns an `Inbox<Message>`. Outboxes
  dial peers on demand via DID resolution. `IpfsGatewayResolver` resolves DIDs
  on both wasm and native.
- **Access control** — `AclMap` + `check_cap`. Capability strings, deny-wins
  evaluation, wildcard principals, local fragment IDs, and group principals.
  See [doc/acl.md](doc/acl.md).

The crate compiles to both native and `wasm32-unknown-unknown`. The same
identity, messaging, and transport code runs in a browser tab and on a server.
Only Kubo RPC (the IPFS daemon HTTP API) is native-only, because it requires
a network-capable HTTP client that is not available in wasm. Browser actors
reach Kubo indirectly through `ma-runtime` over iroh. See
[doc/ipfs-publish.md](doc/ipfs-publish.md) for that flow.

## iroh as transport layer

[iroh](https://iroh.computer) is a QUIC-based peer-to-peer connectivity
library that gives every endpoint a stable public key identity and handles NAT
traversal transparently. Two peers behind different NATs can dial each other
directly without a relay in most network environments; a relay is used only as
a last resort when direct connection genuinely cannot be established.

From `ma-core`'s perspective, the nicest thing about iroh is that dialling
a peer requires nothing but its endpoint ID — a 32-byte public key. There is
no IP address to manage, no DNS, no port forwarding. An actor publishes its
iroh endpoint ID in its DID document, and any other actor that can resolve
that DID can dial in. `IpfsGatewayResolver` resolves the DID from IPFS and
hands back the endpoint ID; `Outbox` dials the connection. The whole sequence
is two calls:

```rust,ignore
let outbox = endpoint.outbox(&resolver, &their_did, INBOX_PROTOCOL_ID).await?;
outbox.send(&envelope).await?;
```

The current transport surface is direct service messaging: a sender resolves a
DID document, chooses one of the recipient's advertised `/ma/...` service
protocols, and sends a signed message over the corresponding iroh connection.
Fan-out, topic subscription, and higher-level broadcast policy belong above
`ma-core`; the crate still defines the broadcast message type and validation
rules, but transport remains direct service-to-service delivery.

## IPFS, IPNS, and IPLD as the data layer

間 uses the [IPFS](https://ipfs.tech) stack not just for file storage but as
the data model for everything. Understanding the three layers helps make sense
of how `ma-core` fits together.

**[IPFS](https://ipfs.tech)** provides content-addressed block storage. A
block is a sequence of bytes; its address (CID) is a hash of its content.
Content never changes at a
given CID — to update something you write a new block and get a new CID. This
immutability is what makes 間's data verifiable: if you have a CID you can
always confirm the data you received matches it.

**[IPNS](https://docs.ipfs.tech/concepts/ipns/)** provides the mutable layer
on top. An IPNS record maps a public key to a CID; the owner can update the record by signing a new mapping with their
private key. A `did:ma:` identity is literally an IPNS key: `did:ma:<k51…>`
where `k51…` is the IPNS key ID encoded in base36. Resolving the DID fetches
the current IPNS record, follows the CID it points to, and retrieves the DID
document from IPFS.

**[IPLD](https://ipld.io)** (InterPlanetary Linked Data) is the data model
that gives structure to IPFS blocks. A DAG-CBOR node is an IPLD node: a map whose values can
themselves be CIDs, forming a directed acyclic graph of linked data. `ma-core`
encodes all DID documents as DAG-CBOR. Each DID document is an IPLD node, and
the fields that reference other documents or objects are CID links. The whole
identity graph is therefore a traversable IPLD DAG rooted in IPNS.

`ma-runtime` takes this further and uses IPLD to store its entire runtime
state. Entity definitions, service registrations, the configuration manifest —
everything the runtime knows about itself lives as IPLD nodes in IPFS, linked
together into a merkle DAG. When an entity is updated, a new DAG-CBOR block is
written and a new CID minted; that CID propagates up the tree, eventually
producing a new root CID that the runtime publishes to IPNS via its DID
document. The runtime never writes a local database or state file — the IPFS
DAG is the state, and the IPNS pointer is the index. Cold-start recovery means
nothing more than resolving your own DID and following the links.

This is what 間 means by genuinely decentralised services. There is no central
server, no shared database, no cloud storage account. Each actor owns its own
data in its own IPLD tree, addressed by content hash, reachable from its DID.
Actors exchange messages over iroh. State changes are IPFS writes. The whole
system composes without any of the parties needing to trust a common
infrastructure provider — or to coordinate on anything other than the DID
document format and the message wire protocol.

## Feature flags

| Feature   | Default | What it enables |
|-----------|---------|-----------------|
| `iroh`    | yes     | iroh QUIC transport backend, `new_ma_endpoint`, `Outbox` |
| `kubo`    | no      | Native Kubo RPC — publish, pin, DAG put/get, key management (non-wasm only) |
| `acl`     | no      | `AclMap`, `check_cap`, capability constants, group principals |
| `config`  | no      | `Config`, `SecretBundle`, `BrowserIdentityExport`; plus native-only `MaArgs`, `Config::from_args`, filesystem helpers |

## Platform support

| Capability | wasm32 | native |
|------------|--------|--------|
| `Inbox`, `Message`, transport parsing | yes | yes |
| iroh QUIC transport (`iroh` feature) | yes | yes |
| `IpfsGatewayResolver` (DID fetch) | yes | yes |
| `SecretBundle` crypto, `Config` serialization | yes | yes |
| Kubo RPC — publish, pin, DAG write | no | yes (`kubo` feature) |
| `Config::from_args`, filesystem, CLI | no | yes |

See [doc/wasm.md](doc/wasm.md) for the full wasm story, including the
`getrandom/js` requirement and the IndexedDB storage pattern.

## Quick orientation

- **Identity** — `SecretBundle` holds four 32-byte keys (iroh, IPNS, Ed25519
  signing, X25519 encryption). `SecretBundle::build_document` produces a
  complete signed `Document` ready to publish. See [doc/config.md](doc/config.md).
- **Messaging** — `Message::new` signs and content-hashes a payload.
  `Envelope` encrypts it for a recipient. `ReplayGuard` blocks duplicates.
  `Inbox` and `Outbox` hide all transport details behind simple send/receive
  interfaces — see [doc/messaging.md](doc/messaging.md).
- **Transport** — `new_ma_endpoint(secret_bytes, ipv6)` starts an iroh endpoint.
  Register services by protocol ID; each gives you an `Inbox<Message>` to
  drain. Transport service strings are parsed by helpers in `transport.rs`.
- **IPFS publishing** — wasm endpoints cannot reach Kubo directly. They build
  a signed `application/vnd.ma.identity.publish.request` message and send it to a
  `ma-runtime` instance over iroh, which validates and publishes on their
  behalf. See [doc/ipfs-publish.md](doc/ipfs-publish.md).
- **ACL** — `check_cap(&acl, sender_did, cap)` with deny-wins semantics.
  See [doc/acl.md](doc/acl.md).

## Build and test

```bash
cargo build          # default features (iroh)

cargo test

make test            # fmt-check + clippy (pedantic, -D warnings) + tests + doc
```

Wasm profile (used by ma-agent):

```bash
cargo check --target wasm32-unknown-unknown --no-default-features --features "iroh,config"
```

Full features:

```bash
cargo check --all-features
```

## Further reading

- [doc/messaging.md](doc/messaging.md) — `Inbox`, `Outbox`, actor model in practice
- [doc/wasm.md](doc/wasm.md) — wasm targets, feature combinations, storage pattern
- [doc/ipfs-publish.md](doc/ipfs-publish.md) — the full wasm→iroh→Kubo publish flow
- [doc/acl.md](doc/acl.md) — `AclMap` format, deny-wins, group principals
- [doc/config.md](doc/config.md) — `Config`, `SecretBundle`, native CLI helpers
