# Inboxes, outboxes, and the actor model

The central idea in 間 is that actors never touch each other's state directly.
Every interaction happens through messages. `ma-core` enforces this at the API
level: the only way to receive something from the network is to read from an
`Inbox`, and the only way to send something is to write to an `Outbox`. Neither
type exposes anything about iroh, QUIC connections, serialization, or
encryption. You work with messages; `ma-core` handles the rest.

## Inboxes

An `Inbox<T>` is a bounded FIFO queue. When you register a service on your
endpoint, you get back an inbox for that service's protocol:

```rust,ignore
use ma_core::{new_ma_endpoint, service::{INBOX_PROTOCOL_ID, RPC_PROTOCOL_ID}};

let mut endpoint = new_ma_endpoint(bundle.iroh_secret_key).await?;

let inbox     = endpoint.service(INBOX_PROTOCOL_ID);
let rpc_inbox = endpoint.service(RPC_PROTOCOL_ID);
```

From that point on, every message that arrives on that protocol is validated
by the endpoint and pushed into the inbox. Your code never needs to listen for
connections, parse CBOR, or decrypt envelopes — that all happens inside
`ma-core` before anything reaches the inbox.

Reading from an inbox is as simple as it gets:

```rust,ignore
use web_time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// Pop one message, or None if the inbox is empty.
if let Some(msg) = inbox.pop(now_secs()) {
    println!("from {}: {}", msg.from(), String::from_utf8_lossy(msg.content()));
}

// Or drain everything that has arrived since last time.
for msg in inbox.drain(now_secs()) {
    handle(msg);
}
```

The `now` parameter is used to enforce per-message expiry. A message whose
`exp` timestamp has passed is simply not returned — it was either dropped when
it arrived or filtered as you drain the queue. The actor never sees stale
messages, and it never needs to check timestamps itself.

### Expiry and bounded capacity

Every `Message` carries an `exp` field: a nanosecond epoch timestamp after
which the message is considered expired. The default is one hour from
creation. Passing `exp = 0` marks a message as never-expiring.
The endpoint computes the expiry when it pushes the message in; consumers only
see messages that were still live when they called `pop` or `drain`.

Inboxes are bounded. If the queue is full when a new message arrives, the
oldest message is evicted to make room. This means a slow consumer will
eventually lose old messages rather than accumulate unbounded memory. The
default capacity is `DEFAULT_INBOX_CAPACITY` (256 messages). For services that
process messages quickly — which is the expected pattern — the queue rarely
holds more than a handful of entries.

### Cloning inboxes

`Inbox<T>` is cheaply cloneable behind an `Arc<Mutex<_>>`. All clones share
the same underlying queue, so you can hand out copies to different tasks or
threads and they all drain from the same stream of incoming messages without
any extra coordination.

## Outboxes

An `Outbox` is a write handle to a remote actor. You ask the endpoint for one
by DID and protocol; the endpoint resolves the DID document, finds the peer's
iroh endpoint ID in its service strings, dials the connection, and hands you
back an outbox:

```rust,ignore
use ma_core::{IpfsGatewayResolver, service::INBOX_PROTOCOL_ID};
use ma_core::ipfs::gateway_resolver::DidDocumentResolver;

// Use default (localhost:8080 + public gateways), or config.ipfs_gateway_resolver()
// when a Config is available.
let resolver = IpfsGatewayResolver::default();
let mut outbox = endpoint.outbox(&resolver, "did:ma:k51qzi5uqu5d…", INBOX_PROTOCOL_ID).await?;
```

Sending is one call:

```rust,ignore
outbox.send(&message).await?;
```

`send` validates the message headers, serializes to CBOR, and transmits over
the iroh connection. If the message is malformed or already expired, it is
rejected before anything hits the wire. The remote actor will find the message
in their inbox, already decrypted and verified, with no knowledge of how it
arrived.

Outboxes are lightweight. A typical endpoint keeps a handful open at once and
there is no need to close them between sends — `ma-core` manages the
underlying connections. Just keep the outbox in scope for as long as you need
it and let it drop naturally. `close()` exists for situations where you
deliberately want to tear down a connection early (for example under extreme
memory pressure), but it should not appear in normal application code.

### Fire-and-forget

For truly one-off sends where you have no outbox in scope, the endpoint also
provides `send_to`:

```rust,ignore
endpoint.send_to("did:ma:k51qzi5uqu5d…", INBOX_PROTOCOL_ID, &message).await?;
```

This dials, sends, and releases in one call. Prefer `outbox` for any peer you
will message more than once — dialling on every send is wasteful.

## How this enforces the actor model

Traditional concurrent code is hard to reason about because state can be
modified from multiple places at once. The actor model avoids this by giving
each actor exclusive ownership of its own state and routing all interactions
through message passing. No actor ever reaches into another actor's memory.

`ma-core`'s inbox/outbox design makes this the path of least resistance:

- **There is no way to share state between actors.** The only API for cross-actor
  communication is `send` and `pop`. There is no shared data structure, no
  callback registration, no event bus.
- **Message delivery is decoupled from processing.** The endpoint fills the
  inbox asynchronously in the background; the actor drains it on its own
  schedule. An actor that is busy computing does not block incoming messages
  from being buffered.
- **All messages are validated before they reach you.** Signature verification,
  decryption, replay detection, and expiry enforcement all happen inside
  `ma-core` before `pop` returns anything. Your actor loop never needs to
  handle protocol-level errors.
- **Senders do not know about receivers.** An outbox is addressed to a DID and
  a protocol string. The sender has no reference to the receiving actor, no
  handle into its state, and no way to observe when or whether the message is
  processed.

In practice this means you can write an actor as a simple loop:

```rust,ignore
loop {
    let now = now_secs();

    for msg in inbox.drain(now) {
        match msg.content_type() {
            "text/plain" => {
                let reply = build_reply(&msg, &bundle)?;
                outbox.send(&reply).await?;
            }
            "application/vnd.ma.rpc.request" => {
                dispatch_rpc(&msg, &state).await?;
            }
            _ => {}
        }
    }

    gloo_timers::future::sleep(Duration::from_millis(poll_interval_ms)).await;
}
```

The loop owns `state` exclusively. Nothing else can touch it. There are no
locks, no channels, no shared references — just messages in and messages out.
This is as close to the pure actor model as Rust gets without a dedicated
actor framework, and it works identically whether the actor runs in a browser
tab or on a server.
