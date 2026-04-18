//! # ma-core
//!
//! A lean DIDComm service library for the ma ecosystem.
//!
//! `ma-core` provides the building blocks for ma-capable endpoints:
//!
//! - **DID documents** — create, validate, resolve, and publish `did:ma:` documents
//!   to IPFS/IPNS (via Kubo or custom backends).
//! - **Service inboxes** — bounded, TTL-aware FIFO queues ([`Inbox`])
//!   for receiving validated messages on named protocol services.
//! - **Outbox sending** — fire-and-forget delivery of validated [`Message`] objects
//!   to remote endpoints, serialized to CBOR on the wire ([`Outbox`]).
//! - **Endpoint abstraction** — the [`MaEndpoint`] trait with an iroh-backed
//!   implementation ([`IrohEndpoint`], behind the `iroh` feature).
//! - **Transport parsing** — extract endpoint IDs and protocols from DID document
//!   service strings (`/iroh/<id>/<protocol>`).
//! - **Identity bootstrap** — secure secret key generation and persistence.
//!
//! ## Services
//!
//! Every endpoint must provide `ma/inbox/0.0.1` (the default inbox).
//! Endpoints may optionally provide `ma/ipfs/0.0.1` to publish DID documents
//! on behalf of others.
//!
//! ## Feature flags
//!
//! - **`kubo`** (default) — enables Kubo RPC client for IPFS publishing.
//! - **`iroh`** — enables the iroh QUIC transport backend ([`IrohEndpoint`],
//!   [`Channel`], [`Outbox`]).
//! - **`gossip`** — enables iroh-gossip broadcast helpers.
//!
//! ## Platform support
//!
//! Core types (`Inbox`, `Service`, transport parsing, validation)
//! compile on all targets including `wasm32-unknown-unknown`. Kubo, DID
//! publishing via Kubo requires a native target.

#![forbid(unsafe_code)]

pub mod endpoint;
pub mod error;
#[cfg(feature = "gossip")]
pub mod gossip;
pub mod identity;
pub mod inbox;
pub mod interfaces;
pub mod ipfs_publish;
#[cfg(feature = "iroh")]
pub mod iroh;
#[cfg(feature = "iroh")]
pub mod outbox;
pub mod resolve;
pub mod service;
pub mod topic;
pub mod transport;
pub(crate) mod ttl_queue;

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub mod kubo;
pub mod pinning;

// ─── Re-export did-ma types so users don't need a separate dependency ───────

pub use did_ma::{
    Did, Document, EncryptionKey, Headers, MaError, Message, Proof, ReplayGuard, SigningKey,
    VerificationMethod, DEFAULT_MAX_CLOCK_SKEW_SECS, DEFAULT_MESSAGE_TTL_SECS,
    DEFAULT_REPLAY_WINDOW_SECS,
};

// ─── Re-export core error type ──────────────────────────────────────────────

pub use error::{Error, Result};

// ─── Re-export service constants ────────────────────────────────────────────

pub use service::{
    Service, BROADCAST_PROTOCOL, BROADCAST_TOPIC, CONTENT_TYPE_BROADCAST, CONTENT_TYPE_DOC,
    CONTENT_TYPE_IPFS_REQUEST, CONTENT_TYPE_MESSAGE, INBOX_PROTOCOL, IPFS_PROTOCOL,
};

// ─── Re-export Inbox ────────────────────────────────────────────────────────

pub use inbox::Inbox;

// ─── Re-export Topic ────────────────────────────────────────────────────────

pub use topic::{topic_id, Topic, TopicId};

// ─── Re-export endpoint trait and implementations ───────────────────────────

pub use endpoint::{MaEndpoint, DEFAULT_DELIVERY_PROTOCOL_ID};
#[cfg(feature = "iroh")]
pub use iroh::channel::Channel;
#[cfg(feature = "iroh")]
pub use iroh::IrohEndpoint;
#[cfg(feature = "iroh")]
pub use outbox::Outbox;

// ─── Re-export iroh primitives so dependents don't need a direct iroh dep ───

#[cfg(feature = "iroh")]
pub use ::iroh::endpoint::{presets, Connection, RecvStream, SendStream};
#[cfg(feature = "iroh")]
pub use ::iroh::protocol::{AcceptError, ProtocolHandler, Router};
#[cfg(feature = "iroh")]
pub use ::iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl, SecretKey};

// ─── Re-export gossip helpers ────────────────────────────────────────────────

#[cfg(feature = "gossip")]
pub use gossip::{
    broadcast_topic_id, gossip_send, gossip_send_text, join_broadcast_channel, join_gossip_topic,
    topic_id_for,
};

// ─── Re-export transport parsing ────────────────────────────────────────────

pub use transport::{
    endpoint_id_from_transport, endpoint_id_from_transport_value, normalize_endpoint_id,
    protocol_from_transport, resolve_endpoint_for_protocol, resolve_inbox_endpoint_id,
    transport_string,
};

// ─── Re-export identity helpers ─────────────────────────────────────────────

pub use identity::{generate_secret_key_file, load_secret_key_bytes, socket_addr_to_multiaddr};

// ─── Re-export DID resolution ───────────────────────────────────────────────

pub use resolve::DidResolver;
#[cfg(not(target_arch = "wasm32"))]
pub use resolve::GatewayResolver;

// ─── Re-export existing modules ─────────────────────────────────────────────

pub use interfaces::{DidPublisher, IpfsPublisher};
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub use ipfs_publish::KuboDidPublisher;
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub use ipfs_publish::{handle_ipfs_publish, publish_did_document_to_kubo};
pub use ipfs_publish::{
    validate_ipfs_publish_request, IpfsPublishDidRequest, IpfsPublishDidResponse,
    ValidatedIpfsPublish,
};
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub use kubo::KuboKey;
pub use pinning::{pin_update_add_rm, PinUpdateOutcome};
