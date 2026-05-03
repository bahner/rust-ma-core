//! # ma-core
//!
//! A lean `DIDComm` service library for the ma ecosystem.
//!
//! `ma-core` provides the building blocks for ma-capable endpoints:
//!
//! - **DID documents** — create, validate, resolve, and publish `did:ma:` documents
//!   to IPFS/IPNS (via Kubo on native targets).
//! - **Service inboxes** — bounded, TTL-aware FIFO queues ([`Inbox`])
//!   for receiving validated messages on named protocol services.
//! - **Outbound sending** — fire-and-forget delivery of validated [`Message`] objects
//!   to remote endpoints, serialized to CBOR on the wire.
//! - **Endpoint abstraction** — the [`MaEndpoint`] trait with pluggable
//!   transport backends.
//! - **Transport parsing** — extract endpoint IDs and protocols from DID document
//!   service strings (`/iroh/<id>/<protocol>`).
//! - **Identity bootstrap** — secure secret key generation and persistence.
//!
//! ## Services
//!
//! Every endpoint must provide `/ma/inbox/0.0.1` (the default inbox).
//! Endpoints may optionally provide `ma/ipfs/0.0.1` to publish DID documents
//! on behalf of others.
//!
//! ## Feature flags
//!
//! - **`kubo`** — enables native IPFS RPC backend for publishing (native only).
//! - **`iroh`** — enables the internal iroh QUIC transport backend.
//! - **`gossip`** — enables internal iroh-gossip broadcast support.
//! - **`config`** — enables [`Config`], [`SecretBundle`], and [`MaArgs`] for
//!   YAML-based daemon configuration, encrypted secret bundles, and CLI
//!   argument parsing.
//!
//! ## Platform support
//!
//! Core types (`Inbox`, `Service`, transport parsing, validation)
//! compile on all targets including `wasm32-unknown-unknown`.
//!
//! ### wasm vs native
//!
//! - `ma-core` supports both wasm and native targets.
//! - `IpfsGatewayResolver` (HTTP gateway DID fetch) is available on wasm and native.
//! - Native IPFS RPC write/pin APIs are native-only (`not(wasm32)` + `kubo` feature).
//! - wasm builds expose only `ipfs::gateway_resolver` (no native RPC helpers).
//! - `config` serialization and `SecretBundle` crypto work on wasm.
//! - `config` filesystem paths, CLI/env merging, and file I/O are native-only.
//! - If your wasm application needs native IPFS RPC write/pin operations, provide
//!   them in a native companion layer.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::if_not_else,
    clippy::items_after_statements,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::uninlined_format_args
)]

#[cfg(feature = "acl")]
pub mod acl;
#[cfg(feature = "config")]
pub mod config;
pub mod endpoint;
pub mod error;
pub mod identity;
pub mod inbox;
pub mod interfaces;
pub mod ipfs;
#[cfg(feature = "iroh")]
#[allow(dead_code)]
mod iroh;
#[cfg(feature = "iroh")]
#[allow(dead_code)]
mod outbox;
pub mod service;
pub mod topic;
pub mod transport;
pub(crate) mod ttl_queue;

// ─── Re-export did-ma types so users don't need a separate dependency ───────

pub use did_ma::{
    Did, Document, EncryptionKey, Headers, MaError, Message, Proof, ReplayGuard, SigningKey,
    VerificationMethod, DEFAULT_MAX_CLOCK_SKEW_SECS, DEFAULT_MESSAGE_TTL_SECS,
    DEFAULT_REPLAY_WINDOW_SECS,
};

// ─── Re-export core error type ──────────────────────────────────────────────

pub use error::{Error, Result};

#[cfg(feature = "acl")]
pub use acl::Acl;

// ─── Re-export service constants ────────────────────────────────────────────

pub use service::{
    Service, BROADCAST_PROTOCOL, BROADCAST_TOPIC, CONTENT_TYPE_BROADCAST, CONTENT_TYPE_DOC,
    CONTENT_TYPE_IPFS_REQUEST, CONTENT_TYPE_MESSAGE, INBOX_PROTOCOL, INBOX_PROTOCOL_ID,
    IPFS_PROTOCOL,
};

// ─── Re-export Inbox ────────────────────────────────────────────────────────

pub use inbox::Inbox;

// ─── Re-export Topic ────────────────────────────────────────────────────────

pub use topic::{topic_id, Topic, TopicId};

// ─── Re-export endpoint trait and implementations ───────────────────────────

pub use endpoint::{MaEndpoint, DEFAULT_DELIVERY_PROTOCOL_ID};
#[cfg(feature = "iroh")]
pub use outbox::Outbox;

/// Create a default ma endpoint backend from 32-byte secret key material.
///
/// This keeps the transport backend type internal while exposing
/// [`MaEndpoint`] and [`Outbox`] as stable API surfaces.
#[cfg(feature = "iroh")]
pub async fn new_ma_endpoint(secret_bytes: [u8; 32]) -> Result<Box<dyn MaEndpoint>> {
    let endpoint = iroh::new_endpoint(secret_bytes).await?;
    Ok(Box::new(endpoint))
}

// ─── Re-export transport parsing ────────────────────────────────────────────

pub use transport::{
    endpoint_id_from_transport, endpoint_id_from_transport_value, normalize_endpoint_id,
    protocol_from_transport, resolve_endpoint_for_protocol, resolve_inbox_endpoint_id,
    transport_string,
};

// ─── Re-export identity helpers ─────────────────────────────────────────────

pub use identity::{generate_secret_key_file, load_secret_key_bytes, socket_addr_to_multiaddr};

// ─── Re-export config types ──────────────────────────────────────────────────

#[cfg(all(feature = "config", not(target_arch = "wasm32")))]
pub use config::MaArgs;
#[cfg(feature = "config")]
pub use config::{BrowserIdentityExport, Config, SecretBundle};

// ─── Re-export DID resolution ───────────────────────────────────────────────

pub use ipfs::gateway_resolver::{DidDocumentResolver, IpfsGatewayResolver};

// ─── Re-export existing modules ─────────────────────────────────────────────

pub use interfaces::{DidPublisher, IpfsPublisher};
pub use ipfs::*;
