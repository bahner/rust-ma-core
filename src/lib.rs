//! # ma-core
//!
//! A lean `DIDComm` service library for the ma ecosystem.
//!
//! `ma-core` provides the building blocks for ma-capable endpoints:
//!
//! - **DID documents** — create, validate, resolve, and publish `did:ma:` documents
//!   to IPFS/IPNS (via Kubo on native targets). Use [`MaExtension`] to build the
//!   `ma:` extension field, and [`config::SecretBundle::build_document`] (`config`
//!   feature) as the single entry point for a complete, signed document.
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
//! Every endpoint should provide `/ma/inbox/0.0.1` (the default inbox) when it
//! wants to receive direct messages. Endpoints may optionally provide
//! `/ma/ipfs/0.0.1` to publish DID documents
//! on behalf of others.
//!
//! ## Feature flags
//!
//! - **`kubo`** — enables native IPFS RPC backend for publishing (native only).
//! - **`iroh`** — enables the internal iroh QUIC transport backend.
//! - **`acl`** — enables [`AclMap`], [`check_cap`], capability constants, and
//!   ACL validation helpers.
//! - **`config`** — enables [`Config`], [`SecretBundle`], and [`MaArgs`] for
//!   YAML-based daemon configuration, encrypted secret bundles, and CLI
//!   argument parsing. Also provides [`config::SecretBundle::build_document`] and
//!   [`config::SecretBundle::signing_key`] for constructing ready-to-publish DID documents.
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
pub mod constants;
pub mod did;
pub mod doc;
pub mod endpoint;
pub mod error;
pub mod identity;
pub mod inbox;
pub mod interfaces;
pub mod ipfs;
#[cfg(feature = "iroh")]
// inbound-only items (accept, open, endpoint_id, read-timeout) are unused on wasm;
// wasm endpoints send but do not accept raw inbound connections.
#[allow(dead_code)]
mod iroh;
pub mod key;
#[cfg(all(feature = "kubo", not(target_arch = "wasm32")))]
mod kubo;
#[cfg(all(feature = "kubo", not(target_arch = "wasm32")))]
pub use kubo::{
    cat_bytes, delete_local_pins_named_in_background, delete_remote_pins_named_in_background,
    in_flight_pin_name, ipfs_add, remote_pin_add_named, remote_pin_replace_named,
};
pub mod msg;
mod multiformat;
#[cfg(feature = "iroh")]
// OutboxWire and related helpers are only consumed by the native iroh inbound path.
#[allow(dead_code)]
mod outbox;
pub mod service;
pub mod transport;
pub(crate) mod ttl_queue;

// ─── Re-export DID/message primitives ───────────────────────────────────────

pub use did::{Did, DID_PREFIX};
pub use doc::{
    now_iso_utc, Document, MaExtension, Proof, VerificationMethod, DEFAULT_DID_CONTEXT,
    DEFAULT_PROOF_PURPOSE, DEFAULT_PROOF_TYPE,
};
pub use error::{Error, MaError, Result};
pub use identity::{
    generate_identity, generate_identity_from_secret, ipns_from_secret, GeneratedIdentity,
};
pub use ipld_core::ipld::Ipld;
pub use key::{
    EncryptionKey, SigningKey, ASSERTION_METHOD_KEY_TYPE, CODEC_ED25519_PUB, CODEC_EDDSA_SIG,
    CODEC_X25519_PUB, KEY_AGREEMENT_KEY_TYPE,
};
pub use msg::{
    decode_content, encode_content, Envelope, Headers, Message, ReplayGuard,
    DEFAULT_MAX_CLOCK_SKEW_SECS, DEFAULT_MESSAGE_TTL_SECS, DEFAULT_REPLAY_WINDOW_SECS,
    MESSAGE_PREFIX,
};
pub use multiformat::{
    CODEC_CBOR, CODEC_DAG_CBOR, CODEC_DAG_JSON, CODEC_IDENTITY, CODEC_JSON, CODEC_RAW,
};

#[cfg(feature = "acl")]
pub use acl::{
    check_cap, is_principal_key, is_valid_acl_key, normalize_principal, validate_acl_map, AclMap,
    CapabilityEntry, CAP_ACL, CAP_CREATE, CAP_CRUD, CAP_DELETE, CAP_IDENTITY_PUBLISH, CAP_INBOX,
    CAP_IPFS, CAP_READ, CAP_RPC, CAP_UPDATE, GROUP_PREFIX, LOCAL_ENTITY_WILDCARD,
};

// ─── Re-export service constants ────────────────────────────────────────────

pub use service::{
    Service, CONTENT_TYPE_CBOR, CONTENT_TYPE_TERM, CONTENT_TYPE_TERM_CBOR, CONTENT_TYPE_TERM_YAML,
    CRUD_PROTOCOL_ID, INBOX_PROTOCOL_ID, IPFS_PROTOCOL_ID, MESSAGE_TYPE_BROADCAST,
    MESSAGE_TYPE_CHAT, MESSAGE_TYPE_CRUD, MESSAGE_TYPE_CRUD_REPLY, MESSAGE_TYPE_DOC,
    MESSAGE_TYPE_EMOTE, MESSAGE_TYPE_IDENTITY_PUBLISH_REQUEST, MESSAGE_TYPE_IPFS_REQUEST,
    MESSAGE_TYPE_MESSAGE, MESSAGE_TYPE_RPC, MESSAGE_TYPE_RPC_REPLY, RPC_PROTOCOL_ID,
};

// ─── Re-export Inbox ────────────────────────────────────────────────────────

pub use inbox::Inbox;

// ─── Re-export endpoint trait and implementations ───────────────────────────

pub use endpoint::MaEndpoint;
#[cfg(feature = "iroh")]
pub use outbox::Outbox;

/// Create a default ma endpoint backend from 32-byte secret key material.
///
/// This keeps the transport backend type internal while exposing
/// [`MaEndpoint`] and [`Outbox`] as stable API surfaces.
#[cfg(feature = "iroh")]
pub async fn new_ma_endpoint(
    secret_bytes: [u8; 32],
    recipient_key: EncryptionKey,
    resolver: std::sync::Arc<dyn DidDocumentResolver>,
    ipv6: bool,
) -> Result<Box<dyn MaEndpoint>> {
    let endpoint = iroh::new_endpoint(secret_bytes, recipient_key, resolver, ipv6).await?;
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

pub use ipfs::gateway::GatewayPool;
pub use ipfs::gateway_resolver::{DidDocumentResolver, IpfsGatewayResolver, IpnsPathResolver};

// ─── Re-export existing modules ─────────────────────────────────────────────

pub use interfaces::{DidPublisher, IpfsPublisher};
pub use ipfs::*;
