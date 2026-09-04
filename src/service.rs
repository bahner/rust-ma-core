//! Service trait for ma endpoint protocol handlers.
//!
//! A `Service` is analogous to an entry in `/etc/services`: a named protocol
//! on a ma endpoint. Register services on an `MaEndpoint` to handle incoming
//! connections on their protocol.

/// Trait that all ma services must implement.
///
/// Each service declares its protocol identifier and provides a handler for
/// incoming connections. Built-in services ship with ma-core; applications
/// add custom services via this trait.
///
/// # Examples
///
/// ```
/// use ma_core::Service;
///
/// struct MyService;
///
/// impl Service for MyService {
///     fn protocol(&self) -> &[u8] { b"/ma/my-service/0.0.1" }
/// }
/// ```
pub trait Service: Send + Sync {
    /// The protocol identifier for this service.
    fn protocol(&self) -> &[u8];
}

// ─── Well-known protocol constants (ma-core scope) ──────────────────────────

pub const INBOX_PROTOCOL_ID: &str = "/ma/inbox/0.0.1";
pub const IPFS_PROTOCOL_ID: &str = "/ma/ipfs/0.0.1";
pub const CRUD_PROTOCOL_ID: &str = "/ma/crud/0.0.1";

// ─── Message types (routing / dispatch category) ────────────────────────────

pub const MESSAGE_TYPE_BROADCAST: &str = "application/vnd.ma.broadcast";
pub const MESSAGE_TYPE_CHAT: &str = "application/vnd.ma.chat";
pub const MESSAGE_TYPE_EMOTE: &str = "application/vnd.ma.emote";
pub const MESSAGE_TYPE_MESSAGE: &str = "application/vnd.ma.message";
/// DID-document publish request — transmits an IPNS secret key so the
/// publisher can sign/publish the caller's `did:ma` document. Requires the
/// `identity-publish` ACL capability (see `ma_core::acl::CAP_IDENTITY_PUBLISH`).
pub const MESSAGE_TYPE_IDENTITY_PUBLISH_REQUEST: &str =
    "application/vnd.ma.identity.publish.request";
/// Generic IPFS content-store request — fire-and-forget. Requires the
/// `ipfs` ACL capability (see `ma_core::acl::CAP_IPFS`).
pub const MESSAGE_TYPE_IPFS_REQUEST: &str = "application/vnd.ma.ipfs.request";
pub const MESSAGE_TYPE_DOC: &str = "application/vnd.ma.doc";

// ─── CRUD message types (/ma/crud/0.0.1) ────────────────────────────────────
//
// Operation is encoded in the CBOR payload, not the message type:
//   GET:    [":get",    ":path"]
//   SET:    [":path",   value]        value = scalar or "/ipfs/…", "/ipns/…", "/ipld/…"
//   DELETE: [":delete", ":path"]

pub const MESSAGE_TYPE_CRUD: &str = "application/vnd.ma.crud.request";
pub const MESSAGE_TYPE_CRUD_REPLY: &str = "application/vnd.ma.crud.reply";

// ─── Content types (inner payload format) ───────────────────────────────────

pub const CONTENT_TYPE_CBOR: &str = "application/cbor";
/// CBOR term — either a bare atom (`:ok`, `:pong`) or a tuple (CBOR array whose first element
/// is a dispatchable atom, e.g. `[:ok, data]` or `[:error, reason]`).
/// Used as `contentType` for RPC and CRUD messages.
pub const CONTENT_TYPE_TERM: &str = "application/vnd.ma.term";
/// Raw CBOR data payload — e.g. an `EntityNode` struct or a `Vec<String>` names list.
/// The `+cbor` suffix follows RFC 6838 §4.2.8 structured-syntax conventions.
pub const CONTENT_TYPE_TERM_CBOR: &str = "application/vnd.ma.term+cbor";
/// Inline YAML string — the CBOR payload is a text string containing a
/// UTF-8 YAML document.  Suitable for config values (scalars, sequences,
/// mappings) that do not need to be stored as separate IPFS objects.
pub const CONTENT_TYPE_TERM_YAML: &str = "application/vnd.ma.term+yaml";
