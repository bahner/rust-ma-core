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

pub const INBOX_PROTOCOL: &[u8] = b"/ma/inbox/0.0.1";
pub const BROADCAST_PROTOCOL: &[u8] = b"/ma/broadcast/0.0.1";
pub const IPFS_PROTOCOL: &[u8] = b"/ma/ipfs/0.0.1";

/// The well-known broadcast topic string (same path as [`BROADCAST_PROTOCOL`]).
pub const BROADCAST_TOPIC: &str = "/ma/broadcast/0.0.1";

// ─── Content types ──────────────────────────────────────────────────────────

pub const CONTENT_TYPE_BROADCAST: &str = "application/x-ma-broadcast";
pub const CONTENT_TYPE_MESSAGE: &str = "application/x-ma-message";
pub const CONTENT_TYPE_IPFS_REQUEST: &str = "application/x-ma-ipfs-request";
pub const CONTENT_TYPE_DOC: &str = "application/x-ma-doc";
