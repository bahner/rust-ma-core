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
///     fn protocol(&self) -> &[u8] { b"ma/my-service/0.0.1" }
///     fn label(&self) -> &str { "my-service" }
/// }
///
/// let svc = MyService;
/// assert_eq!(svc.label(), "my-service");
/// ```
pub trait Service: Send + Sync {
    /// The protocol identifier for this service.
    fn protocol(&self) -> &[u8];

    /// Human-readable label for logging and diagnostics.
    fn label(&self) -> &str;
}

// ─── Well-known protocol constants (ma-core scope) ──────────────────────────

pub const INBOX_PROTOCOL: &[u8] = b"ma/inbox/0.0.1";
pub const BROADCAST_PROTOCOL: &[u8] = b"ma/broadcast/0.0.1";
pub const IPFS_PROTOCOL: &[u8] = b"ma/ipfs/0.0.1";

pub const BROADCAST_TOPIC: &str = "ma/broadcast/0.0.1";

// ─── Content types ──────────────────────────────────────────────────────────

pub const DEFAULT_CONTENT_TYPE: &str = "application/x-ma";
pub const CONTENT_TYPE_CHAT: &str = "application/x-ma-chat";
pub const CONTENT_TYPE_PRESENCE: &str = "application/x-ma-presence";
pub const CONTENT_TYPE_WORLD: &str = "application/x-ma-world";
pub const CONTENT_TYPE_EVENT: &str = "application/x-ma-event";
pub const CONTENT_TYPE_BROADCAST: &str = "application/x-ma-broadcast";
pub const CONTENT_TYPE_WHISPER: &str = "application/x-ma-whisper";
pub const CONTENT_TYPE_MESSAGE: &str = "application/x-ma-message";
