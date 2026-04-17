//! Endpoint trait.
//!
//! [`MaEndpoint`] defines the shared interface for all ma transport endpoints.
//! See [`crate::iroh`] for the iroh-backed implementation.

use async_trait::async_trait;

use crate::error::Result;
use crate::inbox::Inbox;

/// Default inbox capacity for services.
pub const DEFAULT_INBOX_CAPACITY: usize = 256;

/// Default inbox TTL in seconds (5 minutes).
pub const DEFAULT_INBOX_TTL_SECS: u64 = 300;

/// Default protocol ID for unqualified send/request calls.
pub const DEFAULT_DELIVERY_PROTOCOL_ID: &str = "ma/inbox/0.0.1";

/// Shared interface for ma transport endpoints.
///
/// Each implementation provides inbox/outbox
/// messaging and advertises its registered services for DID documents.
#[async_trait]
pub trait MaEndpoint: Send + Sync {
    /// The endpoint's public identifier (hex string).
    fn id(&self) -> String;

    /// Register a service protocol and return an [`Inbox`] for receiving messages.
    fn service(&mut self, protocol: &str) -> Inbox<Vec<u8>>;

    /// Return service strings for all registered protocols.
    ///
    /// Each entry is suitable for inclusion in a DID document's `ma.services` array.
    fn services(&self) -> Vec<String>;

    /// Return service strings as a JSON array value.
    fn services_json(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.services()
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        )
    }

    /// Fire-and-forget to a target on a specific protocol.
    async fn send_to(&self, target: &str, protocol: &str, payload: &[u8]) -> Result<()>;

    /// Fire-and-forget to a target on the default inbox protocol.
    async fn send(&self, target: &str, payload: &[u8]) -> Result<()> {
        self.send_to(target, DEFAULT_DELIVERY_PROTOCOL_ID, payload).await
    }
}
