//! Endpoint trait.
//!
//! [`MaEndpoint`] defines the shared interface for all ma transport endpoints.
//! See [`crate::iroh`] for the iroh-backed implementation.

use async_trait::async_trait;

use crate::error::Result;
use crate::inbox::Inbox;
use crate::service::INBOX_PROTOCOL_ID;
use did_ma::Message;

/// Default inbox capacity for services.
pub const DEFAULT_INBOX_CAPACITY: usize = 256;

/// Default protocol ID for unqualified send/request calls.
pub const DEFAULT_DELIVERY_PROTOCOL_ID: &str = INBOX_PROTOCOL_ID;

/// Shared interface for ma transport endpoints.
///
/// Each implementation provides inbox/outbox
/// messaging and advertises its registered services for DID documents.
#[async_trait]
pub trait MaEndpoint: Send + Sync {
    /// The endpoint's public identifier (hex string).
    fn id(&self) -> String;

    /// Register a service protocol and return an [`Inbox`] for receiving messages.
    fn service(&mut self, protocol: &str) -> Inbox<Message>;

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
    async fn send_to(&self, target: &str, protocol: &str, message: &Message) -> Result<()>;

    /// Fire-and-forget to a target on the default inbox protocol.
    async fn send(&self, target: &str, message: &Message) -> Result<()> {
        self.send_to(target, DEFAULT_DELIVERY_PROTOCOL_ID, message)
            .await
    }
}
