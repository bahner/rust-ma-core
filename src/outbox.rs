//! Transport-agnostic send handle to a remote ma service.
//!
//! An `Outbox` wraps the transport details and exposes only
//! `send()` + `close()`.
//!
//! `send()` takes a [`Message`], validates it,
//! serializes to CBOR, and transmits. Malformed or expired messages
//! are rejected before anything hits the wire.
//!
//! Requires the `iroh` feature.
//!
//! ```ignore
//! let mut outbox = ep.outbox("did:ma:456", "ma/presence/0.0.1").await?;
//! outbox.send(&message).await?;
//! outbox.close();
//! ```

use crate::error::{Error, Result};
use async_trait::async_trait;
use did_ma::Message;

#[async_trait]
pub(crate) trait OutboxWire: Send + std::fmt::Debug {
    async fn send_payload(&mut self, payload: &[u8]) -> Result<()>;
    fn close_box(self: Box<Self>);
}

/// A transport-agnostic write handle to a remote service.
///
/// The caller doesn't need to know the underlying transport.
#[derive(Debug)]
pub struct Outbox {
    inner: Option<Box<dyn OutboxWire>>,
    did: String,
    protocol: String,
}

impl Outbox {
    /// Create an outbox backed by a transport implementation.
    pub(crate) fn from_transport<T>(transport: T, did: String, protocol: String) -> Self
    where
        T: OutboxWire + 'static,
    {
        Self {
            inner: Some(Box::new(transport)),
            did,
            protocol,
        }
    }

    /// Send a ma message to the remote service.
    ///
    /// Validates the message headers, serializes to CBOR, and transmits.
    ///
    /// # Errors
    /// Returns an error if validation, serialization, or transport send fails.
    pub async fn send(&mut self, message: &Message) -> Result<()> {
        message.headers().validate()?;
        let cbor = message.to_cbor()?;
        match self.inner.as_mut() {
            Some(transport) => transport.send_payload(&cbor).await,
            None => Err(Error::ConnectionClosed("outbox is closed".to_string())),
        }
    }

    /// The DID this outbox delivers to.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The protocol this outbox is connected to.
    #[must_use]
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// Close the outbox gracefully.
    pub fn close(mut self) {
        if let Some(transport) = self.inner.take() {
            transport.close_box();
        }
    }
}
