//! Transport-agnostic send handle to a remote ma service.
//!
//! An `Outbox` wraps the transport details and exposes only
//! `send()` + `close()`. Created via [`crate::iroh::IrohEndpoint::outbox`].
//!
//! Requires the `iroh` feature.
//!
//! ```ignore
//! let mut outbox = ep.outbox("did:ma:456", b"ma/presence/0.0.1").await?;
//! outbox.send(event_bytes).await?;
//! outbox.send(event_bytes).await?;
//! outbox.close();
//! ```

use crate::error::Result;
use crate::iroh::channel::Channel;

/// A transport-agnostic write handle to a remote service.
///
/// The caller doesn't need to know the underlying transport.
#[derive(Debug)]
pub struct Outbox {
    inner: OutboxTransport,
    did: String,
    protocol: String,
}

#[derive(Debug)]
enum OutboxTransport {
    Channel(Channel),
}

impl Outbox {
    /// Create an outbox backed by a channel.
    pub(crate) fn from_channel(channel: Channel, did: String, protocol: String) -> Self {
        Self {
            inner: OutboxTransport::Channel(channel),
            did,
            protocol,
        }
    }

    /// Send a payload to the remote service.
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        match &mut self.inner {
            OutboxTransport::Channel(channel) => channel.send(payload).await,
        }
    }

    /// The DID this outbox delivers to.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The protocol this outbox is connected to.
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// Close the outbox gracefully.
    pub fn close(self) {
        match self.inner {
            OutboxTransport::Channel(channel) => channel.close(),
        }
    }
}
