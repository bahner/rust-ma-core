//! Transport-agnostic send handle to a remote ma service.
//!
//! An `Outbox` wraps the transport details and exposes a single `send()`
//! method. Outboxes are lightweight and meant to be kept alive for the
//! duration of a session — `ma-core` manages the underlying connections.
//!
//! `send()` takes a [`Message`], validates it, applies the message type's
//! encryption policy, and transmits. Malformed or expired messages are
//! rejected before anything hits the wire.
//!
//! Requires the `iroh` feature.
//!
//! ```ignore
//! let mut outbox = ep.outbox(&resolver, "did:ma:k51qzi5uqu5d…", INBOX_PROTOCOL_ID).await?;
//! outbox.send(&message).await?;
//! // Keep the outbox alive — no need to close it.
//! ```

use crate::error::{Error, Result};
use crate::{Did, Document, Message};
use async_trait::async_trait;

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
    recipient_document: Document,
    local: bool,
    did: String,
    protocol: String,
}

impl Outbox {
    /// Create an outbox backed by a transport implementation.
    pub(crate) fn from_transport<T>(
        transport: T,
        recipient_document: Document,
        local: bool,
        did: String,
        protocol: String,
    ) -> Self
    where
        T: OutboxWire + 'static,
    {
        Self {
            inner: Some(Box::new(transport)),
            recipient_document,
            local,
            did,
            protocol,
        }
    }

    /// Send a ma message to the remote service.
    ///
    /// Validates the message headers, encrypts non-broadcast remote messages,
    /// and transmits the resulting CBOR payload.
    ///
    /// # Errors
    /// Returns an error if validation, serialization, or transport send fails.
    pub async fn send(&mut self, message: &Message) -> Result<()> {
        message.headers().validate()?;
        let unencrypted = message.message_type == crate::service::MESSAGE_TYPE_BROADCAST
            || (self.local && same_base_did(&message.from, &message.to)?);
        let payload = if unencrypted {
            message.encode()?
        } else {
            message.enclose_for(&self.recipient_document)?.encode()?
        };
        match self.inner.as_mut() {
            Some(transport) => transport.send_payload(&payload).await,
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

fn same_base_did(from: &str, to: &str) -> Result<bool> {
    let (from_base, _) = Did::parse(from)?;
    let (to_base, _) = Did::parse(to)?;
    Ok(from_base == to_base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_identity_from_secret, Envelope, SigningKey};
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone)]
    struct CaptureWire(Arc<Mutex<Vec<u8>>>);

    #[async_trait]
    impl OutboxWire for CaptureWire {
        async fn send_payload(&mut self, payload: &[u8]) -> Result<()> {
            self.0
                .lock()
                .expect("capture lock")
                .extend_from_slice(payload);
            Ok(())
        }

        fn close_box(self: Box<Self>) {}
    }

    fn signing_key(identity: &crate::GeneratedIdentity) -> SigningKey {
        let did = Did::new_url(&identity.subject_url.ipns, Some("sign")).expect("signing DID");
        let bytes = hex::decode(&identity.signing_private_key_hex).expect("private key hex");
        SigningKey::from_private_key_bytes(did, bytes.try_into().expect("private key length"))
            .expect("signing key")
    }

    fn outbox(recipient_document: &Document, local: bool) -> (Outbox, Arc<Mutex<Vec<u8>>>) {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let outbox = Outbox::from_transport(
            CaptureWire(captured.clone()),
            recipient_document.clone(),
            local,
            recipient_document.id.clone(),
            crate::service::INBOX_PROTOCOL_ID.to_string(),
        );
        (outbox, captured)
    }

    #[tokio::test]
    async fn remote_message_is_transmitted_as_envelope() {
        let sender = generate_identity_from_secret([1; 32]).expect("sender identity");
        let recipient = generate_identity_from_secret([2; 32]).expect("recipient identity");
        let message = Message::new(
            sender.document.id.clone(),
            recipient.document.id.clone(),
            crate::service::MESSAGE_TYPE_MESSAGE,
            "text/plain",
            b"secret",
            &signing_key(&sender),
        )
        .expect("message");
        let (mut outbox, captured) = outbox(&recipient.document, false);

        outbox.send(&message).await.expect("send message");

        let payload = captured.lock().expect("capture lock");
        Envelope::decode(&payload).expect("encrypted envelope");
        assert!(
            Message::decode(&payload).is_err(),
            "raw message reached wire"
        );
    }

    #[tokio::test]
    async fn broadcast_is_transmitted_as_raw_message() {
        let sender = generate_identity_from_secret([1; 32]).expect("sender identity");
        let recipient = generate_identity_from_secret([2; 32]).expect("recipient identity");
        let message = Message::new(
            sender.document.id.clone(),
            String::new(),
            crate::service::MESSAGE_TYPE_BROADCAST,
            "text/plain",
            b"public",
            &signing_key(&sender),
        )
        .expect("broadcast");
        let (mut outbox, captured) = outbox(&recipient.document, false);

        outbox.send(&message).await.expect("send broadcast");

        let payload = captured.lock().expect("capture lock");
        assert_eq!(Message::decode(&payload).expect("raw message"), message);
    }

    #[tokio::test]
    async fn local_same_base_did_is_transmitted_as_raw_message() {
        let identity = generate_identity_from_secret([1; 32]).expect("identity");
        let from = format!("{}#sender", identity.document.id);
        let to = format!("{}#recipient", identity.document.id);
        let message = Message::new(
            from,
            to,
            crate::service::MESSAGE_TYPE_MESSAGE,
            "text/plain",
            b"local",
            &signing_key(&identity),
        )
        .expect("message");
        let (mut outbox, captured) = outbox(&identity.document, true);

        outbox.send(&message).await.expect("send local message");

        let payload = captured.lock().expect("capture lock");
        assert_eq!(Message::decode(&payload).expect("raw message"), message);
    }

    #[tokio::test]
    async fn local_wire_does_not_exempt_different_base_dids() {
        let sender = generate_identity_from_secret([1; 32]).expect("sender identity");
        let recipient = generate_identity_from_secret([2; 32]).expect("recipient identity");
        let message = Message::new(
            sender.document.id.clone(),
            recipient.document.id.clone(),
            crate::service::MESSAGE_TYPE_MESSAGE,
            "text/plain",
            b"secret",
            &signing_key(&sender),
        )
        .expect("message");
        let (mut outbox, captured) = outbox(&recipient.document, true);

        outbox.send(&message).await.expect("send message");

        let payload = captured.lock().expect("capture lock");
        Envelope::decode(&payload).expect("encrypted envelope");
    }
}
