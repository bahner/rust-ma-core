//! Iroh-backed [`MaEndpoint`] implementation.

use async_trait::async_trait;
use iroh::{endpoint::presets, Endpoint, EndpointAddr, EndpointId, SecretKey};
use tracing::debug;

use crate::endpoint::{MaEndpoint, DEFAULT_INBOX_CAPACITY};
use crate::error::{Error, Result};
use crate::inbox::Inbox;
use crate::iroh::channel::Channel;
use crate::outbox::Outbox;
use crate::resolve::DidResolver;
use crate::transport::{resolve_endpoint_for_protocol, transport_string};
use did_ma::Message;

/// An iroh-backed ma endpoint.
pub struct IrohEndpoint {
    endpoint: Endpoint,
    protocols: Vec<String>,
}

impl IrohEndpoint {
    /// Create an endpoint from raw 32-byte secret key material.
    pub async fn new(secret_bytes: [u8; 32]) -> Result<Self> {
        let secret = SecretKey::from_bytes(&secret_bytes);
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .bind()
            .await
            .map_err(|e| Error::Transport(format!("endpoint bind failed: {e}")))?;
        let _ = endpoint.online().await;

        debug!(
            endpoint_id = %endpoint.id(),
            "iroh endpoint online"
        );

        Ok(Self {
            endpoint,
            protocols: Vec::new(),
        })
    }

    /// Access the underlying iroh endpoint (for Router setup, gossip, etc.).
    pub fn inner(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Consume self and return the underlying iroh endpoint.
    pub fn into_inner(self) -> Endpoint {
        self.endpoint
    }

    /// The endpoint's typed iroh identifier.
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Open a persistent write-only [`Channel`] to a remote endpoint.
    pub async fn open(&self, target: &str, protocol: &str) -> Result<Channel> {
        let addr = self.resolve_addr(target)?;
        let connection = self
            .endpoint
            .connect(addr, protocol.as_bytes())
            .await
            .map_err(|e| Error::Transport(format!("connect failed: {e}")))?;
        let (send, _recv) = connection
            .open_bi()
            .await
            .map_err(|e| Error::Transport(format!("open_bi failed: {e}")))?;
        Ok(Channel::new(connection, send))
    }

    fn resolve_addr(&self, target: &str) -> Result<EndpointAddr> {
        let target_id: EndpointId = target
            .trim()
            .parse()
            .map_err(|e| Error::Transport(format!("invalid endpoint id: {e}")))?;
        let mut addr = EndpointAddr::new(target_id);
        // Add our own relay URL as a routing hint.
        // DNS-based address lookup is not available in wasm_browser, so without
        // a relay hint the connect will time out. Both endpoints use the N0
        // preset whose relays interconnect, so any N0 relay URL is a valid hint.
        if let Some(relay_url) = self.endpoint.addr().relay_urls().next() {
            addr = addr.with_relay_url(relay_url.clone());
        }
        Ok(addr)
    }

    /// Open a transport-agnostic [`Outbox`] to a remote DID on a given protocol.
    ///
    /// Resolves the DID document, finds a matching service for the
    /// requested protocol, and opens a persistent channel.
    pub async fn outbox(
        &self,
        resolver: &dyn DidResolver,
        did: &str,
        protocol: &str,
    ) -> Result<Outbox> {
        let doc = resolver.resolve(did).await?;

        let services = doc
            .ma
            .as_ref()
            .and_then(|ma| ma.get("services").ok().flatten())
            .and_then(|services| serde_json::to_value(services).ok());
        let endpoint_id =
            resolve_endpoint_for_protocol(services.as_ref(), protocol).ok_or_else(|| {
                Error::NoInboxTransport(format!("{} has no service for {}", did, protocol,))
            })?;

        let channel = self.open(&endpoint_id, protocol).await?;
        Ok(Outbox::from_channel(
            channel,
            did.to_string(),
            protocol.to_string(),
        ))
    }

    /// Shut down the endpoint.
    pub async fn close(self) {
        self.endpoint.close().await;
    }
}

#[async_trait]
impl MaEndpoint for IrohEndpoint {
    fn id(&self) -> String {
        self.endpoint.id().to_string()
    }

    fn service(&mut self, protocol: &str) -> Inbox<Message> {
        if !self.protocols.contains(&protocol.to_string()) {
            self.protocols.push(protocol.to_string());
        }
        Inbox::new(DEFAULT_INBOX_CAPACITY)
    }

    fn services(&self) -> Vec<String> {
        let id = self.endpoint.id().to_string();
        self.protocols
            .iter()
            .map(|proto| transport_string(&id, proto))
            .collect()
    }

    async fn send_to(&self, target: &str, protocol: &str, message: &Message) -> Result<()> {
        message.headers().validate()?;
        let cbor = message.to_cbor()?;
        let mut channel = self.open(target, protocol).await?;
        channel.send(&cbor).await?;
        channel.close();
        Ok(())
    }
}
