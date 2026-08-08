//! Endpoint trait.
//!
//! [`MaEndpoint`] defines the shared interface for all ma transport endpoints.
//! The crate currently provides an internal iroh-backed transport implementation.

use async_trait::async_trait;

#[cfg(feature = "iroh")]
use crate::error::Error;
use crate::error::Result;
use crate::inbox::Inbox;
#[cfg(feature = "iroh")]
use crate::ipfs::DidDocumentResolver;
#[cfg(feature = "iroh")]
use crate::transport::resolve_endpoint_for_protocol;
#[cfg(feature = "iroh")]
use crate::Document;
use crate::Message;
#[cfg(feature = "iroh")]
use crate::Outbox;

/// Default inbox capacity for services.
pub const DEFAULT_INBOX_CAPACITY: usize = 256;

/// Shared interface for ma transport endpoints.
///
/// Each implementation provides inbox/outbox
/// messaging and advertises its registered services for DID documents.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait MaEndpoint: Send + Sync {
    /// The endpoint's public identifier (hex string).
    fn id(&self) -> String;

    /// Register a service protocol and return an [`Inbox`] for receiving messages.
    ///
    /// Implementations should ensure the service is reachable for inbound delivery
    /// once it has been registered, so callers do not need a second explicit
    /// "listen" step in the common case.
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

    /// Build a [`crate::MaExtension`] pre-populated with this endpoint's
    /// service strings.
    ///
    /// Use this as the starting point when constructing the `ma:` field for a
    /// DID document. Chain additional builder methods on the returned value
    /// before passing it to [`crate::config::SecretBundle::build_document`] or
    /// [`crate::Document::set_ma_extension`]:
    ///
    /// ```ignore
    /// let ma = endpoint.ma_extension().kind("world");
    /// let document = bundle.build_document(ma)?;
    /// ```
    fn ma_extension(&self) -> crate::doc::MaExtension {
        crate::doc::MaExtension::new().services(self.services())
    }

    /// Send an explicitly unencrypted broadcast to a transport endpoint.
    ///
    /// Point-to-point messages must use [`Self::outbox`] so the recipient DID
    /// document is available for envelope encryption.
    async fn send_broadcast_to(
        &self,
        target: &str,
        protocol: &str,
        message: &Message,
    ) -> Result<()>;

    /// Gracefully shut down the endpoint, closing all cached connections.
    async fn close(&mut self);

    /// Open a transport-agnostic outbox to a remote DID and protocol.
    ///
    /// Resolves the DID document, checks `ma.services` for the requested
    /// protocol, and delegates the actual transport connection to
    /// [`Self::connect_outbox`]. Override this only for non-standard resolution.
    #[cfg(feature = "iroh")]
    async fn outbox(
        &self,
        resolver: &dyn DidDocumentResolver,
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
                Error::NoInboxTransport(format!("{did} has no service for {protocol}"))
            })?;

        self.connect_outbox(&doc, &endpoint_id, did, protocol).await
    }

    /// Open a transport-level outbox given a pre-resolved document and endpoint ID.
    ///
    /// Implementors use `doc` for transport-specific routing hints (e.g. relay URLs)
    /// and `endpoint_id` as the peer address on their transport layer.
    #[cfg(feature = "iroh")]
    async fn connect_outbox(
        &self,
        doc: &Document,
        endpoint_id: &str,
        did: &str,
        protocol: &str,
    ) -> Result<Outbox>;
}
