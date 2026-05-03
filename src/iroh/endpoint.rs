//! Iroh-backed [`MaEndpoint`] implementation.

use async_trait::async_trait;
use iroh::{
    endpoint::{presets, Connection},
    protocol::{AcceptError, ProtocolHandler, Router},
    Endpoint, EndpointAddr, EndpointId, RelayUrl, SecretKey,
};
use tracing::{debug, warn};

use crate::endpoint::{MaEndpoint, DEFAULT_INBOX_CAPACITY};
use crate::error::{Error, Result};
use crate::inbox::Inbox;
use crate::iroh::channel::Channel;
use crate::outbox::Outbox;
use crate::transport::transport_string;
use did_ma::{now_iso_utc, Document, Ipld, Message};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

const MA_IROH_KEY: &str = "iroh";
const MA_IROH_ENDPOINT_ID_KEY: &str = "endpoint_id";
const MA_IROH_RELAY_URL_KEY: &str = "relay_url";
const DEFAULT_MAX_INBOUND_MESSAGE_SIZE: usize = 1024 * 1024;

/// An iroh-backed ma endpoint.
pub struct IrohEndpoint {
    endpoint: Endpoint,
    protocols: Vec<String>,
    inboxes: BTreeMap<String, Inbox<Message>>,
    router: Option<Router>,
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
        endpoint.online().await;

        debug!(
            endpoint_id = %endpoint.id(),
            "iroh endpoint online"
        );

        Ok(Self {
            endpoint,
            protocols: Vec::new(),
            inboxes: BTreeMap::new(),
            router: None,
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

    /// Reconcile `document.ma.iroh` from the live iroh endpoint state.
    ///
    /// Returns `Ok(true)` if the document was changed and should be re-published.
    /// Returns `Ok(false)` when the existing value already matches live state.
    pub fn reconcile_document_ma_iroh(&self, document: &mut Document) -> Result<bool> {
        let endpoint_id = self.endpoint.id().to_string();
        let relay_url = self
            .endpoint
            .addr()
            .relay_urls()
            .map(std::string::ToString::to_string)
            .min()
            .ok_or_else(|| {
                Error::Transport("iroh endpoint has no relay URL available".to_string())
            })?;

        Ok(reconcile_document_ma_iroh_fields(
            document,
            endpoint_id,
            relay_url,
        ))
    }

    /// Open a persistent write-only [`Channel`] to a remote endpoint.
    ///
    /// # Errors
    /// Returns an error if target parsing, connection, or stream opening fails.
    pub async fn open(&self, target: &str, protocol: &str) -> Result<Channel> {
        let addr = self.resolve_addr(target)?;
        self.open_addr(addr, protocol).await
    }

    async fn open_addr(&self, addr: EndpointAddr, protocol: &str) -> Result<Channel> {
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

    /// Shut down the endpoint.
    pub async fn close(self) {
        if let Some(router) = self.router {
            let _ = router.shutdown().await;
            return;
        }
        self.endpoint.close().await;
    }

    /// Start the inbound router for all registered services.
    pub fn start_router(&mut self) {
        if self.router.is_some() {
            return;
        }

        let mut builder = Router::builder(self.endpoint.clone());
        for protocol in &self.protocols {
            if let Some(inbox) = self.inboxes.get(protocol) {
                let handler = InboxProtocolHandler::new(protocol.clone(), inbox.clone());
                builder = builder.accept(protocol.as_bytes(), handler);
            }
        }

        self.router = Some(builder.spawn());
    }

    /// Remove a registered service protocol.
    ///
    /// Returns `true` when a service existed and was removed.
    /// If the router is already running, it is reloaded so ALPN handlers
    /// match the updated service set.
    pub fn remove_service(&mut self, protocol: &str) -> bool {
        let normalized = normalize_protocol(protocol);
        let removed = self.inboxes.remove(&normalized).is_some();
        if !removed {
            return false;
        }

        self.protocols.retain(|p| p != &normalized);
        self.reload_router_if_running();
        true
    }

    fn reload_router_if_running(&mut self) {
        if self.router.is_none() {
            return;
        }

        // Dropping `Router` aborts the old accept loop quickly; we then spawn
        // a new one with an updated protocol map.
        self.router.take();
        self.start_router();
    }

    fn resolve_addr_with_route(
        &self,
        endpoint_id: &str,
        route: Option<MaIrohRoute>,
    ) -> Result<EndpointAddr> {
        let target_id: EndpointId = endpoint_id
            .trim()
            .parse()
            .map_err(|e| Error::Transport(format!("invalid endpoint id: {e}")))?;

        let mut addr = EndpointAddr::new(target_id);

        if let Some(route) = route {
            if let Some(relay_url) = route.relay_url {
                addr = addr.with_relay_url(relay_url);
            }
        }

        // Fallback to local relay hint if remote route did not provide one.
        if addr.relay_urls().next().is_none() {
            if let Some(relay_url) = self.endpoint.addr().relay_urls().next() {
                addr = addr.with_relay_url(relay_url.clone());
            }
        }

        Ok(addr)
    }
}

#[derive(Debug, Clone)]
struct MaIrohRoute {
    relay_url: Option<RelayUrl>,
}

fn extract_ma_iroh_route(ma: Option<&Ipld>) -> Option<MaIrohRoute> {
    let iroh = ma.and_then(|ma_root| ma_root.get(MA_IROH_KEY).ok().flatten())?;
    let iroh_json = serde_json::to_value(iroh).ok()?;
    let iroh_obj = iroh_json.as_object()?;

    let relay_url = iroh_obj
        .get(MA_IROH_RELAY_URL_KEY)
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<RelayUrl>().ok());

    Some(MaIrohRoute { relay_url })
}

fn reconcile_document_ma_iroh_fields(
    document: &mut Document,
    endpoint_id: String,
    relay_url: String,
) -> bool {
    let mut ma_root = match &document.ma {
        Some(Ipld::Map(map)) => map.clone(),
        _ => BTreeMap::new(),
    };

    let next = ma_iroh_ipld(endpoint_id, relay_url);
    let unchanged = ma_root.get(MA_IROH_KEY) == Some(&next);
    if unchanged {
        return false;
    }

    ma_root.insert(MA_IROH_KEY.to_string(), next);
    document.set_ma(Ipld::Map(ma_root));
    document.updated_at = now_iso_utc();
    true
}

fn ma_iroh_ipld(endpoint_id: String, relay_url: String) -> Ipld {
    let mut iroh = BTreeMap::new();
    iroh.insert(
        MA_IROH_ENDPOINT_ID_KEY.to_string(),
        Ipld::String(endpoint_id),
    );
    iroh.insert(MA_IROH_RELAY_URL_KEY.to_string(), Ipld::String(relay_url));
    Ipld::Map(iroh)
}

#[async_trait]
impl MaEndpoint for IrohEndpoint {
    fn id(&self) -> String {
        self.endpoint.id().to_string()
    }

    fn service(&mut self, protocol: &str) -> Inbox<Message> {
        let normalized = normalize_protocol(protocol);
        if !self.protocols.contains(&normalized) {
            self.protocols.push(normalized.clone());
        }
        if let Some(existing) = self.inboxes.get(&normalized) {
            return existing.clone();
        }

        let inbox = Inbox::new(DEFAULT_INBOX_CAPACITY);
        self.inboxes.insert(normalized, inbox.clone());
        if self.router.is_some() {
            self.reload_router_if_running();
        } else {
            self.start_router();
        }
        inbox
    }

    fn services(&self) -> Vec<String> {
        let id = self.endpoint.id().to_string();
        self.protocols
            .iter()
            .map(|proto| transport_string(&id, proto))
            .collect()
    }

    async fn connect_outbox(
        &self,
        doc: &Document,
        endpoint_id: &str,
        did: &str,
        protocol: &str,
    ) -> Result<Outbox> {
        let route = extract_ma_iroh_route(doc.ma.as_ref());
        let addr = self.resolve_addr_with_route(endpoint_id, route)?;
        let channel = self.open_addr(addr, protocol).await?;
        Ok(Outbox::from_transport(
            channel,
            did.to_string(),
            protocol.to_string(),
        ))
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

#[derive(Debug, Clone)]
struct InboxProtocolHandler {
    protocol: String,
    inbox: Inbox<Message>,
    max_message_size: usize,
}

impl InboxProtocolHandler {
    fn new(protocol: String, inbox: Inbox<Message>) -> Self {
        Self {
            protocol,
            inbox,
            max_message_size: DEFAULT_MAX_INBOUND_MESSAGE_SIZE,
        }
    }
}

impl ProtocolHandler for InboxProtocolHandler {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        loop {
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(streams) => streams,
                Err(err) => {
                    debug!(
                        protocol = %self.protocol,
                        remote = %connection.remote_id(),
                        error = %err,
                        "inbound connection closed"
                    );
                    break;
                }
            };

            let payload = match recv.read_to_end(self.max_message_size).await {
                Ok(payload) => payload,
                Err(err) => {
                    warn!(
                        protocol = %self.protocol,
                        remote = %connection.remote_id(),
                        error = %err,
                        "failed to read inbound stream"
                    );
                    let _ = send.finish();
                    continue;
                }
            };

            let _ = send.finish();

            let message = match Message::from_cbor(&payload) {
                Ok(message) => message,
                Err(err) => {
                    warn!(
                        protocol = %self.protocol,
                        remote = %connection.remote_id(),
                        error = %err,
                        "invalid inbound message payload"
                    );
                    continue;
                }
            };

            if let Err(err) = message.headers().validate() {
                warn!(
                    protocol = %self.protocol,
                    remote = %connection.remote_id(),
                    error = %err,
                    "invalid inbound message headers"
                );
                continue;
            }

            let expires_at = if message.ttl == 0 {
                0
            } else {
                message_created_at_secs(message.created_at).saturating_add(message.ttl)
            };

            self.inbox.push(now_secs(), expires_at, message);
        }

        Ok(())
    }
}

fn normalize_protocol(input: &str) -> String {
    let protocol = input.trim();
    if protocol.is_empty() {
        return String::new();
    }

    format!("/{}", protocol.trim_start_matches('/'))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn message_created_at_secs(created_at: f64) -> u64 {
    if !created_at.is_finite() || created_at <= 0.0 {
        0
    } else if created_at >= u64::MAX as f64 {
        u64::MAX
    } else {
        created_at.floor() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::{
        extract_ma_iroh_route, reconcile_document_ma_iroh_fields, MA_IROH_KEY,
        MA_IROH_RELAY_URL_KEY,
    };
    use did_ma::{Did, Document, Ipld};
    use std::collections::BTreeMap;

    fn test_doc() -> Document {
        let did = Did::new_url(
            "k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr",
            None::<String>,
        )
        .expect("valid did");
        Document::new(&did, &did)
    }

    #[test]
    fn reconcile_sets_ma_iroh() {
        let mut doc = test_doc();

        let changed = reconcile_document_ma_iroh_fields(
            &mut doc,
            "abc123".to_string(),
            "https://relay.example".to_string(),
        );

        assert!(changed);
        let ma = doc.ma.expect("ma should be present");
        let map = match ma {
            Ipld::Map(map) => map,
            _ => panic!("ma should be map"),
        };
        assert!(map.contains_key(MA_IROH_KEY));
    }

    #[test]
    fn reconcile_is_idempotent_after_normalization() {
        let mut doc = test_doc();
        let _ = reconcile_document_ma_iroh_fields(
            &mut doc,
            "abc123".to_string(),
            "https://relay.example".to_string(),
        );

        let changed = reconcile_document_ma_iroh_fields(
            &mut doc,
            "abc123".to_string(),
            "https://relay.example".to_string(),
        );

        assert!(!changed);
    }

    #[test]
    fn reconcile_preserves_other_ma_fields() {
        let mut doc = test_doc();
        let mut ma = BTreeMap::new();
        ma.insert("services".to_string(), Ipld::Map(BTreeMap::new()));
        doc.set_ma(Ipld::Map(ma));

        let changed = reconcile_document_ma_iroh_fields(
            &mut doc,
            "abc123".to_string(),
            "https://relay.example".to_string(),
        );

        assert!(changed);
        let ma = doc.ma.expect("ma should be present");
        let map = match ma {
            Ipld::Map(map) => map,
            _ => panic!("ma should be map"),
        };
        assert!(map.contains_key("services"));
        assert!(map.contains_key(MA_IROH_KEY));

        let iroh = map.get(MA_IROH_KEY).expect("iroh should exist");
        let iroh_map = match iroh {
            Ipld::Map(iroh_map) => iroh_map,
            _ => panic!("iroh should be map"),
        };
        assert!(iroh_map.contains_key(MA_IROH_RELAY_URL_KEY));
    }

    #[test]
    fn extract_ma_iroh_route_parses_relay_url() {
        let mut iroh = BTreeMap::new();
        iroh.insert(
            MA_IROH_RELAY_URL_KEY.to_string(),
            Ipld::String("https://relay.example".to_string()),
        );

        let mut ma = BTreeMap::new();
        ma.insert(MA_IROH_KEY.to_string(), Ipld::Map(iroh));

        let route = extract_ma_iroh_route(Some(&Ipld::Map(ma))).expect("route should parse");
        assert!(route.relay_url.is_some());
    }

    #[test]
    fn extract_ma_iroh_route_returns_none_without_iroh() {
        let ma = Ipld::Map(BTreeMap::new());
        let route = extract_ma_iroh_route(Some(&ma));
        assert!(route.is_none());
    }

    // ─── IrohEndpoint service/router lifecycle tests ─────────────────────────

    fn test_secret() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = 42;
        bytes
    }

    fn test_message() -> did_ma::Message {
        use did_ma::{Did, SigningKey};
        let did =
            Did::new_identity("k51qzi5uqu5dkkciu33khkzbcmxtyhn376i1e83tya8kuy7z9euedzyr5nhoew")
                .expect("valid did");
        let did_id = did.id();
        let sk = SigningKey::generate(did).expect("signing key");
        did_ma::Message::new(
            did_id,
            String::new(),
            crate::service::CONTENT_TYPE_BROADCAST,
            b"test".to_vec(),
            &sk,
        )
        .expect("message")
    }

    // Requires network (iroh endpoint bind); run with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "requires iroh network runtime"]
    async fn service_returns_shared_inbox() {
        use super::IrohEndpoint;
        use crate::endpoint::MaEndpoint;

        let mut endpoint = IrohEndpoint::new(test_secret()).await.unwrap();
        let inbox_a = endpoint.service("/ma/inbox/0.0.1");
        let inbox_b = endpoint.service("/ma/inbox/0.0.1");

        // Both clones point to the same underlying queue.
        inbox_a.push(0, 0, test_message());
        assert_eq!(inbox_b.len(), 1, "cloned inbox should share the same queue");

        endpoint.close().await;
    }

    #[tokio::test]
    #[ignore = "requires iroh network runtime"]
    async fn service_auto_starts_router() {
        use super::IrohEndpoint;
        use crate::endpoint::MaEndpoint;

        let mut endpoint = IrohEndpoint::new(test_secret()).await.unwrap();
        assert!(endpoint.router.is_none(), "router should start stopped");

        endpoint.service("/ma/inbox/0.0.1");

        assert!(
            endpoint.router.is_some(),
            "router should auto-start on first service registration"
        );

        endpoint.close().await;
    }

    #[tokio::test]
    #[ignore = "requires iroh network runtime"]
    async fn remove_service_updates_protocol_list() {
        use super::IrohEndpoint;
        use crate::endpoint::MaEndpoint;

        let mut endpoint = IrohEndpoint::new(test_secret()).await.unwrap();
        let _inbox = endpoint.service("/ma/custom/1.0");
        assert!(endpoint
            .services()
            .iter()
            .any(|s| s.contains("/ma/custom/1.0")));

        let removed = endpoint.remove_service("/ma/custom/1.0");
        assert!(
            removed,
            "remove_service should return true for registered protocol"
        );
        assert!(
            endpoint
                .services()
                .iter()
                .all(|s| !s.contains("/ma/custom/1.0")),
            "protocol should be absent from services after removal"
        );

        endpoint.close().await;
    }

    #[tokio::test]
    #[ignore = "requires iroh network runtime"]
    async fn service_after_start_router_triggers_reload() {
        use super::IrohEndpoint;
        use crate::endpoint::MaEndpoint;

        let mut endpoint = IrohEndpoint::new(test_secret()).await.unwrap();
        endpoint.service("/ma/inbox/0.0.1");
        endpoint.start_router();
        assert!(
            endpoint.router.is_some(),
            "router should be running after start_router"
        );

        // Adding a new service while router is running should transparently reload.
        endpoint.service("/ma/custom/1.0");
        assert!(
            endpoint.router.is_some(),
            "router should still be running after service addition"
        );
        assert!(
            endpoint
                .services()
                .iter()
                .any(|s| s.contains("/ma/custom/1.0")),
            "new service should appear in services() after hot-add"
        );

        endpoint.close().await;
    }
}
