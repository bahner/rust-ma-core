//! Iroh-backed [`MaEndpoint`] implementation.

use async_trait::async_trait;
use iroh::{endpoint::presets, Endpoint, EndpointAddr, EndpointId, RelayUrl, SecretKey};
use tracing::debug;

use crate::endpoint::{MaEndpoint, DEFAULT_INBOX_CAPACITY};
use crate::error::{Error, Result};
use crate::inbox::Inbox;
use crate::iroh::channel::Channel;
use crate::outbox::Outbox;
use crate::resolve::DidResolver;
use crate::transport::{resolve_endpoint_for_protocol, transport_string};
use did_ma::{now_iso_utc, Document, Ipld, Message};
use std::collections::BTreeMap;
use std::net::SocketAddr;

const MA_IROH_KEY: &str = "iroh";
const MA_IROH_NODE_ID_KEY: &str = "node_id";
const MA_IROH_RELAY_URL_KEY: &str = "relay_url";
const MA_IROH_DIRECT_ADDRESSES_KEY: &str = "direct_addresses";

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

    /// Reconcile `document.ma.iroh` from the live iroh endpoint state.
    ///
    /// Returns `Ok(true)` if the document was changed and should be re-published.
    /// Returns `Ok(false)` when the existing value already matches live state.
    pub fn reconcile_document_ma_iroh(&self, document: &mut Document) -> Result<bool> {
        let node_id = self.endpoint.id().to_string();
        let relay_url = self
            .endpoint
            .addr()
            .relay_urls()
            .map(|url| url.to_string())
            .min()
            .ok_or_else(|| {
                Error::Transport("iroh endpoint has no relay URL available".to_string())
            })?;
        let direct_addresses = self
            .endpoint
            .addr()
            .ip_addrs()
            .map(|addr| addr.to_string())
            .collect();

        Ok(reconcile_document_ma_iroh_fields(
            document,
            node_id,
            relay_url,
            direct_addresses,
        ))
    }

    /// Open a persistent write-only [`Channel`] to a remote endpoint.
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

        let route = extract_ma_iroh_route(doc.ma.as_ref());
        let addr = self.resolve_addr_with_route(&endpoint_id, route)?;

        let channel = self.open_addr(addr, protocol).await?;
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
            for direct_addr in route.direct_addresses {
                addr = addr.with_ip_addr(direct_addr);
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
    direct_addresses: Vec<SocketAddr>,
}

fn extract_ma_iroh_route(ma: Option<&Ipld>) -> Option<MaIrohRoute> {
    let iroh = ma.and_then(|ma_root| ma_root.get(MA_IROH_KEY).ok().flatten())?;
    let iroh_json = serde_json::to_value(iroh).ok()?;
    let iroh_obj = iroh_json.as_object()?;

    let relay_url = iroh_obj
        .get(MA_IROH_RELAY_URL_KEY)
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<RelayUrl>().ok());

    let direct_addresses = iroh_obj
        .get(MA_IROH_DIRECT_ADDRESSES_KEY)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| s.parse::<SocketAddr>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(MaIrohRoute {
        relay_url,
        direct_addresses,
    })
}

fn reconcile_document_ma_iroh_fields(
    document: &mut Document,
    node_id: String,
    relay_url: String,
    direct_addresses: Vec<String>,
) -> bool {
    let mut ma_root = match &document.ma {
        Some(Ipld::Map(map)) => map.clone(),
        _ => BTreeMap::new(),
    };

    let next = ma_iroh_ipld(node_id, relay_url, direct_addresses);
    let unchanged = ma_root.get(MA_IROH_KEY) == Some(&next);
    if unchanged {
        return false;
    }

    ma_root.insert(MA_IROH_KEY.to_string(), next);
    document.set_ma(Ipld::Map(ma_root));
    document.updated_at = now_iso_utc();
    true
}

fn ma_iroh_ipld(node_id: String, relay_url: String, direct_addresses: Vec<String>) -> Ipld {
    let mut normalized_direct = direct_addresses;
    normalized_direct.sort();
    normalized_direct.dedup();

    let mut iroh = BTreeMap::new();
    iroh.insert(MA_IROH_NODE_ID_KEY.to_string(), Ipld::String(node_id));
    iroh.insert(MA_IROH_RELAY_URL_KEY.to_string(), Ipld::String(relay_url));
    iroh.insert(
        MA_IROH_DIRECT_ADDRESSES_KEY.to_string(),
        Ipld::List(normalized_direct.into_iter().map(Ipld::String).collect()),
    );
    Ipld::Map(iroh)
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

#[cfg(test)]
mod tests {
    use super::{
        extract_ma_iroh_route, reconcile_document_ma_iroh_fields, MA_IROH_DIRECT_ADDRESSES_KEY,
        MA_IROH_KEY, MA_IROH_RELAY_URL_KEY,
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
            vec!["198.51.100.1:4001".to_string()],
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
            vec![
                "203.0.113.1:4001".to_string(),
                "198.51.100.1:4001".to_string(),
                "198.51.100.1:4001".to_string(),
            ],
        );

        let changed = reconcile_document_ma_iroh_fields(
            &mut doc,
            "abc123".to_string(),
            "https://relay.example".to_string(),
            vec![
                "198.51.100.1:4001".to_string(),
                "203.0.113.1:4001".to_string(),
            ],
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
            vec!["203.0.113.1:4001".to_string()],
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
        let direct = iroh_map
            .get(MA_IROH_DIRECT_ADDRESSES_KEY)
            .expect("direct addresses should be present");
        assert!(matches!(direct, Ipld::List(_)));
    }

    #[test]
    fn extract_ma_iroh_route_parses_relay_and_direct_addresses() {
        let mut iroh = BTreeMap::new();
        iroh.insert(
            MA_IROH_RELAY_URL_KEY.to_string(),
            Ipld::String("https://relay.example".to_string()),
        );
        iroh.insert(
            MA_IROH_DIRECT_ADDRESSES_KEY.to_string(),
            Ipld::List(vec![
                Ipld::String("127.0.0.1:7000".to_string()),
                Ipld::String("invalid-address".to_string()),
                Ipld::String("192.0.2.10:7777".to_string()),
            ]),
        );

        let mut ma = BTreeMap::new();
        ma.insert(MA_IROH_KEY.to_string(), Ipld::Map(iroh));

        let route = extract_ma_iroh_route(Some(&Ipld::Map(ma))).expect("route should parse");
        assert!(route.relay_url.is_some());
        assert_eq!(route.direct_addresses.len(), 2);
    }

    #[test]
    fn extract_ma_iroh_route_returns_none_without_iroh() {
        let ma = Ipld::Map(BTreeMap::new());
        let route = extract_ma_iroh_route(Some(&ma));
        assert!(route.is_none());
    }
}
