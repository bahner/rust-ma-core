#[cfg(not(target_arch = "wasm32"))]
use web_time::{SystemTime, UNIX_EPOCH};
// Iroh-backed [`MaEndpoint`] implementation.

use async_trait::async_trait;
use iroh::{
    endpoint::{presets, Connection, SendStream},
    protocol::{AcceptError, ProtocolHandler, Router},
    Endpoint, EndpointAddr, EndpointId, SecretKey,
};
use tokio::io::AsyncWriteExt;
#[cfg(not(target_arch = "wasm32"))]
use tokio::time::timeout;
use tracing::debug;
#[cfg(not(target_arch = "wasm32"))]
use tracing::warn;

use crate::endpoint::{MaEndpoint, DEFAULT_INBOX_CAPACITY};
use crate::error::{Error, Result};
use crate::inbox::Inbox;
use crate::iroh::channel::Channel;
use crate::outbox::{Outbox, OutboxWire};
use crate::transport::transport_string;
use crate::{Document, Message};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;

const DEFAULT_MAX_INBOUND_MESSAGE_SIZE: usize = 1024 * 1024;
/// Maximum time to wait for a complete inbound stream before treating the
/// connection as a slowloris/stall attack and dropping it.
const DEFAULT_INBOUND_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

type ConnectLocks = Mutex<HashMap<(String, String), Arc<AsyncMutex<()>>>>;

/// An iroh-backed ma endpoint.
pub struct IrohEndpoint {
    endpoint: Endpoint,
    protocols: Vec<String>,
    inboxes: BTreeMap<String, Inbox<Message>>,
    router: Option<Router>,
    /// Cached open connections keyed by (`endpoint_id`, protocol).
    ///
    /// Keeping a `Connection` clone alive prevents iroh from sending
    /// `APPLICATION_CLOSE` when a `Channel` is dropped after sending,
    /// which would otherwise race with the receiver's `accept_bi()` loop.
    ///
    /// Shared with `InboxProtocolHandler` so that inbound connections from
    /// NAT-ed peers (e.g. browser wasm) are cached and reused for replies.
    connection_cache: Arc<Mutex<HashMap<(String, String), Connection>>>,
    /// Per-`(endpoint_id, protocol)` mutex that serialises concurrent fresh-connection
    /// attempts to the *same* peer+protocol pair.
    ///
    /// Using one lock per key (rather than a single global lock) means a hung or slow
    /// connection attempt to one peer can never block connections to a different peer.
    connect_locks: ConnectLocks,
}

impl IrohEndpoint {
    /// Create an endpoint from raw 32-byte secret key material.
    ///
    /// When `ipv6` is `false` the endpoint binds an IPv4-only socket
    /// (`0.0.0.0:0`). This suppresses the `NetworkUnreachable` warnings that
    /// appear on hosts without a working IPv6 stack.
    pub async fn new(secret_bytes: [u8; 32], ipv6: bool) -> Result<Self> {
        let secret = SecretKey::from_bytes(&secret_bytes);
        let endpoint = if ipv6 {
            Endpoint::builder(presets::N0)
                .secret_key(secret)
                .bind()
                .await
                .map_err(|e| Error::Transport(format!("endpoint bind failed: {e}")))?
        } else {
            #[cfg(not(target_arch = "wasm32"))]
            let ep = Endpoint::builder(presets::N0)
                .secret_key(secret)
                .clear_ip_transports()
                .bind_addr("0.0.0.0:0")
                .map_err(|e| Error::Transport(format!("endpoint bind_addr failed: {e}")))?
                .bind()
                .await
                .map_err(|e| Error::Transport(format!("endpoint bind failed: {e}")))?;
            #[cfg(target_arch = "wasm32")]
            let ep = Endpoint::builder(presets::N0)
                .secret_key(secret)
                .bind()
                .await
                .map_err(|e| Error::Transport(format!("endpoint bind failed: {e}")))?;
            ep
        };
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
            connection_cache: Arc::new(Mutex::new(HashMap::new())),
            connect_locks: Mutex::new(HashMap::new()),
        })
    }

    /// Access the underlying iroh endpoint (for Router setup, etc.).
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
        let (send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| Error::Transport(format!("open_bi failed: {e}")))?;
        let _ = recv.stop(0u32.into());
        Ok(Channel::new(connection, send))
    }

    /// Try to reuse a cached connection for `cache_key`, if one exists.
    ///
    /// Returns `Some(Channel)` if a working cached connection was found and
    /// `open_bi` succeeded, or `None` if the entry was absent, already closed,
    /// or stale (in which case the entry is evicted so the caller can reconnect).
    async fn try_cached_channel(
        &self,
        cache_key: &(String, String),
        endpoint_id: &str,
        protocol: &str,
        label: &str,
    ) -> Option<Channel> {
        let conn = self
            .connection_cache
            .lock()
            .unwrap()
            .get(cache_key)
            .cloned()?;

        if conn.close_reason().is_some() {
            debug!(
                endpoint_id,
                protocol, "cached connection already closed{}, evicting", label
            );
            self.evict_if_closed(cache_key);
            return None;
        }

        match conn.open_bi().await {
            Ok((send, mut recv)) => {
                let _ = recv.stop(0u32.into());
                debug!(endpoint_id, protocol, "reusing cached connection{}", label);
                Some(Channel::new(conn, send))
            }
            Err(err) => {
                debug!(
                    endpoint_id,
                    protocol,
                    error = %err,
                    "cached connection stale{}, reconnecting",
                    label,
                );
                self.evict_if_closed(cache_key);
                None
            }
        }
    }

    /// Spawn a per-connection `accept_bi()` loop on an **outbound** connection
    /// so that streams the remote opens on it reach the correct inbox.
    ///
    /// The iroh `Router` only watches connections from `endpoint.accept()`
    /// (connections the remote dialled into us).  When we dial out first and
    /// the remote caches and reuses *our* connection to send its next message
    /// (exactly what a NAT-ed browser peer does), the Router never sees those
    /// streams — without this loop they are silently discarded and the peer's
    /// messages black-hole.  Mirrors the wasm loop in [`get_or_connect`] and
    /// the inbound path in [`InboxProtocolHandler::accept`].
    ///
    /// The loop exits when the connection closes (`accept_bi` fails).
    #[cfg(not(target_arch = "wasm32"))]
    fn spawn_outbound_accept_loop(&self, connection: &Connection, protocol: &str) {
        let normalized = normalize_protocol(protocol);
        let Some(inbox) = self.inboxes.get(&normalized) else {
            // No local service registered for this protocol — nothing could
            // consume inbound streams, so don't spawn a loop.
            return;
        };
        let inbox = inbox.clone();
        let conn = connection.clone();
        tokio::spawn(async move {
            loop {
                let (mut send, mut recv) = match conn.accept_bi().await {
                    Ok(streams) => streams,
                    Err(err) => {
                        debug!(
                            protocol = %normalized,
                            remote = %conn.remote_id(),
                            error = %err,
                            "outbound connection closed; accept loop ended"
                        );
                        break;
                    }
                };
                let inbox = inbox.clone();
                let proto = normalized.clone();
                let remote = conn.remote_id();
                tokio::spawn(async move {
                    let payload = match timeout(
                        DEFAULT_INBOUND_READ_TIMEOUT,
                        recv.read_to_end(DEFAULT_MAX_INBOUND_MESSAGE_SIZE),
                    )
                    .await
                    {
                        Ok(Ok(payload)) => payload,
                        Ok(Err(err)) => {
                            warn!(
                                protocol = %proto,
                                remote = %remote,
                                error = %err,
                                "failed to read inbound stream on outbound connection"
                            );
                            let _ = send.finish();
                            return;
                        }
                        Err(_elapsed) => {
                            warn!(
                                protocol = %proto,
                                remote = %remote,
                                "inbound stream read on outbound connection timed out — dropping stream"
                            );
                            let _ = send.finish();
                            return;
                        }
                    };

                    let _ = send.finish();

                    let message = match Message::decode(&payload) {
                        Ok(message) => message,
                        Err(err) => {
                            warn!(
                                protocol = %proto,
                                remote = %remote,
                                error = %err,
                                "invalid inbound message payload on outbound connection"
                            );
                            return;
                        }
                    };

                    if let Err(err) = message.headers().validate() {
                        warn!(
                            protocol = %proto,
                            remote = %remote,
                            error = %err,
                            "invalid inbound message headers on outbound connection"
                        );
                        return;
                    }

                    inbox.push(now_secs(), message.exp, message);
                });
            }
        });
    }

    /// Evict the cache entry for `cache_key` only if the current entry is
    /// already closed.
    ///
    /// This prevents a TOCTOU race in [`try_cached_channel`]: the connection is
    /// cloned under one lock acquisition and the eviction requires a second one.
    /// In the window between the two, a concurrent slow-path task may have
    /// already evicted the stale entry and inserted a fresh, live connection.
    /// A blind `remove(key)` would then delete that fresh connection, forcing
    /// yet another reconnect on the next call.
    ///
    /// By re-checking `close_reason()` inside the lock we ensure we only evict
    /// an entry that is still dead.  If another task has already replaced it
    /// with a live connection (`close_reason() == None`), we leave it alone;
    /// the slow-path reconnect that follows will overwrite the bad entry anyway.
    fn evict_if_closed(&self, cache_key: &(String, String)) {
        let mut cache = self.connection_cache.lock().unwrap();
        if cache
            .get(cache_key)
            .is_some_and(|c| c.close_reason().is_some())
        {
            cache.remove(cache_key);
        }
    }

    /// Like [`open_addr`] but reuses a cached connection when available.
    ///
    /// The cache stores a `Connection` clone.  Because iroh `Connection` is an
    /// `Arc`-backed handle, keeping one clone in the cache prevents the QUIC
    /// connection from being torn down when the `Channel` returned to the
    /// caller is later dropped.  This eliminates the race between the sender
    /// dropping its connection handle and the receiver's `accept_bi()` loop.
    ///
    /// If the cached connection is stale (remote restarted, idle timeout, etc.)
    /// `open_bi()` will return an error; in that case the entry is evicted and
    /// a fresh connection is established and cached in its place.
    async fn open_addr_cached(
        &self,
        endpoint_id: &str,
        addr: EndpointAddr,
        protocol: &str,
    ) -> Result<Channel> {
        let cache_key = (endpoint_id.to_string(), protocol.to_string());

        // Fast path: try to reuse an existing open connection (no async lock needed).
        if let Some(channel) = self
            .try_cached_channel(&cache_key, endpoint_id, protocol, "")
            .await
        {
            return Ok(channel);
        }

        // Slow path: serialise concurrent fresh-connection attempts *per key*.
        // Tasks blocked here will re-check the cache below and reuse the
        // connection established by whoever went first.
        // Using a per-key lock means a hung connect() to one peer can never
        // block connections to a different peer or a different protocol.
        let peer_lock = {
            let mut locks = self.connect_locks.lock().unwrap();
            locks
                .entry(cache_key.clone())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        let _connect_guard = peer_lock.lock().await;

        // Re-check after acquiring the lock — another task may have just
        // connected and cached the result while we were waiting.
        if let Some(channel) = self
            .try_cached_channel(&cache_key, endpoint_id, protocol, " (post-lock)")
            .await
        {
            return Ok(channel);
        }

        // Establish a fresh connection and cache a clone.
        let connection = self
            .endpoint
            .connect(addr, protocol.as_bytes())
            .await
            .map_err(|e| Error::Transport(format!("connect failed: {e}")))?;
        let (send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| Error::Transport(format!("open_bi failed: {e}")))?;
        let _ = recv.stop(0u32.into());

        self.connection_cache
            .lock()
            .unwrap()
            .insert(cache_key, connection.clone());

        // The remote may cache and reuse this connection for its own sends;
        // service those streams so they are not black-holed (the Router only
        // watches inbound connections).
        #[cfg(not(target_arch = "wasm32"))]
        self.spawn_outbound_accept_loop(&connection, protocol);

        Ok(Channel::new(connection, send))
    }

    /// Shut down the endpoint.
    pub async fn close(&mut self) {
        // Gracefully close all cached connections before shutting down.
        let connections: Vec<Connection> = self
            .connection_cache
            .lock()
            .unwrap()
            .drain()
            .map(|(_, conn)| conn)
            .collect();
        for conn in connections {
            conn.close(0u32.into(), b"done");
        }

        // Close the underlying endpoint first. This sends CONNECTION_CLOSE to
        // all peers — including inbound connections managed by the router —
        // causing every accept_bi() to return an error and break out of the
        // accept loop. Without this, router.shutdown() waits forever for
        // accept() tasks that are blocked on accept_bi() waiting for the next
        // inbound stream from a peer that may never open one.
        self.endpoint.close().await;

        if let Some(router) = self.router.take() {
            let _ = router.shutdown().await;
        }
    }

    /// Start the inbound router for all registered services.
    pub fn start_router(&mut self) {
        if self.router.is_some() {
            return;
        }

        let mut builder = Router::builder(self.endpoint.clone());
        for protocol in &self.protocols {
            if let Some(inbox) = self.inboxes.get(protocol) {
                let handler = InboxProtocolHandler::new(
                    protocol.clone(),
                    inbox.clone(),
                    Arc::clone(&self.connection_cache),
                );
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

    /// Get an existing cached connection to `endpoint_id`/`protocol`, or establish a
    /// new one.
    ///
    /// Unlike [`open_addr_cached`] this does **not** open a bi-directional stream on the
    /// connection.  Use this when you want to warm up the connection for future sends
    /// without causing the accepting side to block on an idle stream.
    #[allow(clippy::too_many_lines)]
    async fn get_or_connect(
        &self,
        endpoint_id: &str,
        addr: EndpointAddr,
        protocol: &str,
    ) -> Result<Connection> {
        let cache_key = (endpoint_id.to_string(), protocol.to_string());

        // Fast path: reuse live cached connection.
        // NOTE: The MutexGuard must be dropped before calling evict_if_closed
        // (which also locks connection_cache). Using a `let` statement rather
        // than `if let` ensures the guard is released at the semicolon and not
        // extended to the end of the block by Rust's temporary-lifetime rules.
        let maybe_conn = self
            .connection_cache
            .lock()
            .unwrap()
            .get(&cache_key)
            .cloned();
        if let Some(conn) = maybe_conn {
            if conn.close_reason().is_none() {
                debug!(endpoint_id, protocol, "reusing cached connection");
                return Ok(conn);
            }
            self.evict_if_closed(&cache_key);
        }

        // Slow path: serialise concurrent fresh-connection attempts per key.
        let peer_lock = {
            let mut locks = self.connect_locks.lock().unwrap();
            locks
                .entry(cache_key.clone())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        let _connect_guard = peer_lock.lock().await;

        // Re-check after acquiring the lock.
        // Same MutexGuard-lifetime fix as the fast path above.
        let maybe_conn_post = self
            .connection_cache
            .lock()
            .unwrap()
            .get(&cache_key)
            .cloned();
        if let Some(conn) = maybe_conn_post {
            if conn.close_reason().is_none() {
                debug!(
                    endpoint_id,
                    protocol, "reusing cached connection (post-lock)"
                );
                return Ok(conn);
            }
            self.evict_if_closed(&cache_key);
        }

        // Establish a fresh connection and cache it.
        let connection = self
            .endpoint
            .connect(addr, protocol.as_bytes())
            .await
            .map_err(|e| Error::Transport(format!("connect failed: {e}")))?;

        self.connection_cache
            .lock()
            .unwrap()
            .insert(cache_key, connection.clone());

        // The iroh Router only watches connections from endpoint.accept().
        // When the remote reuses our outbound connection to send its next
        // message (NAT-ed browser peers do exactly this), the Router never
        // sees those streams — service them here so they reach the inbox.
        #[cfg(not(target_arch = "wasm32"))]
        self.spawn_outbound_accept_loop(&connection, protocol);

        // In WASM the iroh Router only watches connections from endpoint.accept()
        // (connections the remote dialled into us). When the remote reuses our
        // outbound connection to open a reply stream, the Router never sees it.
        // Spawn a per-connection accept_bi() loop so those reply streams reach
        // the correct inbox regardless of which connection path the remote uses.
        #[cfg(target_arch = "wasm32")]
        {
            let normalized = normalize_protocol(protocol);
            if let Some(inbox) = self.inboxes.get(&normalized) {
                let inbox_clone = inbox.clone();
                let conn_clone = connection.clone();
                let proto_label = normalized.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    loop {
                        match conn_clone.accept_bi().await {
                            Ok((mut send, mut recv)) => {
                                let inbox = inbox_clone.clone();
                                let label = proto_label.clone();
                                wasm_bindgen_futures::spawn_local(async move {
                                    web_sys::console::info_1(
                                        &format!("[iroh] reply stream on outbound conn: protocol={label}").into(),
                                    );
                                    let payload = match recv
                                        .read_to_end(DEFAULT_MAX_INBOUND_MESSAGE_SIZE)
                                        .await
                                    {
                                        Ok(p) => p,
                                        Err(e) => {
                                            web_sys::console::warn_1(
                                                &format!(
                                                    "[iroh] outbound reply stream read error: {e}"
                                                )
                                                .into(),
                                            );
                                            let _ = send.finish();
                                            return;
                                        }
                                    };
                                    let _ = send.finish();
                                    let message = match Message::decode(&payload) {
                                        Ok(m) => m,
                                        Err(e) => {
                                            web_sys::console::warn_1(
                                                &format!("[iroh] outbound reply decode error: {e}")
                                                    .into(),
                                            );
                                            return;
                                        }
                                    };
                                    if let Err(e) = message.headers().validate() {
                                        web_sys::console::warn_1(
                                            &format!("[iroh] outbound reply headers invalid: {e}")
                                                .into(),
                                        );
                                        return;
                                    }
                                    web_sys::console::info_1(
                                        &format!("[iroh] outbound reply push: protocol={label} msg_id={}", message.id).into(),
                                    );
                                    inbox.push(now_secs(), message.exp, message);
                                });
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        }

        Ok(connection)
    }

    fn resolve_addr(&self, endpoint_id: &str) -> Result<EndpointAddr> {
        let target_id: EndpointId = endpoint_id
            .trim()
            .parse()
            .map_err(|e| Error::Transport(format!("invalid endpoint id: {e}")))?;

        let mut addr = EndpointAddr::new(target_id);

        // Add local relay URL as a routing hint.
        // DNS-based address lookup is not available in wasm_browser, so without
        // a relay hint the connect will time out. Both endpoints use the N0
        // preset whose relays interconnect, so any N0 relay URL is a valid hint.
        if let Some(relay_url) = self.endpoint.addr().relay_urls().next() {
            addr = addr.with_relay_url(relay_url.clone());
        }
        Ok(addr)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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
        _doc: &Document,
        endpoint_id: &str,
        did: &str,
        protocol: &str,
    ) -> Result<Outbox> {
        if endpoint_id == self.id() {
            let normalized = normalize_protocol(protocol);
            let inbox = self
                .inboxes
                .get(&normalized)
                .ok_or_else(|| Error::NoInboxTransport(format!("no local inbox for {protocol}")))?;
            return Ok(Outbox::from_transport(
                LoopbackWire {
                    inbox: inbox.clone(),
                },
                did.to_string(),
                protocol.to_string(),
            ));
        }
        let addr = self.resolve_addr(endpoint_id)?;
        // Use get_or_connect rather than open_addr_cached so that no bi-directional
        // stream is opened proactively.  Opening a stream here would cause the
        // accepting side's read_to_end() to block until the stream is finished,
        // which only happens when the Outbox is dropped — leading to accept-handler
        // timeouts when the Outbox is held idle between sends.
        let connection = self.get_or_connect(endpoint_id, addr, protocol).await?;
        Ok(Outbox::from_transport(
            CachedChannel { connection },
            did.to_string(),
            protocol.to_string(),
        ))
    }

    async fn send_to(&self, target: &str, protocol: &str, message: &Message) -> Result<()> {
        message.headers().validate()?;
        if target == self.id() {
            let normalized = normalize_protocol(protocol);
            let inbox = self
                .inboxes
                .get(&normalized)
                .ok_or_else(|| Error::NoInboxTransport(format!("no local inbox for {protocol}")))?;
            inbox.push(now_secs(), message.exp, message.clone());
            return Ok(());
        }
        let cbor = message.encode()?;
        let addr = self.resolve_addr(target)?;
        let mut channel = self.open_addr_cached(target, addr, protocol).await?;
        channel.send(&cbor).await?;
        Ok(())
    }

    async fn close(&mut self) {
        IrohEndpoint::close(self).await;
    }
}

/// Delivers a message directly into a local [`Inbox`] without going through
/// the iroh transport layer.
///
/// iroh rejects QUIC connections where the target is the sender's own endpoint
/// ID. For self-addressed messages we bypass the network entirely and push
/// straight into the registered inbox — which is both correct per Hewitt's
/// actor model and more efficient than a loopback network hop.
#[derive(Debug)]
struct LoopbackWire {
    inbox: Inbox<Message>,
}

#[async_trait]
impl OutboxWire for LoopbackWire {
    async fn send_payload(&mut self, payload: &[u8]) -> Result<()> {
        let message = Message::decode(payload)?;
        message.headers().validate()?;
        self.inbox.push(now_secs(), message.exp, message);
        Ok(())
    }

    fn close_box(self: Box<Self>) {}
}

/// A write handle backed by a persistent cached [`Connection`].
///
/// Unlike [`Channel`], `CachedChannel` opens a **new** bi-directional stream
/// for every message and finishes it immediately after sending.  This prevents
/// the accepting side's `read_to_end()` from waiting indefinitely on an idle
/// stream while the outbox is held between sends, which would otherwise cause
/// the iroh Router to time out the accept handler.
#[derive(Debug)]
struct CachedChannel {
    connection: Connection,
}

#[async_trait]
impl OutboxWire for CachedChannel {
    async fn send_payload(&mut self, payload: &[u8]) -> Result<()> {
        let (mut send, mut recv): (SendStream, _) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| Error::Transport(format!("open_bi failed: {e}")))?;
        // Explicitly stop the recv half immediately — we never read from it.
        // This sends STOP_SENDING to the remote rather than relying on Drop.
        let _ = recv.stop(0u32.into());
        send.write_all(payload)
            .await
            .map_err(|e| Error::Transport(format!("channel write failed: {e}")))?;
        send.flush()
            .await
            .map_err(|e| Error::Transport(format!("channel flush failed: {e}")))?;
        let _ = send.finish();
        Ok(())
    }

    /// The underlying connection is owned by the endpoint's connection cache,
    /// not by this handle.  Dropping this clone does not close the connection;
    /// the cache clone keeps it alive until `IrohEndpoint::close()` is called.
    fn close_box(self: Box<Self>) {}
}

#[derive(Debug, Clone)]
struct InboxProtocolHandler {
    protocol: String,
    inbox: Inbox<Message>,
    max_message_size: usize,
    /// Shared with `IrohEndpoint` — inbound connections are inserted here so
    /// the outbound send path can reuse them for replies to NAT-ed peers.
    connection_cache: Arc<Mutex<HashMap<(String, String), Connection>>>,
}

impl InboxProtocolHandler {
    fn new(
        protocol: String,
        inbox: Inbox<Message>,
        connection_cache: Arc<Mutex<HashMap<(String, String), Connection>>>,
    ) -> Self {
        Self {
            protocol,
            inbox,
            max_message_size: DEFAULT_MAX_INBOUND_MESSAGE_SIZE,
            connection_cache,
        }
    }
}

impl ProtocolHandler for InboxProtocolHandler {
    #[allow(clippy::too_many_lines)]
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        // Cache this inbound connection so the outbound send path can reuse it
        // for replies without needing to open a new connection back through NAT.
        let cache_key = (connection.remote_id().to_string(), self.protocol.clone());
        self.connection_cache
            .lock()
            .unwrap()
            .insert(cache_key.clone(), connection.clone());

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
                    #[cfg(target_arch = "wasm32")]
                    web_sys::console::warn_1(
                        &format!(
                            "[iroh] accept_bi closed: protocol={} remote={} err={}",
                            self.protocol,
                            connection.remote_id(),
                            err
                        )
                        .into(),
                    );
                    break;
                }
            };

            // stream cannot block `accept_bi()` from picking up the next stream
            // on the same connection.
            let handler = self.clone();
            let remote_id = connection.remote_id();

            #[cfg(not(target_arch = "wasm32"))]
            tokio::spawn(async move {
                let payload = match timeout(
                    DEFAULT_INBOUND_READ_TIMEOUT,
                    recv.read_to_end(handler.max_message_size),
                )
                .await
                {
                    Ok(Ok(payload)) => payload,
                    Ok(Err(err)) => {
                        warn!(
                            protocol = %handler.protocol,
                            remote = %remote_id,
                            error = %err,
                            "failed to read inbound stream"
                        );
                        let _ = send.finish();
                        return;
                    }
                    Err(_elapsed) => {
                        warn!(
                            protocol = %handler.protocol,
                            remote = %remote_id,
                            "inbound stream read timed out — dropping stream"
                        );
                        let _ = send.finish();
                        return;
                    }
                };

                let _ = send.finish();

                let message = match Message::decode(&payload) {
                    Ok(message) => message,
                    Err(err) => {
                        warn!(
                            protocol = %handler.protocol,
                            remote = %remote_id,
                            error = %err,
                            "invalid inbound message payload"
                        );
                        return;
                    }
                };

                if let Err(err) = message.headers().validate() {
                    warn!(
                        protocol = %handler.protocol,
                        remote = %remote_id,
                        error = %err,
                        "invalid inbound message headers"
                    );
                    return;
                }

                handler.inbox.push(now_secs(), message.exp, message);
            });

            #[cfg(target_arch = "wasm32")]
            wasm_bindgen_futures::spawn_local(async move {
                web_sys::console::info_1(
                    &format!(
                        "[iroh] inbound stream: protocol={} remote={}",
                        handler.protocol, remote_id
                    )
                    .into(),
                );
                let payload = match recv.read_to_end(handler.max_message_size).await {
                    Ok(payload) => payload,
                    Err(err) => {
                        web_sys::console::warn_1(
                            &format!("[iroh] failed to read inbound stream: protocol={} remote={} err={}", handler.protocol, remote_id, err).into(),
                        );
                        let _ = send.finish();
                        return;
                    }
                };

                let _ = send.finish();

                let message = match Message::decode(&payload) {
                    Ok(message) => message,
                    Err(err) => {
                        web_sys::console::warn_1(
                            &format!("[iroh] invalid inbound message payload: protocol={} remote={} err={}", handler.protocol, remote_id, err).into(),
                        );
                        return;
                    }
                };

                if let Err(err) = message.headers().validate() {
                    web_sys::console::warn_1(
                        &format!(
                            "[iroh] invalid inbound message headers: protocol={} remote={} err={}",
                            handler.protocol, remote_id, err
                        )
                        .into(),
                    );
                    return;
                }

                web_sys::console::debug_1(
                    &format!(
                        "[iroh] inbox push: protocol={} msg_id={}",
                        handler.protocol, message.id
                    )
                    .into(),
                );

                handler.inbox.push(now_secs(), message.exp, message);
            });
        }

        // Connection closed — evict from cache so stale entries don't block
        // future reconnects from the same peer.
        self.connection_cache.lock().unwrap().remove(&cache_key);

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
    #[cfg(target_arch = "wasm32")]
    {
        return (js_sys::Date::now() / 1000.0).floor() as u64;
    }

    #[cfg(not(target_arch = "wasm32"))]
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
    use crate::{Did, Document};

    fn test_doc() -> Document {
        let did = Did::new_url(
            "k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr",
            None::<String>,
        )
        .expect("valid did");
        Document::new(&did, &did)
    }

    // ─── IrohEndpoint service/router lifecycle tests ─────────────────────────

    fn test_secret() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = 42;
        bytes
    }

    fn test_message() -> crate::Message {
        use crate::{Did, SigningKey};
        let did =
            Did::new_identity("k51qzi5uqu5dkkciu33khkzbcmxtyhn376i1e83tya8kuy7z9euedzyr5nhoew")
                .expect("valid did");
        let did_id = did.id();
        let sk = SigningKey::generate(did).expect("signing key");
        crate::Message::new(
            did_id,
            String::new(),
            crate::service::MESSAGE_TYPE_BROADCAST,
            "application/octet-stream",
            b"test",
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

        let mut endpoint = IrohEndpoint::new(test_secret(), true).await.unwrap();
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

        let mut endpoint = IrohEndpoint::new(test_secret(), true).await.unwrap();
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

        let mut endpoint = IrohEndpoint::new(test_secret(), true).await.unwrap();
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

        let mut endpoint = IrohEndpoint::new(test_secret(), true).await.unwrap();
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

    // Reproduces the "runtime stops receiving RPC after dialling out" bug:
    // A dials B (A's connection is cached on both sides), then B *reuses* the
    // cached inbound connection to send back to A.  Without the outbound
    // accept loop, A's Router never sees B's stream and the message
    // black-holes.  With the fix it must arrive in A's inbox.
    #[tokio::test]
    #[ignore = "requires iroh network runtime"]
    async fn outbound_connection_receives_reply_streams() {
        use super::IrohEndpoint;
        use crate::endpoint::MaEndpoint;

        let mut secret_a = test_secret();
        secret_a[1] = 1;
        let mut secret_b = test_secret();
        secret_b[1] = 2;

        let mut a = IrohEndpoint::new(secret_a, true).await.unwrap();
        let mut b = IrohEndpoint::new(secret_b, true).await.unwrap();
        let a_inbox = a.service("/ma/rpc/0.0.1");
        let _b_inbox = b.service("/ma/rpc/0.0.1");

        // A dials B (as the runtime does when delivering a reply to a peer
        // that never dialled it first).
        a.send_to(&b.id(), "/ma/rpc/0.0.1", &test_message())
            .await
            .expect("A -> B send failed");

        // Give B's accept handler time to cache the inbound connection.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(
            b.connection_cache
                .lock()
                .unwrap()
                .contains_key(&(a.id(), "/ma/rpc/0.0.1".to_string())),
            "B should have cached the inbound connection from A"
        );

        // B sends to A — send_to's cache fast path reuses the inbound
        // connection A dialled up, exercising A's outbound accept loop.
        b.send_to(&a.id(), "/ma/rpc/0.0.1", &test_message())
            .await
            .expect("B -> A send failed");

        // The message must arrive in A's inbox.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if !a_inbox.is_empty() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "BUG: message sent over A's outbound connection never reached A's inbox"
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        a.close().await;
        b.close().await;
    }

    // ─── Pure unit tests (no network) ────────────────────────────────────────

    #[test]
    fn normalize_protocol_adds_leading_slash() {
        use super::normalize_protocol;
        assert_eq!(normalize_protocol("ma/inbox/0.0.1"), "/ma/inbox/0.0.1");
    }

    #[test]
    fn normalize_protocol_preserves_existing_leading_slash() {
        use super::normalize_protocol;
        assert_eq!(normalize_protocol("/ma/inbox/0.0.1"), "/ma/inbox/0.0.1");
    }

    #[test]
    fn normalize_protocol_strips_multiple_leading_slashes() {
        use super::normalize_protocol;
        assert_eq!(normalize_protocol("///ma/custom/1.0"), "/ma/custom/1.0");
    }

    #[test]
    fn normalize_protocol_empty_string_stays_empty() {
        use super::normalize_protocol;
        assert_eq!(normalize_protocol(""), "");
    }

    #[test]
    fn normalize_protocol_whitespace_only_stays_empty() {
        use super::normalize_protocol;
        assert_eq!(normalize_protocol("   "), "");
    }

    #[test]
    fn message_created_at_secs_floors_fractional_value() {
        use super::message_created_at_secs;
        assert_eq!(message_created_at_secs(1_000_000.9), 1_000_000);
    }

    #[test]
    fn message_created_at_secs_zero_returns_zero() {
        use super::message_created_at_secs;
        assert_eq!(message_created_at_secs(0.0), 0);
    }

    #[test]
    fn message_created_at_secs_negative_returns_zero() {
        use super::message_created_at_secs;
        assert_eq!(message_created_at_secs(-1.0), 0);
    }

    #[test]
    fn message_created_at_secs_nan_returns_zero() {
        use super::message_created_at_secs;
        assert_eq!(message_created_at_secs(f64::NAN), 0);
    }

    #[test]
    fn message_created_at_secs_infinity_returns_zero() {
        use super::message_created_at_secs;
        // +Infinity is not finite → falls into the 0 branch.
        assert_eq!(message_created_at_secs(f64::INFINITY), 0);
    }

    #[test]
    fn message_created_at_secs_u64_max_returns_u64_max() {
        use super::message_created_at_secs;
        assert_eq!(message_created_at_secs(u64::MAX as f64), u64::MAX);
    }
}
