//! IPFS gateway DID document resolver traits and implementations.

#[cfg(target_arch = "wasm32")]
use async_trait::async_trait;
#[cfg(not(target_arch = "wasm32"))]
use async_trait::async_trait;
use did_ma::Document;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

/// Trait for resolving a DID to its DID document.
///
/// Ship with `IpfsGatewayResolver` for HTTP gateway resolution.
/// Implement this trait for custom resolution strategies.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait DidDocumentResolver: Send + Sync {
    async fn resolve(&self, did: &str) -> crate::error::Result<Document>;

    /// Update resolver cache TTLs at runtime.
    ///
    /// Default implementation is a no-op for resolvers without mutable cache policy.
    fn set_cache_ttls(&self, _positive_ttl: Duration, _negative_ttl: Duration) {}

    /// Return current resolver cache TTLs when supported.
    fn cache_ttls(&self) -> Option<(Duration, Duration)> {
        None
    }
}

/// Resolves DID documents via an IPFS/IPNS HTTP gateway.
///
/// The gateway must serve DID documents at `/ipns/<key-id>`.
pub struct IpfsGatewayResolver {
    gateways: Vec<String>,
    client: reqwest::Client,
    positive_ttl: Mutex<Duration>,
    negative_ttl: Mutex<Duration>,
    localhost_cooldown: Duration,
    cache: Mutex<HashMap<String, CacheEntry>>,
    localhost_blocked_until: Mutex<Option<Instant>>,
}

#[derive(Clone)]
struct CacheEntry {
    expires_at: Instant,
    value: CacheValue,
}

#[derive(Clone)]
enum CacheValue {
    Hit(String),
    Miss(String),
}

impl IpfsGatewayResolver {
    const LOCALHOST_GATEWAY: &'static str = "http://127.0.0.1:8080/";
    const DEFAULT_PUBLIC_GATEWAYS: [&'static str; 2] = ["https://dweb.link/", "https://w3s.link/"];

    pub fn new(gateway_url: impl Into<String>) -> Self {
        let primary = normalize_gateway_url(&gateway_url.into());

        let mut gateways = Vec::new();
        push_gateway(&mut gateways, Self::LOCALHOST_GATEWAY);
        push_gateway(&mut gateways, &primary);
        for fallback in Self::DEFAULT_PUBLIC_GATEWAYS {
            push_gateway(&mut gateways, fallback);
        }

        #[cfg(not(target_arch = "wasm32"))]
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(4))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        #[cfg(target_arch = "wasm32")]
        let client = reqwest::Client::builder()
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            gateways,
            client,
            positive_ttl: Mutex::new(Duration::from_mins(1)),
            negative_ttl: Mutex::new(Duration::from_secs(10)),
            localhost_cooldown: Duration::from_secs(20),
            cache: Mutex::new(HashMap::new()),
            localhost_blocked_until: Mutex::new(None),
        }
    }

    #[must_use]
    pub fn with_cache_ttls(self, positive_ttl: Duration, negative_ttl: Duration) -> Self {
        self.set_cache_ttls_inner(positive_ttl, negative_ttl);
        self
    }

    fn set_cache_ttls_inner(&self, positive_ttl: Duration, negative_ttl: Duration) {
        if let Ok(mut ttl) = self.positive_ttl.lock() {
            *ttl = positive_ttl;
        }
        if let Ok(mut ttl) = self.negative_ttl.lock() {
            *ttl = negative_ttl;
        }
    }

    fn positive_ttl(&self) -> Duration {
        self.positive_ttl
            .lock()
            .map_or(Duration::from_secs(0), |ttl| *ttl)
    }

    fn negative_ttl(&self) -> Duration {
        self.negative_ttl
            .lock()
            .map_or(Duration::from_secs(0), |ttl| *ttl)
    }

    #[must_use]
    pub fn with_localhost_cooldown(mut self, cooldown: Duration) -> Self {
        self.localhost_cooldown = cooldown;
        self
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DidDocumentResolver for IpfsGatewayResolver {
    async fn resolve(&self, did: &str) -> crate::error::Result<Document> {
        let parsed = did_ma::Did::try_from(did).map_err(crate::error::Error::Validation)?;
        let did_key = did.to_string();
        let positive_ttl = self.positive_ttl();
        let negative_ttl = self.negative_ttl();
        let cache_hit_enabled = !positive_ttl.is_zero();
        let cache_miss_enabled = !negative_ttl.is_zero();

        if let Some(cached) = self.read_cache(&did_key, cache_hit_enabled, cache_miss_enabled) {
            return match cached {
                CacheValue::Hit(body) => {
                    Document::unmarshal(&body).map_err(|e| crate::error::Error::Resolution {
                        did: did_key,
                        detail: format!("cached document parse failed: {e}"),
                    })
                }
                CacheValue::Miss(detail) => Err(crate::error::Error::Resolution {
                    did: did_key,
                    detail,
                }),
            };
        }

        let mut errors = Vec::new();
        let now = Instant::now();

        for gateway in &self.gateways {
            if is_localhost_gateway(gateway) && self.localhost_is_blocked(now) {
                errors.push(format!("{} -> skipped (cooldown)", gateway));
                continue;
            }

            let url = format!("{}ipns/{}", gateway, parsed.ipns);

            let response = match self.client.get(&url).send().await {
                Ok(response) => response,
                Err(err) => {
                    if is_localhost_gateway(gateway) {
                        self.block_localhost_until(Some(now + self.localhost_cooldown));
                    }
                    errors.push(format!("{url} -> {err}"));
                    continue;
                }
            };

            if !response.status().is_success() {
                if is_localhost_gateway(gateway) {
                    self.block_localhost_until(Some(now + self.localhost_cooldown));
                }
                errors.push(format!("{url} -> HTTP {}", response.status()));
                continue;
            }

            let body = match response.text().await {
                Ok(body) => body,
                Err(err) => {
                    if is_localhost_gateway(gateway) {
                        self.block_localhost_until(Some(now + self.localhost_cooldown));
                    }
                    errors.push(format!("{url} -> {err}"));
                    continue;
                }
            };

            let doc = match Document::unmarshal(&body) {
                Ok(doc) => doc,
                Err(err) => {
                    errors.push(format!("{url} -> invalid DID document: {err}"));
                    continue;
                }
            };

            if is_localhost_gateway(gateway) {
                self.block_localhost_until(None);
            }

            if cache_hit_enabled {
                self.write_cache(did_key.clone(), CacheValue::Hit(body), now + positive_ttl);
            }
            return Ok(doc);
        }

        let detail = format!("all gateways failed: {}", errors.join(" | "));
        if cache_miss_enabled {
            self.write_cache(
                did_key.clone(),
                CacheValue::Miss(detail.clone()),
                now + negative_ttl,
            );
        }

        Err(crate::error::Error::Resolution {
            did: did_key,
            detail,
        })
    }

    fn set_cache_ttls(&self, positive_ttl: Duration, negative_ttl: Duration) {
        self.set_cache_ttls_inner(positive_ttl, negative_ttl);
    }

    fn cache_ttls(&self) -> Option<(Duration, Duration)> {
        Some((self.positive_ttl(), self.negative_ttl()))
    }
}

impl IpfsGatewayResolver {
    fn read_cache(
        &self,
        did: &str,
        cache_hit_enabled: bool,
        cache_miss_enabled: bool,
    ) -> Option<CacheValue> {
        if !cache_hit_enabled && !cache_miss_enabled {
            return None;
        }

        let mut cache = self.cache.lock().ok()?;
        let entry = cache.get(did).cloned()?;
        if entry.expires_at <= Instant::now() {
            cache.remove(did);
            return None;
        }

        match entry.value {
            CacheValue::Hit(value) if cache_hit_enabled => Some(CacheValue::Hit(value)),
            CacheValue::Miss(value) if cache_miss_enabled => Some(CacheValue::Miss(value)),
            _ => None,
        }
    }

    fn write_cache(&self, did: String, value: CacheValue, expires_at: Instant) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(did, CacheEntry { expires_at, value });
        }
    }

    fn localhost_is_blocked(&self, now: Instant) -> bool {
        let guard = match self.localhost_blocked_until.lock() {
            Ok(guard) => guard,
            Err(_) => return false,
        };
        guard.as_ref().is_some_and(|blocked| *blocked > now)
    }

    fn block_localhost_until(&self, until: Option<Instant>) {
        if let Ok(mut guard) = self.localhost_blocked_until.lock() {
            *guard = until;
        }
    }
}

fn normalize_gateway_url(input: &str) -> String {
    let mut url = input.trim().to_string();
    if !url.ends_with('/') {
        url.push('/');
    }
    url
}

fn push_gateway(gateways: &mut Vec<String>, candidate: &str) {
    let normalized = normalize_gateway_url(candidate);
    if !gateways.iter().any(|g| g.eq_ignore_ascii_case(&normalized)) {
        gateways.push(normalized);
    }
}

fn is_localhost_gateway(gateway: &str) -> bool {
    gateway.starts_with("http://127.0.0.1:") || gateway.starts_with("http://localhost:")
}
