//! DID document resolution over the IPFS gateway pool.
//!
//! Thin composition layer: [`GatewayPool`] does the HTTP work, a
//! [`TtlCache`] remembers outcomes, and this module only knows how to turn
//! gateway bytes into validated [`Document`]s.

use super::gateway::GatewayPool;
use super::ttl_cache::{Cached, TtlCache};
use crate::Document;
use async_trait::async_trait;
use web_time::Duration;

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

/// Trait for resolving an `/ipns/<name>` path to its current `/ipfs/<cid>` path.
///
/// Implemented by [`IpfsGatewayResolver`] (HTTP gateways); alternative
/// backends (e.g. a local Kubo RPC) can implement it too.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait IpnsPathResolver: Send + Sync {
    async fn resolve_ipns_path(&self, path: &str) -> crate::error::Result<String>;
}

/// Resolves DID documents via an IPFS/IPNS HTTP gateway.
///
/// The gateway must serve DID documents at `/ipns/<key-id>`.
/// Cached document bytes and negative outcomes expire on independent TTLs.
pub struct IpfsGatewayResolver {
    pool: GatewayPool,
    cache: TtlCache<Vec<u8>>,
    ipns_cache: TtlCache<String>,
}

impl Default for IpfsGatewayResolver {
    /// Build a local-first resolver for development and native runtimes.
    fn default() -> Self {
        Self::from_pool(GatewayPool::default())
    }
}

impl From<GatewayPool> for IpfsGatewayResolver {
    fn from(pool: GatewayPool) -> Self {
        Self::from_pool(pool)
    }
}

impl IpfsGatewayResolver {
    /// Build a public-gateway resolver with no localhost probing.
    #[must_use]
    pub fn public_default() -> Self {
        Self::from_pool(GatewayPool::public_default())
    }

    /// Build a resolver using the caller-provided primary gateway followed by
    /// the standard public fallbacks. Localhost is used only if `gateway_url`
    /// itself points at localhost.
    #[must_use]
    pub fn new(gateway_url: impl Into<String>) -> Self {
        Self::from_pool(GatewayPool::new(gateway_url))
    }

    /// Build a local-first resolver: localhost, then the caller-provided
    /// primary gateway, then the standard public fallbacks.
    #[must_use]
    pub fn local_first(gateway_url: impl Into<String>) -> Self {
        Self::from_pool(GatewayPool::local_first(gateway_url))
    }

    fn from_pool(pool: GatewayPool) -> Self {
        Self {
            pool,
            cache: TtlCache::new(Duration::from_mins(1), Duration::from_secs(10)),
            ipns_cache: TtlCache::new(Duration::from_mins(1), Duration::from_secs(10)),
        }
    }

    /// The underlying gateway pool, for generic content fetches.
    #[must_use]
    pub fn pool(&self) -> &GatewayPool {
        &self.pool
    }

    #[must_use]
    pub fn with_cache_ttls(self, positive_ttl: Duration, negative_ttl: Duration) -> Self {
        self.cache.set_ttls(positive_ttl, negative_ttl);
        self.ipns_cache.set_ttls(positive_ttl, negative_ttl);
        self
    }

    /// Override the base per-gateway failure cooldown. The cooldown
    /// escalates Fibonacci-style per consecutive failure and resets on
    /// success. `Duration::ZERO` disables cooldowns entirely.
    #[must_use]
    pub fn with_base_cooldown(mut self, cooldown: Duration) -> Self {
        self.pool = self.pool.with_base_cooldown(cooldown);
        self
    }

    /// Override the per-request timeout (default 6 seconds). Covers the
    /// whole request, connection through body transfer.
    #[must_use]
    pub fn with_request_timeout(self, timeout: Duration) -> Self {
        self.pool.set_request_timeout(Some(timeout));
        self
    }

    /// Update the per-request timeout at runtime.
    /// Pass `None` to revert to the 6-second built-in default.
    pub fn set_request_timeout(&self, timeout: Option<Duration>) {
        self.pool.set_request_timeout(timeout);
    }

    /// Resolve an `/ipns/<name>` reference to its current `/ipfs/<cid>` path.
    pub async fn resolve_ipns_path(&self, path: &str) -> crate::error::Result<String> {
        self.resolve_ipns_path_cached(path).await
    }

    async fn resolve_ipns_path_cached(&self, path: &str) -> crate::error::Result<String> {
        if let Some(cached) = self.ipns_cache.read(path) {
            return Self::cached_ipns_result(cached, path);
        }

        let lock = self.ipns_cache.lock_for(path);
        let _guard = lock.lock().await;

        if let Some(cached) = self.ipns_cache.read(path) {
            self.ipns_cache.release_lock(path, &lock);
            return Self::cached_ipns_result(cached, path);
        }

        match self.pool.resolve_ipns_path(path).await {
            Ok(resolved) => {
                self.ipns_cache
                    .write_hit(path.to_string(), resolved.clone());
                self.ipns_cache.release_lock(path, &lock);
                Ok(resolved)
            }
            Err(e) => {
                let detail = e.to_string();
                self.ipns_cache.write_miss(path.to_string(), detail);
                self.ipns_cache.release_lock(path, &lock);
                Err(e)
            }
        }
    }

    fn cached_ipns_result(cached: Cached<String>, path: &str) -> crate::error::Result<String> {
        match cached {
            Cached::Hit(resolved) => Ok(resolved),
            Cached::Miss(detail) => Err(crate::error::Error::IpnsResolution {
                path: path.to_string(),
                detail,
            }),
        }
    }

    fn cached_result(cached: Cached<Vec<u8>>, did: String) -> crate::error::Result<Document> {
        match cached {
            Cached::Hit(body) => {
                parse_document_bytes(&body).map_err(|detail| crate::error::Error::Resolution {
                    did,
                    detail: format!("cached document parse failed: {detail}"),
                })
            }
            Cached::Miss(detail) => Err(crate::error::Error::Resolution { did, detail }),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DidDocumentResolver for IpfsGatewayResolver {
    async fn resolve(&self, did: &str) -> crate::error::Result<Document> {
        let parsed = crate::Did::try_from(did).map_err(crate::error::Error::Validation)?;
        // Always key by base DID — all DID-URLs under the same identity share one document.
        let did_key = parsed.base_id();

        if let Some(cached) = self.cache.read(&did_key) {
            return Self::cached_result(cached, did_key);
        }

        let resolve_lock = self.cache.lock_for(&did_key);
        let _resolve_guard = resolve_lock.lock().await;

        // Another caller may have populated the cache while this caller waited
        // for the per-DID lock.
        if let Some(cached) = self.cache.read(&did_key) {
            self.cache.release_lock(&did_key, &resolve_lock);
            return Self::cached_result(cached, did_key);
        }

        let path = format!("/ipns/{}", parsed.ipns);
        let fetched = self
            .pool
            .fetch(&path, Some("application/vnd.ipld.dag-cbor"), |body| {
                parse_document_bytes(body)
                    .map(|document| (document, body.to_vec()))
                    .map_err(|detail| format!("invalid DID document: {detail}"))
            })
            .await;

        match fetched {
            Ok((document, body)) => {
                self.cache.write_hit(did_key.clone(), body);
                self.cache.release_lock(&did_key, &resolve_lock);
                Ok(document)
            }
            Err(detail) => {
                tracing::warn!(did = %did_key, error = %detail, "DID document resolve failed");
                self.cache.write_miss(did_key.clone(), detail.clone());
                self.cache.release_lock(&did_key, &resolve_lock);
                Err(crate::error::Error::Resolution {
                    did: did_key,
                    detail,
                })
            }
        }
    }

    fn set_cache_ttls(&self, positive_ttl: Duration, negative_ttl: Duration) {
        self.cache.set_ttls(positive_ttl, negative_ttl);
        self.ipns_cache.set_ttls(positive_ttl, negative_ttl);
    }

    fn cache_ttls(&self) -> Option<(Duration, Duration)> {
        Some((self.cache.positive_ttl(), self.cache.negative_ttl()))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl IpnsPathResolver for IpfsGatewayResolver {
    async fn resolve_ipns_path(&self, path: &str) -> crate::error::Result<String> {
        self.resolve_ipns_path_cached(path).await
    }
}

fn parse_document_bytes(bytes: &[u8]) -> std::result::Result<Document, String> {
    let document =
        Document::decode(bytes).map_err(|err| format!("DAG-CBOR decode failed: {err}"))?;
    document
        .validate()
        .map_err(|err| format!("document validation failed: {err}"))?;
    document
        .verify()
        .map_err(|err| format!("document proof verification failed: {err}"))?;
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::{parse_document_bytes, IpfsGatewayResolver};
    use crate::{
        generate_identity_from_secret, ipfs::ttl_cache::Cached,
        multiformat::signature_multibase_encode, CODEC_EDDSA_SIG,
    };

    #[test]
    fn parses_dag_cbor_documents() {
        let identity = generate_identity_from_secret([7u8; 32]).expect("identity");
        let cbor = identity.document.encode().expect("cbor");
        let parsed = parse_document_bytes(&cbor).expect("parsed cbor");
        assert_eq!(parsed, identity.document);
    }

    #[test]
    fn rejects_non_document_payloads() {
        let err = parse_document_bytes(b"<html>nope</html>").expect_err("invalid payload");
        assert!(err.contains("DAG-CBOR decode failed"));
    }

    #[test]
    fn rejects_json_documents() {
        let identity = generate_identity_from_secret([5u8; 32]).expect("identity");
        let json = serde_json::to_vec(&identity.document).expect("json serialize");
        let err = parse_document_bytes(&json).expect_err("resolver requires DAG-CBOR");
        assert!(err.contains("DAG-CBOR decode failed"));
    }

    #[test]
    fn rejects_document_with_mutated_payload() {
        let identity = generate_identity_from_secret([9u8; 32]).expect("identity");
        let mut document = identity.document;
        document.updated_at = "2026-08-08T12:00:00Z".to_string();

        let err = parse_document_bytes(&document.encode().expect("cbor"))
            .expect_err("mutated payload must fail proof verification");
        assert!(err.contains("document proof verification failed"));
    }

    #[test]
    fn rejects_document_with_malformed_proof() {
        let identity = generate_identity_from_secret([11u8; 32]).expect("identity");
        let mut document = identity.document;
        document.proof.proof_value = "not-multibase".to_string();

        let err = parse_document_bytes(&document.encode().expect("cbor"))
            .expect_err("malformed proof must fail verification");
        assert!(err.contains("document proof verification failed"));
    }

    #[test]
    fn rejects_document_with_unknown_proof_key() {
        let identity = generate_identity_from_secret([13u8; 32]).expect("identity");
        let mut document = identity.document;
        document.proof.verification_method = format!("{}#unknown", document.id);

        let err = parse_document_bytes(&document.encode().expect("cbor"))
            .expect_err("unknown proof key must fail verification");
        assert!(err.contains("document proof verification failed"));
    }

    #[test]
    fn rejects_document_without_assertion_relationship() {
        let identity = generate_identity_from_secret([15u8; 32]).expect("identity");
        let mut document = identity.document;
        document.assertion_method.clear();

        let err = parse_document_bytes(&document.encode().expect("cbor"))
            .expect_err("missing assertion relationship must fail validation");
        assert!(err.contains("document validation failed"));
    }

    #[test]
    fn rejects_document_with_invalid_signature() {
        let identity = generate_identity_from_secret([17u8; 32]).expect("identity");
        let mut document = identity.document;
        document.proof.proof_value = signature_multibase_encode(CODEC_EDDSA_SIG, &[0; 64]);

        let err = parse_document_bytes(&document.encode().expect("cbor"))
            .expect_err("invalid signature must fail proof verification");
        assert!(err.contains("document proof verification failed"));
    }

    #[test]
    fn rejects_unverified_cached_document() {
        let identity = generate_identity_from_secret([19u8; 32]).expect("identity");
        let did = identity.document.id.clone();
        let mut document = identity.document;
        document.updated_at = "2026-08-08T12:00:00Z".to_string();

        let err =
            IpfsGatewayResolver::cached_result(Cached::Hit(document.encode().expect("cbor")), did)
                .expect_err("cached document must be proof-verified");
        assert!(err.to_string().contains("cached document parse failed"));
    }

    #[test]
    fn resolver_constructors_delegate_to_pool() {
        let resolver = IpfsGatewayResolver::new("https://example.test/ipfs");
        assert_eq!(
            resolver.pool().gateways(),
            [
                "https://example.test/ipfs/".to_string(),
                "https://ipfs.io/".to_string(),
            ]
        );
    }
}
