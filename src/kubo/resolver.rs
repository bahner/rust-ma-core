//! DID/IPNS resolution backed by the Kubo RPC API.
//!
//! Native-only (`kubo` feature). This is the single DID/IPNS resolver for
//! native runtimes, using the Kubo RPC endpoints (`/api/v0/dag/get`,
//! `/api/v0/name/resolve`). It is the read-side companion to the Kubo
//! publishing backend. wasm hosts implement the same traits with their own
//! backend (verified-fetch).

use async_trait::async_trait;

use super::kubo::{fetch_did_document, name_resolve};
use crate::ipfs::resolver::{DidDocumentResolver, IpnsPathResolver};
use crate::{Did, Document};

/// Resolves DID documents and IPNS paths via a local Kubo daemon's RPC API.
///
/// The ma runtime resolves peer DIDs through its own node
/// (`http://127.0.0.1:5001` by default) rather than through a public HTTP
/// gateway. Pass this into [`new_ma_endpoint`](crate::new_ma_endpoint) exactly
/// like the gateway resolver.
pub struct KuboDidResolver {
    kubo_url: String,
}

impl KuboDidResolver {
    /// Build a resolver for the given Kubo RPC API URL (e.g.
    /// `http://127.0.0.1:5001`).
    #[must_use]
    pub fn new(kubo_url: impl Into<String>) -> Self {
        Self {
            kubo_url: kubo_url.into(),
        }
    }

    /// The Kubo RPC API URL this resolver talks to.
    #[must_use]
    pub fn kubo_url(&self) -> &str {
        &self.kubo_url
    }
}

#[async_trait]
impl DidDocumentResolver for KuboDidResolver {
    async fn resolve(&self, did: &str) -> crate::error::Result<Document> {
        let parsed = Did::try_from(did).map_err(crate::error::Error::Validation)?;
        let did_key = parsed.base_id();
        match fetch_did_document(&self.kubo_url, &parsed).await {
            Ok(document) => Ok(document),
            Err(error) => Err(crate::error::Error::Resolution {
                did: did_key,
                detail: error.to_string(),
            }),
        }
    }
}

#[async_trait]
impl IpnsPathResolver for KuboDidResolver {
    async fn resolve_ipns_path(&self, path: &str) -> crate::error::Result<String> {
        if !path.starts_with("/ipns/") || path.len() <= "/ipns/".len() {
            return Err(crate::error::Error::IpnsResolution {
                path: path.to_string(),
                detail: "expected a non-empty /ipns/<name> path".to_string(),
            });
        }
        match name_resolve(&self.kubo_url, path, true).await {
            Ok(resolved) => Ok(resolved),
            Err(error) => Err(crate::error::Error::IpnsResolution {
                path: path.to_string(),
                detail: error.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::KuboDidResolver;
    use crate::ipfs::resolver::{DidDocumentResolver, IpnsPathResolver};

    fn resolver() -> KuboDidResolver {
        KuboDidResolver::new("http://127.0.0.1:5001")
    }

    #[test]
    fn stores_the_kubo_url() {
        let resolver = KuboDidResolver::new("http://127.0.0.1:5001");
        assert_eq!(resolver.kubo_url(), "http://127.0.0.1:5001");
    }

    #[tokio::test]
    async fn rejects_invalid_did_before_any_rpc_call() {
        let error = resolver()
            .resolve("not-a-did")
            .await
            .expect_err("invalid DID must fail before any RPC call");
        assert!(
            matches!(error, crate::error::Error::Validation(_)),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn rejects_malformed_ipns_path_before_any_rpc_call() {
        let resolver = resolver();
        for path in ["", "ipns/k51abc", "/ipfs/bafycid"] {
            let error = resolver
                .resolve_ipns_path(path)
                .await
                .expect_err("non-/ipns/ path must fail before any RPC call");
            assert!(
                matches!(error, crate::error::Error::IpnsResolution { .. }),
                "{path}: {error:?}"
            );
        }
    }
}
