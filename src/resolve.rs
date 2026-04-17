//! DID document resolution traits and implementations.

use async_trait::async_trait;
use did_ma::Document;

/// Trait for resolving a DID to its DID document.
///
/// Ship with `GatewayResolver` for HTTP gateway resolution.
/// Implement this trait for custom resolution strategies.
#[async_trait]
pub trait DidResolver: Send + Sync {
    async fn resolve(&self, did: &str) -> crate::error::Result<Document>;
}

/// Resolves DID documents via an IPFS/IPNS HTTP gateway.
///
/// The gateway must serve DID documents at `/ipns/<key-id>`.
#[cfg(not(target_arch = "wasm32"))]
pub struct GatewayResolver {
    gateway_url: String,
    client: reqwest::Client,
}

#[cfg(not(target_arch = "wasm32"))]
impl GatewayResolver {
    pub fn new(gateway_url: impl Into<String>) -> Self {
        let mut url = gateway_url.into();
        // Ensure trailing slash
        if !url.ends_with('/') {
            url.push('/');
        }
        Self {
            gateway_url: url,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .expect("failed to build HTTP client"),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl DidResolver for GatewayResolver {
    async fn resolve(&self, did: &str) -> crate::error::Result<Document> {
        let parsed = did_ma::Did::try_from(did).map_err(crate::error::Error::Validation)?;
        let url = format!("{}ipns/{}", self.gateway_url, parsed.ipns);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| crate::error::Error::Resolution {
                did: did.to_string(),
                detail: e.to_string(),
            })?;

        if !response.status().is_success() {
            return Err(crate::error::Error::Resolution {
                did: did.to_string(),
                detail: format!("gateway returned {}", response.status()),
            });
        }

        let body = response
            .text()
            .await
            .map_err(|e| crate::error::Error::Resolution {
                did: did.to_string(),
                detail: e.to_string(),
            })?;

        Document::unmarshal(&body).map_err(|e| crate::error::Error::Resolution {
            did: did.to_string(),
            detail: e.to_string(),
        })
    }
}
