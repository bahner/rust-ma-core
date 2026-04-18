//! DID document publishing to IPFS/IPNS.
//!
//! Provides request/response types, validation, and (with the `kubo` feature)
//! the [`KuboDidPublisher`] for publishing signed DID documents via the
//! `ma/ipfs/0.0.1` service.

use anyhow::{anyhow, Result};
use did_ma::{Did, Document, Message};
use serde::{Deserialize, Serialize};

pub const MA_IPNS_ALIAS_HASH_PREFIX: &str = "ma-";

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
use base64::engine::general_purpose::STANDARD as B64;
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
use base64::Engine;
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
use std::time::Duration;

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
use crate::kubo::{dag_put, import_key, list_keys, name_publish_with_retry, IpnsPublishOptions};
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
use reqwest::Url;

use crate::service::CONTENT_TYPE_IPFS_REQUEST;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpfsPublishDidRequest {
    pub did_document_json: String,
    #[serde(default)]
    pub ipns_private_key_base64: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpfsPublishDidResponse {
    pub ok: bool,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
}

pub struct ValidatedIpfsPublish {
    pub request: IpfsPublishDidRequest,
    pub document: Document,
    pub document_did: Did,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
#[derive(Clone, Debug)]
pub struct KuboDidPublisher {
    kubo_url: String,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
impl KuboDidPublisher {
    pub fn new(kubo_url: impl AsRef<str>) -> Result<Self> {
        let kubo_url = normalize_kubo_url(kubo_url.as_ref())?;
        Ok(Self { kubo_url })
    }

    pub fn kubo_url(&self) -> &str {
        &self.kubo_url
    }

    pub async fn publish_signed_message(
        &self,
        message_cbor: &[u8],
    ) -> Result<IpfsPublishDidResponse> {
        handle_ipfs_publish(&self.kubo_url, message_cbor).await
    }

    pub async fn publish_document(
        &self,
        did_document_json: &str,
        ipns_private_key_base64: &str,
    ) -> Result<Option<String>> {
        publish_did_document_to_kubo(&self.kubo_url, did_document_json, ipns_private_key_base64)
            .await
    }

    pub async fn wait_until_ready(&self, attempts: u32) -> Result<()> {
        crate::kubo::wait_for_api(&self.kubo_url, attempts).await
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
fn normalize_kubo_url(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("kubo_url must not be empty"));
    }

    let parsed =
        Url::parse(trimmed).map_err(|e| anyhow!("invalid kubo_url '{}': {}", trimmed, e))?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(anyhow!(
            "kubo_url must use http or https scheme, got '{}'",
            scheme
        ));
    }

    if parsed.host_str().is_none() {
        return Err(anyhow!("kubo_url must include a host"));
    }

    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(anyhow!(
            "kubo_url must not include query params or fragments"
        ));
    }

    let mut base = format!("{}://{}", scheme, parsed.host_str().unwrap_or_default());
    if let Some(port) = parsed.port() {
        base.push(':');
        base.push_str(&port.to_string());
    }

    let mut path = parsed.path().trim_end_matches('/').to_string();
    if path.ends_with("/api/v0") {
        path.truncate(path.len() - "/api/v0".len());
    }
    if !path.is_empty() && path != "/" {
        if !path.starts_with('/') {
            base.push('/');
        }
        base.push_str(&path);
    }

    Ok(base)
}

pub fn validate_ipfs_publish_request(message_cbor: &[u8]) -> Result<ValidatedIpfsPublish> {
    let message =
        Message::from_cbor(message_cbor).map_err(|e| anyhow!("invalid signed message: {}", e))?;

    if message.content_type != CONTENT_TYPE_IPFS_REQUEST {
        return Err(anyhow!(
            "expected {} on ma/ipfs/1, got {}",
            CONTENT_TYPE_IPFS_REQUEST,
            message.content_type
        ));
    }

    let sender_did = Did::try_from(message.from.as_str())
        .map_err(|e| anyhow!("invalid sender did '{}': {}", message.from, e))?;

    let request: IpfsPublishDidRequest = serde_json::from_slice(&message.content)
        .map_err(|e| anyhow!("invalid IPFS publish payload: {}", e))?;

    let document = Document::unmarshal(&request.did_document_json)
        .map_err(|e| anyhow!("invalid DID document JSON: {}", e))?;
    document
        .validate()
        .map_err(|e| anyhow!("invalid DID document: {}", e))?;
    document
        .verify()
        .map_err(|e| anyhow!("DID document signature verification failed: {}", e))?;

    let document_did = Did::try_from(document.id.as_str())
        .map_err(|e| anyhow!("invalid document DID '{}': {}", document.id, e))?;

    if document_did.ipns != sender_did.ipns {
        return Err(anyhow!(
            "sender IPNS '{}' does not match document IPNS '{}'",
            sender_did.ipns,
            document_did.ipns
        ));
    }

    message
        .verify_with_document(&document)
        .map_err(|e| anyhow!("request signature verification failed: {}", e))?;

    Ok(ValidatedIpfsPublish {
        request,
        document,
        document_did,
    })
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub async fn publish_did_document_to_kubo(
    kubo_url: &str,
    did_document_json: &str,
    ipns_private_key_base64: &str,
) -> Result<Option<String>> {
    let document = Document::unmarshal(did_document_json)
        .map_err(|e| anyhow!("invalid DID document JSON: {}", e))?;
    let document_did = Did::try_from(document.id.as_str())
        .map_err(|e| anyhow!("invalid document DID '{}': {}", document.id, e))?;
    let document_ipns_id = document_did.ipns.clone();

    // Deterministic key name derived from the DID IPNS identity.
    // Same DID always maps to the same Kubo key name — idempotent, no cleanup needed.
    let hash = blake3::hash(document_ipns_id.as_bytes());
    let key_name = format!("{}{}", MA_IPNS_ALIAS_HASH_PREFIX, &hash.to_hex()[..16]);

    let existing_key = list_keys(kubo_url)
        .await?
        .into_iter()
        .find(|k| k.name == key_name);

    if let Some(existing) = existing_key {
        if existing.id.trim() != document_ipns_id {
            return Err(anyhow!(
                "existing key '{}' has IPNS id '{}' but document DID IPNS is '{}'",
                key_name,
                existing.id,
                document_ipns_id
            ));
        }
    } else {
        if ipns_private_key_base64.trim().is_empty() {
            return Err(anyhow!(
                "ipns_private_key_base64 is required when key is not present in Kubo"
            ));
        }

        let key_bytes = B64
            .decode(ipns_private_key_base64.trim())
            .map_err(|e| anyhow!("invalid base64 key payload: {}", e))?;

        let imported = import_key(kubo_url, &key_name, key_bytes).await?;
        if imported.id.trim() != document_ipns_id {
            return Err(anyhow!(
                "imported key IPNS id '{}' does not match document DID IPNS '{}'",
                imported.id,
                document_ipns_id
            ));
        }
    }

    let document_cid = dag_put(kubo_url, &document).await?;
    let ipns_options = IpnsPublishOptions::default();
    name_publish_with_retry(
        kubo_url,
        &key_name,
        &document_cid,
        &ipns_options,
        3,
        Duration::from_millis(1_000),
    )
    .await?;

    Ok(Some(document_cid))
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub async fn handle_ipfs_publish(
    kubo_url: &str,
    message_cbor: &[u8],
) -> Result<IpfsPublishDidResponse> {
    let validated = validate_ipfs_publish_request(message_cbor)?;

    let cid = publish_did_document_to_kubo(
        kubo_url,
        &validated.request.did_document_json,
        &validated.request.ipns_private_key_base64,
    )
    .await?;

    Ok(IpfsPublishDidResponse {
        ok: true,
        message: "did document published via ma/ipfs/0.0.1".to_string(),
        did: Some(validated.document_did.id()),
        cid,
    })
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "kubo"))]
mod tests {
    use super::normalize_kubo_url;

    #[test]
    fn normalizes_trailing_slash() {
        assert_eq!(
            normalize_kubo_url("http://127.0.0.1:5001/").expect("normalize url"),
            "http://127.0.0.1:5001"
        );
    }

    #[test]
    fn strips_api_v0_suffix() {
        assert_eq!(
            normalize_kubo_url("http://127.0.0.1:5001/api/v0").expect("normalize url"),
            "http://127.0.0.1:5001"
        );
    }

    #[test]
    fn keeps_custom_base_path() {
        assert_eq!(
            normalize_kubo_url("http://localhost:5001/kubo").expect("normalize url"),
            "http://localhost:5001/kubo"
        );
    }

    #[test]
    fn rejects_empty_url() {
        assert!(normalize_kubo_url("   ").is_err());
    }

    #[test]
    fn rejects_non_http_scheme() {
        assert!(normalize_kubo_url("ftp://127.0.0.1:5001").is_err());
    }
}
