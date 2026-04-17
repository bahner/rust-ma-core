//! Kubo RPC client for IPFS operations.
//!
//! HTTP helpers for the Kubo `/api/v0/` endpoints: data add/cat, DAG
//! put/get, IPNS name publish/resolve, key management, and pinning.

use anyhow::{anyhow, Result};
use did_ma::{Did, Document};
use reqwest::multipart;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;
use tracing::warn;

pub const DEFAULT_KUBO_API_URL: &str = "http://127.0.0.1:5001";

// ─── Response types ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct AddResponse {
    #[serde(rename = "Hash")]
    hash: String,
}

#[derive(Debug, Deserialize)]
struct DagPutCid {
    #[serde(rename = "/")]
    slash: String,
}

#[derive(Debug, Deserialize)]
struct DagPutResponse {
    #[serde(default, rename = "Cid")]
    cid_upper: Option<DagPutCid>,
    #[serde(default)]
    cid: Option<DagPutCid>,
}

#[derive(Debug, Deserialize)]
struct NamePublishResponse {
    #[serde(default, rename = "Value")]
    value_upper: String,
    #[serde(default, rename = "value")]
    value_lower: String,
}

#[derive(Debug, Deserialize)]
struct NameResolveResponse {
    #[serde(default, rename = "Path")]
    path_upper: String,
    #[serde(default, rename = "path")]
    path_lower: String,
}

#[derive(Debug, Deserialize)]
struct VersionResponse {
    #[serde(default, rename = "Version")]
    version_upper: String,
    #[serde(default, rename = "version")]
    version_lower: String,
}

#[derive(Debug, Deserialize)]
struct KeyListEntry {
    #[serde(default, rename = "Name")]
    name: String,
    #[serde(default, rename = "name")]
    name_lower: String,
    #[serde(default, rename = "Id")]
    id: String,
    #[serde(default, rename = "id")]
    id_lower: String,
}

#[derive(Debug, Deserialize)]
struct KeyListResponse {
    #[serde(default, rename = "Keys")]
    keys: Vec<KeyListEntry>,
}

#[derive(Debug, Deserialize)]
struct KeyImportResponse {
    #[serde(default, rename = "Name")]
    name_upper: String,
    #[serde(default, rename = "name")]
    name_lower: String,
    #[serde(default, rename = "Id")]
    id_upper: String,
    #[serde(default, rename = "id")]
    id_lower: String,
}

#[derive(Clone, Debug)]
pub struct KuboKey {
    pub name: String,
    pub id: String,
}

// ─── Publish options ────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct IpnsPublishOptions {
    pub timeout: Duration,
    pub allow_offline: bool,
    pub lifetime: String,
    pub ttl: Option<String>,
    pub resolve: bool,
    pub quieter: bool,
}

impl Default for IpnsPublishOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(15),
            allow_offline: true,
            lifetime: "8760h".to_string(),
            ttl: None,
            resolve: false,
            quieter: true,
        }
    }
}

// ─── Readiness ──────────────────────────────────────────────────────────────

pub async fn wait_for_api(kubo_url: &str, attempts: u32) -> Result<()> {
    if attempts == 0 {
        return Err(anyhow!("kubo readiness attempts must be >= 1"));
    }

    let base = kubo_url.trim_end_matches('/');
    let url = format!("{base}/api/v0/version");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        .build()?;

    let mut backoff = Duration::from_millis(200);
    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 1..=attempts {
        let result = async {
            let response = client.post(&url).send().await?.error_for_status()?;
            let body = response.text().await?;
            let parsed: VersionResponse = serde_json::from_str(&body)
                .map_err(|e| anyhow!("failed parsing version response: {} body={}", e, body))?;
            let version = if !parsed.version_upper.is_empty() {
                parsed.version_upper
            } else {
                parsed.version_lower
            };
            if version.trim().is_empty() {
                return Err(anyhow!("missing version field in response: {}", body));
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;

        match result {
            Ok(()) => return Ok(()),
            Err(err) => {
                warn!("kubo readiness {}/{}: {}", attempt, attempts, err);
                last_err = Some(err);
                if attempt < attempts {
                    sleep(backoff).await;
                    let doubled = backoff.as_millis().saturating_mul(2);
                    backoff = Duration::from_millis(std::cmp::min(doubled, 5_000) as u64);
                }
            }
        }
    }
    Err(anyhow!(
        "kubo API not ready after {} attempts: {}",
        attempts,
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    ))
}

// ─── Add / Cat ──────────────────────────────────────────────────────────────

pub async fn ipfs_add(kubo_url: &str, data: Vec<u8>) -> Result<String> {
    let base = kubo_url.trim_end_matches('/');
    let url = format!("{base}/api/v0/add");

    let part = multipart::Part::bytes(data).file_name("data");
    let form = multipart::Form::new().part("file", part);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let body = client
        .post(url)
        .query(&[("pin", "true")])
        .multipart(form)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let parsed: AddResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow!("failed parsing add response: {} body={}", e, body))?;
    Ok(parsed.hash)
}

pub async fn cat_bytes(kubo_url: &str, cid: &str) -> Result<Vec<u8>> {
    let base = kubo_url.trim_end_matches('/');
    let url = format!("{base}/api/v0/cat");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let bytes = client
        .post(url)
        .query(&[("arg", cid)])
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    Ok(bytes.to_vec())
}

pub async fn cat_text(kubo_url: &str, cid: &str) -> Result<String> {
    let bytes = cat_bytes(kubo_url, cid).await?;
    String::from_utf8(bytes).map_err(|e| anyhow!("non-utf8 content from {}: {}", cid, e))
}

// ─── DAG ────────────────────────────────────────────────────────────────────

pub async fn dag_put<T: Serialize>(kubo_url: &str, value: &T) -> Result<String> {
    let base = kubo_url.trim_end_matches('/');
    let url = format!("{base}/api/v0/dag/put");
    let payload = serde_json::to_vec(value)?;

    let part = multipart::Part::bytes(payload)
        .file_name("node.json")
        .mime_str("application/json")?;
    let form = multipart::Form::new().part("file", part);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let body = client
        .post(url)
        .query(&[
            ("store-codec", "dag-cbor"),
            ("input-codec", "dag-json"),
            ("pin", "true"),
        ])
        .multipart(form)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let parsed: DagPutResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow!("failed parsing dag/put response: {} body={}", e, body))?;
    parsed
        .cid_upper
        .or(parsed.cid)
        .map(|c| c.slash)
        .ok_or_else(|| anyhow!("missing CID in dag/put response: {}", body))
}

pub async fn dag_get<T: DeserializeOwned>(kubo_url: &str, cid: &str) -> Result<T> {
    let base = kubo_url.trim_end_matches('/');
    let url = format!("{base}/api/v0/dag/get");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let body = client
        .post(url)
        .query(&[("arg", cid)])
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    serde_json::from_str::<T>(&body).map_err(|e| {
        anyhow!(
            "failed parsing dag/get response for {}: {} body={}",
            cid,
            e,
            body
        )
    })
}

// ─── Name publish / resolve ─────────────────────────────────────────────────

fn normalize_ipfs_arg(cid_or_path: &str) -> String {
    let mut value = cid_or_path.trim().to_string();
    while let Some(rest) = value.strip_prefix("/ipfs/") {
        value = rest.to_string();
    }
    while let Some(rest) = value.strip_prefix('/') {
        value = rest.to_string();
    }
    format!("/ipfs/{value}")
}

pub async fn name_publish(kubo_url: &str, key_name: &str, cid: &str) -> Result<String> {
    let options = IpnsPublishOptions::default();
    name_publish_with_options(kubo_url, key_name, cid, &options).await
}

pub async fn name_publish_with_options(
    kubo_url: &str,
    key_name: &str,
    cid: &str,
    options: &IpnsPublishOptions,
) -> Result<String> {
    let base = kubo_url.trim_end_matches('/');
    let url = format!("{base}/api/v0/name/publish");
    let arg = normalize_ipfs_arg(cid);

    let client = reqwest::Client::builder()
        .timeout(options.timeout)
        .build()?;

    let allow_offline = if options.allow_offline {
        "true"
    } else {
        "false"
    };
    let resolve = if options.resolve { "true" } else { "false" };
    let quieter = if options.quieter { "true" } else { "false" };

    let mut params: Vec<(&str, &str)> = vec![
        ("arg", arg.as_str()),
        ("key", key_name),
        ("allow-offline", allow_offline),
        ("lifetime", options.lifetime.as_str()),
        ("resolve", resolve),
        ("quieter", quieter),
    ];
    if let Some(ref ttl) = options.ttl {
        params.push(("ttl", ttl.as_str()));
    }

    let body = client
        .post(url)
        .query(&params)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let parsed: NamePublishResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow!("failed parsing name/publish response: {} body={}", e, body))?;
    let value = if !parsed.value_upper.is_empty() {
        parsed.value_upper
    } else {
        parsed.value_lower
    };
    if value.is_empty() {
        return Err(anyhow!("missing value in name/publish response: {}", body));
    }
    Ok(value)
}

pub async fn name_publish_with_retry(
    kubo_url: &str,
    key_name: &str,
    cid: &str,
    options: &IpnsPublishOptions,
    attempts: u32,
    initial_backoff: Duration,
) -> Result<String> {
    if attempts == 0 {
        return Err(anyhow!("name publish attempts must be >= 1"));
    }

    let mut backoff = initial_backoff;
    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 1..=attempts {
        match name_publish_with_options(kubo_url, key_name, cid, options).await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if let Ok(value) = verify_name_target_after_error(kubo_url, key_name, cid).await {
                    warn!(
                        "name publish attempt {}/{} reported error for key '{}' but resolve confirms target; accepting: {}",
                        attempt, attempts, key_name, value
                    );
                    return Ok(value);
                }
                warn!(
                    "name publish attempt {}/{} failed for key '{}' cid '{}': {}",
                    attempt, attempts, key_name, cid, err
                );
                last_err = Some(err);
                if attempt < attempts {
                    sleep(backoff).await;
                    let doubled = backoff.as_millis().saturating_mul(2);
                    backoff = Duration::from_millis(std::cmp::min(doubled, 30_000) as u64);
                }
            }
        }
    }

    Err(anyhow!(
        "name publish failed after {} attempt(s): {}",
        attempts,
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    ))
}

async fn verify_name_target_after_error(
    kubo_url: &str,
    key_name: &str,
    cid: &str,
) -> Result<String> {
    let expected = normalize_ipfs_arg(cid);
    let resolved = name_resolve(kubo_url, &format!("/ipns/{key_name}"), true).await?;
    if resolved.trim() == expected {
        return Ok(resolved);
    }
    Err(anyhow!(
        "post-error resolve mismatch for key '{}': expected '{}' got '{}'",
        key_name,
        expected,
        resolved
    ))
}

pub async fn name_resolve(kubo_url: &str, path: &str, recursive: bool) -> Result<String> {
    let base = kubo_url.trim_end_matches('/');
    let url = format!("{base}/api/v0/name/resolve");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    let recursive_flag = if recursive { "true" } else { "false" };
    let body = client
        .post(url)
        .query(&[("arg", path), ("recursive", recursive_flag)])
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let parsed: NameResolveResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow!("failed parsing name/resolve response: {} body={}", e, body))?;
    let resolved = if !parsed.path_upper.is_empty() {
        parsed.path_upper
    } else {
        parsed.path_lower
    };
    if resolved.is_empty() {
        return Err(anyhow!("missing path in name/resolve response: {}", body));
    }
    Ok(resolved)
}

// ─── DID document fetch ─────────────────────────────────────────────────────

pub async fn fetch_did_document(kubo_url: &str, did: &Did) -> Result<Document> {
    let ipns_path = format!("/ipns/{}", did.ipns);
    let mut backoff = Duration::from_millis(150);
    let mut last_err: Option<anyhow::Error> = None;
    let mut document: Option<Document> = None;

    for attempt in 1..=4 {
        // DID documents are stored as DAG-CBOR via dag/put.
        match dag_get::<Document>(kubo_url, &ipns_path).await {
            Ok(doc) => {
                document = Some(doc);
                break;
            }
            Err(dag_err) => {
                // Fallback: resolve IPNS manually then dag_get the CID.
                match name_resolve(kubo_url, &ipns_path, true).await {
                    Ok(resolved_path) => {
                        match dag_get::<Document>(kubo_url, &resolved_path).await {
                            Ok(doc) => {
                                document = Some(doc);
                                break;
                            }
                            Err(err) => {
                                last_err = Some(anyhow!(
                                    "dag_get failed for {}: direct={} resolved={}",
                                    ipns_path,
                                    dag_err,
                                    err
                                ));
                            }
                        }
                    }
                    Err(resolve_err) => {
                        last_err = Some(anyhow!(
                            "dag_get and name/resolve both failed for {}: dag={} resolve={}",
                            ipns_path,
                            dag_err,
                            resolve_err
                        ));
                        if !should_retry_name_resolve_error(&resolve_err) {
                            break;
                        }
                    }
                }
            }
        }

        if attempt < 4 {
            sleep(backoff).await;
            let doubled = backoff.as_millis().saturating_mul(2);
            backoff = Duration::from_millis(std::cmp::min(doubled, 2_000) as u64);
        }
    }

    let document = document.ok_or_else(|| {
        anyhow!(
            "failed to fetch DID document for {} via {} after retries: {}",
            did.id(),
            ipns_path,
            last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown error".to_string())
        )
    })?;

    document.validate()?;
    document.verify()?;

    let doc_did = Did::try_from(document.id.as_str())
        .map_err(|e| anyhow!("DID document has invalid id '{}': {}", document.id, e))?;
    if doc_did.ipns != did.ipns {
        return Err(anyhow!(
            "DID document IPNS mismatch: expected {} but document id is {}",
            did.base_id(),
            document.id
        ));
    }

    Ok(document)
}

fn should_retry_name_resolve_error(err: &anyhow::Error) -> bool {
    let text = err.to_string().to_ascii_lowercase();
    if text.contains("http status client error") {
        return false;
    }
    if text.contains("missing path in name/resolve response") {
        return false;
    }
    true
}

// ─── Pin ────────────────────────────────────────────────────────────────────

pub async fn pin_add_named(kubo_url: &str, cid: &str, name: &str) -> Result<()> {
    let base = kubo_url.trim_end_matches('/');
    let url = format!("{base}/api/v0/pin/add");
    let arg = normalize_ipfs_arg(cid);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    client
        .post(url)
        .query(&[("arg", arg.as_str()), ("recursive", "true"), ("name", name)])
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

pub async fn pin_rm(kubo_url: &str, cid: &str) -> Result<()> {
    let base = kubo_url.trim_end_matches('/');
    let url = format!("{base}/api/v0/pin/rm");
    let arg = normalize_ipfs_arg(cid);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    client
        .post(url)
        .query(&[("arg", arg.as_str()), ("recursive", "true")])
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

// ─── Key management ─────────────────────────────────────────────────────────

pub async fn generate_key(kubo_url: &str, key_name: &str) -> Result<()> {
    let base = kubo_url.trim_end_matches('/');
    let url = format!("{base}/api/v0/key/gen");

    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?
        .post(url)
        .query(&[("arg", key_name), ("type", "ed25519")])
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

pub async fn import_key(kubo_url: &str, key_name: &str, key_bytes: Vec<u8>) -> Result<KuboKey> {
    let base = kubo_url.trim_end_matches('/');
    let url = format!("{base}/api/v0/key/import");

    let part = multipart::Part::bytes(key_bytes)
        .file_name("ipns.key")
        .mime_str("application/octet-stream")?;
    let form = multipart::Form::new().part("file", part);

    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?
        .post(url)
        .query(&[("arg", key_name), ("allow-any-key-type", "true")])
        .multipart(form)
        .send()
        .await?
        .error_for_status()?;

    let body = response.text().await?;
    let parsed: KeyImportResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow!("failed parsing key/import response: {} body={}", e, body))?;

    let name = if !parsed.name_upper.trim().is_empty() {
        parsed.name_upper.trim().to_string()
    } else {
        parsed.name_lower.trim().to_string()
    };
    let id = if !parsed.id_upper.trim().is_empty() {
        parsed.id_upper.trim().to_string()
    } else {
        parsed.id_lower.trim().to_string()
    };

    if name.is_empty() || id.is_empty() {
        return Err(anyhow!("missing name/id in key/import response: {}", body));
    }

    Ok(KuboKey { name, id })
}

pub async fn list_keys(kubo_url: &str) -> Result<Vec<KuboKey>> {
    let base = kubo_url.trim_end_matches('/');
    let url = format!("{base}/api/v0/key/list");

    let body = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?
        .post(url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let parsed: KeyListResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow!("failed parsing key/list response: {} body={}", e, body))?;
    Ok(parsed
        .keys
        .into_iter()
        .filter_map(|k| {
            let name = if !k.name.trim().is_empty() {
                k.name.trim().to_string()
            } else {
                k.name_lower.trim().to_string()
            };
            let id = if !k.id.trim().is_empty() {
                k.id.trim().to_string()
            } else {
                k.id_lower.trim().to_string()
            };
            if name.is_empty() {
                None
            } else {
                Some(KuboKey { name, id })
            }
        })
        .collect())
}

pub async fn list_key_names(kubo_url: &str) -> Result<Vec<String>> {
    let keys = list_keys(kubo_url).await?;
    Ok(keys.into_iter().map(|k| k.name).collect())
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_ipfs_arg_from_raw_cid() {
        assert_eq!(normalize_ipfs_arg("QmExampleCid"), "/ipfs/QmExampleCid");
    }

    #[test]
    fn normalize_ipfs_arg_from_prefixed_path() {
        assert_eq!(
            normalize_ipfs_arg("/ipfs/QmExampleCid"),
            "/ipfs/QmExampleCid"
        );
    }

    #[test]
    fn normalize_ipfs_arg_from_double_prefixed_path() {
        assert_eq!(
            normalize_ipfs_arg("/ipfs//ipfs/QmExampleCid"),
            "/ipfs/QmExampleCid"
        );
    }

    #[test]
    fn does_not_retry_http_client_status_errors() {
        let err = anyhow!(
            "HTTP status client error (404 Not Found) for url (http://127.0.0.1:5001/api/v0/name/resolve)"
        );
        assert!(!should_retry_name_resolve_error(&err));
    }

    #[test]
    fn retries_http_server_status_errors() {
        let err = anyhow!(
            "HTTP status server error (500 Internal Server Error) for url (http://127.0.0.1:5001/api/v0/name/resolve)"
        );
        assert!(should_retry_name_resolve_error(&err));
    }

    #[test]
    fn retries_network_errors() {
        let err =
            anyhow!("error sending request for url (http://127.0.0.1:5001/api/v0/name/resolve)");
        assert!(should_retry_name_resolve_error(&err));
    }
}
