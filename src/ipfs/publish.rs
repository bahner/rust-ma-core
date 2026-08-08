//! DID document publishing to IPFS/IPNS.
//!
//! Provides request/response types, validation, and (with the `kubo` feature)
//! the [`IpfsDidPublisher`] for publishing signed DID documents via the
//! `ma/ipfs/0.0.1` service.

use crate::{Did, Document, Ipld, Message};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

pub const MA_IPNS_ALIAS_HASH_PREFIX: &str = "ma-";

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
use web_time::Duration;

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
use crate::kubo::{
    dag_put_cbor, import_key, in_flight_pin_name, list_keys, name_publish_with_retry,
    pin_add_named, remote_pin_add_named, wait_for_api, IpnsPublishOptions, PinCleanupRequest,
    PinCleanupScheduler,
};
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
use reqwest::Url;
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
use zeroize::Zeroizing;

use crate::service::{MESSAGE_TYPE_IDENTITY_PUBLISH_REQUEST, MESSAGE_TYPE_IPFS_REQUEST};

// ── Wire formats ──────────────────────────────────────────────────────────

/// CBOR payload for `application/vnd.ma.identity.publish.request` messages
/// on `/ma/ipfs/0.0.1`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityPublishRequest {
    /// dag-cbor encoded signed [`Document`].
    pub document: Vec<u8>,
    /// Raw 32-byte IPNS signing key (Ed25519 seed). Must be zeroized by receiver.
    pub ipns_secret_key: Vec<u8>,
}

/// CBOR payload for `application/vnd.ma.ipfs.request` messages on
/// `/ma/ipfs/0.0.1`. Receiver replies with the resulting CID.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpfsStoreRequest {
    pub content: Vec<u8>,
    pub content_type: String,
}

fn encode_cbor<T: Serialize>(payload: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(payload, &mut buf)
        .map_err(|e| anyhow!("failed to encode CBOR payload: {}", e))?;
    Ok(buf)
}

fn sanitize_key_part(part: &str) -> String {
    let mut sanitized = String::new();
    let mut last_was_separator = false;

    for byte in part.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() {
            sanitized.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if ch == '-' || ch == '_' {
            if !last_was_separator && !sanitized.is_empty() {
                sanitized.push(ch);
                last_was_separator = true;
            }
        } else if !last_was_separator && !sanitized.is_empty() {
            sanitized.push('-');
            last_was_separator = true;
        }
    }

    while sanitized.ends_with(['-', '_']) {
        sanitized.pop();
    }

    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

fn document_ma_type(document: &Document) -> &str {
    match document.ma.as_ref() {
        Some(Ipld::Map(map)) => match map.get("type") {
            Some(Ipld::String(kind)) => kind,
            _ => "unknown",
        },
        _ => "unknown",
    }
}

/// Build a deterministic Kubo IPNS key name from operator-visible parts.
///
/// The IPNS identity is only exposed as a short blake3 suffix. Callers may add
/// local context such as a runtime slug, while delegated agent publishes can
/// remain anonymous apart from their `ma.type`.
#[must_use]
pub fn ipns_key_name_for_parts(parts: &[&str], ipns_id: &str) -> String {
    let name_parts = if parts.is_empty() {
        vec!["unknown".to_string()]
    } else {
        parts.iter().map(|part| sanitize_key_part(part)).collect()
    };
    let hash = blake3::hash(ipns_id.as_bytes());
    format!(
        "{}{}-{}",
        MA_IPNS_ALIAS_HASH_PREFIX,
        name_parts.join("-"),
        &hash.to_hex()[..16]
    )
}

/// Build the default deterministic Kubo IPNS key name for a DID document.
///
/// Uses `ma.type` when present and falls back to `unknown`.
#[must_use]
pub fn ipns_key_name_for_document(document: &Document) -> String {
    let document_did = Did::try_from(document.id.as_str());
    let ipns_id = document_did
        .as_ref()
        .map_or(document.id.as_str(), |did| did.ipns.as_str());
    ipns_key_name_for_parts(&[document_ma_type(document)], ipns_id)
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

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
#[derive(Clone, Debug)]
/// Publication policy for a native DID document.
pub struct DidDocumentPublishOptions {
    /// Deterministic Kubo key-name components; defaults to the document kind.
    pub key_parts: Vec<String>,
    /// IPNS publication settings.
    pub ipns: IpnsPublishOptions,
    /// Number of bounded retries for IPNS and remote pinning.
    pub attempts: u32,
    /// Initial Fibonacci retry delay.
    pub initial_backoff: Duration,
    /// Optional remote pin service replication policy.
    pub remote_pin: Option<RemotePinOptions>,
    /// Replace older pins with the same name in a background best-effort job.
    pub overwrite: bool,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
impl Default for DidDocumentPublishOptions {
    fn default() -> Self {
        Self {
            key_parts: Vec::new(),
            ipns: IpnsPublishOptions::default(),
            attempts: 3,
            initial_backoff: Duration::from_secs(1),
            remote_pin: None,
            overwrite: true,
        }
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
#[derive(Clone, Debug, Eq, PartialEq)]
/// Remote Kubo pin service configuration for a published DID document.
pub struct RemotePinOptions {
    /// Kubo pin-service name.
    pub service: String,
    /// Human-readable label for the remote pin.
    pub name: String,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
#[derive(Clone, Debug, Eq, PartialEq)]
/// Remote replication outcome after local pinning and IPNS publication.
pub enum RemotePinStatus {
    /// The new CID was replicated and stale-pin cleanup was scheduled.
    Replicated { cleanup_scheduled: bool },
    /// Local publication succeeded, but replication failed after retries.
    Degraded { error: String },
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
#[derive(Clone, Debug, Eq, PartialEq)]
/// Confirmed outcome of a locally pinned DID document publication.
pub struct PublishedDidDocument {
    /// CID stored and published through IPNS.
    pub cid: String,
    /// Deterministic Kubo IPNS key alias.
    pub key_name: String,
    /// IPNS identity rooted by the DID.
    pub ipns_id: String,
    /// Kubo accepted the required local recursive pin.
    pub local_pinned: bool,
    /// Whether a detached stale-pin cleanup job was scheduled.
    pub cleanup_scheduled: bool,
    /// Optional remote replication state.
    pub remote_pin: Option<RemotePinStatus>,
}

pub struct ValidatedIdentityPublish {
    pub document_bytes: Vec<u8>,
    pub ipns_secret_key: Vec<u8>,
    pub document: Document,
    pub document_did: Did,
}

/// Validated store request.
pub struct ValidatedIpfsStore {
    pub content: Vec<u8>,
    pub content_type: String,
    pub sender_did: String,
    pub msg_id: String,
}

/// Build CBOR content bytes for `application/vnd.ma.identity.publish.request`.
///
/// The returned bytes are the payload to place in `Message.content` when
/// sending to `/ma/ipfs/0.0.1`.
pub fn generate_identity_publish_request(
    did_document: &Document,
    ipns_secret_key: &[u8],
) -> Result<Vec<u8>> {
    let document_bytes = did_document
        .encode()
        .map_err(|e| anyhow!("failed to encode DID document as dag-cbor: {}", e))?;
    encode_cbor(&IdentityPublishRequest {
        document: document_bytes,
        ipns_secret_key: ipns_secret_key.to_vec(),
    })
}

/// Build a signed `application/vnd.ma.ipfs.request` message (generic store).
///
/// Returns the complete signed [`Message`] ready to send on `/ma/ipfs/0.0.1`.
pub fn generate_ipfs_store_request(
    sender_did: &str,
    publisher_did: &str,
    content: Vec<u8>,
    content_type: &str,
    signing_key: &crate::SigningKey,
) -> Result<Message> {
    let payload = encode_cbor(&IpfsStoreRequest {
        content,
        content_type: content_type.to_string(),
    })?;
    Message::new(
        sender_did,
        publisher_did,
        MESSAGE_TYPE_IPFS_REQUEST,
        "application/cbor",
        &payload,
        signing_key,
    )
    .map_err(|e| anyhow!("failed to build ipfs-store message: {}", e))
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
#[derive(Clone, Debug)]
pub struct IpfsDidPublisher {
    kubo_url: String,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
impl IpfsDidPublisher {
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
        did_document: Vec<u8>,
        ipns_private_key: Zeroizing<Vec<u8>>,
        options: DidDocumentPublishOptions,
    ) -> Result<PublishedDidDocument> {
        publish_did_document_to_kubo(
            &self.kubo_url,
            PinCleanupScheduler::global(),
            did_document,
            ipns_private_key,
            options,
        )
        .await
    }

    pub async fn wait_until_ready(&self, attempts: u32) -> Result<()> {
        wait_for_api(&self.kubo_url, attempts).await
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

/// Validate a full identity-publish request from raw message CBOR bytes.
///
/// Used internally by [`IpfsDidPublisher::publish_signed_message`].
pub fn validate_identity_publish_request(message_cbor: &[u8]) -> Result<ValidatedIdentityPublish> {
    let message =
        Message::decode(message_cbor).map_err(|e| anyhow!("invalid signed message: {}", e))?;
    validate_identity_publish_message(&message)
}

/// Validate an `application/vnd.ma.identity.publish.request` message.
///
/// Verifies the DID document signature and that the sender IPNS matches the
/// document DID. Returns a [`ValidatedIdentityPublish`].
pub fn validate_identity_publish_message(message: &Message) -> Result<ValidatedIdentityPublish> {
    if message.message_type != MESSAGE_TYPE_IDENTITY_PUBLISH_REQUEST {
        return Err(anyhow!(
            "expected {} on /ma/ipfs/0.0.1, got {}",
            MESSAGE_TYPE_IDENTITY_PUBLISH_REQUEST,
            message.message_type
        ));
    }

    let payload: IdentityPublishRequest =
        ciborium::de::from_reader(message.payload().as_slice())
            .map_err(|e| anyhow!("invalid identity-publish request payload: {}", e))?;
    let IdentityPublishRequest {
        document: document_bytes,
        ipns_secret_key,
    } = payload;

    let sender_did = Did::try_from(message.from.as_str())
        .map_err(|e| anyhow!("invalid sender did '{}': {}", message.from, e))?;

    let document = Document::decode(&document_bytes)
        .map_err(|e| anyhow!("invalid DID document dag-cbor: {}", e))?;
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

    Ok(ValidatedIdentityPublish {
        document_bytes,
        ipns_secret_key,
        document,
        document_did,
    })
}

/// Validate an `application/vnd.ma.ipfs.request` message (generic store).
///
/// Extracts content and sender identity. Returns a [`ValidatedIpfsStore`].
pub fn validate_ipfs_request(message: &Message) -> Result<ValidatedIpfsStore> {
    if message.message_type != MESSAGE_TYPE_IPFS_REQUEST {
        return Err(anyhow!(
            "expected {} on /ma/ipfs/0.0.1, got {}",
            MESSAGE_TYPE_IPFS_REQUEST,
            message.message_type
        ));
    }

    let payload: IpfsStoreRequest = ciborium::de::from_reader(message.payload().as_slice())
        .map_err(|e| anyhow!("invalid IPFS store request payload: {}", e))?;

    Ok(ValidatedIpfsStore {
        content: payload.content,
        content_type: payload.content_type,
        sender_did: message.from.clone(),
        msg_id: message.id.clone(),
    })
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
async fn publish_did_document_to_kubo(
    kubo_url: &str,
    cleanup: &PinCleanupScheduler,
    did_document: Vec<u8>,
    ipns_private_key: Zeroizing<Vec<u8>>,
    options: DidDocumentPublishOptions,
) -> Result<PublishedDidDocument> {
    let document = Document::decode(&did_document)
        .map_err(|e| anyhow!("invalid DID document dag-cbor: {}", e))?;
    let document_did = Did::try_from(document.id.as_str())
        .map_err(|e| anyhow!("invalid document DID '{}': {}", document.id, e))?;
    let document_ipns_id = document_did.ipns.clone();

    let key_parts: Vec<&str> = if options.key_parts.is_empty() {
        vec![document_ma_type(&document)]
    } else {
        options.key_parts.iter().map(String::as_str).collect()
    };
    let key_name = ipns_key_name_for_parts(&key_parts, &document_ipns_id);
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
        if ipns_private_key.is_empty() {
            return Err(anyhow!(
                "ipns_private_key is required when key is not present in Kubo"
            ));
        }

        let raw_key: [u8; 32] = ipns_private_key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("ipns_private_key must be 32 bytes"))?;
        let keypair = libp2p_identity::Keypair::ed25519_from_bytes(raw_key)
            .map_err(|e| anyhow!("invalid ipns key: {}", e))?;
        let protobuf_key = keypair
            .to_protobuf_encoding()
            .map_err(|e| anyhow!("failed to encode ipns key: {}", e))?;
        let imported = import_key(kubo_url, &key_name, protobuf_key).await?;
        if imported.id.trim() != document_ipns_id {
            return Err(anyhow!(
                "imported key IPNS id '{}' does not match document DID IPNS '{}'",
                imported.id,
                document_ipns_id
            ));
        }
    }

    let pin_name = options
        .remote_pin
        .as_ref()
        .map(|remote| remote.name.clone())
        .unwrap_or_else(|| key_name.clone());
    // With overwrite, pin under an in-flight name so the fresh pin is safe
    // while the cleanup worker removes stale pins; the worker renames it to
    // the requested name once everything is clean.
    let add_name = if options.overwrite {
        in_flight_pin_name(&pin_name)
    } else {
        pin_name.clone()
    };
    let published_cid = dag_put_cbor(kubo_url, did_document, false).await?;
    pin_add_named(kubo_url, &published_cid, &add_name).await?;
    name_publish_with_retry(
        kubo_url,
        &key_name,
        &document_ipns_id,
        &published_cid,
        &options.ipns,
        options.attempts,
        options.initial_backoff,
    )
    .await?;

    let (cleanup_scheduled, remote_pin) =
        confirm_pins_and_schedule_cleanup(kubo_url, cleanup, pin_name, &published_cid, options)
            .await;

    Ok(PublishedDidDocument {
        cid: published_cid,
        key_name,
        ipns_id: document_ipns_id,
        local_pinned: true,
        cleanup_scheduled,
        remote_pin,
    })
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
async fn confirm_pins_and_schedule_cleanup(
    kubo_url: &str,
    cleanup: &PinCleanupScheduler,
    pin_name: String,
    published_cid: &str,
    options: DidDocumentPublishOptions,
) -> (bool, Option<RemotePinStatus>) {
    let (remote_pin, remote_service) = match options.remote_pin {
        Some(remote) => match remote_pin_with_retry(
            kubo_url,
            &remote,
            published_cid,
            options.attempts,
            options.initial_backoff,
        )
        .await
        {
            Ok(()) => (
                Some(RemotePinStatus::Replicated {
                    cleanup_scheduled: false,
                }),
                Some(remote.service),
            ),
            Err(error) => (
                Some(RemotePinStatus::Degraded {
                    error: error.to_string(),
                }),
                None,
            ),
        },
        None => (None, None),
    };
    let cleanup_scheduled = options.overwrite
        && cleanup.schedule(PinCleanupRequest {
            kubo_url: kubo_url.to_string(),
            name: pin_name,
            protected_cid: published_cid.to_string(),
            cleanup_local: true,
            remote_service,
        });
    let remote_pin = remote_pin.map(|status| match status {
        RemotePinStatus::Replicated { .. } => RemotePinStatus::Replicated { cleanup_scheduled },
        RemotePinStatus::Degraded { error } => RemotePinStatus::Degraded { error },
    });

    (cleanup_scheduled, remote_pin)
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
async fn remote_pin_with_retry(
    kubo_url: &str,
    remote: &RemotePinOptions,
    cid: &str,
    attempts: u32,
    initial_backoff: Duration,
) -> Result<()> {
    if attempts == 0 {
        return Err(anyhow!("remote pin attempts must be >= 1"));
    }
    let mut delay = initial_backoff;
    let mut previous_delay = Duration::ZERO;
    let mut last_error = None;
    for attempt in 1..=attempts {
        match remote_pin_add_named(kubo_url, &remote.service, cid, &remote.name).await {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
        if attempt < attempts {
            tokio::time::sleep(delay).await;
            let next = previous_delay.saturating_add(delay);
            previous_delay = delay;
            delay = std::cmp::min(next, Duration::from_secs(30));
        }
    }
    Err(last_error.expect("at least one remote pin attempt"))
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub async fn handle_ipfs_publish(
    kubo_url: &str,
    message_cbor: &[u8],
) -> Result<IpfsPublishDidResponse> {
    let validated = validate_identity_publish_request(message_cbor)?;

    let published = publish_did_document_to_kubo(
        kubo_url,
        PinCleanupScheduler::global(),
        validated.document_bytes,
        Zeroizing::new(validated.ipns_secret_key),
        DidDocumentPublishOptions::default(),
    )
    .await?;

    Ok(IpfsPublishDidResponse {
        ok: true,
        message: "did document published via ma/ipfs/0.0.1".to_string(),
        did: Some(validated.document_did.id()),
        cid: Some(published.cid),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_identity_from_secret, Did, MaExtension, SigningKey};

    #[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
    use super::normalize_kubo_url;

    fn test_identity(seed: u8) -> crate::GeneratedIdentity {
        generate_identity_from_secret([seed; 32]).expect("identity")
    }

    fn test_signing_key(identity: &crate::GeneratedIdentity) -> SigningKey {
        let sign_url = Did::new_url(&identity.subject_url.ipns, None::<String>).expect("did url");
        let private_key: [u8; 32] = hex::decode(&identity.signing_private_key_hex)
            .expect("decode key")
            .try_into()
            .expect("private key bytes");
        SigningKey::from_private_key_bytes(sign_url, private_key).expect("signing key")
    }

    fn ipfs_url(identity: &crate::GeneratedIdentity) -> String {
        format!("{}#ipfs", identity.document.id)
    }

    fn expected_key_name(parts: &[&str], ipns_id: &str) -> String {
        let hash = blake3::hash(ipns_id.as_bytes());
        format!(
            "{}{}-{}",
            MA_IPNS_ALIAS_HASH_PREFIX,
            parts.join("-"),
            &hash.to_hex()[..16]
        )
    }

    #[test]
    fn document_key_name_uses_ma_type() {
        let identity = test_identity(11);
        let mut document = identity.document.clone();
        document.set_ma_extension(MaExtension::new().kind("agent"));

        assert_eq!(
            ipns_key_name_for_document(&document),
            expected_key_name(&["agent"], &identity.subject_url.ipns)
        );
    }

    #[test]
    fn document_key_name_falls_back_to_unknown_type() {
        let identity = test_identity(12);

        assert_eq!(
            ipns_key_name_for_document(&identity.document),
            expected_key_name(&["unknown"], &identity.subject_url.ipns)
        );
    }

    #[test]
    fn key_name_parts_allow_runtime_slug() {
        let ipns_id = "k51qzi5uqu5example";

        assert_eq!(
            ipns_key_name_for_parts(&["runtime", "my-slug"], ipns_id),
            expected_key_name(&["runtime", "my-slug"], ipns_id)
        );
        assert_eq!(
            ipns_key_name_for_parts(&["runtime", "my-slug", "runtime"], ipns_id),
            expected_key_name(&["runtime", "my-slug", "runtime"], ipns_id)
        );
    }

    #[test]
    fn key_name_parts_are_sanitized() {
        let ipns_id = "k51qzi5uqu5example";

        assert_eq!(
            ipns_key_name_for_parts(&["Runtime", "my slug!", "***"], ipns_id),
            expected_key_name(&["runtime", "my-slug", "unknown"], ipns_id)
        );
    }

    #[test]
    fn generate_request_embeds_cbor_document_and_private_key() {
        let identity = test_identity(21);
        let payload =
            generate_identity_publish_request(&identity.document, b"secret-key").expect("payload");
        let request: IdentityPublishRequest =
            ciborium::de::from_reader(payload.as_slice()).expect("decode request");

        assert_eq!(
            request.document,
            identity.document.encode().expect("document bytes")
        );
        assert_eq!(request.ipns_secret_key, b"secret-key".to_vec());
    }

    #[test]
    fn validate_identity_publish_request_accepts_signed_request() {
        let identity = test_identity(22);
        let signing_key = test_signing_key(&identity);
        let payload =
            generate_identity_publish_request(&identity.document, b"private-key").expect("payload");
        let message = Message::new(
            identity.document.id.clone(),
            ipfs_url(&identity),
            MESSAGE_TYPE_IDENTITY_PUBLISH_REQUEST,
            "application/cbor",
            &payload,
            &signing_key,
        )
        .expect("message");
        let encoded = message.encode().expect("message cbor");

        let validated = validate_identity_publish_request(&encoded).expect("validated request");
        assert_eq!(validated.document, identity.document);
        assert_eq!(validated.ipns_secret_key, b"private-key".to_vec());
    }

    #[test]
    fn validate_identity_publish_request_rejects_wrong_content_type() {
        let identity = test_identity(23);
        let signing_key = test_signing_key(&identity);
        let payload =
            generate_identity_publish_request(&identity.document, b"private-key").expect("payload");
        let message = Message::new(
            identity.document.id.clone(),
            ipfs_url(&identity),
            "application/x-test",
            "application/cbor",
            &payload,
            &signing_key,
        )
        .expect("message");
        let encoded = message.encode().expect("message cbor");

        let err = validate_identity_publish_request(&encoded)
            .err()
            .expect("wrong content type");
        assert!(err
            .to_string()
            .contains("expected application/vnd.ma.identity.publish.request"));
    }

    #[test]
    fn validate_identity_publish_request_rejects_ipns_mismatch() {
        let sender_identity = test_identity(24);
        let document_identity = test_identity(25);
        let signing_key = test_signing_key(&sender_identity);
        let payload =
            generate_identity_publish_request(&document_identity.document, b"private-key")
                .expect("payload");
        let message = Message::new(
            sender_identity.document.id.clone(),
            ipfs_url(&sender_identity),
            MESSAGE_TYPE_IDENTITY_PUBLISH_REQUEST,
            "application/cbor",
            &payload,
            &signing_key,
        )
        .expect("message");
        let encoded = message.encode().expect("message cbor");

        let err = validate_identity_publish_request(&encoded)
            .err()
            .expect("ipns mismatch");
        assert!(err.to_string().contains("does not match document IPNS"));
    }

    #[test]
    fn validate_identity_publish_request_rejects_invalid_document_bytes() {
        let identity = test_identity(26);
        let signing_key = test_signing_key(&identity);
        let payload = encode_cbor(&IdentityPublishRequest {
            document: b"not dag-cbor".to_vec(),
            ipns_secret_key: b"private-key".to_vec(),
        })
        .expect("encode request");
        let message = Message::new(
            identity.document.id.clone(),
            ipfs_url(&identity),
            MESSAGE_TYPE_IDENTITY_PUBLISH_REQUEST,
            "application/cbor",
            &payload,
            &signing_key,
        )
        .expect("message");
        let encoded = message.encode().expect("message cbor");

        let err = validate_identity_publish_request(&encoded)
            .err()
            .expect("invalid document");
        assert!(
            err.to_string()
                .contains("invalid identity-publish request payload")
                || err.to_string().contains("invalid DID document dag-cbor")
        );
    }

    #[test]
    fn validate_identity_publish_request_rejects_malformed_document_shapes() {
        let identity = test_identity(27);
        let signing_key = test_signing_key(&identity);

        let mut wrong_context = identity.document.clone();
        wrong_context.context = vec!["https://www.w3.org/ns/did/v1".to_string()];

        let mut fragmented_id = identity.document.clone();
        fragmented_id.id.push_str("#subject");

        let mut fragmented_controller = identity.document.clone();
        fragmented_controller.controller[0].push_str("#controller");

        let mut wrong_method_type = identity.document.clone();
        wrong_method_type.verification_method[0].key_type = "JsonWebKey2020".to_string();

        let mut missing_relationship_target = identity.document.clone();
        missing_relationship_target.assertion_method[0] =
            format!("{}#unknown", missing_relationship_target.id);

        let mut wrong_assertion_codec = identity.document.clone();
        wrong_assertion_codec.assertion_method[0] = wrong_assertion_codec.key_agreement[0].clone();

        let mut wrong_agreement_codec = identity.document.clone();
        wrong_agreement_codec.key_agreement[0] = wrong_agreement_codec.assertion_method[0].clone();

        for (name, document) in [
            ("wrong context", wrong_context),
            ("fragmented document id", fragmented_id),
            ("fragmented controller", fragmented_controller),
            ("wrong verification method type", wrong_method_type),
            ("missing relationship target", missing_relationship_target),
            ("wrong assertion codec", wrong_assertion_codec),
            ("wrong key-agreement codec", wrong_agreement_codec),
        ] {
            let payload = generate_identity_publish_request(&document, b"private-key")
                .expect("publish payload");
            let message = Message::new(
                identity.document.id.clone(),
                ipfs_url(&identity),
                MESSAGE_TYPE_IDENTITY_PUBLISH_REQUEST,
                "application/cbor",
                &payload,
                &signing_key,
            )
            .expect("message");

            let err = validate_identity_publish_request(&message.encode().expect("message cbor"))
                .err()
                .unwrap_or_else(|| panic!("accepted malformed document: {name}"));
            assert!(
                err.to_string().contains("invalid DID document"),
                "unexpected error for {name}: {err}"
            );
        }
    }

    #[test]
    fn validate_identity_publish_request_rejects_invalid_proof_metadata() {
        let identity = test_identity(28);
        let signing_key = test_signing_key(&identity);

        let mut wrong_type = identity.document.clone();
        wrong_type.proof.proof_type = "DataIntegrityProof".to_string();

        let mut wrong_purpose = identity.document.clone();
        wrong_purpose.proof.proof_purpose = "authentication".to_string();

        for (name, document) in [("proof type", wrong_type), ("proof purpose", wrong_purpose)] {
            let payload = generate_identity_publish_request(&document, b"private-key")
                .expect("publish payload");
            let message = Message::new(
                identity.document.id.clone(),
                ipfs_url(&identity),
                MESSAGE_TYPE_IDENTITY_PUBLISH_REQUEST,
                "application/cbor",
                &payload,
                &signing_key,
            )
            .expect("message");

            let err = validate_identity_publish_request(&message.encode().expect("message cbor"))
                .err()
                .unwrap_or_else(|| panic!("accepted invalid {name}"));
            assert!(
                err.to_string()
                    .contains("DID document signature verification failed"),
                "unexpected error for {name}: {err}"
            );
        }
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
    #[test]
    fn normalizes_trailing_slash() {
        assert_eq!(
            normalize_kubo_url("http://127.0.0.1:5001/").expect("normalize url"),
            "http://127.0.0.1:5001"
        );
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
    #[test]
    fn strips_api_v0_suffix() {
        assert_eq!(
            normalize_kubo_url("http://127.0.0.1:5001/api/v0").expect("normalize url"),
            "http://127.0.0.1:5001"
        );
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
    #[test]
    fn keeps_custom_base_path() {
        assert_eq!(
            normalize_kubo_url("http://localhost:5001/kubo").expect("normalize url"),
            "http://localhost:5001/kubo"
        );
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
    #[test]
    fn rejects_empty_url() {
        assert!(normalize_kubo_url("   ").is_err());
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
    #[test]
    fn rejects_non_http_scheme() {
        assert!(normalize_kubo_url("ftp://127.0.0.1:5001").is_err());
    }
}
