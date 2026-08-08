use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Verifier};
use nanoid::nanoid;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use web_time::{SystemTime, UNIX_EPOCH};

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::{
    constants,
    did::Did,
    doc::Document,
    error::{MaError, MaResult as Result},
    key::{EncryptionKey, SigningKey},
};

pub const MESSAGE_PREFIX: &str = "/ma/";

pub const DEFAULT_REPLAY_WINDOW_SECS: u64 = 120;
pub const DEFAULT_MAX_CLOCK_SKEW_SECS: u64 = 30;
pub const DEFAULT_MESSAGE_TTL_SECS: u64 = 3600;

/// Prefix `payload` with a multicodec varint so the codec is self-describing.
pub fn encode_content(codec: u64, payload: &[u8]) -> Vec<u8> {
    crate::multiformat::multicodec_encode(codec, payload)
}

/// Peel the multicodec varint prefix from `content` bytes.
/// Returns `(codec, payload)`.
pub fn decode_content(content: &[u8]) -> crate::error::MaResult<(u64, Vec<u8>)> {
    crate::multiformat::multicodec_decode(content)
}

/// Map a `content_type` string to the multicodec codec used to prefix the payload.
/// `Message::new` applies this automatically — callers never handle raw prefixes.
fn codec_for(content_type: &str) -> u64 {
    match content_type {
        "application/vnd.ipld.dag-cbor" => crate::multiformat::CODEC_DAG_CBOR,
        // application/vnd.ma.term: CBOR term — bare atom (:ok, :pong) or tuple ([:verb, ...]).
        "application/cbor" | "application/vnd.ma.term" => crate::multiformat::CODEC_CBOR,
        _ => crate::multiformat::CODEC_IDENTITY,
    }
}

#[must_use]
pub fn default_protocol() -> String {
    format!("{MESSAGE_PREFIX}{}", constants::VERSION)
}

/// Signed message headers (without content body).
///
/// Headers include a BLAKE3 hash of the content for integrity verification.
/// Extracted from a [`Message`] via [`Message::headers`] or [`Message::unsigned_headers`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Headers {
    pub id: String,
    #[serde(rename = "protocol")]
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub from: String,
    pub to: String,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
    #[serde(default)]
    pub exp: u64,
    #[serde(rename = "contentType")]
    pub content_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "replyTo")]
    pub reply_to: Option<String>,
    #[serde(rename = "contentHash")]
    pub content_hash: [u8; 32],
    pub signature: Vec<u8>,
}

impl Headers {
    pub fn validate(&self) -> Result<()> {
        validate_message_id(&self.id)?;
        validate_protocol(&self.protocol)?;
        if let Some(reply_to) = &self.reply_to {
            validate_message_id(reply_to)?;
        }

        if self.content_type.is_empty() {
            return Err(MaError::MissingContentType);
        }

        Did::validate(&self.from)?;
        let recipient_is_empty = self.to.trim().is_empty();

        if self.message_type == crate::service::MESSAGE_TYPE_BROADCAST {
            if !recipient_is_empty {
                return Err(MaError::BroadcastMustNotHaveRecipient);
            }
        } else {
            if recipient_is_empty {
                return Err(MaError::MessageRequiresRecipient);
            }
            Did::validate_url(&self.to).map_err(|_| MaError::InvalidRecipient)?;
        }
        validate_message_freshness(self.created_at, self.exp)?;

        Ok(())
    }
}

/// A signed actor-to-actor message.
///
/// Messages are signed on creation using the sender's [`SigningKey`].
/// The signature covers the CBOR-serialized headers (including a BLAKE3
/// hash of the content), ensuring both integrity and authenticity.
///
/// # Examples
///
/// ```
/// use ma_core::{generate_identity_from_secret, Message, SigningKey, Did};
///
/// let sender = generate_identity_from_secret([1u8; 32]).unwrap();
/// let recipient = generate_identity_from_secret([2u8; 32]).unwrap();
///
/// let sign_url = Did::new_url(&sender.subject_url.ipns, None::<String>).unwrap();
/// let signing_key = SigningKey::from_private_key_bytes(
///     sign_url,
///     hex::decode(&sender.signing_private_key_hex).unwrap().try_into().unwrap(),
/// ).unwrap();
///
/// // Create a signed message
/// let msg = Message::new(
///     sender.document.id.clone(),
///     format!("{}#inbox", recipient.document.id),
///     "application/vnd.ma.message",
///     "text/plain",
///     b"hello",
///     &signing_key,
/// ).unwrap();
///
/// // Verify against sender's document
/// msg.verify_with_document(&sender.document).unwrap();
///
/// // Serialize to wire format
/// let bytes = msg.encode().unwrap();
/// let restored = Message::decode(&bytes).unwrap();
/// assert_eq!(msg.id, restored.id);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    #[serde(rename = "protocol")]
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub from: String,
    pub to: String,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
    #[serde(default)]
    pub exp: u64,
    #[serde(rename = "contentType")]
    pub content_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "replyTo")]
    pub reply_to: Option<String>,
    pub content: Vec<u8>,
    pub signature: Vec<u8>,
}

struct MessageOptions {
    exp: u64,
    reply_to: Option<String>,
}

impl Message {
    pub fn new(
        from: impl Into<String>,
        to: impl Into<String>,
        message_type: impl Into<String>,
        content_type: impl Into<String>,
        content: &[u8],
        signing_key: &SigningKey,
    ) -> Result<Self> {
        let exp = now_unix_secs()? + DEFAULT_MESSAGE_TTL_SECS;
        Self::new_with_exp(
            from,
            to,
            message_type,
            content_type,
            content,
            exp,
            signing_key,
        )
    }

    /// Create and sign a reply whose correlation header is covered by the signature.
    pub fn new_reply(
        from: impl Into<String>,
        to: impl Into<String>,
        message_type: impl Into<String>,
        content_type: impl Into<String>,
        content: &[u8],
        reply_to: impl Into<String>,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        let exp = now_unix_secs()? + DEFAULT_MESSAGE_TTL_SECS;
        Self::new_with_options(
            from,
            to,
            message_type,
            content_type,
            content,
            MessageOptions {
                exp,
                reply_to: Some(reply_to.into()),
            },
            signing_key,
        )
    }

    pub fn new_with_exp(
        from: impl Into<String>,
        to: impl Into<String>,
        message_type: impl Into<String>,
        content_type: impl Into<String>,
        content: &[u8],
        exp: u64,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        Self::new_with_options(
            from,
            to,
            message_type,
            content_type,
            content,
            MessageOptions {
                exp,
                reply_to: None,
            },
            signing_key,
        )
    }

    fn new_with_options(
        from: impl Into<String>,
        to: impl Into<String>,
        message_type: impl Into<String>,
        content_type: impl Into<String>,
        content: &[u8],
        options: MessageOptions,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        let content_type_str: String = content_type.into();
        let encoded = encode_content(codec_for(&content_type_str), content);
        let mut message = Self {
            id: nanoid!(),
            protocol: default_protocol(),
            message_type: message_type.into(),
            from: from.into(),
            to: to.into(),
            created_at: now_unix_secs()?,
            exp: options.exp,
            content_type: content_type_str,
            reply_to: options.reply_to,
            content: encoded,
            signature: Vec::new(),
        };

        message.unsigned_headers().validate()?;
        message.validate_content()?;
        message.sign(signing_key)?;
        Ok(message)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(self, &mut out)
            .map_err(|error| MaError::CborEncode(error.to_string()))?;
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ciborium::de::from_reader(bytes).map_err(|error| MaError::CborDecode(error.to_string()))
    }

    /// Return the decoded content payload, stripping the multicodec varint prefix
    /// applied by [`Message::new`].
    #[must_use]
    pub fn payload(&self) -> Vec<u8> {
        decode_content(&self.content)
            .map(|(_, p)| p)
            .unwrap_or_else(|_| self.content.clone())
    }

    #[must_use]
    pub fn unsigned_headers(&self) -> Headers {
        Headers {
            id: self.id.clone(),
            protocol: self.protocol.clone(),
            message_type: self.message_type.clone(),
            from: self.from.clone(),
            to: self.to.clone(),
            created_at: self.created_at,
            exp: self.exp,
            content_type: self.content_type.clone(),
            reply_to: self.reply_to.clone(),
            content_hash: content_hash(&self.content),
            signature: Vec::new(),
        }
    }

    #[must_use]
    pub fn headers(&self) -> Headers {
        let mut headers = self.unsigned_headers();
        headers.signature.clone_from(&self.signature);
        headers
    }

    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<()> {
        let bytes = self.unsigned_headers_cbor()?;
        self.signature = signing_key.sign(&bytes);
        Ok(())
    }

    pub fn verify_with_document(&self, sender_document: &Document) -> Result<()> {
        if self.from.is_empty() {
            return Err(MaError::MissingSender);
        }

        if self.signature.is_empty() {
            return Err(MaError::MissingSignature);
        }

        let sender_did = Did::try_from(self.from.as_str())?;
        if sender_document.id != sender_did.base_id() {
            return Err(MaError::InvalidRecipient);
        }

        self.headers().validate()?;
        let bytes = self.unsigned_headers_cbor()?;
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| MaError::InvalidMessageSignature)?;
        sender_document
            .assertion_method_public_key()?
            .verify(&bytes, &signature)
            .map_err(|_| MaError::InvalidMessageSignature)
    }

    pub fn enclose_for(&self, recipient_document: &Document) -> Result<Envelope> {
        self.headers().validate()?;

        let recipient_public_key =
            X25519PublicKey::from(recipient_document.key_agreement_public_key_bytes()?);
        let ephemeral_secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
        let shared_secret = ephemeral_secret
            .diffie_hellman(&recipient_public_key)
            .to_bytes();

        let encrypted_headers = encrypt(
            &self.headers_cbor()?,
            derive_symmetric_key(&shared_secret, constants::BLAKE3_HEADERS_LABEL),
        )?;

        let encrypted_content = encrypt(
            &self.content,
            derive_symmetric_key(&shared_secret, constants::blake3_content_label()),
        )?;

        Ok(Envelope {
            ephemeral_key: ephemeral_public.as_bytes().to_vec(),
            encrypted_content,
            encrypted_headers,
        })
    }

    fn headers_cbor(&self) -> Result<Vec<u8>> {
        to_cbor(&self.headers())
    }

    fn unsigned_headers_cbor(&self) -> Result<Vec<u8>> {
        to_cbor(&self.unsigned_headers())
    }

    fn validate_content(&self) -> Result<()> {
        if self.content.is_empty() {
            return Err(MaError::MissingContent);
        }
        Ok(())
    }

    fn from_headers(headers: Headers) -> Result<Self> {
        headers.validate()?;
        Ok(Self {
            id: headers.id,
            protocol: headers.protocol,
            message_type: headers.message_type,
            from: headers.from,
            to: headers.to,
            created_at: headers.created_at,
            exp: headers.exp,
            content_type: headers.content_type,
            reply_to: headers.reply_to,
            content: Vec::new(),
            signature: headers.signature,
        })
    }
}

fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out)
        .map_err(|error| MaError::CborEncode(error.to_string()))?;
    Ok(out)
}

/// Sliding-window replay guard for message deduplication.
///
/// Tracks seen message IDs within a configurable time window and rejects
/// duplicates. Use with [`Envelope::open_with_replay_guard`] for
/// transport-level replay protection.
///
/// # Examples
///
/// ```
/// use ma_core::ReplayGuard;
///
/// let mut guard = ReplayGuard::new(120); // 2-minute window
/// // or use the default (120 seconds):
/// let mut guard = ReplayGuard::default();
/// ```
#[derive(Debug, Clone)]
pub struct ReplayGuard {
    seen: HashMap<String, u64>,
    window_secs: u64,
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new(DEFAULT_REPLAY_WINDOW_SECS)
    }
}

impl ReplayGuard {
    #[must_use]
    pub fn new(window_secs: u64) -> Self {
        Self {
            seen: HashMap::new(),
            window_secs,
        }
    }

    pub fn check_and_insert(&mut self, headers: &Headers) -> Result<()> {
        headers.validate()?;
        self.prune_old()?;
        if self.seen.contains_key(&headers.id) {
            return Err(MaError::ReplayDetected);
        }
        self.seen.insert(headers.id.clone(), now_unix_secs()?);
        Ok(())
    }

    fn prune_old(&mut self) -> Result<()> {
        let now = now_unix_secs()?;
        self.seen
            .retain(|_, seen_at| now.saturating_sub(*seen_at) <= self.window_secs);
        Ok(())
    }
}

/// An encrypted message envelope for transport.
///
/// Contains an ephemeral X25519 public key and XChaCha20-Poly1305 encrypted
/// headers and content. Created by [`Message::enclose_for`] and opened by
/// [`Envelope::open`] or [`Envelope::open_with_replay_guard`].
///
/// # Examples
///
/// ```
/// use ma_core::{generate_identity_from_secret, Message, Envelope, EncryptionKey, SigningKey, Did};
///
/// let alice = generate_identity_from_secret([1u8; 32]).unwrap();
/// let bob = generate_identity_from_secret([2u8; 32]).unwrap();
///
/// let alice_sign_url = Did::new_url(&alice.subject_url.ipns, None::<String>).unwrap();
/// let alice_key = SigningKey::from_private_key_bytes(
///     alice_sign_url,
///     hex::decode(&alice.signing_private_key_hex).unwrap().try_into().unwrap(),
/// ).unwrap();
///
/// let msg = Message::new(
///     alice.document.id.clone(),
///     format!("{}#inbox", bob.document.id),
///     "application/vnd.ma.message",
///     "text/plain",
///     b"secret",
///     &alice_key,
/// ).unwrap();
///
/// // Encrypt for Bob
/// let envelope = msg.enclose_for(&bob.document).unwrap();
///
/// // Bob decrypts
/// let bob_enc_url = Did::new_url(&bob.subject_url.ipns, None::<String>).unwrap();
/// let bob_enc_key = EncryptionKey::from_private_key_bytes(
///     bob_enc_url,
///     hex::decode(&bob.encryption_private_key_hex).unwrap().try_into().unwrap(),
/// ).unwrap();
/// let decrypted = envelope.open(&bob_enc_key, &alice.document).unwrap();
/// assert_eq!(decrypted.payload(), b"secret");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(rename = "ephemeralKey")]
    pub ephemeral_key: Vec<u8>,
    #[serde(rename = "encryptedContent")]
    pub encrypted_content: Vec<u8>,
    #[serde(rename = "encryptedHeaders")]
    pub encrypted_headers: Vec<u8>,
}

impl Envelope {
    pub fn verify(&self) -> Result<()> {
        if self.ephemeral_key.is_empty() {
            return Err(MaError::MissingEnvelopeField("ephemeralKey"));
        }
        if self.ephemeral_key.len() != 32 {
            return Err(MaError::InvalidEphemeralKeyLength);
        }
        if self.encrypted_content.is_empty() {
            return Err(MaError::MissingEnvelopeField("encryptedContent"));
        }
        if self.encrypted_headers.is_empty() {
            return Err(MaError::MissingEnvelopeField("encryptedHeaders"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(self, &mut out)
            .map_err(|error| MaError::CborEncode(error.to_string()))?;
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ciborium::de::from_reader(bytes).map_err(|error| MaError::CborDecode(error.to_string()))
    }

    pub fn open(
        &self,
        recipient_key: &EncryptionKey,
        sender_document: &Document,
    ) -> Result<Message> {
        self.verify()?;

        let shared_secret = compute_shared_secret(&self.ephemeral_key, recipient_key)?;
        let headers = self.decrypt_headers(&shared_secret)?;
        headers.validate()?;
        let content = self.decrypt_content(&shared_secret)?;

        let mut message = Message::from_headers(headers)?;
        message.content = content;
        message.verify_with_document(sender_document)?;
        Ok(message)
    }

    #[cfg(feature = "iroh")]
    pub(crate) fn decrypt(&self, recipient_key: &EncryptionKey) -> Result<Message> {
        self.verify()?;

        let shared_secret = compute_shared_secret(&self.ephemeral_key, recipient_key)?;
        let headers = self.decrypt_headers(&shared_secret)?;
        headers.validate()?;
        let content = self.decrypt_content(&shared_secret)?;

        let mut message = Message::from_headers(headers)?;
        message.content = content;
        Ok(message)
    }

    pub fn open_with_replay_guard(
        &self,
        recipient_key: &EncryptionKey,
        sender_document: &Document,
        replay_guard: &mut ReplayGuard,
    ) -> Result<Message> {
        self.verify()?;

        let shared_secret = compute_shared_secret(&self.ephemeral_key, recipient_key)?;
        let headers = self.decrypt_headers(&shared_secret)?;
        let content = self.decrypt_content(&shared_secret)?;

        let mut message = Message::from_headers(headers)?;
        message.content = content;
        message.verify_with_document(sender_document)?;
        replay_guard.check_and_insert(&message.headers())?;
        Ok(message)
    }

    fn decrypt_headers(&self, shared_secret: &[u8; 32]) -> Result<Headers> {
        let decrypted = decrypt(
            &self.encrypted_headers,
            shared_secret,
            constants::BLAKE3_HEADERS_LABEL,
        )?;
        ciborium::de::from_reader(decrypted.as_slice())
            .map_err(|error| MaError::CborDecode(error.to_string()))
    }

    fn decrypt_content(&self, shared_secret: &[u8; 32]) -> Result<Vec<u8>> {
        decrypt(
            &self.encrypted_content,
            shared_secret,
            constants::blake3_content_label(),
        )
    }
}

fn validate_message_id(id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(MaError::EmptyMessageId);
    }

    if !id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err(MaError::InvalidMessageId);
    }

    Ok(())
}

fn validate_protocol(kind: &str) -> Result<()> {
    if kind == default_protocol() {
        return Ok(());
    }

    Err(MaError::InvalidMessageType)
}

fn now_unix_secs() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| MaError::InvalidMessageTimestamp)
}

fn validate_message_freshness(created_at: u64, exp: u64) -> Result<()> {
    let now = now_unix_secs()?;

    if created_at > now + DEFAULT_MAX_CLOCK_SKEW_SECS {
        return Err(MaError::MessageFromFuture);
    }

    if exp == 0 {
        return Ok(()); // 0 = never expires
    }

    if now > exp + DEFAULT_MAX_CLOCK_SKEW_SECS {
        return Err(MaError::MessageTooOld);
    }

    Ok(())
}

fn compute_shared_secret(
    ephemeral_key_bytes: &[u8],
    recipient_key: &EncryptionKey,
) -> Result<[u8; 32]> {
    let ephemeral_public = X25519PublicKey::from(
        <[u8; 32]>::try_from(ephemeral_key_bytes)
            .map_err(|_| MaError::InvalidEphemeralKeyLength)?,
    );
    Ok(recipient_key.shared_secret(&ephemeral_public))
}

fn derive_symmetric_key(shared_secret: &[u8; 32], label: &str) -> Key {
    let derived = blake3::derive_key(label, shared_secret);
    *Key::from_slice(&derived)
}

fn encrypt(data: &[u8], key: Key) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(&key);
    let nonce = XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng);
    let encrypted = cipher.encrypt(&nonce, data).map_err(|_| MaError::Crypto)?;

    let mut out = nonce.to_vec();
    out.extend_from_slice(&encrypted);
    Ok(out)
}

fn decrypt(data: &[u8], shared_secret: &[u8; 32], label: &str) -> Result<Vec<u8>> {
    if data.len() < 24 {
        return Err(MaError::CiphertextTooShort);
    }

    let key = derive_symmetric_key(shared_secret, label);
    let cipher = XChaCha20Poly1305::new(&key);
    let nonce = XNonce::from_slice(&data[..24]);

    cipher
        .decrypt(nonce, &data[24..])
        .map_err(|_| MaError::Crypto)
}

fn content_hash(content: &[u8]) -> [u8; 32] {
    blake3::hash(content).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{doc::VerificationMethod, key::EncryptionKey};

    fn fixture_documents() -> (
        SigningKey,
        EncryptionKey,
        Document,
        SigningKey,
        EncryptionKey,
        Document,
    ) {
        let sender_ipns = crate::ipns_from_secret([1; 32]).expect("sender ipns");
        let sender_did = Did::new_url(&sender_ipns, None::<String>).expect("sender did");
        let sender_sign_url = Did::new_url(&sender_ipns, None::<String>).expect("sender sign did");
        let sender_enc_url = Did::new_url(&sender_ipns, None::<String>).expect("sender enc did");
        let sender_signing = SigningKey::generate(sender_sign_url).expect("sender signing key");
        let sender_encryption =
            EncryptionKey::generate(sender_enc_url).expect("sender encryption key");

        let recipient_ipns = crate::ipns_from_secret([2; 32]).expect("recipient ipns");
        let recipient_did = Did::new_url(&recipient_ipns, None::<String>).expect("recipient did");
        let recipient_sign_url =
            Did::new_url(&recipient_ipns, None::<String>).expect("recipient sign did");
        let recipient_enc_url =
            Did::new_url(&recipient_ipns, None::<String>).expect("recipient enc did");
        let recipient_signing =
            SigningKey::generate(recipient_sign_url).expect("recipient signing key");
        let recipient_encryption =
            EncryptionKey::generate(recipient_enc_url).expect("recipient encryption key");

        let mut sender_document = Document::new(&sender_did, &sender_did);
        let sender_assertion = VerificationMethod::new(
            sender_did.base_id(),
            sender_did.base_id(),
            sender_signing.key_type.clone(),
            sender_signing.did.fragment.as_deref().unwrap_or_default(),
            sender_signing.public_key_multibase.clone(),
        )
        .expect("sender assertion vm");
        let sender_key_agreement = VerificationMethod::new(
            sender_did.base_id(),
            sender_did.base_id(),
            sender_encryption.key_type.clone(),
            sender_encryption
                .did
                .fragment
                .as_deref()
                .unwrap_or_default(),
            sender_encryption.public_key_multibase.clone(),
        )
        .expect("sender key agreement vm");
        sender_document
            .add_verification_method(sender_assertion.clone())
            .expect("add sender assertion");
        sender_document
            .add_verification_method(sender_key_agreement.clone())
            .expect("add sender key agreement");
        sender_document.assertion_method = vec![sender_assertion.id.clone()];
        sender_document.key_agreement = vec![sender_key_agreement.id.clone()];
        sender_document
            .sign(&sender_signing, &sender_assertion)
            .expect("sign sender doc");

        let mut recipient_document = Document::new(&recipient_did, &recipient_did);
        let recipient_assertion = VerificationMethod::new(
            recipient_did.base_id(),
            recipient_did.base_id(),
            recipient_signing.key_type.clone(),
            recipient_signing
                .did
                .fragment
                .as_deref()
                .unwrap_or_default(),
            recipient_signing.public_key_multibase.clone(),
        )
        .expect("recipient assertion vm");
        let recipient_key_agreement = VerificationMethod::new(
            recipient_did.base_id(),
            recipient_did.base_id(),
            recipient_encryption.key_type.clone(),
            recipient_encryption
                .did
                .fragment
                .as_deref()
                .unwrap_or_default(),
            recipient_encryption.public_key_multibase.clone(),
        )
        .expect("recipient key agreement vm");
        recipient_document
            .add_verification_method(recipient_assertion.clone())
            .expect("add recipient assertion");
        recipient_document
            .add_verification_method(recipient_key_agreement.clone())
            .expect("add recipient key agreement");
        recipient_document.assertion_method = vec![recipient_assertion.id.clone()];
        recipient_document.key_agreement = vec![recipient_key_agreement.id.clone()];
        recipient_document
            .sign(&recipient_signing, &recipient_assertion)
            .expect("sign recipient doc");

        (
            sender_signing,
            sender_encryption,
            sender_document,
            recipient_signing,
            recipient_encryption,
            recipient_document,
        )
    }

    fn inbox_url(document: &Document) -> String {
        format!("{}#inbox", document.id)
    }

    #[test]
    fn did_round_trip() {
        let did = Did::new_url(
            "k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr",
            Some("bahner"),
        )
        .expect("did must build");
        let parsed = Did::try_from(did.id().as_str()).expect("did must parse");
        assert_eq!(did, parsed);
    }

    #[test]
    fn subject_url_round_trip() {
        let did = Did::new_url(
            "k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr",
            None::<String>,
        )
        .expect("subject did must build");
        let parsed = Did::try_from(did.id().as_str()).expect("subject did must parse");
        assert_eq!(did, parsed);
    }

    #[test]
    fn document_signs_and_verifies() {
        let (sender_signing, _, sender_document, _, _, _) = fixture_documents();
        sender_signing.validate().expect("signing key validates");
        sender_document.validate().expect("document validates");
    }

    #[test]
    fn envelope_round_trip() {
        let (sender_signing, _, sender_document, _, recipient_encryption, recipient_document) =
            fixture_documents();
        let message = Message::new(
            sender_document.id.clone(),
            inbox_url(&recipient_document),
            "application/vnd.ma.message",
            "text/plain",
            b"look",
            &sender_signing,
        )
        .expect("message creation");
        message
            .verify_with_document(&sender_document)
            .expect("message signature verifies");

        let envelope = message
            .enclose_for(&recipient_document)
            .expect("message encloses");
        let opened = envelope
            .open(&recipient_encryption, &sender_document)
            .expect("envelope opens");

        assert_eq!(opened.payload(), b"look");
        assert_eq!(opened.from, sender_document.id);
        assert_eq!(opened.to, inbox_url(&recipient_document));
    }

    #[test]
    fn tampered_content_fails_signature_verification() {
        let (sender_signing, _, sender_document, _, _, recipient_document) = fixture_documents();
        let mut message = Message::new(
            sender_document.id.clone(),
            inbox_url(&recipient_document),
            "application/vnd.ma.message",
            "text/plain",
            b"look",
            &sender_signing,
        )
        .expect("message creation");

        message.content = b"tampered".to_vec();
        let result = message.verify_with_document(&sender_document);
        assert!(matches!(result, Err(MaError::InvalidMessageSignature)));
    }

    #[test]
    fn reply_constructor_signs_correlation_header() {
        let (sender_signing, _, sender_document, _, _, recipient_document) = fixture_documents();
        let mut reply = Message::new_reply(
            sender_document.id.clone(),
            inbox_url(&recipient_document),
            "application/vnd.ma.rpc.reply",
            "application/vnd.ma.term",
            b":ok",
            "request-id",
            &sender_signing,
        )
        .expect("reply creation");

        reply
            .verify_with_document(&sender_document)
            .expect("reply signature covers replyTo");
        assert_eq!(reply.reply_to.as_deref(), Some("request-id"));

        reply.reply_to = Some("different-request-id".to_string());
        assert!(matches!(
            reply.verify_with_document(&sender_document),
            Err(MaError::InvalidMessageSignature)
        ));
    }

    #[test]
    fn stale_message_is_rejected() {
        let (sender_signing, _, sender_document, _, _, recipient_document) = fixture_documents();
        let mut message = Message::new(
            sender_document.id.clone(),
            inbox_url(&recipient_document),
            "application/vnd.ma.message",
            "text/plain",
            b"look",
            &sender_signing,
        )
        .expect("message creation");

        message.created_at = 0;
        message.exp = 1; // 1 s epoch — well in the past
        message
            .sign(&sender_signing)
            .expect("re-sign with past timestamps");
        let result = message.verify_with_document(&sender_document);
        assert!(matches!(result, Err(MaError::MessageTooOld)));
    }

    #[test]
    fn future_message_is_rejected() {
        let (sender_signing, _, sender_document, _, _, recipient_document) = fixture_documents();
        let mut message = Message::new(
            sender_document.id.clone(),
            inbox_url(&recipient_document),
            "application/vnd.ma.message",
            "text/plain",
            b"look",
            &sender_signing,
        )
        .expect("message creation");

        message.created_at =
            now_unix_secs().expect("current timestamp") + DEFAULT_MAX_CLOCK_SKEW_SECS + 60;
        message
            .sign(&sender_signing)
            .expect("re-sign with updated timestamp");

        let result = message.verify_with_document(&sender_document);
        assert!(matches!(result, Err(MaError::MessageFromFuture)));
    }

    #[test]
    fn exp_zero_disables_expiration() {
        let (sender_signing, _, sender_document, _, _, recipient_document) = fixture_documents();
        let mut message = Message::new(
            sender_document.id.clone(),
            inbox_url(&recipient_document),
            "application/vnd.ma.message",
            "text/plain",
            b"look",
            &sender_signing,
        )
        .expect("message creation");

        message.created_at = 0;
        message.exp = 0; // 0 = never expires
        message.sign(&sender_signing).expect("re-sign with exp=0");

        message
            .verify_with_document(&sender_document)
            .expect("exp=0 should bypass expiration check");
    }

    #[test]
    fn custom_ttl_rejects_expired_message() {
        let (sender_signing, _, sender_document, _, _, recipient_document) = fixture_documents();
        let now_secs = now_unix_secs().expect("current timestamp");
        // Create with a valid 60-second window.
        let mut message = Message::new_with_exp(
            sender_document.id.clone(),
            inbox_url(&recipient_document),
            "application/vnd.ma.message",
            "text/plain",
            b"look",
            now_secs + 60,
            &sender_signing,
        )
        .expect("message creation with custom exp");

        // Rewind exp to 1 ns (well in the past) and re-sign.
        message.exp = 1;
        message
            .sign(&sender_signing)
            .expect("re-sign with expired exp");

        let result = message.verify_with_document(&sender_document);
        assert!(matches!(result, Err(MaError::MessageTooOld)));
    }

    #[test]
    fn replay_guard_rejects_duplicate_envelope() {
        let (sender_signing, _, sender_document, _, recipient_encryption, recipient_document) =
            fixture_documents();
        let message = Message::new(
            sender_document.id.clone(),
            inbox_url(&recipient_document),
            "application/vnd.ma.message",
            "text/plain",
            b"look",
            &sender_signing,
        )
        .expect("message creation");

        let envelope = message
            .enclose_for(&recipient_document)
            .expect("message encloses");
        let mut replay_guard = ReplayGuard::default();

        envelope
            .open_with_replay_guard(&recipient_encryption, &sender_document, &mut replay_guard)
            .expect("first delivery accepted");

        let second = envelope.open_with_replay_guard(
            &recipient_encryption,
            &sender_document,
            &mut replay_guard,
        );
        assert!(matches!(second, Err(MaError::ReplayDetected)));
    }

    #[test]
    fn rejected_envelope_does_not_consume_replay_id() {
        let (sender_signing, _, sender_document, _, recipient_encryption, recipient_document) =
            fixture_documents();
        let message = Message::new(
            sender_document.id.clone(),
            inbox_url(&recipient_document),
            "application/vnd.ma.message",
            "text/plain",
            b"look",
            &sender_signing,
        )
        .expect("message creation");
        let envelope = message
            .enclose_for(&recipient_document)
            .expect("message encloses");
        let mut tampered = envelope.clone();
        tampered.encrypted_content[0] ^= 0xff;
        let mut guard = ReplayGuard::default();

        assert!(tampered
            .open_with_replay_guard(&recipient_encryption, &sender_document, &mut guard,)
            .is_err());

        envelope
            .open_with_replay_guard(&recipient_encryption, &sender_document, &mut guard)
            .expect("valid envelope remains acceptable");
    }

    #[test]
    fn broadcast_allows_empty_recipient() {
        let (sender_signing, _, sender_document, _, _, _) = fixture_documents();
        let message = Message::new(
            sender_document.id.clone(),
            String::new(),
            "application/vnd.ma.broadcast",
            "text/plain",
            b"hello everyone",
            &sender_signing,
        )
        .expect("broadcast message creation");

        message
            .verify_with_document(&sender_document)
            .expect("broadcast with empty recipient verifies");
    }

    #[test]
    fn broadcast_rejects_recipient() {
        let (sender_signing, _, sender_document, _, _, recipient_document) = fixture_documents();
        let result = Message::new(
            sender_document.id.clone(),
            inbox_url(&recipient_document),
            "application/vnd.ma.broadcast",
            "text/plain",
            b"hello everyone",
            &sender_signing,
        );

        assert!(matches!(
            result,
            Err(MaError::BroadcastMustNotHaveRecipient)
        ));
    }

    #[test]
    fn message_requires_recipient() {
        let (sender_signing, _, sender_document, _, _, _) = fixture_documents();
        let result = Message::new(
            sender_document.id.clone(),
            String::new(),
            "application/vnd.ma.message",
            "text/plain",
            b"secret",
            &sender_signing,
        );

        assert!(matches!(result, Err(MaError::MessageRequiresRecipient)));
    }

    #[test]
    fn custom_message_requires_recipient() {
        let (sender_signing, _, sender_document, _, _, _) = fixture_documents();
        let result = Message::new(
            sender_document.id.clone(),
            String::new(),
            "application/x-ma-custom",
            "text/plain",
            b"whatever",
            &sender_signing,
        );

        assert!(matches!(result, Err(MaError::MessageRequiresRecipient)));
    }

    #[test]
    fn unknown_content_type_allows_recipient() {
        let (sender_signing, _, sender_document, _, _, recipient_document) = fixture_documents();
        let message = Message::new(
            sender_document.id.clone(),
            inbox_url(&recipient_document),
            "application/x-ma-custom",
            "text/plain",
            b"whatever",
            &sender_signing,
        )
        .expect("custom content type with recipient");

        message
            .verify_with_document(&sender_document)
            .expect("custom type with recipient verifies");
    }
}
