//! Error types for ma-core.

use thiserror::Error;

// ─── Primitive DID/message errors (from ma-did) ─────────────────────────────

pub type MaResult<T> = std::result::Result<T, MaError>;

#[derive(Debug, Error)]
pub enum MaError {
    #[error("empty DID")]
    EmptyDid,
    #[error("invalid DID prefix, expected did:ma:")]
    InvalidDidPrefix,
    #[error("missing DID identifier")]
    MissingIdentifier,
    #[error("missing DID fragment")]
    MissingFragment,
    #[error("unexpected DID fragment")]
    UnexpectedFragment,
    #[error("invalid DID format")]
    InvalidDidFormat,
    #[error("invalid DID fragment: {0}")]
    InvalidFragment(String),
    #[error("invalid DID identifier")]
    InvalidIdentifier,
    #[error("invalid message id")]
    InvalidMessageId,
    #[error("empty message id")]
    EmptyMessageId,
    #[error("invalid message type")]
    InvalidMessageType,
    #[error("invalid key type")]
    InvalidKeyType,
    #[error("invalid identity secret")]
    InvalidIdentitySecret,
    #[error("invalid recipient")]
    InvalidRecipient,
    #[error("missing message content")]
    MissingContent,
    #[error("missing message content type")]
    MissingContentType,
    #[error("missing sender")]
    MissingSender,
    #[error("missing signature")]
    MissingSignature,
    #[error("message timestamp is invalid")]
    InvalidMessageTimestamp,
    #[error("message is too old")]
    MessageTooOld,
    #[error("message timestamp is too far in the future")]
    MessageFromFuture,
    #[error("replay detected")]
    ReplayDetected,
    #[error("broadcast messages must not have a recipient")]
    BroadcastMustNotHaveRecipient,
    #[error("encrypted messages require a recipient")]
    MessageRequiresRecipient,
    #[error("context missing")]
    EmptyContext,
    #[error("invalid DID document context")]
    InvalidContext,
    #[error("controller missing")]
    EmptyController,
    #[error("verification method missing type")]
    VerificationMethodMissingType,
    #[error("invalid verification method type: {0}")]
    InvalidVerificationMethodType(String),
    #[error("unknown verification method: {0}")]
    UnknownVerificationMethod(String),
    #[error("public key multibase is empty")]
    EmptyPublicKeyMultibase,
    #[error("invalid public key multibase")]
    InvalidPublicKeyMultibase,
    #[error("invalid multicodec, expected {expected}, got {actual}")]
    InvalidMulticodec { expected: u64, actual: u64 },
    #[error("invalid key length, expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("proof is missing")]
    MissingProof,
    #[error("document signature is invalid")]
    InvalidDocumentSignature,
    #[error("message signature is invalid")]
    InvalidMessageSignature,
    #[error("invalid createdAt timestamp: {0}")]
    InvalidCreatedAt(String),
    #[error("invalid updatedAt timestamp: {0}")]
    InvalidUpdatedAt(String),
    #[error("missing envelope field: {0}")]
    MissingEnvelopeField(&'static str),
    #[error("invalid ephemeral key length")]
    InvalidEphemeralKeyLength,
    #[error("ciphertext too short")]
    CiphertextTooShort,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("CBOR encode failed: {0}")]
    CborEncode(String),
    #[error("CBOR decode failed: {0}")]
    CborDecode(String),
    #[error("JSON encode failed: {0}")]
    JsonEncode(String),
    #[error("JSON decode failed: {0}")]
    JsonDecode(String),
}

// ─── Service-level errors ────────────────────────────────────────────────────

/// Errors returned by ma-core public APIs.
#[derive(Debug, Error)]
pub enum Error {
    // ─── Transport ──────────────────────────────────────────────────────
    #[error("transport error: {0}")]
    Transport(String),

    #[error("transport connect failed: {0}")]
    Connect(String),

    #[error("transport bind failed: {0}")]
    Bind(String),

    #[error("stream open failed: {0}")]
    StreamOpen(String),

    #[error("connection closed: {0}")]
    ConnectionClosed(String),

    // ─── Validation ─────────────────────────────────────────────────────
    #[error("message validation failed: {0}")]
    Validation(#[from] MaError),

    #[error("message signature verification failed")]
    SignatureVerification,

    #[error("replay detected for message {0}")]
    Replay(String),

    // ─── Resolution ─────────────────────────────────────────────────────
    #[error("DID resolution failed for {did}: {detail}")]
    Resolution { did: String, detail: String },

    #[error("IPNS resolution failed for {path}: {detail}")]
    IpnsResolution { path: String, detail: String },

    #[error("no inbox transport in DID document for {0}")]
    NoInboxTransport(String),

    #[error("invalid transport string: {0}")]
    InvalidTransport(String),

    // ─── Identity / key bootstrap ───────────────────────────────────────
    #[error("secret key error: {0}")]
    SecretKey(String),

    #[error("endpoint ID derivation failed: {0}")]
    EndpointId(String),

    // ─── Config ─────────────────────────────────────────────────────────
    #[cfg(feature = "config")]
    #[error("config error: {0}")]
    Config(String),

    // ─── Secrets bundle ──────────────────────────────────────────────────
    #[cfg(feature = "config")]
    #[error("secrets error: {0}")]
    Secrets(String),

    // ─── ACL ─────────────────────────────────────────────────────────────
    #[cfg(feature = "acl")]
    #[error("acl error: {0}")]
    Acl(String),

    // ─── Service registration ───────────────────────────────────────────
    #[error("duplicate service ALPN: {0}")]
    DuplicateService(String),

    // ─── Generic pass-through ───────────────────────────────────────────
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
