//! Error types for ma-core.

use thiserror::Error;

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
    Validation(#[from] did_ma::MaError),

    #[error("message signature verification failed")]
    SignatureVerification,

    #[error("replay detected for message {0}")]
    Replay(String),

    // ─── Resolution ─────────────────────────────────────────────────────
    #[error("DID resolution failed for {did}: {detail}")]
    Resolution { did: String, detail: String },

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

    // ─── Service registration ───────────────────────────────────────────
    #[error("duplicate service ALPN: {0}")]
    DuplicateService(String),

    // ─── Generic pass-through ───────────────────────────────────────────
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
