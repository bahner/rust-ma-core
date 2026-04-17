//! Wire protocol types for ma transport.
//!
//! These are the canonical request/response types exchanged over framed
//! bi-streams on any ma service (inbox, avatar, etc.).

use serde::{Deserialize, Serialize};

/// Request sent from a client to a service over a framed bi-stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServiceRequest {
    /// A signed CBOR message payload.
    Signed { message_cbor: Vec<u8> },
}

/// Response returned by a service after processing a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceResponse {
    pub ok: bool,
    pub message: String,
}

impl ServiceResponse {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
        }
    }
}
