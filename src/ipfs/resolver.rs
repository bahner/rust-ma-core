//! DID / IPNS resolution contract.
//!
//! These traits are the resolution seam between `ma-core` and its hosts:
//! native runtimes implement them with the Kubo RPC client (`KuboDidResolver`),
//! and wasm hosts supply their own backend (verified-fetch). `ma-core` ships no
//! HTTP gateway resolver — clients that cannot use Kubo provide IPFS themselves.

use crate::Document;
use async_trait::async_trait;
use web_time::Duration;

/// Trait for resolving a DID to its DID document.
///
/// Native implementations resolve through Kubo RPC (`KuboDidResolver`);
/// browser-side implementations use verified-fetch. Implement this trait for
/// custom resolution strategies.
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
/// Implemented by `KuboDidResolver` (native, Kubo RPC) and by browser-side
/// resolvers.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait IpnsPathResolver: Send + Sync {
    async fn resolve_ipns_path(&self, path: &str) -> crate::error::Result<String>;
}

/// Decode, validate, and verify a DID document from raw DAG-CBOR bytes.
///
/// The single trusted entry point for turning stored bytes into a validated,
/// proof-verified [`Document`]: decodes DAG-CBOR, runs [`Document::validate`],
/// and verifies the proof with [`Document::verify`]. Resolution backends can
/// reuse this to inherit the same guarantees.
pub fn parse_document_bytes(bytes: &[u8]) -> std::result::Result<Document, String> {
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
    use super::parse_document_bytes;
    use crate::{
        generate_identity_from_secret, multiformat::signature_multibase_encode, CODEC_EDDSA_SIG,
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
}
