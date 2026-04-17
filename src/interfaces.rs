//! Trait interfaces for pluggable DID and IPFS publishing backends.
//!
//! Implement these traits to decouple domain logic from a specific
//! transport or storage backend.

pub trait DidPublisher {
    type Error;

    fn publish_did_document(
        &self,
        actor_id: &str,
        document_json: &str,
    ) -> Result<String, Self::Error>;
}

pub trait IpfsPublisher {
    type Error;

    fn put_json(&self, value_json: &str) -> Result<String, Self::Error>;
    fn publish_name(&self, key_name: &str, cid: &str) -> Result<String, Self::Error>;
}
