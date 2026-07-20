//! IPFS-relaterte APIs.
//!
//! Plattformuavhengig:
//! - `gateway_resolver` — DID-dokument-henting via HTTP gateway (fungerer på wasm og native).
//! - `publish` — payload-bygging/validering for `/ma/ipfs/0.0.1`.
//!
//! For Kubo-spesifikke operasjoner (RPC write/pin/publish), se `crate::kubo`.

pub mod gateway_resolver;
pub mod publish;

pub use gateway_resolver::{DidDocumentResolver, IpfsGatewayResolver};

// Always-available APIs for building and validating IPFS requests (wasm-safe)
pub use publish::{
    generate_identity_publish_request, generate_ipfs_store_request, ipns_key_name_for_document,
    ipns_key_name_for_parts, validate_identity_publish_message, validate_identity_publish_request,
    validate_ipfs_request, IdentityPublishRequest, IpfsPublishDidResponse, IpfsStoreRequest,
    ValidatedIdentityPublish, ValidatedIpfsStore, MA_IPNS_ALIAS_HASH_PREFIX,
};

// Native + kubo-specific publishing backend
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub use publish::{handle_ipfs_publish, IpfsDidPublisher};
