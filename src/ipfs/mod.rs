//! IPFS-related APIs.
//!
//! Platform-independent (wasm and native):
//! - `resolver` — [`DidDocumentResolver`] / [`IpnsPathResolver`]: the DID/IPNS
//!   resolution contract, plus [`parse_document_bytes`]. Hosts supply the
//!   implementation (Kubo RPC on native, verified-fetch on wasm).
//! - `publish` — payload build/validation for `/ma/ipfs/0.0.1`.
//!
//! Publishing, pinning, key management, DID/IPNS resolution and content reads
//! all go through `crate::kubo` (native, `kubo` feature); wasm hosts provide
//! their own IPFS backend.

pub mod publish;
pub mod resolver;

pub use resolver::{parse_document_bytes, DidDocumentResolver, IpnsPathResolver};

// Always-available APIs for building and validating IPFS requests (wasm-safe)
pub use publish::{
    generate_identity_publish_request, generate_ipfs_store_request, ipns_key_name_for_document,
    ipns_key_name_for_parts, validate_identity_publish_message, validate_identity_publish_request,
    validate_ipfs_request, IdentityPublishRequest, IpfsPublishDidResponse, IpfsStoreRequest,
    ValidatedIdentityPublish, ValidatedIpfsStore, MA_IPNS_ALIAS_HASH_PREFIX,
};

// Native + kubo-specific publishing backend
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub use crate::kubo::IpnsPublishOptions;
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub use publish::{
    handle_ipfs_publish, DidDocumentPublishOptions, IpfsDidPublisher, PublishedDidDocument,
    RemotePinOptions, RemotePinStatus,
};
