//! IPFS-related APIs.
//!
//! Cross-platform:
//! - `gateway_resolver` for DID fetch over HTTP gateways.
//!
//! Native-only (requires `kubo` feature):
//! - IPFS RPC write/pin/publish helpers.

pub mod gateway_resolver;

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
mod kubo;
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
mod pinning;
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
mod publish;

pub use gateway_resolver::{DidDocumentResolver, IpfsGatewayResolver};

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub use kubo::{
    cat_bytes, cat_text, dag_get, dag_put, fetch_did_document, generate_key, import_key, ipfs_add,
    list_key_names, list_keys, name_publish, name_publish_with_options, name_publish_with_retry,
    name_resolve, pin_add_named, pin_rm, remove_key, wait_for_api, IpnsPublishOptions, KuboKey,
};
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub use pinning::{pin_update_add_rm, PinUpdateOutcome};
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub use publish::{
    handle_ipfs_publish, publish_did_document_to_kubo, validate_ipfs_publish_request,
    IpfsDidPublisher, IpfsPublishDidRequest, IpfsPublishDidResponse, ValidatedIpfsPublish,
};
