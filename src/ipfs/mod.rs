//! Native-only Kubo/IPFS module.
//!
//! This module is available only on non-wasm targets with the `kubo` feature
//! and groups read/write operations against a directly reachable Kubo API.

pub mod kubo;
pub mod pinning;
pub mod publish;

pub use kubo::{
    cat_bytes, cat_text, dag_get, dag_put, fetch_did_document, generate_key, import_key, ipfs_add,
    list_key_names, list_keys, name_publish, name_publish_with_options, name_publish_with_retry,
    name_resolve, pin_add_named, pin_rm, remove_key, wait_for_api, IpnsPublishOptions, KuboKey,
};
pub use pinning::{pin_update_add_rm, PinUpdateOutcome};
pub use publish::{
    handle_ipfs_publish, publish_did_document_to_kubo, validate_ipfs_publish_request,
    IpfsPublishDidRequest, IpfsPublishDidResponse, KuboDidPublisher, ValidatedIpfsPublish,
};
