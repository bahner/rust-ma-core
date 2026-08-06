//! Kubo IPFS RPC client.
//!
//! All APIs here require a running Kubo daemon and are native-only.
//! Enabled with the `kubo` feature flag.

#![allow(dead_code)]

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
#[allow(clippy::module_inception)]
mod kubo;
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
mod pinning;

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub use kubo::IpnsPublishOptions;
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub(crate) use kubo::{
    dag_put_cbor, import_key, list_keys, name_publish_with_retry, name_resolve, wait_for_api,
};

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub use kubo::{cat_bytes, ipfs_add};
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub use pinning::{PinCleanupRequest, PinCleanupScheduler};
