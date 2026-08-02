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
mod publish;

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub(crate) use kubo::{
    dag_put, import_key, list_keys, name_publish_with_retry, wait_for_api, IpnsPublishOptions,
};

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub use kubo::{cat_bytes, ipfs_add};
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo", feature = "config"))]
pub use pinning::remote_pin_replace;
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub use pinning::PinReplaceOutcome;
