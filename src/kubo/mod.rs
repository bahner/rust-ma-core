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
    dag_put_cbor, import_key, list_keys, name_publish_with_retry, pin_add_named, wait_for_api,
};

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub use kubo::{cat_bytes, ipfs_add, remote_pin_add_named};
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub use pinning::{
    delete_local_pins_named_in_background, delete_remote_pins_named_in_background,
    in_flight_pin_name, remote_pin_replace_named, PinCleanupRequest, PinCleanupScheduler,
};
