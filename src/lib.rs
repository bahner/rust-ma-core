#![forbid(unsafe_code)]

pub mod interfaces;
pub mod ipfs_publish;
#[cfg(not(target_arch = "wasm32"))]
pub mod kubo;
pub mod pinning;

pub use interfaces::{DidPublisher, IpfsPublisher};
pub use ipfs_publish::{
	CONTENT_TYPE_DOC, IpfsPublishDidRequest, IpfsPublishDidResponse,
	ValidatedIpfsPublish, validate_ipfs_publish_request,
};
#[cfg(not(target_arch = "wasm32"))]
pub use ipfs_publish::{handle_ipfs_publish, publish_did_document_to_kubo};
#[cfg(not(target_arch = "wasm32"))]
pub use ipfs_publish::KuboDidPublisher;
#[cfg(not(target_arch = "wasm32"))]
pub use kubo::KuboKey;
pub use pinning::{PinUpdateOutcome, pin_update_add_rm};
