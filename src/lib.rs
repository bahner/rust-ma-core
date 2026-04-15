#![forbid(unsafe_code)]

pub mod addressing;
#[cfg(not(target_arch = "wasm32"))]
pub mod bootstrap_identity;
pub mod capability_acl;
pub mod command_syntax;
pub mod interfaces;
#[cfg(not(target_arch = "wasm32"))]
pub mod kubo;
pub mod pinning;
pub mod ttl_cache;

pub use addressing::{
    create_world_did, did_root, endpoint_id_from_address, endpoint_id_from_transport_value,
    find_alias_for_address, find_did_by_endpoint, humanize_identifier, humanize_text,
    normalize_endpoint_id, normalize_iroh_address, normalize_relay_url, resolve_alias_input,
    resolve_inbox_endpoint_id, same_ipns,
};
#[cfg(not(target_arch = "wasm32"))]
pub use bootstrap_identity::{default_ma_config_root, ensure_local_ipns_key_file};
pub use capability_acl::{
    CapabilityAcl, CompiledCapabilityAcl, CompiledSubjectAcl, capability_pattern_matches,
    compile_acl, compile_acl_from_text, evaluate_compiled_acl, evaluate_compiled_acl_with_owner,
    parse_capability_acl_text, parse_object_local_capability_acl, subject_has_capability,
    subject_has_capability_with_owner, validate_capability_acl,
};
pub use command_syntax::{parse_property_command, parse_property_command_for_keys, PropertyCommand};
pub use interfaces::{DidPublisher, IpfsPublisher};
#[cfg(not(target_arch = "wasm32"))]
pub use kubo::KuboKey;
pub use pinning::{PinUpdateOutcome, pin_update_add_rm};
pub use ttl_cache::TtlCache;
