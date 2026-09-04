//! Capability-based access control for ma identities.
//!
//! An [`AclMap`] maps principal strings to [`CapabilityEntry`] values.
//! Deny always wins over allow; a wildcard deny closes access to everyone.
//!
//! # Capabilities
//!
//! Capabilities are plain strings. Built-in system capabilities:
//!
//! | Capability | Meaning |
//! |------------|---------|
//! | `"inbox"`  | Deliver messages via `/ma/inbox/0.0.1` |
//! | `"ipfs"`   | Store generic content via `/ma/ipfs/0.0.1` |
//! | `"identity-publish"` | Publish DID documents via `/ma/ipfs/0.0.1` |
//! | `"crud"`   | Access `/ma/crud/0.0.1` |
//! | `"read"`   | Read entities, config, and namespace contents |
//! | `"create"` | Create new namespaces or entities |
//! | `"update"` | Update existing namespaces or entities |
//! | `"delete"` | Delete namespaces or entities |
//! | `"*"`      | Wildcard — grants **all** capabilities at this level |
//!
//! Entity and namespace ACLs may also use arbitrary capability strings that
//! correspond to verb names or sub-namespace names.
//!
//! # Key forms in an [`AclMap`]
//!
//! Keys are **principal strings** — exactly one of:
//!
//! | Form | Meaning |
//! |------|---------|
//! | `"*"` | Wildcard — matches any caller |
//! | `"did:ma:<identity>"` | Bare DID (no fragment) |
//! | `"#<local>"` | Local entity identifier |
//! | `"+<handle>.<path>"` | Named group of principals (unlimited depth) |
//!
//! # YAML format
//!
//! ```yaml
//! acl:
//!   "*": [rpc, create]          # everyone: RPC + create
//!   "did:ma:alice": ["*"]        # alice: all capabilities
//!   "did:ma:bob": [rpc, read]   # bob: restricted
//!   "did:ma:eve":               # null / absent → explicit deny
//!   "+carlotta.friends": [rpc]         # group: all members get rpc
//!   "+alice.project4.admins": ["*"]  # deep path: project4 admins get all caps
//!   "+alice.enemies":                # group: all members denied
//! ```
//!
//! # Example
//!
//! ```rust
//! # use ma_core::{AclMap, CapabilityEntry, check_cap, CAP_INBOX};
//! let mut acl = AclMap::new();
//! acl.insert("*".to_string(), CapabilityEntry::from_caps([CAP_INBOX]));
//! acl.insert("did:ma:k51evil".to_string(), CapabilityEntry::Deny);
//! assert!(check_cap(&acl, "did:ma:k51good", CAP_INBOX).is_ok());
//! assert!(check_cap(&acl, "did:ma:k51evil", CAP_INBOX).is_err());
//! ```

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "acl")]
use crate::{Error, Result};

// ── Capability constants ───────────────────────────────────────────────────────

/// Deliver messages to an endpoint's inbox (`/ma/inbox/0.0.1`).
pub const CAP_INBOX: &str = "inbox";
/// Store generic content via `/ma/ipfs/0.0.1` (fire-and-forget).
pub const CAP_IPFS: &str = "ipfs";
/// Publish DID documents via `/ma/ipfs/0.0.1`.
///
/// Separated from [`CAP_IPFS`] because identity-publish transmits an IPNS
/// secret key and may need to be gated more tightly than generic content
/// storage.
pub const CAP_IDENTITY_PUBLISH: &str = "identity-publish";
/// Access the structured CRUD service via `/ma/crud/0.0.1`.
pub const CAP_CRUD: &str = "crud";
/// Read entities, config, and namespace contents.
pub const CAP_READ: &str = "read";
/// Create new namespaces or entities.
pub const CAP_CREATE: &str = "create";
/// Update existing namespaces or entities.
pub const CAP_UPDATE: &str = "update";
/// Delete namespaces or entities.
pub const CAP_DELETE: &str = "delete";
/// Read or modify ACL documents.
///
/// Separates ACL-administration rights from general CRUD access.
/// A principal with `acl` capability can read and update ACL documents
/// without necessarily having access to the resources those ACLs protect.
pub const CAP_ACL: &str = "acl";

// ── Group-principal prefix ─────────────────────────────────────────────────────

/// Sigil that marks a group principal in an [`AclMap`] key.
///
/// A group key has the form `+<handle>.<path>` where `<handle>` is the owning
/// identity's handle and `<path>` is a dot-separated path of arbitrary depth
/// into that handle's group tree (e.g. `+alice.project4.admins`).
pub const GROUP_PREFIX: &str = "+";

/// Local-entity wildcard principal.
///
/// The bare `"#"` key in an [`AclMap`] matches **any** caller whose principal
/// starts with `"#"` — i.e. any entity running on the same runtime instance.
///
/// It sits between the specific `"#<name>"` form and the global `"*"` wildcard
/// in lookup priority:
///
/// ```text
/// // specific entity  > local wildcard  > global wildcard
/// //   "#fortune"         "#"                 "*"
/// ```
///
/// The runtime pre-normalises intra-runtime callers from their full DID-URL form
/// (`did:ma:<our_did>#fortune`) to the bare fragment form (`#fortune`) before
/// the ACL lookup, so that these keys resolve correctly.
///
/// ## YAML example
///
/// ```yaml
/// acl:
///   "#": [handle_cast]        # any local entity on this runtime may call
///   "did:ma:alice": ["*"]     # remote alice: all caps
///   "*":                      # everyone else: deny
/// ```
pub const LOCAL_ENTITY_WILDCARD: &str = "#";

// ── CapabilityEntry ────────────────────────────────────────────────────────────

/// Capability set for a principal in an [`AclMap`].
///
/// Serialises as:
/// - `null` → [`Deny`](CapabilityEntry::Deny)
/// - YAML sequence → [`Allow`](CapabilityEntry::Allow)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityEntry {
    /// Explicit deny. Wins over any wildcard allow for the same principal.
    Deny,
    /// Allow the listed capabilities. `["*"]` grants all capabilities.
    Allow(BTreeSet<String>),
}

impl CapabilityEntry {
    /// Construct an `Allow` entry from an iterator of capability name strings.
    pub fn from_caps<I, S>(caps: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::Allow(caps.into_iter().map(Into::into).collect())
    }

    /// Return `true` if this entry grants `cap`.
    /// `"*"` in the capability set grants any capability.
    pub fn has(&self, cap: &str) -> bool {
        match self {
            Self::Deny => false,
            Self::Allow(caps) => caps.contains(cap) || caps.contains("*"),
        }
    }

    /// Return `true` if this is an explicit deny.
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny)
    }
}

impl Serialize for CapabilityEntry {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Deny => serializer.serialize_none(),
            Self::Allow(caps) => {
                use serde::ser::SerializeSeq;
                let mut seq = serializer.serialize_seq(Some(caps.len()))?;
                for cap in caps {
                    seq.serialize_element(cap)?;
                }
                seq.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for CapabilityEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            #[allow(dead_code)]
            Str(String),
            Seq(Vec<String>),
        }
        let opt: Option<Raw> = Option::deserialize(deserializer)?;
        match opt {
            None => Ok(Self::Deny),
            Some(Raw::Seq(v)) if v.is_empty() => Ok(Self::Deny),
            Some(Raw::Seq(v)) => Ok(Self::Allow(v.into_iter().collect())),
            Some(Raw::Str(_)) => Err(serde::de::Error::custom(
                "invalid ACL entry: use a YAML sequence for Allow or null for Deny",
            )),
        }
    }
}

// ── AclMap ─────────────────────────────────────────────────────────────────────

/// Capability-based access control map.
///
/// Keys are principal strings — exactly one of:
/// - `"*"` — wildcard
/// - `"did:ma:<identity>"` — bare DID, no fragment
/// - `"#<local>"` — local entity identifier
/// - `"+<handle>.<path>"` — named group of principals (unlimited depth)
///
/// DID-URLs with fragments (`did:ma:foo#bar`) are **not** valid keys;
/// use [`is_valid_acl_key`] to validate before inserting.
pub type AclMap = HashMap<String, CapabilityEntry>;

// ── check_cap ──────────────────────────────────────────────────────────────────

/// Check whether `caller` has capability `cap` in `acl`.
///
/// 1. Normalise `caller` (strip fragment from DID-URLs).
/// 2. Look up the normalised caller directly — if a principal entry, apply and stop.
/// 3. Fall back to the `"*"` wildcard principal entry.
/// 4. Explicit deny → `Err`; capability absent → `Err`; no entry → `Err`.
///
/// Group principals (`+<handle>.<path>`) are **not** resolved here;
/// they are expanded by the runtime's async `check_full`.
///
/// A `"*"` item inside an `Allow` set grants **all** capabilities.
/// Evaluate a single [`CapabilityEntry`] for `cap` and `caller`.
///
/// Returns `Ok(())` when the entry grants `cap`, or the appropriate `Err`.
#[cfg(feature = "acl")]
fn apply_entry(entry: &CapabilityEntry, cap: &str, caller: &str) -> Result<()> {
    match entry {
        CapabilityEntry::Deny => Err(Error::Acl(format!("operation denied for {caller}"))),
        CapabilityEntry::Allow(caps) if caps.contains(cap) || caps.contains("*") => Ok(()),
        CapabilityEntry::Allow(_) => Err(Error::Acl(format!(
            "capability '{cap}' denied for {caller}"
        ))),
    }
}

#[cfg(feature = "acl")]
pub fn check_cap(acl: &AclMap, caller: &str, cap: &str) -> Result<()> {
    let normalized = normalize_principal(caller);

    // 1. Direct principal match (highest priority).
    if let Some(direct) = acl.get(normalized) {
        return apply_entry(direct, cap, caller);
    }

    // 2. Local-entity wildcard "#" — matches any `#`-prefixed caller.
    if normalized.starts_with('#') {
        if let Some(local_wild) = acl.get(LOCAL_ENTITY_WILDCARD) {
            return apply_entry(local_wild, cap, caller);
        }
    }

    // 3. Global wildcard "*" (lowest priority).
    match acl.get("*") {
        None => Err(Error::Acl(format!("no ACL entry for {caller}"))),
        Some(entry) => apply_entry(entry, cap, caller),
    }
}

/// Return `true` if `key` is a valid [`AclMap`] key.
///
/// Valid keys: `"*"`, `"did:ma:<id>"`, `"#<local>"`, `"+<handle>.<path>"`
/// (where `<path>` is dot-separated with unlimited depth),
/// and arbitrary capability/verb name strings (non-empty).
pub fn is_valid_acl_key(key: &str) -> bool {
    !key.is_empty()
}

/// Return `true` if `key` is a principal key (identifies *who*).
///
/// Valid principal key forms:
/// - `"*"` — global wildcard
/// - `"did:ma:<id>"` — bare DID (no fragment)
/// - `"#"` — local-entity wildcard (any entity on this runtime)
/// - `"#<name>"` — specific local entity by fragment name
/// - `"+<handle>.<path>"` — group principal
pub fn is_principal_key(key: &str) -> bool {
    key == "*"
        || (key.starts_with("did:") && !key.contains('#'))
        || key.starts_with('#')   // covers both "#" (local wildcard) and "#name" (specific)
        || is_valid_group_key(key)
}

/// Return `true` if `key` is a valid group principal.
///
/// Form: `+<handle>.<path>` where `<handle>` is non-empty and `<path>` is a
/// non-empty dot-separated string of arbitrary depth
/// (e.g. `+alice.admins`, `+alice.project4.admins`).
fn is_valid_group_key(key: &str) -> bool {
    if let Some(rest) = key.strip_prefix(GROUP_PREFIX) {
        if let Some(dot) = rest.find('.') {
            let handle = &rest[..dot];
            let path = &rest[dot + 1..];
            return !handle.is_empty() && !path.is_empty();
        }
    }
    false
}

/// Validate all keys in an [`AclMap`], returning a descriptive error for the
/// first invalid key found.
///
/// Call this immediately after loading an ACL from YAML or any external source.
#[cfg(feature = "acl")]
pub fn validate_acl_map(acl: &AclMap) -> Result<()> {
    for key in acl.keys() {
        if !is_valid_acl_key(key) {
            return Err(Error::Acl(format!(
                "invalid ACL key {key:?}: key must be non-empty"
            )));
        }
    }
    Ok(())
}

/// Normalise a caller identity for [`AclMap`] lookup.
///
/// - `did:ma:foo#bar` → `did:ma:foo` (strips fragment from **remote** DID-URLs)
/// - `#local` → `#local` (already-normalised local entity, passed through)
/// - `#` → `#` (local-entity wildcard, passed through)
/// - `*` → `*` (global wildcard, passed through)
///
/// **Note:** Callers from the same runtime arrive as `did:ma:<our_did>#fragment`.
/// The runtime is responsible for converting those to `#fragment` *before*
/// calling this function (or [`check_cap`]) so that `"#<name>"` and `"#"`
/// ACL keys resolve correctly.  This function only strips fragments from
/// foreign DID-URLs; it does not know which DID belongs to the local runtime.
pub fn normalize_principal(did: &str) -> &str {
    if did.starts_with("did:") {
        if let Some(pos) = did.find('#') {
            return &did[..pos];
        }
    }
    did
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(caps: &[&str]) -> CapabilityEntry {
        CapabilityEntry::from_caps(caps.iter().copied())
    }

    fn m(entries: &[(&str, CapabilityEntry)]) -> AclMap {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn wildcard_rpc_allows_rpc() {
        let acl = m(&[("*", allow(&[CAP_INBOX]))]);
        assert!(check_cap(&acl, "did:ma:alice", CAP_INBOX).is_ok());
    }

    #[test]
    fn wildcard_rpc_denies_ipfs() {
        let acl = m(&[("*", allow(&[CAP_INBOX]))]);
        assert!(check_cap(&acl, "did:ma:alice", CAP_IPFS).is_err());
    }

    #[test]
    fn explicit_deny_wins_over_wildcard_allow() {
        let acl = m(&[
            ("*", allow(&[CAP_INBOX, CAP_IPFS])),
            ("did:ma:bandit", CapabilityEntry::Deny),
        ]);
        assert!(check_cap(&acl, "did:ma:bandit", CAP_INBOX).is_err());
    }

    #[test]
    fn exact_match_restricts_below_wildcard() {
        let acl = m(&[
            ("*", allow(&[CAP_INBOX, CAP_IPFS])),
            ("did:ma:bob", allow(&[CAP_INBOX])),
        ]);
        assert!(check_cap(&acl, "did:ma:bob", CAP_INBOX).is_ok());
        assert!(check_cap(&acl, "did:ma:bob", CAP_IPFS).is_err());
    }

    #[test]
    fn did_url_caller_is_normalized() {
        let acl = m(&[("did:ma:alice", allow(&[CAP_INBOX, CAP_IPFS]))]);
        assert!(check_cap(&acl, "did:ma:alice#sign", CAP_INBOX).is_ok());
    }

    #[test]
    fn no_entry_default_deny() {
        assert!(check_cap(&AclMap::new(), "did:ma:anyone", CAP_INBOX).is_err());
    }

    #[test]
    fn wildcard_deny_blocks_all() {
        let acl = m(&[("*", CapabilityEntry::Deny)]);
        assert!(check_cap(&acl, "did:ma:anyone", CAP_INBOX).is_err());
    }

    #[test]
    fn local_entity_key_allowed() {
        let acl = m(&[("#agent", allow(&[CAP_INBOX]))]);
        assert!(check_cap(&acl, "#agent", CAP_INBOX).is_ok());
        assert!(check_cap(&acl, "#other", CAP_INBOX).is_err());
    }

    #[test]
    fn arbitrary_capability_works() {
        let acl = m(&[("did:ma:alice", allow(&["emote", "reply"]))]);
        assert!(check_cap(&acl, "did:ma:alice", "emote").is_ok());
        assert!(check_cap(&acl, "did:ma:alice", "reply").is_ok());
        assert!(check_cap(&acl, "did:ma:alice", "admin").is_err());
    }

    #[test]
    fn wildcard_cap_grants_all_capabilities() {
        let acl = m(&[("did:ma:alice", allow(&["*"]))]);
        assert!(check_cap(&acl, "did:ma:alice", CAP_INBOX).is_ok());
        assert!(check_cap(&acl, "did:ma:alice", CAP_IPFS).is_ok());
        assert!(check_cap(&acl, "did:ma:alice", "emote").is_ok());
        assert!(check_cap(&acl, "did:ma:alice", "admin").is_ok());
    }

    #[test]
    fn owner_capability_is_just_a_string() {
        let acl = m(&[("did:ma:alice", allow(&["owner"]))]);
        assert!(check_cap(&acl, "did:ma:alice", "owner").is_ok());
        assert!(check_cap(&acl, "did:ma:alice", CAP_INBOX).is_err());
    }

    #[test]
    fn normalize_strips_fragment() {
        assert_eq!(normalize_principal("did:ma:foo#bar"), "did:ma:foo");
        assert_eq!(normalize_principal("did:ma:foo"), "did:ma:foo");
        assert_eq!(normalize_principal("#local"), "#local");
        assert_eq!(normalize_principal("#"), "#");
        assert_eq!(normalize_principal("*"), "*");
    }

    // ── Local-entity wildcard ("#") tests ─────────────────────────────────────

    #[test]
    fn local_wildcard_allows_any_hash_prefixed_caller() {
        // "#" matches any #-prefixed caller when there is no specific entry.
        let acl = m(&[("#", allow(&[CAP_INBOX]))]);
        assert!(check_cap(&acl, "#fortune", CAP_INBOX).is_ok());
        assert!(check_cap(&acl, "#scheduler", CAP_INBOX).is_ok());
        assert!(check_cap(&acl, "#any_entity", CAP_INBOX).is_ok());
    }

    #[test]
    fn local_wildcard_does_not_match_remote_callers() {
        // Remote DIDs do not start with '#', so "#" should not grant them.
        let acl = m(&[("#", allow(&[CAP_INBOX]))]);
        assert!(check_cap(&acl, "did:ma:remote", CAP_INBOX).is_err());
    }

    #[test]
    fn specific_local_entity_wins_over_local_wildcard() {
        // "#fortune" is more specific: it restricts below the "#" wildcard.
        let acl = m(&[
            ("#", allow(&[CAP_INBOX, CAP_IPFS])),
            ("#fortune", allow(&[CAP_INBOX])), // only rpc, not ipfs
        ]);
        assert!(check_cap(&acl, "#fortune", CAP_INBOX).is_ok());
        assert!(check_cap(&acl, "#fortune", CAP_IPFS).is_err());
        // Other local entities still get rpc+ipfs from the wildcard.
        assert!(check_cap(&acl, "#other", CAP_IPFS).is_ok());
    }

    #[test]
    fn local_wildcard_deny_blocks_all_local_entities() {
        let acl = m(&[
            ("#", CapabilityEntry::Deny),
            ("*", allow(&[CAP_INBOX])), // global wildcard would allow, but # deny wins
        ]);
        assert!(check_cap(&acl, "#fortune", CAP_INBOX).is_err());
        assert!(check_cap(&acl, "#any", CAP_INBOX).is_err());
        // Remote callers are unaffected by the "#" deny.
        assert!(check_cap(&acl, "did:ma:remote", CAP_INBOX).is_ok());
    }

    #[test]
    fn specific_local_entity_allow_overrides_local_wildcard_deny() {
        // "#fortune" explicit allow wins over "#" deny for that entity.
        let acl = m(&[
            ("#", CapabilityEntry::Deny),
            ("#fortune", allow(&[CAP_INBOX])),
        ]);
        assert!(check_cap(&acl, "#fortune", CAP_INBOX).is_ok());
        assert!(check_cap(&acl, "#other", CAP_INBOX).is_err());
    }

    #[test]
    fn global_wildcard_not_triggered_for_hash_caller_when_local_wildcard_present() {
        // When "#" deny is set, "*" allow must NOT override it for local callers.
        let acl = m(&[("#", CapabilityEntry::Deny), ("*", allow(&[CAP_INBOX]))]);
        // Local entity is denied by "#" — must not fall through to "*".
        assert!(check_cap(&acl, "#fortune", CAP_INBOX).is_err());
    }

    #[test]
    fn local_wildcard_is_key_form_valid() {
        assert!(is_principal_key("#"));
        assert!(is_principal_key("#fortune"));
        assert!(is_principal_key("*"));
        assert!(is_principal_key("did:ma:alice"));
    }

    #[test]
    fn explicit_deny_without_wildcard() {
        // A bare Deny entry with no wildcard still denies.
        let acl = m(&[("did:ma:bandit", CapabilityEntry::Deny)]);
        assert!(check_cap(&acl, "did:ma:bandit", CAP_INBOX).is_err());
        // Others get default deny too (no wildcard).
        assert!(check_cap(&acl, "did:ma:alice", CAP_INBOX).is_err());
    }

    #[test]
    fn multiple_caps_in_single_entry() {
        let acl = m(&[("did:ma:alice", allow(&[CAP_INBOX, CAP_IPFS, CAP_READ]))]);
        assert!(check_cap(&acl, "did:ma:alice", CAP_INBOX).is_ok());
        assert!(check_cap(&acl, "did:ma:alice", CAP_IPFS).is_ok());
        assert!(check_cap(&acl, "did:ma:alice", CAP_READ).is_ok());
        assert!(check_cap(&acl, "did:ma:alice", CAP_CREATE).is_err());
        assert!(check_cap(&acl, "did:ma:alice", CAP_DELETE).is_err());
    }

    #[test]
    fn direct_entry_restricts_even_when_wildcard_is_broader() {
        // Wildcard gives everyone rpc+ipfs, but bob only gets rpc.
        // Direct entry wins and caps don't accumulate from wildcard.
        let acl = m(&[
            ("*", allow(&[CAP_INBOX, CAP_IPFS])),
            ("did:ma:bob", allow(&[CAP_INBOX])),
        ]);
        assert!(check_cap(&acl, "did:ma:bob", CAP_INBOX).is_ok());
        assert!(check_cap(&acl, "did:ma:bob", CAP_IPFS).is_err());
        // Alice (no direct entry) still gets both from wildcard.
        assert!(check_cap(&acl, "did:ma:alice", CAP_INBOX).is_ok());
        assert!(check_cap(&acl, "did:ma:alice", CAP_IPFS).is_ok());
    }

    #[test]
    fn group_principal_allowed() {
        // "+group" keys are not resolved by check_cap; they pass through.
        // Resolution happens in the runtime's async check_full.
        let acl = m(&[("*", allow(&[CAP_INBOX]))]);
        assert!(check_cap(&acl, "did:ma:anyone", CAP_INBOX).is_ok());
    }

    #[test]
    fn valid_acl_keys() {
        assert!(is_valid_acl_key("*"));
        assert!(is_valid_acl_key("did:ma:k51foo"));
        assert!(is_valid_acl_key("#agent"));
        assert!(is_valid_acl_key("+alice.venner"));
        assert!(is_valid_acl_key("+runtime.admins"));
        assert!(is_valid_acl_key("fortune"));
        assert!(is_valid_acl_key("admin"));
        assert!(is_valid_acl_key("emote"));
        assert!(!is_valid_acl_key(""));
    }

    #[cfg(feature = "acl")]
    #[test]
    fn capability_serde_roundtrip() {
        let acl: AclMap = [
            (
                "*".to_string(),
                CapabilityEntry::from_caps(["rpc", "create"]),
            ),
            ("did:ma:bandit".to_string(), CapabilityEntry::Deny),
        ]
        .into_iter()
        .collect();
        let yaml = serde_yaml::to_string(&acl).unwrap();
        let roundtrip: AclMap = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(acl, roundtrip);
    }

    #[cfg(feature = "acl")]
    #[test]
    fn yaml_null_deserializes_to_deny() {
        let yaml = "'did:ma:x': ~\n'*':\n- rpc\n- create\n";
        let acl: AclMap = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(acl.get("did:ma:x"), Some(&CapabilityEntry::Deny));
        assert_eq!(
            acl.get("*"),
            Some(&CapabilityEntry::from_caps(["rpc", "create"]))
        );
    }
}
