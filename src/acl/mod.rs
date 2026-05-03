//! Access control lists for ma identities and DID URLs.
//!
//! An [`Acl`] is a list of allow/deny rules keyed by DID URL or fragment.
//! Deny always wins over allow; an identity-level deny covers all DID-URLs
//! under that identity. The wildcard `*` grants public access.
//!
//! # YAML format
//!
//! ```yaml
//! acl:
//!   - "*"           # public access
//!   - "did:ma:alice"
//!   - "!did:ma:eve"
//!   - "#read"
//!   - "!#write"
//! ```
//!
//! # Example
//!
//! ```rust
//! # use ma_core::Acl;
//! let yaml = "acl:\n  - \"*\"\n  - \"!did:ma:Qmevil\"\n";
//! let acl = Acl::new_from_yaml(yaml).unwrap();
//! assert!(acl.is_allowed("did:ma:Qmgood#read"));
//! assert!(!acl.is_allowed("did:ma:Qmevil#read"));
//! ```

use std::collections::HashSet;
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
use std::sync::{Arc, Mutex};
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
use std::time::Duration;

use cid::Cid;
use did_ma::Did;

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
use crate::ipfs::{ipfs_add, name_publish_with_retry, IpnsPublishOptions};
use crate::{Error, Result};
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
use tokio::task::JoinHandle;
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
use tokio::time::sleep;

// ── Internal entry representation ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    /// `*` — public access
    Any,
    /// `did:ma:…` — allow a full identity or DID-URL
    Allow(Did),
    /// `!did:ma:…` — deny a full identity or DID-URL
    Deny(Did),
    /// `#fragment` — allow by bare fragment (no identity check)
    AllowFragment(String),
    /// `!#fragment` — deny by bare fragment
    DenyFragment(String),
}

impl Entry {
    fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s == "*" {
            return Ok(Entry::Any);
        }
        if let Some(rest) = s.strip_prefix("!#") {
            return Ok(Entry::DenyFragment(rest.to_owned()));
        }
        if let Some(rest) = s.strip_prefix('#') {
            return Ok(Entry::AllowFragment(rest.to_owned()));
        }
        if let Some(rest) = s.strip_prefix('!') {
            let did = Did::try_from(rest)
                .map_err(|e| Error::Acl(format!("invalid DID in deny entry '{rest}': {e}")))?;
            return Ok(Entry::Deny(did));
        }
        if s.starts_with("did:") {
            let did =
                Did::try_from(s).map_err(|e| Error::Acl(format!("invalid DID '{s}': {e}")))?;
            return Ok(Entry::Allow(did));
        }
        Err(Error::Acl(format!("unrecognised ACL entry: '{s}'")))
    }
}

// ── Compiled lookup tables ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct Compiled {
    /// `*` was present
    public: bool,
    /// identity-level denies (ipns key, no fragment)
    deny_identities: HashSet<String>,
    /// DID-URL denies (ipns, fragment)
    deny_urls: HashSet<(String, String)>,
    /// identity-level allows
    allow_identities: HashSet<String>,
    /// DID-URL allows
    allow_urls: HashSet<(String, String)>,
    /// bare-fragment denies
    deny_fragments: HashSet<String>,
    /// bare-fragment allows
    allow_fragments: HashSet<String>,
}

impl Compiled {
    fn build(entries: &[Entry]) -> Self {
        let mut c = Compiled::default();
        for e in entries {
            match e {
                Entry::Any => c.public = true,
                Entry::Allow(did) => {
                    if let Some(frag) = &did.fragment {
                        c.allow_urls.insert((did.ipns.clone(), frag.clone()));
                    } else {
                        c.allow_identities.insert(did.ipns.clone());
                    }
                }
                Entry::Deny(did) => {
                    if let Some(frag) = &did.fragment {
                        c.deny_urls.insert((did.ipns.clone(), frag.clone()));
                    } else {
                        c.deny_identities.insert(did.ipns.clone());
                    }
                }
                Entry::AllowFragment(f) => {
                    c.allow_fragments.insert(f.clone());
                }
                Entry::DenyFragment(f) => {
                    c.deny_fragments.insert(f.clone());
                }
            }
        }
        c
    }
}

// ── Public ACL type ────────────────────────────────────────────────────────────

/// An access control list for an ma entity.
///
/// Create with [`Acl::new_from_yaml`] or [`Acl::new_from_cid`].
#[derive(Debug, Clone)]
pub struct Acl {
    entries: Vec<Entry>,
    compiled: Compiled,
    /// `true` when entries have changed since last publish.
    pub dirty: bool,
    generation: u64,
    /// CID of the last successfully published DAG-CBOR node.
    pub cid: Option<Cid>,
}

impl Acl {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Parse an ACL from a YAML string.
    ///
    /// The YAML must contain an `acl:` key whose value is a sequence of
    /// strings. Any unrecognised entry is a hard error (fail-fast).
    ///
    /// # Errors
    /// Returns [`Error::Acl`] if the YAML is malformed or any entry is invalid.
    pub fn new_from_yaml(yaml: &str) -> Result<Self> {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            acl: Vec<String>,
        }
        let w: Wrapper =
            serde_yaml::from_str(yaml).map_err(|e| Error::Acl(format!("YAML parse error: {e}")))?;

        let entries: Result<Vec<Entry>> = w.acl.iter().map(|s| Entry::parse(s)).collect();
        let entries = entries?;
        let compiled = Compiled::build(&entries);
        Ok(Self {
            entries,
            compiled,
            dirty: true,
            generation: 0,
            cid: None,
        })
    }

    /// Reconstruct an ACL from a previously published YAML payload and its CID.
    ///
    /// Marks the ACL as clean (`dirty = false`) and records the CID.
    ///
    /// # Errors
    /// Returns [`Error::Acl`] if the bytes are not valid UTF-8 or the YAML is
    /// malformed.
    pub fn new_from_cid(cid: Cid, data: &[u8]) -> Result<Self> {
        let yaml = std::str::from_utf8(data)
            .map_err(|e| Error::Acl(format!("ACL data is not UTF-8: {e}")))?;
        let mut acl = Self::new_from_yaml(yaml)?;
        acl.dirty = false;
        acl.cid = Some(cid);
        Ok(acl)
    }

    // ── Mutation ──────────────────────────────────────────────────────────────

    /// Add an allow rule for `did_str`.
    ///
    /// `did_str` may be a bare `#fragment`, `did:ma:…`, or `did:ma:…#fragment`.
    ///
    /// # Errors
    /// Returns [`Error::Acl`] if `did_str` cannot be parsed.
    pub fn allow(&mut self, did_str: &str) -> Result<()> {
        let entry = Entry::parse(did_str)?;
        self.add_entry(entry)
    }

    /// Add a deny rule for `did_str`.
    ///
    /// Prefix with `!` is optional — this method adds the deny semantics
    /// regardless. `did_str` may be `#fragment`, `did:ma:…`, or
    /// `did:ma:…#fragment`.
    ///
    /// # Errors
    /// Returns [`Error::Acl`] if `did_str` cannot be parsed as a DID or fragment.
    pub fn deny(&mut self, did_str: &str) -> Result<()> {
        // Strip a leading `!` if the caller already included it.
        let s = did_str.strip_prefix('!').unwrap_or(did_str);
        let deny_str = if s.starts_with('#') || s.starts_with("did:") {
            format!("!{s}")
        } else {
            return Err(Error::Acl(format!(
                "cannot deny '{did_str}': not a DID or fragment"
            )));
        };
        let entry = Entry::parse(&deny_str)?;
        self.add_entry(entry)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn add_entry(&mut self, entry: Entry) -> Result<()> {
        if !self.entries.contains(&entry) {
            self.entries.push(entry);
            self.compiled = Compiled::build(&self.entries);
            self.dirty = true;
            self.generation = self.generation.wrapping_add(1);
        }
        Ok(())
    }

    // ── Query ─────────────────────────────────────────────────────────────────

    /// Return `true` if `did_str` is permitted by this ACL.
    ///
    /// `did_str` is matched as:
    /// - `did:ma:…#fragment` — full DID-URL
    /// - `did:ma:…` — bare identity
    /// - `#fragment` — bare fragment (no identity context)
    ///
    /// Deny always wins over allow. An identity-level deny blocks all
    /// DID-URLs under that identity.
    pub fn is_allowed(&self, did_str: &str) -> bool {
        let c = &self.compiled;

        // Bare fragment shortcut
        if let Some(frag) = did_str.strip_prefix('#') {
            if c.deny_fragments.contains(frag) {
                return false;
            }
            if c.public {
                return true;
            }
            return c.allow_fragments.contains(frag);
        }

        // Parse as DID (lenient — we already validated on insert)
        let did = match Did::try_from(did_str) {
            Ok(d) => d,
            Err(_) => return false,
        };

        // Identity-level deny knocks out all DID-URLs under that identity
        if c.deny_identities.contains(&did.ipns) {
            return false;
        }

        if let Some(ref frag) = did.fragment {
            // DID-URL deny
            if c.deny_urls.contains(&(did.ipns.clone(), frag.clone())) {
                return false;
            }
            if c.public {
                return true;
            }
            // Allow by full DID-URL or by identity
            if c.allow_urls.contains(&(did.ipns.clone(), frag.clone())) {
                return true;
            }
            c.allow_identities.contains(&did.ipns)
        } else {
            // Bare identity check
            if c.public {
                return true;
            }
            c.allow_identities.contains(&did.ipns)
        }
    }

    // ── Serialisation ─────────────────────────────────────────────────────────

    /// Serialise the ACL to a canonical YAML string.
    ///
    /// # Errors
    /// Returns [`Error::Acl`] if serialisation fails (should not happen in
    /// practice).
    pub fn to_yaml(&self) -> Result<String> {
        let strings: Vec<String> = self.entries.iter().map(entry_to_string).collect();
        #[derive(serde::Serialize)]
        struct Wrapper<'a> {
            acl: &'a [String],
        }
        serde_yaml::to_string(&Wrapper { acl: &strings })
            .map_err(|e| Error::Acl(format!("YAML serialisation error: {e}")))
    }

    // ── Publish bookkeeping ───────────────────────────────────────────────────

    /// Record a successful publish.
    ///
    /// Only updates [`Acl::cid`] and clears [`Acl::dirty`] when `gen` matches
    /// the current generation (i.e. no mutations happened between the publish
    /// call and this confirmation).
    pub fn mark_published(&mut self, cid: Cid, gen: u64) {
        if gen == self.generation {
            self.cid = Some(cid);
            self.dirty = false;
        }
    }

    /// Current generation counter.
    ///
    /// Increments on every mutating operation. Pass this value to
    /// [`Acl::mark_published`] to guard against race conditions.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
#[derive(Debug)]
pub struct AclPublishWorker {
    kubo_url: String,
    ipns_key_name: String,
    retry_delay: Duration,
    publish_task: Option<JoinHandle<()>>,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
impl AclPublishWorker {
    pub fn new(kubo_url: impl AsRef<str>, ipns_key_name: impl AsRef<str>) -> Result<Self> {
        let kubo_url = kubo_url.as_ref().trim().to_string();
        let ipns_key_name = ipns_key_name.as_ref().trim().to_string();

        if kubo_url.is_empty() {
            return Err(Error::Acl("kubo_url must not be empty".to_string()));
        }
        if ipns_key_name.is_empty() {
            return Err(Error::Acl("ipns_key_name must not be empty".to_string()));
        }

        Ok(Self {
            kubo_url,
            ipns_key_name,
            retry_delay: Duration::from_secs(2),
            publish_task: None,
        })
    }

    #[must_use]
    pub fn with_retry_delay(mut self, retry_delay: Duration) -> Self {
        self.retry_delay = retry_delay;
        self
    }

    pub fn on_acl_changed(&mut self, acl: Arc<Mutex<Acl>>) {
        if let Some(task) = self.publish_task.take() {
            task.abort();
        }

        let kubo_url = self.kubo_url.clone();
        let ipns_key_name = self.ipns_key_name.clone();
        let retry_delay = self.retry_delay;

        self.publish_task = Some(tokio::spawn(async move {
            loop {
                let snapshot = {
                    let guard = match acl.lock() {
                        Ok(guard) => guard,
                        Err(_) => return,
                    };

                    if !guard.dirty {
                        return;
                    }

                    let yaml = match guard.to_yaml() {
                        Ok(yaml) => yaml,
                        Err(_) => return,
                    };

                    (guard.generation(), yaml)
                };

                match publish_acl_once(&kubo_url, &ipns_key_name, &snapshot.1).await {
                    Ok(cid) => {
                        let mut guard = match acl.lock() {
                            Ok(guard) => guard,
                            Err(_) => return,
                        };
                        guard.mark_published(cid, snapshot.0);
                        if !guard.dirty {
                            return;
                        }
                    }
                    Err(_) => {
                        sleep(retry_delay).await;
                    }
                }
            }
        }));
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
impl Drop for AclPublishWorker {
    fn drop(&mut self) {
        if let Some(task) = self.publish_task.take() {
            task.abort();
        }
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
async fn publish_acl_once(kubo_url: &str, ipns_key_name: &str, yaml: &str) -> Result<Cid> {
    let cid_str = ipfs_add(kubo_url, yaml.as_bytes().to_vec())
        .await
        .map_err(|e| Error::Acl(format!("ACL IPFS add failed: {e}")))?;

    name_publish_with_retry(
        kubo_url,
        ipns_key_name,
        &cid_str,
        &IpnsPublishOptions::default(),
        3,
        Duration::from_secs(1),
    )
    .await
    .map_err(|e| Error::Acl(format!("ACL IPNS publish failed: {e}")))?;

    cid_str
        .parse::<Cid>()
        .map_err(|e| Error::Acl(format!("invalid CID from IPFS add: {e}")))
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn entry_to_string(e: &Entry) -> String {
    match e {
        Entry::Any => "*".to_owned(),
        Entry::Allow(did) => did.id(),
        Entry::Deny(did) => format!("!{}", did.id()),
        Entry::AllowFragment(f) => format!("#{f}"),
        Entry::DenyFragment(f) => format!("!#{f}"),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn public_yaml() -> &'static str {
        "acl:\n  - \"*\"\n"
    }

    fn restricted_yaml() -> &'static str {
        "acl:\n  - \"did:ma:Qmalice\"\n  - \"!did:ma:Qmeve\"\n"
    }

    // ── new_from_yaml ─────────────────────────────────────────────────────────

    #[test]
    fn parse_public() {
        let acl = Acl::new_from_yaml(public_yaml()).unwrap();
        assert!(acl.compiled.public);
        assert!(acl.dirty);
    }

    #[test]
    fn parse_restricted() {
        let acl = Acl::new_from_yaml(restricted_yaml()).unwrap();
        assert!(!acl.compiled.public);
        assert!(acl.compiled.allow_identities.contains("Qmalice"));
        assert!(acl.compiled.deny_identities.contains("Qmeve"));
    }

    #[test]
    fn parse_fragments() {
        let yaml = "acl:\n  - \"#read\"\n  - \"!#write\"\n";
        let acl = Acl::new_from_yaml(yaml).unwrap();
        assert!(acl.compiled.allow_fragments.contains("read"));
        assert!(acl.compiled.deny_fragments.contains("write"));
    }

    #[test]
    fn parse_did_url() {
        let yaml = "acl:\n  - \"did:ma:Qmalice#edit\"\n";
        let acl = Acl::new_from_yaml(yaml).unwrap();
        assert!(acl
            .compiled
            .allow_urls
            .contains(&("Qmalice".to_owned(), "edit".to_owned())));
    }

    #[test]
    fn parse_unknown_entry_fails() {
        let yaml = "acl:\n  - \"ftp://bad\"\n";
        assert!(Acl::new_from_yaml(yaml).is_err());
    }

    // ── is_allowed ────────────────────────────────────────────────────────────

    #[test]
    fn public_allows_all() {
        let acl = Acl::new_from_yaml(public_yaml()).unwrap();
        assert!(acl.is_allowed("did:ma:Qmanyone#read"));
        assert!(acl.is_allowed("did:ma:Qmanyone"));
    }

    #[test]
    fn deny_identity_blocks_all_urls() {
        let acl = Acl::new_from_yaml("acl:\n  - \"*\"\n  - \"!did:ma:Qmeve\"\n").unwrap();
        assert!(!acl.is_allowed("did:ma:Qmeve"));
        assert!(!acl.is_allowed("did:ma:Qmeve#read"));
    }

    #[test]
    fn allow_identity_permits_urls() {
        let acl = Acl::new_from_yaml(restricted_yaml()).unwrap();
        assert!(acl.is_allowed("did:ma:Qmalice"));
        assert!(acl.is_allowed("did:ma:Qmalice#edit"));
    }

    #[test]
    fn unknown_identity_denied_in_restricted() {
        let acl = Acl::new_from_yaml(restricted_yaml()).unwrap();
        assert!(!acl.is_allowed("did:ma:Qmbob"));
    }

    #[test]
    fn bare_fragment_allow_deny() {
        let acl = Acl::new_from_yaml("acl:\n  - \"#read\"\n  - \"!#write\"\n").unwrap();
        assert!(acl.is_allowed("#read"));
        assert!(!acl.is_allowed("#write"));
        assert!(!acl.is_allowed("#other"));
    }

    // ── allow / deny mutators ─────────────────────────────────────────────────

    #[test]
    fn allow_mutator_idempotent() {
        let mut acl = Acl::new_from_yaml("acl: []\n").unwrap();
        let gen0 = acl.generation();
        acl.allow("did:ma:Qmbob").unwrap();
        let gen1 = acl.generation();
        acl.allow("did:ma:Qmbob").unwrap(); // duplicate — no change
        assert_eq!(acl.generation(), gen1);
        assert!(gen1 > gen0);
        assert!(acl.is_allowed("did:ma:Qmbob"));
    }

    #[test]
    fn deny_mutator() {
        let mut acl = Acl::new_from_yaml("acl:\n  - \"*\"\n").unwrap();
        acl.deny("did:ma:Qmeve").unwrap();
        assert!(acl.dirty);
        assert!(!acl.is_allowed("did:ma:Qmeve"));
    }

    #[test]
    fn deny_mutator_with_bang_prefix() {
        let mut acl = Acl::new_from_yaml("acl:\n  - \"*\"\n").unwrap();
        acl.deny("!did:ma:Qmeve").unwrap(); // leading `!` is stripped
        assert!(!acl.is_allowed("did:ma:Qmeve"));
    }

    // ── to_yaml round-trip ────────────────────────────────────────────────────

    #[test]
    fn yaml_round_trip() {
        let yaml = "acl:\n  - \"*\"\n  - did:ma:Qmalice\n  - '!did:ma:Qmeve'\n";
        let acl = Acl::new_from_yaml(yaml).unwrap();
        let out = acl.to_yaml().unwrap();
        let acl2 = Acl::new_from_yaml(&out).unwrap();
        // Re-serialise must produce the same entries
        assert_eq!(acl.entries, acl2.entries);
    }

    // ── mark_published ────────────────────────────────────────────────────────

    #[test]
    fn mark_published_clears_dirty() {
        let mut acl = Acl::new_from_yaml(public_yaml()).unwrap();
        let gen = acl.generation();
        let cid: Cid = "bafyreigdmqpykrgxyaxtlafqpqhzrb7qy2rh75nldvfd4aq3b6b2x6xkhu"
            .parse()
            .unwrap();
        acl.mark_published(cid, gen);
        assert!(!acl.dirty);
        assert!(acl.cid.is_some());
    }

    #[test]
    fn mark_published_stale_gen_noop() {
        let mut acl = Acl::new_from_yaml(public_yaml()).unwrap();
        let old_gen = acl.generation();
        acl.allow("did:ma:Qmbob").unwrap(); // bumps generation
        let cid: Cid = "bafyreigdmqpykrgxyaxtlafqpqhzrb7qy2rh75nldvfd4aq3b6b2x6xkhu"
            .parse()
            .unwrap();
        acl.mark_published(cid, old_gen); // stale — must be ignored
        assert!(acl.dirty);
        assert!(acl.cid.is_none());
    }
}
