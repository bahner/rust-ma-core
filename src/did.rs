use cid::{Cid, Version};
use libp2p_identity::{PeerId, PublicKey};
use nanoid::nanoid;

use crate::error::{MaError, MaResult as Result};

pub const DID_PREFIX: &str = "did:ma:";
const LIBP2P_KEY_CODEC: u64 = 0x72;

/// A parsed `did:ma:` identifier.
///
/// Without a fragment this is a bare DID: `did:ma:<ipns>`.
/// With a fragment it becomes a DID URL: `did:ma:<ipns>#<fragment>`.
///
/// # Examples
///
/// ```
/// use ma_core::Did;
///
/// // Bare DID (identity)
/// let id = Did::new_identity("k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr").unwrap();
/// assert!(id.is_bare());
/// assert_eq!(id.base_id(), "did:ma:k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr");
///
/// // DID URL with auto-generated fragment
/// let url = Did::new_url("k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr", None::<String>).unwrap();
/// assert!(url.is_url());
///
/// // Parse an incoming DID URL
/// let parsed = Did::try_from("did:ma:k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr#lobby").unwrap();
/// assert_eq!(parsed.fragment.as_deref(), Some("lobby"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Did {
    pub ipns: String,
    /// Local atom/inbox name (for example an avatar inbox in a world).
    /// In practice this often matches a Kubo key name, but this coupling is loose.
    pub fragment: Option<String>,
}

impl Did {
    /// Create a bare DID (`did:ma:<ipns>`) with no fragment.
    pub fn new_identity(ipns: impl Into<String>) -> Result<Self> {
        let ipns = ipns.into();
        validate_identifier(&ipns)?;
        Ok(Self {
            ipns,
            fragment: None,
        })
    }

    /// Create a DID URL (`did:ma:<ipns>#<fragment>`).
    /// If `fragment` is `None`, a nanoid is generated automatically.
    /// Provided fragments are validated as nanoids (`[A-Za-z0-9_-]+`).
    pub fn new_url(ipns: impl Into<String>, fragment: Option<impl Into<String>>) -> Result<Self> {
        let frag = match fragment {
            Some(f) => f.into(),
            None => nanoid!(),
        };
        let ipns = ipns.into();
        validate_identifier(&ipns)?;
        validate_fragment(&frag)?;
        Ok(Self {
            ipns,
            fragment: Some(frag),
        })
    }

    #[must_use]
    pub fn base_id(&self) -> String {
        format!("{DID_PREFIX}{}", self.ipns)
    }

    pub fn with_fragment(&self, fragment: impl Into<String>) -> Result<Self> {
        Self::new_url(self.ipns.clone(), Some(fragment))
    }

    #[must_use]
    pub fn id(&self) -> String {
        match &self.fragment {
            Some(fragment) => format!("{}#{fragment}", self.base_id()),
            None => self.base_id(),
        }
    }

    pub fn parse(input: &str) -> Result<(String, Option<String>)> {
        if input.is_empty() {
            return Err(MaError::EmptyDid);
        }

        let stripped = input
            .strip_prefix(DID_PREFIX)
            .ok_or(MaError::InvalidDidPrefix)?;

        let parts: Vec<_> = stripped.split('#').collect();
        match parts.as_slice() {
            [] | [""] => Err(MaError::MissingIdentifier),
            [_, ..] if parts.len() > 2 => Err(MaError::InvalidDidFormat),
            [identifier] => {
                validate_identifier(identifier)?;
                Ok(((*identifier).to_string(), None))
            }
            [identifier, fragment] => {
                validate_identifier(identifier)?;
                validate_fragment(fragment)?;
                Ok(((*identifier).to_string(), Some((*fragment).to_string())))
            }
            _ => Err(MaError::InvalidDidFormat),
        }
    }

    pub fn validate(input: &str) -> Result<()> {
        Self::parse(input).map(|_| ())
    }

    /// Validate that `input` is a DID URL. The fragment is optional.
    pub fn validate_url(input: &str) -> Result<()> {
        Self::validate(input)
    }

    /// Validate that `input` is a DID URL identifying a fragment resource.
    pub fn validate_resource(input: &str) -> Result<()> {
        match Self::parse(input)? {
            (_, Some(_)) => Ok(()),
            (_, None) => Err(MaError::MissingFragment),
        }
    }

    /// Validate that `input` is a bare DID identity (no fragment).
    pub fn validate_identity(input: &str) -> Result<()> {
        match Self::parse(input)? {
            (_, None) => Ok(()),
            (_, Some(_)) => Err(MaError::UnexpectedFragment),
        }
    }

    /// True when this DID has a fragment (is a DID URL).
    #[must_use]
    pub fn is_url(&self) -> bool {
        self.fragment.is_some()
    }

    /// True when this DID has no fragment (bare DID).
    #[must_use]
    pub fn is_bare(&self) -> bool {
        self.fragment.is_none()
    }
}

impl TryFrom<&str> for Did {
    type Error = MaError;

    /// Parse any valid DID URL.  A bare DID (no fragment) is a valid DID URL
    /// per W3C DID Core §3.2 — the fragment is optional.
    fn try_from(value: &str) -> Result<Self> {
        let (ipns, fragment) = Self::parse(value)?;
        Ok(Self { ipns, fragment })
    }
}

fn validate_identifier(input: &str) -> Result<()> {
    if input.is_empty() {
        return Err(MaError::MissingIdentifier);
    }

    let cid = Cid::try_from(input).map_err(|_| MaError::InvalidIdentifier)?;
    if cid.version() != Version::V1
        || cid.codec() != LIBP2P_KEY_CODEC
        || multibase::encode(multibase::Base::Base36Lower, cid.to_bytes()) != input
    {
        return Err(MaError::InvalidIdentifier);
    }

    let peer_id =
        PeerId::from_multihash(cid.hash().to_owned()).map_err(|_| MaError::InvalidIdentifier)?;
    let public_key = PublicKey::try_decode_protobuf(peer_id.as_ref().digest())
        .map_err(|_| MaError::InvalidIdentifier)?;
    if public_key.try_into_ed25519().is_err() {
        return Err(MaError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_fragment(input: &str) -> Result<()> {
    if input.is_empty()
        || !input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(MaError::InvalidFragment(input.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTIFIER: &str = "k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr";
    const BARE: &str = "did:ma:k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr";
    const URL: &str = "did:ma:k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr#lobby";

    #[test]
    fn is_url_with_fragment() {
        let did = Did::try_from(URL).unwrap();
        assert!(did.is_url());
        assert!(!did.is_bare());
    }

    #[test]
    fn is_bare_without_fragment() {
        let did = Did::try_from(BARE).unwrap();
        assert!(did.is_bare());
        assert!(!did.is_url());
    }

    #[test]
    fn validate_url_accepts_fragment() {
        assert!(Did::validate_url(URL).is_ok());
    }

    #[test]
    fn validate_url_accepts_bare() {
        assert!(Did::validate_url(BARE).is_ok());
    }

    #[test]
    fn validate_resource_requires_fragment() {
        assert!(Did::validate_resource(URL).is_ok());
        assert!(Did::validate_resource(BARE).is_err());
    }

    #[test]
    fn validate_identity_accepts_bare() {
        assert!(Did::validate_identity(BARE).is_ok());
    }

    #[test]
    fn validate_identity_rejects_fragment() {
        assert!(Did::validate_identity(URL).is_err());
    }

    #[test]
    fn new_url_none_generates_nanoid() {
        let url = Did::new_url(IDENTIFIER, None::<String>).unwrap();
        assert!(url.is_url());
        assert!(!url.fragment.unwrap().is_empty());
    }

    #[test]
    fn new_url_accepts_nanoid_fragment() {
        let url = Did::new_url(IDENTIFIER, Some("bahner")).unwrap();
        assert_eq!(url.fragment.as_deref(), Some("bahner"));
    }

    #[test]
    fn new_url_rejects_invalid_chars() {
        assert!(Did::new_url(IDENTIFIER, Some("has space")).is_err());
        assert!(Did::new_url(IDENTIFIER, Some("has.dot")).is_err());
        assert!(Did::new_url(IDENTIFIER, Some("")).is_err());
    }

    #[test]
    fn try_from_accepts_valid_fragment() {
        let did = Did::try_from(URL).unwrap();
        assert_eq!(did.fragment.as_deref(), Some("lobby"));
    }

    #[test]
    fn rejects_non_ipns_identifier() {
        assert!(Did::validate("did:ma:k51qzi5uqu5abc").is_err());
    }

    #[test]
    fn rejects_non_canonical_ipns_base() {
        let cid = Cid::try_from(IDENTIFIER).expect("valid CID");
        let base32 = multibase::encode(multibase::Base::Base32Lower, cid.to_bytes());
        assert!(Did::validate(&format!("did:ma:{base32}")).is_err());
    }
}
