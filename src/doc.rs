use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ipld_core::ipld::Ipld;
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use web_time::{SystemTime, UNIX_EPOCH};

use crate::{
    did::Did,
    error::{MaError, MaResult as Result},
    key::{EncryptionKey, SigningKey, CODEC_ED25519_PUB, CODEC_EDDSA_SIG, CODEC_X25519_PUB},
    multiformat::{
        public_key_multibase_decode, signature_multibase_decode, signature_multibase_encode,
    },
};

pub const DEFAULT_DID_CONTEXT: &[&str] = &["https://www.w3.org/ns/did/v1.1"];
pub const DEFAULT_PROOF_TYPE: &str = "MultiformatSignature2023";
pub const DEFAULT_PROOF_PURPOSE: &str = "assertionMethod";

/// Returns the current UTC time as an RFC 3339 string with whole-second precision.
pub fn now_iso_utc() -> String {
    let unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    i64::try_from(unix_seconds)
        .ok()
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
        .and_then(|timestamp| timestamp.format(&Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub key_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

impl VerificationMethod {
    pub fn new(
        id: impl AsRef<str>,
        controller: impl Into<String>,
        key_type: impl Into<String>,
        fragment: impl AsRef<str>,
        public_key_multibase: impl Into<String>,
    ) -> Result<Self> {
        let base_id = id
            .as_ref()
            .split('#')
            .next()
            .ok_or(MaError::MissingIdentifier)?;

        let method = Self {
            id: format!("{base_id}#{}", fragment.as_ref()),
            key_type: key_type.into(),
            controller: controller.into(),
            public_key_multibase: public_key_multibase.into(),
        };
        method.validate()?;
        Ok(method)
    }

    pub fn fragment(&self) -> Result<String> {
        let did = Did::try_from(self.id.as_str())?;
        did.fragment.ok_or(MaError::MissingFragment)
    }

    pub fn validate(&self) -> Result<()> {
        Did::validate_url(&self.id)?;

        match self.key_type.as_str() {
            "" => return Err(MaError::VerificationMethodMissingType),
            "Multikey" => {}
            _ => {
                return Err(MaError::InvalidVerificationMethodType(
                    self.key_type.clone(),
                ));
            }
        }

        if self.controller.is_empty() {
            return Err(MaError::EmptyController);
        }

        validate_bare_did(&self.controller)?;

        if self.public_key_multibase.is_empty() {
            return Err(MaError::EmptyPublicKeyMultibase);
        }

        public_key_multibase_decode(&self.public_key_multibase)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    #[serde(rename = "type")]
    pub proof_type: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

impl Proof {
    pub fn new(proof_value: impl Into<String>, verification_method: impl Into<String>) -> Self {
        Self {
            proof_type: DEFAULT_PROOF_TYPE.to_string(),
            verification_method: verification_method.into(),
            proof_purpose: DEFAULT_PROOF_PURPOSE.to_string(),
            proof_value: proof_value.into(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.proof_value.is_empty()
    }
}

// ─── ma: extension builder ──────────────────────────────────────────────────

/// Fluent builder for the opaque `ma:` IPLD extension field on a [`Document`].
///
/// `MaExtension` collects the node type, transport service strings, and any
/// custom IPLD fields, then produces the [`Ipld`] value ready for
/// [`Document::set_ma_extension`].
///
/// The idiomatic way to populate `ma:` is to start from the endpoint — which
/// pre-populates services — and chain any additional fields:
///
/// ```ignore
/// // Endpoint pre-populates services; add type and any extras:
/// let ma = endpoint.ma_extension()
///     .kind("world");
///
/// // Build a complete, signed document in one call:
/// let document = bundle.build_document(ma)?;
/// ```
///
/// You can also build a `MaExtension` independently and attach it to an
/// existing document with [`Document::set_ma_extension`] before re-signing.
#[derive(Debug, Default, Clone)]
pub struct MaExtension {
    map: std::collections::BTreeMap<String, Ipld>,
}

impl MaExtension {
    /// Create an empty extension builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set `ma["type"]` to identify the kind of node or service.
    ///
    /// The key name `"type"` follows the existing convention in the ma ecosystem.
    #[must_use]
    pub fn kind(mut self, kind: &str) -> Self {
        self.map
            .insert("type".to_string(), Ipld::String(kind.to_string()));
        self
    }

    /// Append one transport service string to `ma["services"]`.
    ///
    /// Service strings have the form `/iroh/<endpoint-id>/ma/<protocol>/<version>`.
    #[must_use]
    pub fn add_service(mut self, service: &str) -> Self {
        let entry = self
            .map
            .entry("services".to_string())
            .or_insert_with(|| Ipld::List(Vec::new()));
        if let Ipld::List(list) = entry {
            list.push(Ipld::String(service.to_string()));
        }
        self
    }

    /// Replace `ma["services"]` with the given list.
    ///
    /// Use this (rather than repeated [`Self::add_service`] calls) when you
    /// already have the full service list, e.g. from [`crate::MaEndpoint::services`].
    #[must_use]
    pub fn services(mut self, services: Vec<String>) -> Self {
        self.map.insert(
            "services".to_string(),
            Ipld::List(services.into_iter().map(Ipld::String).collect()),
        );
        self
    }

    /// Set an arbitrary IPLD entry in the extension map.
    #[must_use]
    pub fn extra(mut self, key: &str, val: Ipld) -> Self {
        self.map.insert(key.to_string(), val);
        self
    }

    /// Consume the builder and return the final [`Ipld`] value.
    ///
    /// Returns [`Ipld::Null`] if no fields have been set (which causes
    /// [`Document::set_ma_extension`] to clear the `ma` field).
    pub fn build(self) -> Ipld {
        if self.map.is_empty() {
            Ipld::Null
        } else {
            Ipld::Map(self.map)
        }
    }
}

fn is_valid_rfc3339_utc(value: &str) -> bool {
    value.len() == 20 && value.ends_with('Z') && OffsetDateTime::parse(value, &Rfc3339).is_ok()
}

/// A `did:ma:` DID document.
///
/// Contains verification methods, proof, and optional extension data.
/// Documents are signed with Ed25519 over a BLAKE3 hash of the dag-cbor-serialized
/// payload (all fields except `proof`).
///
/// # Examples
///
/// ```
/// use ma_core::{generate_identity_from_secret, Document};
///
/// let id = generate_identity_from_secret([7u8; 32]).unwrap();
///
/// // Verify the signature
/// id.document.verify().unwrap();
///
/// // Validate structural correctness
/// id.document.validate().unwrap();
///
/// // Round-trip through the canonical wire format
/// let bytes = id.document.encode().unwrap();
/// let restored = Document::decode(&bytes).unwrap();
/// assert_eq!(id.document, restored);
/// ```
///
/// # Extension namespace
///
/// The `ma` field is an opaque IPLD value for application-defined
/// extension data. did-ma does not interpret or validate its contents.
/// Using [`Ipld`] gives native support for CID links and canonical DAG-CBOR
/// round-tripping.
///
/// ```
/// use std::collections::BTreeMap;
/// use ipld_core::ipld::Ipld;
/// use ma_core::{Did, Document};
///
/// let did = Did::new_url("k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr", None::<String>).unwrap();
/// let mut doc = Document::new(&did, &did);
/// let ma = Ipld::Map(BTreeMap::from([
///     ("type".into(), Ipld::String("agent".into())),
///     ("services".into(), Ipld::Map(BTreeMap::new())),
/// ]));
/// doc.set_ma(ma);
/// assert!(doc.ma.is_some());
/// doc.clear_ma();
/// assert!(doc.ma.is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Document {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    pub controller: Vec<String>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
    #[serde(rename = "keyAgreement")]
    pub key_agreement: Vec<String>,
    pub proof: Proof,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ma: Option<Ipld>,
}

impl Document {
    pub fn new(identity: &Did, controller: &Did) -> Self {
        let now = now_iso_utc();
        Self {
            context: DEFAULT_DID_CONTEXT
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            id: identity.base_id(),
            controller: vec![controller.base_id()],
            verification_method: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
            proof: Proof::default(),
            created_at: now.clone(),
            updated_at: now,
            ma: None,
        }
    }

    /// Set the opaque `ma` extension namespace from a raw [`Ipld`] value.
    ///
    /// For the ergonomic, structured way to populate this field, prefer
    /// [`Document::set_ma_extension`] with a [`MaExtension`] builder.
    pub fn set_ma(&mut self, ma: Ipld) {
        match &ma {
            Ipld::Null => self.ma = None,
            Ipld::Map(m) if m.is_empty() => self.ma = None,
            _ => self.ma = Some(ma),
        }
    }

    /// Set the `ma` extension field from a [`MaExtension`] builder.
    ///
    /// This is the recommended way to populate the `ma:` namespace. Build an
    /// extension with [`MaExtension`], then call this method before signing
    /// the document. An empty builder (or one whose [`MaExtension::build`]
    /// returns [`Ipld::Null`]) clears the field.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ma = endpoint.ma_extension().kind("world");
    /// document.set_ma_extension(ma);
    /// document.sign(&signing_key, &assertion_vm)?;
    /// ```
    pub fn set_ma_extension(&mut self, ext: MaExtension) {
        self.set_ma(ext.build());
    }

    /// Clear the `ma` extension namespace.
    pub fn clear_ma(&mut self) {
        self.ma = None;
    }

    /// Encode the DID document to its canonical wire format.
    ///
    /// DID documents are always serialized as DAG-CBOR. Use this for
    /// transport, storage, hashing, signing, and IPFS/IPNS publication.
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_ipld_dagcbor::to_vec(self).map_err(|error| MaError::CborEncode(error.to_string()))
    }

    /// Decode a DID document from its canonical wire format.
    ///
    /// DID documents are always encoded as DAG-CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        serde_ipld_dagcbor::from_slice(bytes)
            .map_err(|error| MaError::CborDecode(error.to_string()))
    }

    pub fn add_controller(&mut self, controller: impl Into<String>) -> Result<()> {
        let controller = controller.into();
        Did::validate(&controller)?;
        if !self.controller.contains(&controller) {
            self.controller.push(controller);
        }
        Ok(())
    }

    pub fn add_verification_method(&mut self, method: VerificationMethod) -> Result<()> {
        method.validate()?;
        let duplicate = self.verification_method.iter().any(|existing| {
            existing.id == method.id || existing.public_key_multibase == method.public_key_multibase
        });

        if !duplicate {
            self.verification_method.push(method);
        }

        Ok(())
    }

    pub fn get_verification_method_by_id(&self, method_id: &str) -> Result<&VerificationMethod> {
        self.verification_method
            .iter()
            .find(|method| method.id == method_id)
            .ok_or_else(|| MaError::UnknownVerificationMethod(method_id.to_string()))
    }

    /// Update the `updatedAt` timestamp to the current time.
    pub fn touch(&mut self) {
        self.updated_at = now_iso_utc();
    }

    pub fn assertion_method_public_key(&self) -> Result<VerifyingKey> {
        let assertion_id = self
            .assertion_method
            .first()
            .ok_or_else(|| MaError::UnknownVerificationMethod("assertionMethod".to_string()))?;
        self.verifying_key_for_method(assertion_id)
    }

    fn verifying_key_for_method(&self, method_id: &str) -> Result<VerifyingKey> {
        let vm = self.get_verification_method_by_id(method_id)?;
        let (codec, public_key_bytes) = public_key_multibase_decode(&vm.public_key_multibase)?;
        if codec != CODEC_ED25519_PUB {
            return Err(MaError::InvalidMulticodec {
                expected: CODEC_ED25519_PUB,
                actual: codec,
            });
        }

        let key_len = public_key_bytes.len();
        let bytes: [u8; 32] =
            public_key_bytes
                .try_into()
                .map_err(|_| MaError::InvalidKeyLength {
                    expected: 32,
                    actual: key_len,
                })?;

        VerifyingKey::from_bytes(&bytes).map_err(|_| MaError::Crypto)
    }

    pub fn key_agreement_public_key_bytes(&self) -> Result<[u8; 32]> {
        let agreement_id = self
            .key_agreement
            .first()
            .ok_or_else(|| MaError::UnknownVerificationMethod("keyAgreement".to_string()))?;
        let vm = self.get_verification_method_by_id(agreement_id)?;
        let (codec, public_key_bytes) = public_key_multibase_decode(&vm.public_key_multibase)?;
        if codec != CODEC_X25519_PUB {
            return Err(MaError::InvalidMulticodec {
                expected: CODEC_X25519_PUB,
                actual: codec,
            });
        }

        let key_len = public_key_bytes.len();
        public_key_bytes
            .try_into()
            .map_err(|_| MaError::InvalidKeyLength {
                expected: 32,
                actual: key_len,
            })
    }

    #[must_use]
    pub fn payload_document(&self) -> Self {
        let mut payload = self.clone();
        payload.proof = Proof::default();
        payload
    }

    pub fn payload_bytes(&self) -> Result<Vec<u8>> {
        self.payload_document().encode()
    }

    pub fn payload_hash(&self) -> Result<[u8; 32]> {
        Ok(blake3::hash(&self.payload_bytes()?).into())
    }

    pub fn sign(
        &mut self,
        signing_key: &SigningKey,
        verification_method: &VerificationMethod,
    ) -> Result<()> {
        if signing_key.public_key_multibase != verification_method.public_key_multibase {
            return Err(MaError::InvalidPublicKeyMultibase);
        }

        let signature = signing_key.sign(&self.payload_hash()?);
        let proof_value = signature_multibase_encode(CODEC_EDDSA_SIG, &signature);
        self.proof = Proof::new(proof_value, verification_method.id.clone());
        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        if self.proof.is_empty() {
            return Err(MaError::MissingProof);
        }
        if self.proof.proof_type != DEFAULT_PROOF_TYPE {
            return Err(MaError::InvalidProofType(self.proof.proof_type.clone()));
        }
        if self.proof.proof_purpose != DEFAULT_PROOF_PURPOSE {
            return Err(MaError::InvalidProofPurpose(
                self.proof.proof_purpose.clone(),
            ));
        }

        let (codec, sig_bytes) = signature_multibase_decode(&self.proof.proof_value)?;
        if codec != CODEC_EDDSA_SIG {
            return Err(MaError::InvalidDocumentSignature);
        }
        let signature =
            Signature::from_slice(&sig_bytes).map_err(|_| MaError::InvalidDocumentSignature)?;
        if !self
            .assertion_method
            .contains(&self.proof.verification_method)
        {
            return Err(MaError::UnknownVerificationMethod(
                self.proof.verification_method.clone(),
            ));
        }
        let public_key = self.verifying_key_for_method(&self.proof.verification_method)?;
        public_key
            .verify(&self.payload_hash()?, &signature)
            .map_err(|_| MaError::InvalidDocumentSignature)
    }

    pub fn validate(&self) -> Result<()> {
        if self.context != DEFAULT_DID_CONTEXT {
            return Err(if self.context.is_empty() {
                MaError::EmptyContext
            } else {
                MaError::InvalidContext
            });
        }

        validate_bare_did(&self.id)?;

        if self.controller.is_empty() {
            return Err(MaError::EmptyController);
        }

        for controller in &self.controller {
            validate_bare_did(controller)?;
        }

        if !is_valid_rfc3339_utc(&self.created_at) {
            return Err(MaError::InvalidCreatedAt(self.created_at.clone()));
        }

        if !is_valid_rfc3339_utc(&self.updated_at) {
            return Err(MaError::InvalidUpdatedAt(self.updated_at.clone()));
        }

        for method in &self.verification_method {
            method.validate()?;
        }

        if self.assertion_method.is_empty() {
            return Err(MaError::UnknownVerificationMethod(
                "assertionMethod".to_string(),
            ));
        }

        if self.key_agreement.is_empty() {
            return Err(MaError::UnknownVerificationMethod(
                "keyAgreement".to_string(),
            ));
        }

        self.validate_relationships(&self.assertion_method, CODEC_ED25519_PUB)?;
        self.validate_relationships(&self.key_agreement, CODEC_X25519_PUB)?;

        Ok(())
    }

    fn validate_relationships(&self, relationships: &[String], expected_codec: u64) -> Result<()> {
        for method_id in relationships {
            Did::validate_url(method_id)?;
            let method = self.get_verification_method_by_id(method_id)?;
            let (codec, _) = public_key_multibase_decode(&method.public_key_multibase)?;
            if codec != expected_codec {
                return Err(MaError::InvalidMulticodec {
                    expected: expected_codec,
                    actual: codec,
                });
            }
        }
        Ok(())
    }
}

fn validate_bare_did(value: &str) -> Result<()> {
    let did = Did::try_from(value)?;
    if did.fragment.is_some() {
        return Err(MaError::UnexpectedFragment);
    }
    Ok(())
}

impl TryFrom<&[u8]> for Document {
    type Error = MaError;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes)
    }
}

impl TryFrom<&EncryptionKey> for VerificationMethod {
    type Error = MaError;

    fn try_from(value: &EncryptionKey) -> Result<Self> {
        let fragment = value.did.fragment.clone().ok_or(MaError::MissingFragment)?;
        VerificationMethod::new(
            value.did.base_id(),
            value.did.base_id(),
            value.key_type.clone(),
            fragment,
            value.public_key_multibase.clone(),
        )
    }
}

impl TryFrom<&SigningKey> for VerificationMethod {
    type Error = MaError;

    fn try_from(value: &SigningKey) -> Result<Self> {
        let fragment = value.did.fragment.clone().ok_or(MaError::MissingFragment)?;
        VerificationMethod::new(
            value.did.base_id(),
            value.did.base_id(),
            value.key_type.clone(),
            fragment,
            value.public_key_multibase.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn encode_decode_round_trip() {
        let identity = crate::generate_identity_from_secret([11u8; 32]).expect("identity");
        let bytes = identity.document.encode().expect("encode");
        let decoded = Document::decode(&bytes).expect("decode");
        assert_eq!(decoded, identity.document);
    }

    #[test]
    fn try_from_bytes_round_trip() {
        let identity = crate::generate_identity_from_secret([12u8; 32]).expect("identity");
        let bytes = identity.document.encode().expect("encode");
        let decoded = Document::try_from(bytes.as_slice()).expect("try_from bytes");
        assert_eq!(decoded, identity.document);
    }

    #[test]
    fn decode_rejects_invalid_bytes() {
        let err = Document::decode(b"not dag-cbor").expect_err("invalid bytes");
        assert!(matches!(err, MaError::CborDecode(_)));
    }

    #[test]
    fn payload_document_clears_proof_only() {
        let identity = crate::generate_identity_from_secret([13u8; 32]).expect("identity");
        let payload = identity.document.payload_document();

        assert!(payload.proof.is_empty());
        assert_eq!(payload.id, identity.document.id);
        assert_eq!(payload.controller, identity.document.controller);
        assert_eq!(
            payload.verification_method,
            identity.document.verification_method
        );
        assert_eq!(payload.assertion_method, identity.document.assertion_method);
        assert_eq!(payload.key_agreement, identity.document.key_agreement);
        assert_eq!(payload.created_at, identity.document.created_at);
        assert_eq!(payload.updated_at, identity.document.updated_at);
        assert_eq!(payload.ma, identity.document.ma);
    }

    #[test]
    fn set_ma_stores_opaque_value() {
        let root = Did::new_url(
            "k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr",
            None::<String>,
        )
        .expect("valid test did");
        let mut document = Document::new(&root, &root);

        let ma = Ipld::Map(BTreeMap::from([(
            "type".into(),
            Ipld::String("agent".into()),
        )]));
        document.set_ma(ma.clone());
        assert_eq!(document.ma.as_ref(), Some(&ma));
    }

    #[test]
    fn clear_ma_removes_value() {
        let root = Did::new_url(
            "k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr",
            None::<String>,
        )
        .expect("valid test did");
        let mut document = Document::new(&root, &root);

        document.set_ma(Ipld::Map(BTreeMap::from([(
            "type".into(),
            Ipld::String("agent".into()),
        )])));
        assert!(document.ma.is_some());
        document.clear_ma();
        assert!(document.ma.is_none());
    }

    #[test]
    fn set_ma_null_clears() {
        let root = Did::new_url(
            "k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr",
            None::<String>,
        )
        .expect("valid test did");
        let mut document = Document::new(&root, &root);

        document.set_ma(Ipld::Map(BTreeMap::from([(
            "type".into(),
            Ipld::String("agent".into()),
        )])));
        document.set_ma(Ipld::Null);
        assert!(document.ma.is_none());
    }

    #[test]
    fn validate_accepts_opaque_ma() {
        let identity = crate::identity::generate_identity(
            "k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr",
        )
        .expect("generate identity");
        let mut document = identity.document;
        document.set_ma(Ipld::Map(BTreeMap::from([
            ("type".into(), Ipld::String("bahner".into())),
            ("custom".into(), Ipld::Integer(42)),
        ])));
        document
            .validate()
            .expect("validate should accept any ma value");
    }

    #[test]
    fn canonical_document_passes_structural_validation() {
        let identity = crate::generate_identity_from_secret([21u8; 32]).expect("identity");
        identity.document.validate().expect("canonical document");
    }

    #[test]
    fn document_validation_requires_exact_context() {
        let identity = crate::generate_identity_from_secret([22u8; 32]).expect("identity");

        for context in [
            vec!["https://www.w3.org/ns/did/v1".to_string()],
            vec![
                "https://www.w3.org/ns/did/v1.1".to_string(),
                "https://example.test/context".to_string(),
            ],
        ] {
            let mut document = identity.document.clone();
            document.context = context;
            assert!(matches!(document.validate(), Err(MaError::InvalidContext)));
        }
    }

    #[test]
    fn document_validation_requires_bare_document_and_controller_dids() {
        let identity = crate::generate_identity_from_secret([23u8; 32]).expect("identity");

        let mut document = identity.document.clone();
        document.id.push_str("#subject");
        assert!(matches!(
            document.validate(),
            Err(MaError::UnexpectedFragment)
        ));

        let mut document = identity.document;
        document.controller[0].push_str("#controller");
        assert!(matches!(
            document.validate(),
            Err(MaError::UnexpectedFragment)
        ));
    }

    #[test]
    fn verification_method_validation_requires_multikey_and_bare_controller() {
        let identity = crate::generate_identity_from_secret([24u8; 32]).expect("identity");

        let mut method = identity.document.verification_method[0].clone();
        method.key_type = "JsonWebKey2020".to_string();
        assert!(matches!(
            method.validate(),
            Err(MaError::InvalidVerificationMethodType(_))
        ));

        let mut method = identity.document.verification_method[0].clone();
        method.controller.push_str("#controller");
        assert!(matches!(
            method.validate(),
            Err(MaError::UnexpectedFragment)
        ));
    }

    #[test]
    fn document_validation_requires_relationship_targets_to_exist() {
        let identity = crate::generate_identity_from_secret([25u8; 32]).expect("identity");
        let mut document = identity.document;
        document.assertion_method[0] = format!("{}#unknown", document.id);

        assert!(matches!(
            document.validate(),
            Err(MaError::UnknownVerificationMethod(_))
        ));
    }

    #[test]
    fn document_validation_requires_relationship_codecs() {
        let identity = crate::generate_identity_from_secret([26u8; 32]).expect("identity");

        let mut document = identity.document.clone();
        document.assertion_method[0] = document.key_agreement[0].clone();
        assert!(matches!(
            document.validate(),
            Err(MaError::InvalidMulticodec {
                expected: CODEC_ED25519_PUB,
                actual: CODEC_X25519_PUB,
            })
        ));

        let mut document = identity.document;
        document.key_agreement[0] = document.assertion_method[0].clone();
        assert!(matches!(
            document.validate(),
            Err(MaError::InvalidMulticodec {
                expected: CODEC_X25519_PUB,
                actual: CODEC_ED25519_PUB,
            })
        ));
    }

    #[test]
    fn document_verification_requires_exact_proof_type() {
        let identity = crate::generate_identity_from_secret([27u8; 32]).expect("identity");
        let mut document = identity.document;
        document.proof.proof_type = "DataIntegrityProof".to_string();

        assert!(matches!(
            document.verify(),
            Err(MaError::InvalidProofType(value)) if value == "DataIntegrityProof"
        ));
    }

    #[test]
    fn document_verification_requires_exact_proof_purpose() {
        let identity = crate::generate_identity_from_secret([28u8; 32]).expect("identity");
        let mut document = identity.document;
        document.proof.proof_purpose = "authentication".to_string();

        assert!(matches!(
            document.verify(),
            Err(MaError::InvalidProofPurpose(value)) if value == "authentication"
        ));
    }

    #[test]
    fn timestamp_validation_requires_valid_whole_utc_seconds() {
        assert!(is_valid_rfc3339_utc("2026-08-08T12:34:56Z"));
        assert!(is_valid_rfc3339_utc("2024-02-29T23:59:59Z"));

        for invalid in [
            "2026-08-08T12:34:56.123Z",
            "2026-08-08T12:34:56+00:00",
            "2026-13-08T12:34:56Z",
            "2026-02-30T12:34:56Z",
            "2026-08-08T24:00:00Z",
            " 2026-08-08T12:34:56Z",
        ] {
            assert!(!is_valid_rfc3339_utc(invalid), "accepted {invalid}");
        }
    }

    #[test]
    fn document_validation_rejects_subsecond_created_at_format() {
        let identity = crate::generate_identity_from_secret([29u8; 32]).expect("identity");
        let mut document = identity.document;
        document.created_at = "2026-08-08T12:34:56.123Z".to_string();

        assert!(matches!(
            document.validate(),
            Err(MaError::InvalidCreatedAt(value)) if value == "2026-08-08T12:34:56.123Z"
        ));
    }

    #[test]
    fn document_validation_rejects_subsecond_updated_at_format() {
        let identity = crate::generate_identity_from_secret([30u8; 32]).expect("identity");
        let mut document = identity.document;
        document.updated_at = "2026-08-08T12:34:56.123Z".to_string();

        assert!(matches!(
            document.validate(),
            Err(MaError::InvalidUpdatedAt(value)) if value == "2026-08-08T12:34:56.123Z"
        ));
    }

    #[test]
    fn generated_timestamp_uses_whole_utc_seconds() {
        let timestamp = now_iso_utc();
        assert!(is_valid_rfc3339_utc(&timestamp));
        assert!(!timestamp.contains('.'));
    }
}
