//! Secret bundle: four standard 32-byte keys plus optional user-defined keys,
//! all stored encrypted on disk in a single file.
//!
//! # Extensibility
//!
//! [`SecretBundle`] exposes [`add_key`](SecretBundle::add_key),
//! [`get_key`](SecretBundle::get_key), and
//! [`generate_key`](SecretBundle::generate_key) so that daemons can persist
//! any number of additional named 32-byte keys in the same bundle. All keys
//! survive restart cycles through the normal [`SecretBundle::save`] /
//! [`SecretBundle::load`] cycle.
//!
//! Key names are arbitrary UTF-8 strings; the four standard names (`iroh`,
//! `ipns`, `did_signing`, `did_encryption`) are reserved.
//!
//! # On-disk format
//!
//! ```text
//! [16 bytes  Argon2id salt]
//! [12 bytes  ChaCha20-Poly1305 nonce]
//! [ciphertext (JSON plaintext below) + 16 bytes Poly1305 auth tag]
//! ```
//!
//! The plaintext is a UTF-8 JSON object where every value is a standard
//! base64-encoded 32-byte key. The four standard keys use fixed field names;
//! all extra keys live under a nested `"extra"` object:
//!
//! ```json
//! {
//!   "iroh":           "<base64>",
//!   "ipns":           "<base64>",
//!   "did_signing":    "<base64>",
//!   "did_encryption": "<base64>",
//!   "extra": {
//!     "my_service": "<base64>",
//!     "other_key":  "<base64>"
//!   }
//! }
//! ```
//!
//! Key derivation uses Argon2id with default OWASP-minimum parameters
//! (m=19456, t=2, p=1), producing a 32-byte ChaCha20-Poly1305 encryption key.
//!
//! On `wasm32`, use [`SecretBundle::encrypt`] / [`SecretBundle::decrypt`] with
//! application-managed storage (e.g. IndexedDB/localStorage). File-based
//! [`SecretBundle::load`] / [`SecretBundle::save`] are native-only.

use std::collections::HashMap;

use argon2::Argon2;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
use rand::{rand_core::UnwrapErr, rngs::SysRng, Rng};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{Error, Result};

// Reserved key names – may not be used as extra key names.
const RESERVED: &[&str] = &["iroh", "ipns", "did_signing", "did_encryption"];

// ─── Wire format (JSON) ──────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct BundleJson {
    iroh: String,
    ipns: String,
    did_signing: String,
    did_encryption: String,
    created_at: String,
    #[serde(default)]
    extra: HashMap<String, String>,
}

// ─── Public struct ───────────────────────────────────────────────────────────

/// Standard and user-defined 32-byte secret keys for a ma daemon identity.
///
/// All key material is zeroed from memory when this struct is dropped.
///
/// # Adding custom keys
///
/// ```
/// # #[cfg(all(feature = "config", not(target_arch = "wasm32")))]
/// # {
/// use ma_core::config::SecretBundle;
///
/// // Generate a fresh bundle.
/// let mut bundle = SecretBundle::generate();
///
/// // Generate and store a new random key:
/// bundle.generate_key("my_service_key")?;
///
/// // Or store an existing 32-byte key:
/// let key_bytes = [0u8; 32];
/// bundle.add_key("other_key", key_bytes)?;
///
/// // Retrieve it:
/// let key = bundle.get_key("my_service_key").expect("key not found");
///
/// // Encrypt in-memory and decrypt again:
/// let encrypted = bundle.encrypt("passphrase")?;
/// let restored = SecretBundle::decrypt(&encrypted, "passphrase")?;
/// assert_eq!(bundle.iroh_secret_key, restored.iroh_secret_key);
/// # }
/// # Ok::<(), ma_core::Error>(())
/// ```
pub struct SecretBundle {
    /// iroh QUIC transport secret key.
    pub iroh_secret_key: [u8; 32],
    /// IPNS publishing secret key.
    pub ipns_secret_key: [u8; 32],
    /// DID document signing key (Ed25519).
    pub did_signing_key: [u8; 32],
    /// DID document encryption key (X25519).
    pub did_encryption_key: [u8; 32],

    /// RFC 3339 UTC timestamp of when this bundle (identity) was first created.
    /// Set once at generation time and never modified.
    pub created_at: String,

    /// User-defined extra keys. Names must not collide with the four reserved
    /// standard key names.
    extra_keys: HashMap<String, [u8; 32]>,
}

impl Drop for SecretBundle {
    fn drop(&mut self) {
        self.iroh_secret_key.zeroize();
        self.ipns_secret_key.zeroize();
        self.did_signing_key.zeroize();
        self.did_encryption_key.zeroize();
        for v in self.extra_keys.values_mut() {
            v.zeroize();
        }
    }
}

impl Clone for SecretBundle {
    fn clone(&self) -> Self {
        Self {
            iroh_secret_key: self.iroh_secret_key,
            ipns_secret_key: self.ipns_secret_key,
            did_signing_key: self.did_signing_key,
            did_encryption_key: self.did_encryption_key,
            created_at: self.created_at.clone(),
            extra_keys: self.extra_keys.clone(),
        }
    }
}

impl SecretBundle {
    /// Generate a new bundle with four random standard keys and no extra keys.
    pub fn generate() -> Self {
        let mut rng = UnwrapErr(SysRng);
        let mut b = Self {
            iroh_secret_key: [0u8; 32],
            ipns_secret_key: [0u8; 32],
            did_signing_key: [0u8; 32],
            did_encryption_key: [0u8; 32],
            created_at: crate::doc::now_iso_utc(),
            extra_keys: HashMap::new(),
        };
        rng.fill_bytes(&mut b.iroh_secret_key);
        rng.fill_bytes(&mut b.ipns_secret_key);
        rng.fill_bytes(&mut b.did_signing_key);
        rng.fill_bytes(&mut b.did_encryption_key);
        b
    }

    // ─── Extra key management ────────────────────────────────────────────────

    /// Store a named 32-byte key in this bundle.
    ///
    /// Returns an error if `name` collides with a reserved standard key name
    /// or is empty.
    pub fn add_key(&mut self, name: &str, key: [u8; 32]) -> Result<()> {
        validate_key_name(name)?;
        self.extra_keys.insert(name.to_string(), key);
        Ok(())
    }

    /// Generate a random 32-byte key, store it under `name`, and return it.
    ///
    /// Returns an error if `name` is invalid (see [`add_key`](Self::add_key)).
    pub fn generate_key(&mut self, name: &str) -> Result<[u8; 32]> {
        validate_key_name(name)?;
        let mut key = [0u8; 32];
        UnwrapErr(SysRng).fill_bytes(&mut key);
        self.extra_keys.insert(name.to_string(), key);
        Ok(key)
    }

    /// Retrieve a named extra key, or `None` if it does not exist.
    pub fn get_key(&self, name: &str) -> Option<&[u8; 32]> {
        self.extra_keys.get(name)
    }

    /// Remove a named extra key from the bundle.
    pub fn remove_key(&mut self, name: &str) -> Option<[u8; 32]> {
        self.extra_keys.remove(name)
    }

    /// Iterate over all extra key names.
    pub fn extra_key_names(&self) -> impl Iterator<Item = &str> {
        self.extra_keys.keys().map(String::as_str)
    }

    // ─── JSON serialization ──────────────────────────────────────────────────

    fn to_json_bytes(&self) -> Result<Vec<u8>> {
        let wire = BundleJson {
            iroh: B64.encode(self.iroh_secret_key),
            ipns: B64.encode(self.ipns_secret_key),
            did_signing: B64.encode(self.did_signing_key),
            did_encryption: B64.encode(self.did_encryption_key),
            created_at: self.created_at.clone(),
            extra: self
                .extra_keys
                .iter()
                .map(|(k, v)| (k.clone(), B64.encode(v)))
                .collect(),
        };
        serde_json::to_vec(&wire).map_err(|e| Error::Secrets(e.to_string()))
    }

    fn from_json_bytes(mut data: Vec<u8>) -> Result<Self> {
        let wire: BundleJson = serde_json::from_slice(&data)
            .map_err(|e| Error::Secrets(format!("failed to parse bundle JSON: {e}")))?;

        data.zeroize();

        let decode = |s: &str, field: &str| -> Result<[u8; 32]> {
            let bytes = B64
                .decode(s)
                .map_err(|e| Error::Secrets(format!("base64 decode error in '{field}': {e}")))?;
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::Secrets(format!("'{field}' must be exactly 32 bytes")))
        };

        let mut extra_keys = HashMap::with_capacity(wire.extra.len());
        for (name, val) in &wire.extra {
            extra_keys.insert(name.clone(), decode(val, name)?);
        }

        Ok(Self {
            iroh_secret_key: decode(&wire.iroh, "iroh")?,
            ipns_secret_key: decode(&wire.ipns, "ipns")?,
            did_signing_key: decode(&wire.did_signing, "did_signing")?,
            did_encryption_key: decode(&wire.did_encryption, "did_encryption")?,
            created_at: wire.created_at,
            extra_keys,
        })
    }

    // ─── Encryption / decryption ─────────────────────────────────────────────

    /// Encrypt this bundle with `passphrase` and return the binary blob.
    ///
    /// A fresh random salt and nonce are generated for each call.
    pub fn encrypt(&self, passphrase: &str) -> Result<Vec<u8>> {
        let mut salt = [0u8; 16];
        UnwrapErr(SysRng).fill_bytes(&mut salt);

        let mut key_bytes = [0u8; 32];
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key_bytes)
            .map_err(|e| Error::Secrets(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        UnwrapErr(SysRng).fill_bytes(&mut nonce_bytes);
        let nonce = chacha20poly1305::Nonce::from(nonce_bytes);

        let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
            .map_err(|e| Error::Secrets(e.to_string()))?;

        let mut plaintext = self.to_json_bytes()?;
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_slice())
            .map_err(|e| Error::Secrets(e.to_string()))?;

        plaintext.zeroize();
        key_bytes.zeroize();

        let mut out = Vec::with_capacity(16 + 12 + ciphertext.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a bundle from the on-disk binary format.
    ///
    /// Returns `Err(Error::Secrets)` on authentication failure (wrong
    /// passphrase or corrupted data) without revealing which it was.
    pub fn decrypt(data: &[u8], passphrase: &str) -> Result<Self> {
        if data.len() < 28 {
            return Err(Error::Secrets("secret bundle too short".to_string()));
        }

        let salt = &data[0..16];
        let nonce_bytes: [u8; 12] = data[16..28]
            .try_into()
            .map_err(|_| Error::Secrets("malformed bundle nonce".to_string()))?;
        let ciphertext = &data[28..];

        let mut key_bytes = [0u8; 32];
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), salt, &mut key_bytes)
            .map_err(|e| Error::Secrets(e.to_string()))?;

        let nonce = chacha20poly1305::Nonce::from(nonce_bytes);
        let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
            .map_err(|e| Error::Secrets(e.to_string()))?;
        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| Error::Secrets("decryption failed (wrong passphrase?)".to_string()))?;

        key_bytes.zeroize();

        Self::from_json_bytes(plaintext)
    }

    /// Load and decrypt a bundle from a file.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn load(path: &std::path::Path, passphrase: &str) -> Result<Self> {
        let data = std::fs::read(path)
            .map_err(|e| Error::Secrets(format!("failed to read {}: {e}", path.display())))?;
        Self::decrypt(&data, passphrase)
    }

    /// Encrypt this bundle and write it to `path` with 0600 permissions.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn save(&self, path: &std::path::Path, passphrase: &str) -> Result<()> {
        let encrypted = self.encrypt(passphrase)?;
        super::write_secure(path, &encrypted)
    }

    /// Generate a random alphanumeric passphrase (43 characters ≈ 256 bits entropy).
    pub fn generate_passphrase() -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        // 248 = 62 * 4: reject bytes >= 248 to avoid modulo bias
        const ACCEPT_BELOW: u8 = 248;
        let mut result = String::with_capacity(43);
        let mut buf = [0u8; 64];
        let mut rng = UnwrapErr(SysRng);
        loop {
            rng.fill_bytes(&mut buf);
            for &b in &buf {
                if b < ACCEPT_BELOW {
                    result.push(CHARSET[(b as usize) % 62] as char);
                    if result.len() == 43 {
                        return result;
                    }
                }
            }
        }
    }

    /// Derive the DID identity deterministically from all four bundle keys.
    ///
    /// Unlike [`crate::generate_identity_from_secret`] this method uses the
    /// bundle's own `did_signing_key` and `did_encryption_key` instead of
    /// generating fresh random keys, so the resulting document is identical
    /// on every call with the same bundle — safe to use across daemon restarts.
    ///
    /// Verification method IDs use fixed fragments `#sign` and `#enc`.
    pub fn generate_identity(&self) -> Result<crate::GeneratedIdentity> {
        use crate::{identity::build_identity_from_keys, ipns_from_secret, Did, SigningKey};
        let ipns = ipns_from_secret(self.ipns_secret_key)
            .map_err(|e| Error::Secrets(format!("ipns derivation failed: {e}")))?;
        let sign_did = Did::new_url(&ipns, Some("sign"))
            .map_err(|e| Error::Secrets(format!("sign did: {e}")))?;
        let signing_key = SigningKey::from_private_key_bytes(sign_did, self.did_signing_key)
            .map_err(|e| Error::Secrets(format!("signing key: {e}")))?;
        let encryption_key = self.encryption_key()?;
        let mut identity = build_identity_from_keys(&ipns, &signing_key, &encryption_key)
            .map_err(|e| Error::Secrets(format!("identity generation failed: {e}")))?;
        // Restore the original creation time — build_identity_from_keys sets
        // created_at to now(), but it must reflect when the bundle was first
        // generated, not when the document is rebuilt.
        identity.document.created_at.clone_from(&self.created_at);
        let vm = identity
            .document
            .get_verification_method_by_id(&identity.document.assertion_method[0].clone())
            .map_err(|e| Error::Secrets(format!("assertion vm: {e}")))?;
        let vm = vm.clone();
        identity
            .document
            .sign(&signing_key, &vm)
            .map_err(|e| Error::Secrets(format!("re-sign after created_at restore: {e}")))?;
        Ok(identity)
    }

    /// Reconstruct this identity's X25519 key-agreement key.
    pub fn encryption_key(&self) -> Result<crate::EncryptionKey> {
        let ipns = crate::ipns_from_secret(self.ipns_secret_key)
            .map_err(|error| Error::Secrets(format!("ipns derivation failed: {error}")))?;
        let did = crate::Did::new_url(&ipns, Some("enc"))
            .map_err(|error| Error::Secrets(format!("enc did: {error}")))?;
        crate::EncryptionKey::from_private_key_bytes(did, self.did_encryption_key)
            .map_err(|error| Error::Secrets(format!("encryption key: {error}")))
    }

    /// Build a complete, signed [`crate::Document`] from this bundle and a
    /// [`crate::MaExtension`].
    ///
    /// This is the recommended single entry point for constructing a
    /// ready-to-publish DID document:
    ///
    /// 1. Generates the deterministic base identity from the bundle keys.
    /// 2. Applies the caller-supplied extension (services, type, custom fields).
    /// 3. Re-signs the document so the proof covers the extension data.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ma = endpoint.ma_extension().kind("world");
    /// let document = bundle.build_document(ma)?;
    /// ```
    pub fn build_document(&self, ext: crate::doc::MaExtension) -> Result<crate::Document> {
        use crate::{ipns_from_secret, Did, SigningKey};
        let identity = self.generate_identity()?;
        let mut document = identity.document;
        let ipns = ipns_from_secret(self.ipns_secret_key)
            .map_err(|e| Error::Secrets(format!("ipns derivation: {e}")))?;
        let sign_did = Did::new_url(&ipns, Some("sign"))
            .map_err(|e| Error::Secrets(format!("sign did: {e}")))?;
        let signing_key = SigningKey::from_private_key_bytes(sign_did, self.did_signing_key)
            .map_err(|e| Error::Secrets(format!("signing key: {e}")))?;
        let vm = document
            .get_verification_method_by_id(&document.assertion_method[0].clone())
            .map_err(|e| Error::Secrets(format!("assertion vm: {e}")))?;
        let vm = vm.clone();
        document.set_ma_extension(ext);
        // Bump updatedAt to the actual publication time before signing.
        document.touch();
        document
            .sign(&signing_key, &vm)
            .map_err(|e| Error::Secrets(format!("sign: {e}")))?;
        Ok(document)
    }

    /// Derive the [`crate::SigningKey`] for this bundle.
    ///
    /// The returned key matches the `#sign` verification method in any document
    /// produced by [`Self::build_document`] or [`Self::generate_identity`].
    /// Use it to sign [`crate::Message`] objects after the document is built.
    pub fn signing_key(&self) -> Result<crate::SigningKey> {
        use crate::{ipns_from_secret, Did, SigningKey};
        let ipns = ipns_from_secret(self.ipns_secret_key)
            .map_err(|e| Error::Secrets(format!("ipns derivation: {e}")))?;
        let sign_did = Did::new_url(&ipns, Some("sign"))
            .map_err(|e| Error::Secrets(format!("sign did: {e}")))?;
        SigningKey::from_private_key_bytes(sign_did, self.did_signing_key)
            .map_err(|e| Error::Secrets(format!("signing key: {e}")))
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn validate_key_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::Secrets("key name must not be empty".to_string()));
    }
    if RESERVED.contains(&name) {
        return Err(Error::Secrets(format!(
            "key name '{name}' is reserved for a standard key"
        )));
    }
    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_standard_keys() {
        let bundle = SecretBundle::generate();
        let passphrase = "test-passphrase-1234";
        let encrypted = bundle.encrypt(passphrase).unwrap();
        let restored = SecretBundle::decrypt(&encrypted, passphrase).unwrap();
        assert_eq!(bundle.iroh_secret_key, restored.iroh_secret_key);
        assert_eq!(bundle.ipns_secret_key, restored.ipns_secret_key);
        assert_eq!(bundle.did_signing_key, restored.did_signing_key);
        assert_eq!(bundle.did_encryption_key, restored.did_encryption_key);
    }

    #[test]
    fn roundtrip_with_extra_keys() {
        let mut bundle = SecretBundle::generate();
        bundle.generate_key("my_service").unwrap();
        bundle.generate_key("another_key").unwrap();

        let passphrase = "extra-keys-test";
        let encrypted = bundle.encrypt(passphrase).unwrap();
        let restored = SecretBundle::decrypt(&encrypted, passphrase).unwrap();

        assert_eq!(bundle.get_key("my_service"), restored.get_key("my_service"));
        assert_eq!(
            bundle.get_key("another_key"),
            restored.get_key("another_key")
        );
    }

    #[test]
    fn reserved_name_rejected() {
        let mut bundle = SecretBundle::generate();
        assert!(bundle.add_key("iroh", [0u8; 32]).is_err());
        assert!(bundle.add_key("did_signing", [0u8; 32]).is_err());
    }

    #[test]
    fn empty_name_rejected() {
        let mut bundle = SecretBundle::generate();
        assert!(bundle.add_key("", [0u8; 32]).is_err());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let bundle = SecretBundle::generate();
        let encrypted = bundle.encrypt("correct").unwrap();
        assert!(SecretBundle::decrypt(&encrypted, "wrong").is_err());
    }

    #[test]
    fn get_key_returns_none_for_missing_name() {
        let bundle = SecretBundle::generate();
        assert!(bundle.get_key("nonexistent").is_none());
    }

    #[test]
    fn remove_key_returns_and_deletes_key() {
        let mut bundle = SecretBundle::generate();
        let key = bundle.generate_key("to_remove").unwrap();
        let removed = bundle.remove_key("to_remove");
        assert_eq!(removed, Some(key));
        assert!(bundle.get_key("to_remove").is_none());
    }

    #[test]
    fn extra_key_names_lists_all_added_keys() {
        let mut bundle = SecretBundle::generate();
        bundle.generate_key("alpha").unwrap();
        bundle.generate_key("beta").unwrap();
        let mut names: Vec<&str> = bundle.extra_key_names().collect();
        names.sort_unstable();
        assert_eq!(names, ["alpha", "beta"]);
    }

    #[test]
    fn generate_passphrase_is_43_alphanumeric_chars() {
        let p = SecretBundle::generate_passphrase();
        assert_eq!(p.len(), 43);
        assert!(p.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn truncated_blob_fails_decryption() {
        let bundle = SecretBundle::generate();
        let encrypted = bundle.encrypt("pass").unwrap();
        assert!(SecretBundle::decrypt(&encrypted[..10], "pass").is_err());
    }

    #[test]
    fn generate_identity_is_deterministic() {
        let bundle = SecretBundle::generate();
        let id1 = bundle.generate_identity().unwrap();
        let id2 = bundle.generate_identity().unwrap();
        assert_eq!(
            id1.document.id, id2.document.id,
            "same bundle must always produce the same DID"
        );
        assert_eq!(
            id1.signing_private_key_hex, id2.signing_private_key_hex,
            "same bundle must always produce the same signing key"
        );
    }

    #[test]
    fn signing_key_public_key_matches_document_assertion_method() {
        let bundle = SecretBundle::generate();
        let identity = bundle.generate_identity().unwrap();
        let signing_key = bundle.signing_key().unwrap();
        let sign_vm_id = &identity.document.assertion_method[0];
        let sign_vm = identity
            .document
            .get_verification_method_by_id(sign_vm_id)
            .unwrap();
        assert_eq!(
            signing_key.public_key_multibase, sign_vm.public_key_multibase,
            "signing_key() must match the document's assertion method VM"
        );
    }

    #[test]
    fn add_key_stores_and_retrieves_exact_bytes() {
        let mut bundle = SecretBundle::generate();
        let key_bytes = [0xAB_u8; 32];
        bundle.add_key("exact", key_bytes).unwrap();
        assert_eq!(bundle.get_key("exact"), Some(&key_bytes));
    }

    #[test]
    fn two_encryptions_of_same_bundle_produce_different_ciphertext() {
        // Salt and nonce are random per call — ciphertexts must differ.
        let bundle = SecretBundle::generate();
        let c1 = bundle.encrypt("pw").unwrap();
        let c2 = bundle.encrypt("pw").unwrap();
        assert_ne!(c1, c2, "each encryption must use a fresh salt+nonce");
    }
}
