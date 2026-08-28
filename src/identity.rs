//! Identity bootstrap helpers.
//!
//! - DID generation from secrets (via `generate_identity`, `generate_identity_from_secret`)
//! - Persisted 32-byte secret key management for endpoint identity across restarts

use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use cid::Cid;
use libp2p_identity::PeerId;

use crate::error::{Error, Result};
use crate::{Did, Document, EncryptionKey, MaError, SigningKey, VerificationMethod};

// ─── DID identity generation (from ma-did) ──────────────────────────────────

/// A generated DID identity with keys and a signed document.
///
/// Private keys are hex-encoded for storage. Use [`SigningKey::from_private_key_bytes`]
/// and [`EncryptionKey::from_private_key_bytes`] to reconstruct key objects.
#[derive(Debug, Clone)]
pub struct GeneratedIdentity {
    pub subject_url: Did,
    pub document: Document,
    pub signing_private_key_hex: String,
    pub encryption_private_key_hex: String,
}

fn build_identity(ipns: &str) -> Result<GeneratedIdentity> {
    let sign_url = Did::new_url(ipns, None::<String>).map_err(Error::Validation)?;
    let enc_url = Did::new_url(ipns, None::<String>).map_err(Error::Validation)?;

    let signing_key = SigningKey::generate(sign_url).map_err(Error::Validation)?;
    let encryption_key = EncryptionKey::generate(enc_url).map_err(Error::Validation)?;

    build_identity_from_keys(ipns, &signing_key, &encryption_key)
}

/// Build a [`GeneratedIdentity`] from caller-supplied signing and encryption keys.
///
/// Uses fixed well-known fragments (`"sign"` / `"enc"`) for the verification
/// method IDs so that the resulting document is identical on every call with
/// the same inputs — no random nanoids, no per-call divergence.
///
/// This is the correct building block when restoring an identity from a
/// [`SecretBundle`](crate::config::SecretBundle): pass
/// `bundle.did_signing_key` and `bundle.did_encryption_key` and get back the
/// same document every time.
pub(crate) fn build_identity_from_keys(
    ipns: &str,
    signing_key: &SigningKey,
    encryption_key: &EncryptionKey,
) -> Result<GeneratedIdentity> {
    let subject_url = Did::new_identity(ipns).map_err(Error::Validation)?;

    let mut document = Document::new(&subject_url, &subject_url);

    // Use fixed fragments so the VM IDs are stable across restarts.
    let assertion_vm = VerificationMethod::new(
        subject_url.base_id(),
        subject_url.base_id(),
        signing_key.key_type.clone(),
        "sign",
        signing_key.public_key_multibase.clone(),
    )
    .map_err(Error::Validation)?;

    let key_agreement_vm = VerificationMethod::new(
        subject_url.base_id(),
        subject_url.base_id(),
        encryption_key.key_type.clone(),
        "enc",
        encryption_key.public_key_multibase.clone(),
    )
    .map_err(Error::Validation)?;

    let assertion_vm_id = assertion_vm.id.clone();
    document
        .add_verification_method(assertion_vm.clone())
        .map_err(Error::Validation)?;
    document
        .add_verification_method(key_agreement_vm.clone())
        .map_err(Error::Validation)?;
    document.assertion_method = vec![assertion_vm_id];
    document.key_agreement = vec![key_agreement_vm.id.clone()];
    document
        .sign(signing_key, &assertion_vm)
        .map_err(Error::Validation)?;

    Ok(GeneratedIdentity {
        subject_url,
        document,
        signing_private_key_hex: hex::encode(signing_key.private_key_bytes()),
        encryption_private_key_hex: hex::encode(encryption_key.private_key_bytes()),
    })
}

/// Derive the `did:ma` IPNS identifier from a caller-managed Ed25519 secret.
pub fn ipns_from_secret(secret: [u8; 32]) -> Result<String> {
    let keypair = libp2p_identity::Keypair::ed25519_from_bytes(secret)
        .map_err(|_| Error::Validation(MaError::InvalidIdentitySecret))?;
    let peer_id = PeerId::from_public_key(&keypair.public());
    // libp2p-identity's From<PeerId> for Multihash gives the identity multihash
    // of the protobuf-encoded public key. Wrap it in a CIDv1 with the libp2p-key
    // codec (0x72) and encode as base36lower — the standard k51... IPNS format.
    let cid = Cid::new_v1(0x72, peer_id.into());
    Ok(multibase::encode(
        multibase::Base::Base36Lower,
        cid.to_bytes(),
    ))
}

/// Generate a base DID identity with keys and a signed document.
pub fn generate_identity(ipns: &str) -> Result<GeneratedIdentity> {
    build_identity(ipns)
}

/// Generate a base DID identity where the `did:ma` IPNS identifier is derived
/// from a caller-managed Ed25519 secret.
pub fn generate_identity_from_secret(secret: [u8; 32]) -> Result<GeneratedIdentity> {
    let ipns = ipns_from_secret(secret)?;
    build_identity(&ipns)
}

// ─── Secret key file helpers ─────────────────────────────────────────────────

/// Load a secret key from a 32-byte file on disk.
///
/// Returns `Ok(None)` if the file does not exist.
pub fn load_secret_key_bytes(path: &Path) -> Result<Option<[u8; 32]>> {
    if !path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(path).map_err(|e| Error::SecretKey(e.to_string()))?;
    let key_bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::SecretKey(format!("invalid key file length in {}", path.display())))?;

    Ok(Some(key_bytes))
}

/// Generate a new random 32-byte secret key and write it to disk.
///
/// Fails if the file already exists (to prevent accidental overwrites).
/// Uses OS-level secure file permissions via `crate::secure_fs` when
/// compiled as part of a crate that provides it, otherwise writes directly.
pub fn generate_secret_key_file(path: &Path) -> Result<[u8; 32]> {
    if path.exists() {
        return Err(Error::SecretKey(format!(
            "secret key already exists at {}",
            path.display()
        )));
    }

    let mut key_bytes = [0u8; 32];
    use rand::{rand_core::UnwrapErr, rngs::SysRng, Rng};
    UnwrapErr(SysRng).fill_bytes(&mut key_bytes);

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            Error::SecretKey(format!("failed to create dir {}: {}", parent.display(), e))
        })?;
    }

    fs::write(path, key_bytes)
        .map_err(|e| Error::SecretKey(format!("failed to write {}: {}", path.display(), e)))?;

    // Best-effort permission hardening on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o400));
    }

    Ok(key_bytes)
}

/// Convert a socket address to a multiaddr string (QUIC-v1 over UDP).
pub fn socket_addr_to_multiaddr(addr: &SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(ip) => format!("/ip4/{}/udp/{}/quic-v1", ip, addr.port()),
        IpAddr::V6(ip) => format!("/ip6/{}/udp/{}/quic-v1", ip, addr.port()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;

    fn test_tmp_file(name: &str) -> PathBuf {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tmp")
            .join("identity-tests");
        fs::create_dir_all(&root).expect("failed creating test tmp directory");
        root.join(name)
    }

    #[test]
    fn multiaddr_ipv4() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
        assert_eq!(
            socket_addr_to_multiaddr(&addr),
            "/ip4/127.0.0.1/udp/4433/quic-v1"
        );
    }

    #[test]
    fn multiaddr_ipv6() {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5555);
        assert_eq!(socket_addr_to_multiaddr(&addr), "/ip6/::1/udp/5555/quic-v1");
    }

    #[test]
    fn load_missing_returns_none() {
        let path = test_tmp_file("nonexistent-key");
        let _ = fs::remove_file(&path);
        assert!(load_secret_key_bytes(&path).unwrap().is_none());
    }

    #[test]
    fn generate_and_load_round_trip() {
        let path = test_tmp_file("round-trip-key");
        let _ = fs::remove_file(&path);

        let generated = generate_secret_key_file(&path).unwrap();
        let loaded = load_secret_key_bytes(&path).unwrap().unwrap();
        assert_eq!(generated, loaded);

        // Cleanup
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn generate_refuses_overwrite() {
        let path = test_tmp_file("no-overwrite-key");
        let _ = fs::remove_file(&path);

        generate_secret_key_file(&path).unwrap();
        let err = generate_secret_key_file(&path).unwrap_err();
        assert!(matches!(err, crate::error::Error::SecretKey(_)));

        // Cleanup
        let _ = fs::remove_file(&path);
    }
}
