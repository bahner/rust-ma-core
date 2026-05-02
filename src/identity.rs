//! Secure secret key bootstrap helpers.
//!
//! These functions manage persisted 32-byte secret keys so that an endpoint
//! retains the same identity across restarts.

use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use crate::error::{Error, Result};

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
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut key_bytes);

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
