#[cfg(not(target_arch = "wasm32"))]
use std::{
    env, fs,
    path::{Path, PathBuf},
};

#[cfg(not(target_arch = "wasm32"))]
use anyhow::{anyhow, Context, Result};
#[cfg(not(target_arch = "wasm32"))]
use libp2p_identity::Keypair;

#[cfg(not(target_arch = "wasm32"))]
pub fn default_ma_config_root() -> Result<PathBuf> {
    let home = env::var("HOME").context("HOME env var is not set")?;
    Ok(Path::new(&home).join(".config").join("ma"))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn ensure_local_ipns_key_file(
    config_root: &Path,
    key_file_name: &str,
) -> Result<(Vec<u8>, PathBuf)> {
    if key_file_name.trim().is_empty() {
        return Err(anyhow!("key_file_name is required"));
    }

    let keys_dir = config_root.join("keys");
    fs::create_dir_all(&keys_dir).context("failed to create key directory")?;

    let key_path = keys_dir.join(key_file_name);
    if key_path.exists() {
        let existing = fs::read(&key_path).context("failed to read local ipns key")?;
        if !existing.is_empty() {
            return Ok((existing, key_path));
        }
    }

    let keypair = Keypair::generate_ed25519();
    let encoded = keypair
        .to_protobuf_encoding()
        .map_err(|e| anyhow!("failed to encode local ipns key: {}", e))?;

    fs::write(&key_path, &encoded).context("failed to write local ipns key")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&key_path)
            .context("failed to read key permissions")?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&key_path, perms).context("failed setting key file permissions")?;
    }

    Ok((encoded, key_path))
}
