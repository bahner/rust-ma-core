//! Configuration for ma-core-based daemons.
//!
//! Provides [`Config`], a configuration model that supports:
//!
//! - native daemon bootstrapping from CLI/env/YAML/defaults via
//!   [`Config::from_args`]
//! - storage-agnostic serialization workflows (including wasm) via
//!   [`Config::from_yaml_str`] and [`Config::to_yaml_string`]
//!
//! Native `from_args` resolves fields from (in decreasing priority):
//!
//! 1. Explicit CLI arguments (via [`MaArgs`])
//! 2. `MA_<MA_DEFAULT_SLUG>_*` environment variables (slug-prefixed, set per binary)
//! 3. `MA_*` environment variables (static fallback, shared across binaries)
//! 4. YAML config file (`XDG_CONFIG_HOME/ma/<slug>.yaml`)
//! 5. Built-in defaults
//!
//! # Native compile-time constant requirement
//!
//! Binaries using [`Config::from_args`] **must** declare a compile-time
//! constant:
//!
//! ```no_run
//! const MA_DEFAULT_SLUG: &str = "panteia";
//! ```
//!
//! This constant serves a dual purpose:
//! - **Default slug** — used for file naming when `--slug` is not set.
//! - **Env-var prefix** — uppercased to `MA_PANTEIA_*` for env-var lookup.
//!   This prefix is fixed at compile time and cannot be changed at runtime.
//!   Only file-naming can be overridden via `--slug`.

#[cfg(not(target_arch = "wasm32"))]
pub mod cli;
#[cfg(not(target_arch = "wasm32"))]
mod logging;
#[cfg(target_arch = "wasm32")]
mod logging_wasm;
pub mod secrets;

#[cfg(not(target_arch = "wasm32"))]
pub use cli::MaArgs;
pub use secrets::SecretBundle;

#[cfg(target_arch = "wasm32")]
use std::path::PathBuf;
#[cfg(not(target_arch = "wasm32"))]
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

// ─── Defaults ────────────────────────────────────────────────────────────────

const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_LOG_LEVEL_STDOUT: &str = "warn";
const DEFAULT_DID_RESOLVER_POSITIVE_TTL_SECS: u64 = 60;
const DEFAULT_DID_RESOLVER_NEGATIVE_TTL_SECS: u64 = 10;
#[cfg(not(target_arch = "wasm32"))]
const DEFAULT_KUBO_RPC_URL: &str = "http://127.0.0.1:5001";

// ─── Config struct ───────────────────────────────────────────────────────────

/// Runtime configuration for a ma daemon.
///
/// Build via [`Config::from_args`] on native targets or via YAML/string
/// serialization helpers on wasm.
#[derive(Debug, Clone)]
pub struct Config {
    /// Short printable slug identifying this daemon instance.
    /// Used in default file names: `<slug>.yaml`, `<slug>.bin`, `<slug>.log`.
    pub slug: String,

    /// Log level written to the log file (e.g. `"info"`, `"debug"`).
    pub log_level: String,

    /// Log level written to stdout.
    pub log_level_stdout: String,

    /// Cache TTL (seconds) for successful DID document resolutions.
    /// Set to `0` to disable positive cache entries.
    pub did_resolver_positive_ttl_secs: u64,

    /// Cache TTL (seconds) for failed DID document resolutions.
    /// Set to `0` to disable negative cache entries.
    pub did_resolver_negative_ttl_secs: u64,

    /// Path to the log file. `None` → resolved to `XDG_DATA_HOME/ma/<slug>.log`
    /// on first use.
    pub log_file: Option<PathBuf>,

    #[cfg(not(target_arch = "wasm32"))]
    /// Kubo JSON-RPC API URL.
    pub kubo_rpc_url: String,

    #[cfg(not(target_arch = "wasm32"))]
    /// IPNS key alias registered in Kubo for this daemon.
    pub kubo_key_alias: String,

    /// Path to the encrypted secret bundle. `None` → `XDG_CONFIG_HOME/ma/<slug>.bin`.
    pub secret_bundle: Option<PathBuf>,

    /// Passphrase to unlock the secret bundle.
    /// In headless configs this is stored in cleartext in the YAML file.
    pub secret_bundle_passphrase: Option<String>,

    /// Path where this config was loaded from or will be saved to.
    pub config_path: Option<PathBuf>,

    /// Extra user-defined YAML keys that are not part of the core schema.
    /// Preserved during load and save so callers can extend the config freely.
    pub extra: serde_yaml::Mapping,
}

/// Browser-friendly identity export payload.
///
/// Contains serialized config text and an encrypted secret bundle encoded as
/// base64 so it can be stored or copied as plain JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserIdentityExport {
    pub version: u8,
    pub config_yaml: String,
    pub encrypted_secret_bundle_base64: String,
}

impl BrowserIdentityExport {
    pub fn new(config_yaml: String, encrypted_secret_bundle: &[u8]) -> Self {
        Self {
            version: 1,
            config_yaml,
            encrypted_secret_bundle_base64: B64.encode(encrypted_secret_bundle),
        }
    }

    pub fn encrypted_secret_bundle_bytes(&self) -> Result<Vec<u8>> {
        B64.decode(self.encrypted_secret_bundle_base64.as_bytes())
            .map_err(|e| Error::Config(format!("invalid encrypted bundle base64: {e}")))
    }

    pub fn to_json_string(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| Error::Config(format!("failed to serialize browser export: {e}")))
    }

    pub fn from_json_str(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| Error::Config(format!("failed to parse browser export JSON: {e}")))
    }
}

// ─── XDG path helpers ────────────────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
fn project_dirs() -> Result<directories::ProjectDirs> {
    directories::ProjectDirs::from("", "ma", "ma")
        .ok_or_else(|| Error::Config("cannot determine XDG base directories".to_string()))
}

/// Default YAML config path: `XDG_CONFIG_HOME/ma/<slug>.yaml`.
#[cfg(not(target_arch = "wasm32"))]
pub fn default_config_path(slug: &str) -> Result<PathBuf> {
    Ok(project_dirs()?.config_dir().join(format!("{slug}.yaml")))
}

/// Default secret bundle path: `XDG_CONFIG_HOME/ma/<slug>.bin`.
#[cfg(not(target_arch = "wasm32"))]
pub fn default_secret_bundle_path(slug: &str) -> Result<PathBuf> {
    Ok(project_dirs()?.config_dir().join(format!("{slug}.bin")))
}

/// Default log file path: `XDG_DATA_HOME/ma/<slug>.log`.
#[cfg(not(target_arch = "wasm32"))]
pub fn default_log_file_path(slug: &str) -> Result<PathBuf> {
    Ok(project_dirs()?.data_dir().join(format!("{slug}.log")))
}

// ─── Secure file I/O ─────────────────────────────────────────────────────────

/// Write `data` to `path`, creating parent directories as needed.
///
/// On Unix the file is created (or truncated) with mode `0600`. On other
/// platforms the file is written without special permission handling.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn write_secure(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::Config(format!("failed to create dir {}: {e}", parent.display()))
        })?;
    }

    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| Error::Config(format!("failed to open {}: {e}", path.display())))?
    };

    #[cfg(not(unix))]
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| Error::Config(format!("failed to open {}: {e}", path.display())))?;

    file.write_all(data)
        .map_err(|e| Error::Config(format!("failed to write {}: {e}", path.display())))?;

    // Belt-and-suspenders: also set permissions after creation (handles the
    // case where the file already existed with wider permissions).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            Error::Config(format!(
                "failed to set permissions on {}: {e}",
                path.display()
            ))
        })?;
    }

    Ok(())
}

/// Check that a file's permissions are not wider than `0600` and log a
/// warning if they are. Only active on Unix.
#[cfg(all(not(target_arch = "wasm32"), unix))]
fn check_permissions(path: &Path) {
    use std::os::unix::fs::MetadataExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.mode() & 0o777;
        if mode > 0o600 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{mode:04o}"),
                "config file has permissions wider than 0600 — consider `chmod 0600 {}`",
                path.display()
            );
        }
    }
}

#[cfg(all(not(target_arch = "wasm32"), not(unix)))]
fn check_permissions(_path: &Path) {}

// ─── YAML helpers ────────────────────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
fn load_yaml_mapping(path: &Path) -> Result<serde_yaml::Mapping> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("failed to read {}: {e}", path.display())))?;
    let val: serde_yaml::Value = serde_yaml::from_str(&content)
        .map_err(|e| Error::Config(format!("invalid YAML in {}: {e}", path.display())))?;
    if let serde_yaml::Value::Mapping(m) = val {
        Ok(m)
    } else {
        Err(Error::Config(format!(
            "config file {} must be a YAML mapping",
            path.display()
        )))
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn yaml_str(m: &serde_yaml::Mapping, key: &str) -> Option<String> {
    m.get(serde_yaml::Value::String(key.to_string()))
        .and_then(|v| v.as_str())
        .map(String::from)
}

#[cfg(not(target_arch = "wasm32"))]
fn yaml_path(m: &serde_yaml::Mapping, key: &str) -> Option<PathBuf> {
    m.get(serde_yaml::Value::String(key.to_string()))
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
}

#[cfg(not(target_arch = "wasm32"))]
fn yaml_u64(m: &serde_yaml::Mapping, key: &str) -> Option<u64> {
    m.get(serde_yaml::Value::String(key.to_string()))
        .and_then(|v| match v {
            serde_yaml::Value::Number(n) => n.as_u64(),
            serde_yaml::Value::String(s) => s.parse::<u64>().ok(),
            _ => None,
        })
}

// ─── Config impl ─────────────────────────────────────────────────────────────

impl Config {
    /// Construct a config value suitable for wasm/local storage workflows.
    ///
    /// This constructor is storage-agnostic and does not touch the filesystem.
    pub fn new_for_storage(slug: impl AsRef<str>) -> Self {
        let slug = slug.as_ref().to_string();
        Self {
            slug: slug.clone(),
            log_level: DEFAULT_LOG_LEVEL.to_string(),
            log_level_stdout: DEFAULT_LOG_LEVEL_STDOUT.to_string(),
            did_resolver_positive_ttl_secs: DEFAULT_DID_RESOLVER_POSITIVE_TTL_SECS,
            did_resolver_negative_ttl_secs: DEFAULT_DID_RESOLVER_NEGATIVE_TTL_SECS,
            log_file: None,
            #[cfg(not(target_arch = "wasm32"))]
            kubo_rpc_url: DEFAULT_KUBO_RPC_URL.to_string(),
            #[cfg(not(target_arch = "wasm32"))]
            kubo_key_alias: slug,
            secret_bundle: None,
            secret_bundle_passphrase: None,
            config_path: None,
            extra: serde_yaml::Mapping::new(),
        }
    }

    /// Deserialize a config value from YAML text without filesystem I/O.
    pub fn from_yaml_str(yaml_text: &str) -> Result<Self> {
        let val: serde_yaml::Value = serde_yaml::from_str(yaml_text)
            .map_err(|e| Error::Config(format!("failed to parse config YAML: {e}")))?;
        let mut m = match val {
            serde_yaml::Value::Mapping(m) => m,
            _ => {
                return Err(Error::Config(
                    "config YAML must be a mapping at the top level".to_string(),
                ));
            }
        };

        let take_str = |map: &mut serde_yaml::Mapping, key: &str| {
            map.remove(serde_yaml::Value::String(key.to_string()))
                .and_then(|v| v.as_str().map(ToOwned::to_owned))
        };

        let take_path = |map: &mut serde_yaml::Mapping, key: &str| {
            map.remove(serde_yaml::Value::String(key.to_string()))
                .and_then(|v| v.as_str().map(PathBuf::from))
        };

        let take_u64 = |map: &mut serde_yaml::Mapping, key: &str| {
            map.remove(serde_yaml::Value::String(key.to_string()))
                .and_then(|v| match v {
                    serde_yaml::Value::Number(n) => n.as_u64(),
                    serde_yaml::Value::String(s) => s.parse::<u64>().ok(),
                    _ => None,
                })
        };

        let slug = take_str(&mut m, "slug").unwrap_or_else(|| "ma".to_string());
        let log_level =
            take_str(&mut m, "log_level").unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_string());
        let log_level_stdout = take_str(&mut m, "log_level_stdout")
            .unwrap_or_else(|| DEFAULT_LOG_LEVEL_STDOUT.to_string());
        let did_resolver_positive_ttl_secs = take_u64(&mut m, "did_resolver_positive_ttl_secs")
            .unwrap_or(DEFAULT_DID_RESOLVER_POSITIVE_TTL_SECS);
        let did_resolver_negative_ttl_secs = take_u64(&mut m, "did_resolver_negative_ttl_secs")
            .unwrap_or(DEFAULT_DID_RESOLVER_NEGATIVE_TTL_SECS);
        // `config_path` is runtime state and should never be restored from YAML.
        let _ignored_config_path = take_path(&mut m, "config_path");
        #[cfg(not(target_arch = "wasm32"))]
        let kubo_rpc_url =
            take_str(&mut m, "kubo_rpc_url").unwrap_or_else(|| DEFAULT_KUBO_RPC_URL.to_string());
        #[cfg(not(target_arch = "wasm32"))]
        let kubo_key_alias = take_str(&mut m, "kubo_key_alias").unwrap_or_else(|| slug.clone());

        Ok(Self {
            slug,
            log_level,
            log_level_stdout,
            did_resolver_positive_ttl_secs,
            did_resolver_negative_ttl_secs,
            log_file: take_path(&mut m, "log_file"),
            #[cfg(not(target_arch = "wasm32"))]
            kubo_rpc_url,
            #[cfg(not(target_arch = "wasm32"))]
            kubo_key_alias,
            secret_bundle: take_path(&mut m, "secret_bundle"),
            secret_bundle_passphrase: take_str(&mut m, "secret_bundle_passphrase"),
            config_path: None,
            extra: m,
        })
    }

    /// Serialize config to YAML text without filesystem I/O.
    pub fn to_yaml_string(&self) -> Result<String> {
        let mut m = self.extra.clone();

        let mut set = |k: &str, v: serde_yaml::Value| {
            m.insert(serde_yaml::Value::String(k.to_string()), v);
        };

        set("slug", serde_yaml::Value::String(self.slug.clone()));
        set(
            "log_level",
            serde_yaml::Value::String(self.log_level.clone()),
        );
        set(
            "log_level_stdout",
            serde_yaml::Value::String(self.log_level_stdout.clone()),
        );
        set(
            "did_resolver_positive_ttl_secs",
            serde_yaml::Value::Number(serde_yaml::Number::from(
                self.did_resolver_positive_ttl_secs,
            )),
        );
        set(
            "did_resolver_negative_ttl_secs",
            serde_yaml::Value::Number(serde_yaml::Number::from(
                self.did_resolver_negative_ttl_secs,
            )),
        );
        #[cfg(not(target_arch = "wasm32"))]
        set(
            "kubo_rpc_url",
            serde_yaml::Value::String(self.kubo_rpc_url.clone()),
        );
        #[cfg(not(target_arch = "wasm32"))]
        set(
            "kubo_key_alias",
            serde_yaml::Value::String(self.kubo_key_alias.clone()),
        );

        if let Some(ref p) = self.log_file {
            set(
                "log_file",
                serde_yaml::Value::String(p.to_string_lossy().into_owned()),
            );
        }
        if let Some(ref p) = self.secret_bundle {
            set(
                "secret_bundle",
                serde_yaml::Value::String(p.to_string_lossy().into_owned()),
            );
        }
        if let Some(ref pw) = self.secret_bundle_passphrase {
            set(
                "secret_bundle_passphrase",
                serde_yaml::Value::String(pw.clone()),
            );
        }

        serde_yaml::to_string(&serde_yaml::Value::Mapping(m))
            .map_err(|e| Error::Config(format!("failed to serialize config: {e}")))
    }

    /// Serialize config to YAML text while excluding secret passphrase fields.
    ///
    /// Useful for browser storage where passphrases should be provided by
    /// runtime user input instead of persisted state.
    pub fn to_yaml_string_without_passphrase(&self) -> Result<String> {
        let mut copy = self.clone();
        copy.secret_bundle_passphrase = None;
        copy.to_yaml_string()
    }

    #[cfg(not(target_arch = "wasm32"))]
    /// Build a `Config` by merging CLI arguments, environment variables, a
    /// YAML config file, and built-in defaults.
    ///
    /// # Required compile-time constant
    ///
    /// Callers **MUST** pass a compile-time constant `MA_DEFAULT_SLUG: &'static str`.
    /// This determines BOTH the default slug for file naming AND the fixed
    /// env-var prefix `MA_<MA_DEFAULT_SLUG>_*`. The prefix cannot be changed
    /// at runtime; only file naming may be overridden via `--slug`.
    ///
    /// ```
    /// # #[cfg(all(feature = "config", not(target_arch = "wasm32")))]
    /// # {
    /// use ma_core::config::{Config, MaArgs};
    /// let args = MaArgs::default();
    /// let config = Config::from_args(&args, "doctest")?;
    /// assert_eq!(config.slug, "doctest");
    /// # }
    /// # Ok::<(), ma_core::Error>(())
    /// ```
    ///
    /// # Priority
    ///
    /// For each field the resolution order is:
    /// 1. Explicit CLI argument
    /// 2. `MA_<MA_DEFAULT_SLUG>_FIELD` environment variable
    /// 3. `MA_FIELD` environment variable (static fallback)
    /// 4. Value from the YAML config file
    /// 5. Built-in default
    #[allow(clippy::too_many_lines)]
    pub fn from_args(args: &MaArgs, default_slug: &'static str) -> Result<Self> {
        // The env-var prefix is determined by the compile-time constant.
        // e.g. default_slug = "panteia"  →  prefix = "PANTEIA"
        let prefix = default_slug.to_uppercase().replace('-', "_");

        // Slug: CLI/env via clap (MA_SLUG) → compile-time default.
        let slug = args
            .slug
            .clone()
            .unwrap_or_else(|| default_slug.to_string());

        // Config file path: explicit → slug-based XDG default.
        let config_path = if let Some(ref p) = args.config {
            p.clone()
        } else {
            default_config_path(&slug)?
        };

        // Load YAML if the file exists.
        let yaml = if config_path.exists() {
            check_permissions(&config_path);
            Some(load_yaml_mapping(&config_path)?)
        } else {
            None
        };

        // Helper: resolve a string field through the priority chain.
        // NOTE: closures borrow `yaml` and `prefix` immutably; NLL ensures
        // the borrows end before we move `yaml` below.
        let resolve_str = |cli: Option<String>, env_key: &str, default: &str| -> String {
            cli.or_else(|| std::env::var(format!("MA_{prefix}_{env_key}")).ok())
                .or_else(|| std::env::var(format!("MA_{env_key}")).ok())
                .or_else(|| {
                    yaml.as_ref()
                        .and_then(|m| yaml_str(m, &env_key.to_lowercase()))
                })
                .unwrap_or_else(|| default.to_string())
        };

        let resolve_opt_str = |cli: Option<String>, env_key: &str| -> Option<String> {
            cli.or_else(|| std::env::var(format!("MA_{prefix}_{env_key}")).ok())
                .or_else(|| std::env::var(format!("MA_{env_key}")).ok())
                .or_else(|| {
                    yaml.as_ref()
                        .and_then(|m| yaml_str(m, &env_key.to_lowercase()))
                })
        };

        let resolve_opt_path = |cli: Option<PathBuf>, env_key: &str| -> Option<PathBuf> {
            cli.or_else(|| {
                std::env::var(format!("MA_{prefix}_{env_key}"))
                    .ok()
                    .map(PathBuf::from)
            })
            .or_else(|| {
                std::env::var(format!("MA_{env_key}"))
                    .ok()
                    .map(PathBuf::from)
            })
            .or_else(|| {
                yaml.as_ref()
                    .and_then(|m| yaml_path(m, &env_key.to_lowercase()))
            })
        };

        let resolve_u64 = |cli: Option<u64>, env_key: &str, default: u64| -> u64 {
            cli.or_else(|| {
                std::env::var(format!("MA_{prefix}_{env_key}"))
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
            })
            .or_else(|| {
                std::env::var(format!("MA_{env_key}"))
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
            })
            .or_else(|| {
                yaml.as_ref()
                    .and_then(|m| yaml_u64(m, &env_key.to_lowercase()))
            })
            .unwrap_or(default)
        };

        let log_level = resolve_str(args.log_level.clone(), "LOG_LEVEL", DEFAULT_LOG_LEVEL);
        let log_level_stdout = resolve_str(
            args.log_level_stdout.clone(),
            "LOG_LEVEL_STDOUT",
            DEFAULT_LOG_LEVEL_STDOUT,
        );
        let log_file = resolve_opt_path(args.log_file.clone(), "LOG_FILE");
        let did_resolver_positive_ttl_secs = resolve_u64(
            args.did_resolver_positive_ttl_secs,
            "DID_RESOLVER_POSITIVE_TTL_SECS",
            DEFAULT_DID_RESOLVER_POSITIVE_TTL_SECS,
        );
        let did_resolver_negative_ttl_secs = resolve_u64(
            args.did_resolver_negative_ttl_secs,
            "DID_RESOLVER_NEGATIVE_TTL_SECS",
            DEFAULT_DID_RESOLVER_NEGATIVE_TTL_SECS,
        );
        let kubo_rpc_url = resolve_str(
            args.kubo_rpc_url.clone(),
            "KUBO_RPC_URL",
            DEFAULT_KUBO_RPC_URL,
        );
        let kubo_key_alias =
            resolve_str(args.kubo_key_alias.clone(), "KUBO_KEY_ALIAS", &slug.clone());
        let secret_bundle = resolve_opt_path(args.secret_bundle.clone(), "SECRET_BUNDLE");
        let secret_bundle_passphrase = resolve_opt_str(
            args.secret_bundle_passphrase.clone(),
            "SECRET_BUNDLE_PASSPHRASE",
        );

        // Extra: all YAML keys that are not part of the core schema.
        let known: &[&str] = &[
            "slug",
            "log_level",
            "log_level_stdout",
            "log_file",
            "did_resolver_positive_ttl_secs",
            "did_resolver_negative_ttl_secs",
            "kubo_rpc_url",
            "kubo_key_alias",
            "secret_bundle",
            "secret_bundle_passphrase",
            // Legacy key; ignored and never persisted.
            "config_path",
        ];
        let extra = yaml
            .map(|mut m| {
                for k in known {
                    m.remove(serde_yaml::Value::String((*k).to_string()));
                }
                m
            })
            .unwrap_or_default();

        Ok(Config {
            slug,
            log_level,
            log_level_stdout,
            did_resolver_positive_ttl_secs,
            did_resolver_negative_ttl_secs,
            log_file,
            #[cfg(not(target_arch = "wasm32"))]
            kubo_rpc_url,
            #[cfg(not(target_arch = "wasm32"))]
            kubo_key_alias,
            secret_bundle,
            secret_bundle_passphrase,
            config_path: Some(config_path),
            extra,
        })
    }

    /// The effective log file path: `self.log_file` if set, otherwise the
    /// XDG default `XDG_DATA_HOME/ma/<slug>.log`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn effective_log_file(&self) -> Result<PathBuf> {
        if let Some(ref p) = self.log_file {
            Ok(p.clone())
        } else {
            default_log_file_path(&self.slug)
        }
    }

    /// The effective secret bundle path: `self.secret_bundle` if set,
    /// otherwise the XDG default `XDG_CONFIG_HOME/ma/<slug>.bin`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn effective_secret_bundle(&self) -> Result<PathBuf> {
        if let Some(ref p) = self.secret_bundle {
            Ok(p.clone())
        } else {
            default_secret_bundle_path(&self.slug)
        }
    }

    /// Build a gateway-backed DID resolver using config TTL settings.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn ipfs_gateway_resolver(&self) -> crate::ipfs::IpfsGatewayResolver {
        crate::ipfs::IpfsGatewayResolver::new(self.kubo_rpc_url.clone()).with_cache_ttls(
            std::time::Duration::from_secs(self.did_resolver_positive_ttl_secs),
            std::time::Duration::from_secs(self.did_resolver_negative_ttl_secs),
        )
    }

    /// Save this config to [`Self::config_path`] as YAML with 0600
    /// permissions. Returns an error if `config_path` is not set.
    ///
    /// Known fields are serialized explicitly; extra fields are merged in
    /// afterwards so user-defined keys are preserved.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn save(&self) -> Result<()> {
        let path = self
            .config_path
            .as_ref()
            .ok_or_else(|| Error::Config("cannot save config: no config_path set".to_string()))?;

        let yaml_text = self.to_yaml_string()?;

        write_secure(path, yaml_text.as_bytes())
    }

    /// Generate a complete headless config:
    ///
    /// 1. Generate a fresh [`SecretBundle`] with four random 32-byte keys.
    /// 2. Encrypt the bundle (using `args.secret_bundle_passphrase` or a
    ///    freshly generated random passphrase).
    /// 3. Write the encrypted bundle to `XDG_CONFIG_HOME/ma/<slug>.bin`
    ///    (or the path from `--secret-bundle`) with mode 0600.
    /// 4. Write the YAML config to `XDG_CONFIG_HOME/ma/<slug>.yaml`
    ///    (or the path from `--config`) with the passphrase in cleartext and
    ///    mode 0600.
    /// 5. Print the paths of both files to stdout.
    ///
    /// Returns an error if either file already exists.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn gen_headless(args: &MaArgs, default_slug: &'static str) -> Result<()> {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;

        let slug = args.slug.as_deref().unwrap_or(default_slug).to_string();

        let config_path = if let Some(ref p) = args.config {
            p.clone()
        } else {
            default_config_path(&slug)?
        };
        let bundle_path = if let Some(ref p) = args.secret_bundle {
            p.clone()
        } else {
            default_secret_bundle_path(&slug)?
        };

        if config_path.exists() {
            return Err(Error::Config(format!(
                "config file already exists: {} (remove it first or use --config)",
                config_path.display()
            )));
        }
        if bundle_path.exists() {
            return Err(Error::Config(format!(
                "secret bundle already exists: {} (remove it first or use --secret-bundle)",
                bundle_path.display()
            )));
        }

        // Generate or use provided passphrase.
        let passphrase = if let Some(ref p) = args.secret_bundle_passphrase {
            p.clone()
        } else {
            let mut bytes = [0u8; 32];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            STANDARD.encode(bytes)
        };

        // Generate and save the bundle.
        let bundle = SecretBundle::generate();
        bundle.save(&bundle_path, &passphrase)?;

        // Build and save the config.
        let config = Config {
            slug: slug.clone(),
            log_level: DEFAULT_LOG_LEVEL.to_string(),
            log_level_stdout: DEFAULT_LOG_LEVEL_STDOUT.to_string(),
            did_resolver_positive_ttl_secs: DEFAULT_DID_RESOLVER_POSITIVE_TTL_SECS,
            did_resolver_negative_ttl_secs: DEFAULT_DID_RESOLVER_NEGATIVE_TTL_SECS,
            log_file: None,
            #[cfg(not(target_arch = "wasm32"))]
            kubo_rpc_url: DEFAULT_KUBO_RPC_URL.to_string(),
            #[cfg(not(target_arch = "wasm32"))]
            kubo_key_alias: slug.clone(),
            secret_bundle: Some(bundle_path.clone()),
            secret_bundle_passphrase: Some(passphrase),
            config_path: Some(config_path.clone()),
            extra: serde_yaml::Mapping::new(),
        };
        config.save()?;

        println!("Config:        {}", config_path.display());
        println!("Secret bundle: {}", bundle_path.display());

        Ok(())
    }
}
