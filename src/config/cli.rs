//! Command-line argument struct for ma-core-based binaries.
//!
//! Flatten [`MaArgs`] into your own `#[derive(Parser)]` struct so that every
//! binary in the ma ecosystem accepts a consistent set of arguments:
//!
//! ```rust,ignore
//! use clap::Parser;
//! use ma_core::config::MaArgs;
//!
//! const MA_DEFAULT_SLUG: &str = "panteia";
//!
//! #[derive(Parser)]
//! struct Cli {
//!     #[command(flatten)]
//!     ma: MaArgs,
//! }
//!
//! fn main() -> anyhow::Result<()> {
//!     let cli = Cli::parse();
//!     let config = ma_core::config::Config::from_args(&cli.ma, MA_DEFAULT_SLUG)?;
//!     config.init_logging()?;
//!     Ok(())
//! }
//! ```

use std::path::PathBuf;

use clap::Args;

/// Standard ma-core CLI arguments.
///
/// Add these to your binary with `#[command(flatten)]`.
///
/// All fields are resolved from `MA_*` environment variables, a YAML config
/// file, and built-in defaults — in that priority order.
#[derive(Args, Debug, Clone, Default)]
pub struct MaArgs {
    /// Path to the YAML config file. Overrides the slug-derived default
    /// (`XDG_CONFIG_HOME/ma/<slug>.yaml`).
    ///
    /// Environment variable: `MA_CONFIG`
    #[arg(long, env = "MA_CONFIG")]
    pub config: Option<PathBuf>,

    /// Runtime slug. Overrides `MA_DEFAULT_SLUG` for file naming
    /// (`<slug>.yaml`, `<slug>.bin`, `<slug>.log`) only.
    ///
    /// Environment variable: `MA_SLUG`
    #[arg(long, env = "MA_SLUG")]
    pub slug: Option<String>,

    /// Log level for the log file (`trace`, `debug`, `info`, `warn`, `error`).
    ///
    /// Environment variable: `MA_LOG_LEVEL`. Falls back to YAML → default `"info"`.
    #[arg(long)]
    pub log_level: Option<String>,

    /// Path to the log file. Defaults to `XDG_DATA_HOME/ma/<slug>.log`.
    ///
    /// Environment variable: `MA_LOG_FILE`. Falls back to YAML → XDG default.
    #[arg(long)]
    pub log_file: Option<PathBuf>,

    /// Log level for stdout output (`trace`, `debug`, `info`, `warn`, `error`).
    ///
    /// Environment variable: `MA_LOG_LEVEL_STDOUT`. Falls back to YAML → default `"info"`.
    #[arg(long)]
    pub log_level_stdout: Option<String>,

    /// Positive DID cache TTL in seconds.
    ///
    /// Set to `0` to disable caching successful DID resolutions.
    /// Environment variable: `MA_DID_RESOLVER_POSITIVE_TTL_SECS`. Falls back to YAML → default `60`.
    #[arg(long)]
    pub did_resolver_positive_ttl_secs: Option<u64>,

    /// Negative DID cache TTL in seconds.
    ///
    /// Set to `0` to disable caching failed DID resolutions.
    /// Environment variable: `MA_DID_RESOLVER_NEGATIVE_TTL_SECS`. Falls back to YAML → default `10`.
    #[arg(long)]
    pub did_resolver_negative_ttl_secs: Option<u64>,

    /// Path to the encrypted secret bundle file.
    /// Defaults to `XDG_CONFIG_HOME/ma/<slug>.bin`.
    ///
    /// Environment variable: `MA_SECRET_BUNDLE`. Falls back to YAML → XDG default.
    #[arg(long)]
    pub secret_bundle: Option<PathBuf>,

    /// Passphrase to unlock the secret bundle.
    ///
    /// In headless configs this is stored in cleartext in the YAML file.
    /// Prefer setting via environment variable rather than CLI to avoid
    /// shell history exposure.
    ///
    /// Environment variable: `MA_SECRET_BUNDLE_PASSPHRASE`. Falls back to YAML.
    #[arg(long)]
    pub secret_bundle_passphrase: Option<String>,

    /// Kubo RPC API URL. Defaults to `http://127.0.0.1:5001`.
    ///
    /// Environment variable: `MA_KUBO_RPC_URL`. Falls back to YAML → default.
    #[arg(long)]
    pub kubo_rpc_url: Option<String>,

    /// IPNS key alias used in Kubo. Defaults to the slug.
    ///
    /// Environment variable: `MA_KUBO_KEY_ALIAS`. Falls back to YAML → slug.
    #[arg(long)]
    pub kubo_key_alias: Option<String>,

    /// Mirror selected CIDs to a configured Kubo remote pinning service.
    ///
    /// Environment variable: `MA_PIN_REMOTE`. Falls back to YAML → `false`.
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub pin_remote: Option<bool>,

    /// Kubo remote pinning service name, e.g. `pinata`.
    ///
    /// Environment variable: `MA_PIN_REMOTE_SERVICE`. Falls back to YAML.
    #[arg(long)]
    pub pin_remote_service: Option<String>,

    /// Operator-visible remote pin name. Callers may supply a default when unset.
    ///
    /// Environment variable: `MA_PIN_REMOTE_NAME`. Falls back to YAML.
    #[arg(long)]
    pub pin_remote_name: Option<String>,

    /// Replace older pins with the same managed name after a new pin succeeds.
    ///
    /// Environment variable: `MA_PIN_OVERWRITE`. Falls back to YAML → `true`.
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub pin_overwrite: Option<bool>,

    /// Maximum stale pins removed by one asynchronous cleanup worker pass.
    ///
    /// Environment variable: `MA_OLD_PIN_BATCH_SIZE`. Falls back to YAML → `100`.
    #[arg(long)]
    pub old_pin_batch_size: Option<u64>,

    /// Generate a headless config with a fresh secret bundle, write both
    /// files with 0600 permissions, and exit.
    ///
    /// If `--secret-bundle-passphrase` is not provided, a random passphrase
    /// is generated and written into the config file.
    #[arg(long)]
    pub gen_headless_config: bool,
}
