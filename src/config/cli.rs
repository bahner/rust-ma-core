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
/// `MA_CONFIG` and `MA_SLUG` are the only statically-named environment
/// variables; all other fields are resolved dynamically in
/// [`Config::from_args`] using the binary's compile-time `MA_DEFAULT_SLUG`
/// constant as a prefix (e.g. `MA_PANTEIA_LOG_LEVEL`), with a plain
/// `MA_LOG_LEVEL`-style fallback.
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
    /// The env-var prefix `MA_<MA_DEFAULT_SLUG>_*` is always determined by
    /// the compile-time constant — this value does **not** change the prefix.
    ///
    /// Environment variable: `MA_SLUG`
    #[arg(long, env = "MA_SLUG")]
    pub slug: Option<String>,

    /// Log level for the log file (`trace`, `debug`, `info`, `warn`, `error`).
    ///
    /// Resolved via `MA_<MA_DEFAULT_SLUG>_LOG_LEVEL` → `MA_LOG_LEVEL` → YAML
    /// → default `"info"`.
    #[arg(long)]
    pub log_level: Option<String>,

    /// Path to the log file. Defaults to `XDG_DATA_HOME/ma/<slug>.log`.
    ///
    /// Resolved via `MA_<MA_DEFAULT_SLUG>_LOG_FILE` → `MA_LOG_FILE` → YAML
    /// → XDG default.
    #[arg(long)]
    pub log_file: Option<PathBuf>,

    /// Log level for stdout output (`trace`, `debug`, `info`, `warn`, `error`).
    ///
    /// Resolved via `MA_<MA_DEFAULT_SLUG>_LOG_LEVEL_STDOUT` →
    /// `MA_LOG_LEVEL_STDOUT` → YAML → default `"warn"`.
    #[arg(long)]
    pub log_level_stdout: Option<String>,

    /// Path to the encrypted secret bundle file.
    /// Defaults to `XDG_CONFIG_HOME/ma/<slug>.bin`.
    ///
    /// Resolved via `MA_<MA_DEFAULT_SLUG>_SECRET_BUNDLE` →
    /// `MA_SECRET_BUNDLE` → YAML → XDG default.
    #[arg(long)]
    pub secret_bundle: Option<PathBuf>,

    /// Passphrase to unlock the secret bundle.
    ///
    /// In headless configs this is stored in cleartext in the YAML file.
    /// Prefer setting via environment variable rather than CLI to avoid
    /// shell history exposure.
    ///
    /// Resolved via `MA_<MA_DEFAULT_SLUG>_SECRET_BUNDLE_PASSPHRASE` →
    /// `MA_SECRET_BUNDLE_PASSPHRASE` → YAML.
    #[arg(long)]
    pub secret_bundle_passphrase: Option<String>,

    /// Kubo RPC API URL. Defaults to `http://127.0.0.1:5001`.
    ///
    /// Resolved via `MA_<MA_DEFAULT_SLUG>_KUBO_RPC_URL` →
    /// `MA_KUBO_RPC_URL` → YAML → default.
    #[arg(long)]
    pub kubo_rpc_url: Option<String>,

    /// IPNS key alias used in Kubo. Defaults to the slug.
    ///
    /// Resolved via `MA_<MA_DEFAULT_SLUG>_KUBO_KEY_ALIAS` →
    /// `MA_KUBO_KEY_ALIAS` → YAML → slug.
    #[arg(long)]
    pub kubo_key_alias: Option<String>,

    /// Generate a headless config with a fresh secret bundle, write both
    /// files with 0600 permissions, and exit.
    ///
    /// If `--secret-bundle-passphrase` is not provided, a random passphrase
    /// is generated and written into the config file.
    #[arg(long)]
    pub gen_headless_config: bool,
}
