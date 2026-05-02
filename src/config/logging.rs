//! Logging initialisation for ma-core-based daemons.
//!
//! [`Config::init_logging`] sets up a two-layer [`tracing_subscriber`]
//! registry:
//! - A **file layer** that writes structured log lines at `config.log_level`
//!   to `config.effective_log_file()`.
//! - A **stdout layer** that writes human-readable log lines at
//!   `config.log_level_stdout`.
//!
//! Call this once, early in `main`, before spawning any tasks.

use tracing_subscriber::{
    filter::LevelFilter, fmt, layer::SubscriberExt, prelude::*, util::SubscriberInitExt,
};

use crate::error::{Error, Result};

use super::Config;

impl Config {
    /// Initialise the global `tracing` subscriber.
    ///
    /// Sets up:
    /// - A file appender writing at `self.log_level` to
    ///   `self.effective_log_file()`.
    /// - A stdout writer writing at `self.log_level_stdout`.
    ///
    /// Uses [`try_init`](tracing_subscriber::util::SubscriberInitExt::try_init)
    /// so that calling this more than once (e.g. in tests) does not panic.
    pub fn init_logging(&self) -> Result<()> {
        let file_level: LevelFilter = self
            .log_level
            .parse()
            .map_err(|_| Error::Config(format!("invalid log_level: {}", self.log_level)))?;

        let stdout_level: LevelFilter = self.log_level_stdout.parse().map_err(|_| {
            Error::Config(format!(
                "invalid log_level_stdout: {}",
                self.log_level_stdout
            ))
        })?;

        let log_path = self.effective_log_file()?;

        // Ensure the log directory exists.
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::Config(format!(
                    "failed to create log directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| {
                Error::Config(format!(
                    "failed to open log file {}: {e}",
                    log_path.display()
                ))
            })?;

        let file_layer = fmt::layer()
            .with_writer(std::sync::Mutex::new(log_file))
            .with_ansi(false)
            .with_filter(file_level);

        let stdout_layer = fmt::layer()
            .with_writer(std::io::stdout)
            .with_filter(stdout_level);

        tracing_subscriber::registry()
            .with(file_layer)
            .with(stdout_layer)
            .try_init()
            .map_err(|e| Error::Config(format!("failed to initialise logging: {e}")))?;

        Ok(())
    }
}
