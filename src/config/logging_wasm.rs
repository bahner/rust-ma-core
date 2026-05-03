//! Logging initialisation for wasm targets.
//!
//! [`Config::init_logging`] installs a `tracing_subscriber` formatter whose
//! output writer forwards log lines to browser `console.log`.

use std::io::Write;

use tracing_subscriber::{
    filter::LevelFilter, fmt, layer::SubscriberExt, prelude::*, util::SubscriberInitExt,
};

use crate::error::{Error, Result};

use super::Config;

struct ConsoleMakeWriter;

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ConsoleMakeWriter {
    type Writer = ConsoleWriter;

    fn make_writer(&'a self) -> Self::Writer {
        ConsoleWriter::default()
    }
}

#[derive(Default)]
struct ConsoleWriter {
    buf: Vec<u8>,
}

impl Write for ConsoleWriter {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for ConsoleWriter {
    fn drop(&mut self) {
        if self.buf.is_empty() {
            return;
        }

        let msg = String::from_utf8_lossy(&self.buf).to_string();
        web_sys::console::log_1(&wasm_bindgen::JsValue::from_str(msg.trim_end()));
    }
}

impl Config {
    /// Initialise global logging on wasm by forwarding `tracing` output to
    /// browser console.
    ///
    /// Uses `log_level_stdout` as the effective console filter.
    pub fn init_logging(&self) -> Result<()> {
        let console_level: LevelFilter = self.log_level_stdout.parse().map_err(|_| {
            Error::Config(format!(
                "invalid log_level_stdout: {}",
                self.log_level_stdout
            ))
        })?;

        let console_layer = fmt::layer()
            .with_writer(ConsoleMakeWriter)
            .with_ansi(false)
            .with_filter(console_level);

        tracing_subscriber::registry()
            .with(console_layer)
            .try_init()
            .map_err(|e| Error::Config(format!("failed to initialise wasm logging: {e}")))?;

        Ok(())
    }
}
