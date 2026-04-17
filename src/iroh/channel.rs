//! Write-only persistent connection handle to a remote ma endpoint.
//!
//! A `Channel` wraps an iroh `Connection` + `SendStream` for sending
//! one-way messages. Created via [`crate::iroh::IrohEndpoint::open`].

use iroh::endpoint::{Connection, SendStream};
use tokio::io::AsyncWriteExt;

use crate::error::{Error, Result};

/// A persistent write-only handle to a remote endpoint on a specific protocol.
///
/// The channel stays open until explicitly closed or the connection drops.
#[derive(Debug)]
pub struct Channel {
    connection: Connection,
    send: SendStream,
}

impl Channel {
    /// Create a channel from an existing connection and send stream.
    pub(crate) fn new(connection: Connection, send: SendStream) -> Self {
        Self { connection, send }
    }

    /// Send a payload over the channel.
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        self.send
            .write_all(payload)
            .await
            .map_err(|e| Error::Transport(format!("channel write failed: {e}")))?;
        self.send
            .flush()
            .await
            .map_err(|e| Error::Transport(format!("channel flush failed: {e}")))?;
        Ok(())
    }

    /// Close the channel gracefully.
    pub fn close(mut self) {
        let _ = self.send.finish();
        self.connection.close(0u32.into(), b"done");
    }

    /// Access the underlying iroh connection.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        let _ = self.send.finish();
    }
}
