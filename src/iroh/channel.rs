//! Write-only persistent connection handle to a remote ma endpoint.
//!
//! A `Channel` wraps an iroh `Connection` + `SendStream` for sending
//! framed one-way messages. Created via [`MaEndpoint::open`].

use iroh::endpoint::{Connection, SendStream};

use crate::error::Result;
use crate::frame::{write_frame, DEFAULT_MAX_FRAME_SIZE};

/// A persistent write-only handle to a remote endpoint on a specific protocol.
///
/// Messages are sent as length-prefixed frames. The channel stays open until
/// explicitly closed or the connection drops.
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

    /// Send a framed payload over the channel.
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        write_frame(&mut self.send, payload, DEFAULT_MAX_FRAME_SIZE).await
    }

    /// Send a framed payload with a custom max frame size.
    pub async fn send_with_max(&mut self, payload: &[u8], max_size: usize) -> Result<()> {
        write_frame(&mut self.send, payload, max_size).await
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
