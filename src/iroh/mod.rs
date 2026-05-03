//! Iroh transport backend.

pub mod channel;
mod endpoint;
#[cfg(feature = "gossip")]
pub mod gossip;

use crate::error::Result;

pub(crate) async fn new_endpoint(secret_bytes: [u8; 32]) -> Result<endpoint::IrohEndpoint> {
    endpoint::IrohEndpoint::new(secret_bytes).await
}
