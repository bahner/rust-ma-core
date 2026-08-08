//! Iroh transport backend.

pub mod channel;
mod endpoint;

use crate::error::Result;
use crate::{DidDocumentResolver, EncryptionKey};
use std::sync::Arc;

pub(crate) async fn new_endpoint(
    secret_bytes: [u8; 32],
    recipient_key: EncryptionKey,
    resolver: Arc<dyn DidDocumentResolver>,
    ipv6: bool,
) -> Result<endpoint::IrohEndpoint> {
    endpoint::IrohEndpoint::new(secret_bytes, recipient_key, resolver, ipv6).await
}
