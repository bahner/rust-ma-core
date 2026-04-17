//! Framed I/O helpers for length-prefixed message exchange.
//!
//! The wire format is simple: a 4-byte big-endian u32 length prefix followed
//! by exactly that many bytes of payload. Both sides use the same framing.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Default maximum frame size (256 KiB).
pub const DEFAULT_MAX_FRAME_SIZE: usize = 256 * 1024;

/// Write a length-prefixed frame to `writer`.
///
/// Format: `[u32 big-endian length][payload bytes]`
pub async fn write_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    payload: &[u8],
    max_size: usize,
) -> crate::error::Result<()> {
    if payload.len() > max_size {
        return Err(crate::error::Error::FrameTooLarge {
            size: payload.len(),
            max: max_size,
        });
    }
    writer
        .write_u32(payload.len() as u32)
        .await
        .map_err(|e| crate::error::Error::FrameIo(e.to_string()))?;
    writer
        .write_all(payload)
        .await
        .map_err(|e| crate::error::Error::FrameIo(e.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|e| crate::error::Error::FrameIo(e.to_string()))?;
    Ok(())
}

/// Read a length-prefixed frame from `reader`.
///
/// Returns the payload bytes. Rejects frames larger than `max_size`.
pub async fn read_frame<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    max_size: usize,
) -> crate::error::Result<Vec<u8>> {
    let len = reader
        .read_u32()
        .await
        .map_err(|e| crate::error::Error::FrameIo(e.to_string()))? as usize;
    if len > max_size {
        return Err(crate::error::Error::FrameTooLarge {
            size: len,
            max: max_size,
        });
    }
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|e| crate::error::Error::FrameIo(e.to_string()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn round_trip() {
        let payload = b"hello world";
        let mut buf = Vec::new();
        write_frame(&mut buf, payload, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();

        let mut cursor = Cursor::new(buf);
        let result = read_frame(&mut cursor, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        assert_eq!(result, payload);
    }

    #[tokio::test]
    async fn rejects_oversized_write() {
        let payload = vec![0u8; 100];
        let mut buf = Vec::new();
        let err = write_frame(&mut buf, &payload, 50).await.unwrap_err();
        assert!(matches!(err, crate::error::Error::FrameTooLarge { size: 100, max: 50 }));
    }

    #[tokio::test]
    async fn rejects_oversized_read() {
        // Write a frame claiming 1000 bytes with max 50.
        let mut buf = Vec::new();
        buf.extend_from_slice(&1000u32.to_be_bytes());
        buf.extend_from_slice(&vec![0u8; 1000]);

        let mut cursor = Cursor::new(buf);
        let err = read_frame(&mut cursor, 50).await.unwrap_err();
        assert!(matches!(err, crate::error::Error::FrameTooLarge { size: 1000, max: 50 }));
    }

    #[tokio::test]
    async fn empty_frame() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &[], DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();

        let mut cursor = Cursor::new(buf);
        let result = read_frame(&mut cursor, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        assert!(result.is_empty());
    }
}
