//! Service inbox — a bounded FIFO receive queue with per-message TTL.
//!
//! Messages are pushed by the [`MaEndpoint`](crate::endpoint::MaEndpoint)
//! implementation after validating incoming data. Each message carries its
//! own `created_at` and `ttl` — the endpoint computes `expires_at` from
//! those fields. Consumers only read from the inbox via
//! [`pop`](Inbox::pop), [`peek`](Inbox::peek), or [`drain`](Inbox::drain).

use crate::ttl_queue::TtlQueue;

/// A bounded FIFO receive queue for incoming ma messages.
///
/// Only the endpoint pushes messages into the inbox after validation.
/// Expiry is determined per-message from the message's own `created_at + ttl`.
/// Consumers read via [`pop`](Inbox::pop), [`peek`](Inbox::peek),
/// or [`drain`](Inbox::drain).
#[derive(Debug, Clone)]
pub struct Inbox<T> {
    queue: TtlQueue<T>,
}

impl<T> Inbox<T> {
    /// Create an inbox with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: TtlQueue::new(capacity),
        }
    }

    /// Push an item with a computed expiry timestamp.
    ///
    /// `expires_at` should be `message.created_at + message.ttl`.
    /// Pass `expires_at = 0` for items that never expire.
    ///
    /// Used by endpoint implementations and for local in-process delivery
    /// (e.g. world routing a message directly to an object/room inbox).
    pub fn push(&mut self, now: u64, expires_at: u64, item: T) {
        self.queue.push(now, expires_at, item);
    }

    /// Pop the oldest non-expired item.
    pub fn pop(&mut self, now: u64) -> Option<T> {
        self.queue.pop(now)
    }

    /// Peek at the oldest non-expired item.
    pub fn peek(&mut self, now: u64) -> Option<&T> {
        self.queue.peek(now)
    }

    /// Drain all non-expired items in FIFO order.
    pub fn drain(&mut self, now: u64) -> Vec<T> {
        self.queue.drain(now)
    }

    /// Number of items in the queue (may include not-yet-evicted expired items).
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_ttl_respected() {
        let mut inbox = Inbox::new(8);
        // Message created at t=100 with ttl=60 → expires at 160
        inbox.push(100, 160, "msg");
        assert_eq!(inbox.peek(100), Some(&"msg"));
        assert_eq!(inbox.pop(161), None);
    }

    #[test]
    fn different_message_ttls() {
        let mut inbox = Inbox::new(8);
        // Short-lived message: created_at=100, ttl=10 → expires_at=110
        inbox.push(100, 110, "short");
        // Long-lived message: created_at=100, ttl=60 → expires_at=160
        inbox.push(100, 160, "long");
        // At t=111, "short" is expired, "long" still fresh
        assert_eq!(inbox.pop(111), Some("long"));
    }

    #[test]
    fn zero_expires_at_never_expires() {
        let mut inbox = Inbox::new(4);
        inbox.push(100, 0, "forever");
        assert_eq!(inbox.pop(u64::MAX), Some("forever"));
    }
}
