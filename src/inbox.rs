//! Service inbox — a bounded FIFO receive queue with a default TTL.
//!
//! Wraps [`TtlQueue`] and adds a configurable default TTL so callers can
//! `push(now, item)` without computing `expires_at` each time.

use crate::ttl_queue::TtlQueue;

/// A bounded FIFO receive queue with a default message TTL.
///
/// Items pushed without an explicit TTL use the default. Pass `default_ttl_secs = 0`
/// for items that never expire.
#[derive(Debug, Clone)]
pub struct Inbox<T> {
    queue: TtlQueue<T>,
    default_ttl_secs: u64,
}

impl<T> Inbox<T> {
    /// Create an inbox with the given capacity and default TTL (seconds).
    ///
    /// `default_ttl_secs = 0` means items never expire by default.
    pub fn new(capacity: usize, default_ttl_secs: u64) -> Self {
        Self {
            queue: TtlQueue::new(capacity),
            default_ttl_secs,
        }
    }

    /// Push an item using the default TTL.
    pub fn push(&mut self, now: u64, item: T) {
        let expires_at = if self.default_ttl_secs == 0 {
            0
        } else {
            now.saturating_add(self.default_ttl_secs)
        };
        self.queue.push(now, expires_at, item);
    }

    /// Push an item with a custom TTL (seconds). `ttl_secs = 0` means no expiry.
    pub fn push_with_ttl(&mut self, now: u64, ttl_secs: u64, item: T) {
        let expires_at = if ttl_secs == 0 {
            0
        } else {
            now.saturating_add(ttl_secs)
        };
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
    fn default_ttl_applied() {
        let mut inbox = Inbox::new(8, 60);
        inbox.push(100, "msg");
        // At t=100, item expires at 160 — still fresh
        assert_eq!(inbox.peek(100), Some(&"msg"));
        // At t=161, expired
        assert_eq!(inbox.pop(161), None);
    }

    #[test]
    fn custom_ttl_overrides_default() {
        let mut inbox = Inbox::new(8, 60);
        inbox.push_with_ttl(100, 10, "short");
        inbox.push(100, "default");
        // At t=111, "short" is expired, "default" still fresh
        assert_eq!(inbox.pop(111), Some("default"));
    }

    #[test]
    fn zero_default_ttl_never_expires() {
        let mut inbox = Inbox::new(4, 0);
        inbox.push(100, "forever");
        assert_eq!(inbox.pop(u64::MAX), Some("forever"));
    }
}
