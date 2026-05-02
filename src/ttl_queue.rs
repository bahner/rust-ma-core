//! A bounded FIFO queue with per-item TTL and lazy eviction.
//!
//! Designed for service mailboxes: incoming messages sit in a queue until
//! consumed or expired. Wasm-compatible (no `std::time` — caller supplies
//! `now` as a Unix-epoch seconds value).

use std::collections::VecDeque;

/// A bounded FIFO queue where each item carries an expiry timestamp.
///
/// Expired items are evicted lazily on `push`, `pop`, and `drain`.
/// When the queue is at capacity, the oldest item is dropped on `push`.
#[derive(Debug, Clone)]
pub struct TtlQueue<T> {
    buf: VecDeque<(u64, T)>,
    capacity: usize,
}

impl<T> TtlQueue<T> {
    /// Create a new queue with the given maximum capacity.
    ///
    /// # Panics
    /// Panics if `capacity` is 0.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "TtlQueue capacity must be > 0");
        Self {
            buf: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Push an item with an absolute expiry timestamp (Unix epoch seconds).
    ///
    /// Pass `expires_at = 0` for items that never expire.
    /// If the queue is full after eviction, the oldest item is silently dropped.
    pub fn push(&mut self, now: u64, expires_at: u64, item: T) {
        self.evict(now);
        if self.buf.len() >= self.capacity {
            self.buf.pop_front();
        }
        self.buf.push_back((expires_at, item));
    }

    /// Pop the oldest non-expired item, evicting any expired head entries first.
    pub fn pop(&mut self, now: u64) -> Option<T> {
        self.evict(now);
        self.buf.pop_front().map(|(_, item)| item)
    }

    /// Peek at the oldest non-expired item without removing it.
    pub fn peek(&mut self, now: u64) -> Option<&T> {
        self.evict(now);
        self.buf.front().map(|(_, item)| item)
    }

    /// Drain all non-expired items, returning them in FIFO order.
    pub fn drain(&mut self, now: u64) -> Vec<T> {
        self.evict(now);
        self.buf.drain(..).map(|(_, item)| item).collect()
    }

    /// Number of items currently in the queue (including not-yet-evicted expired items).
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Remove expired items from the front of the queue.
    fn evict(&mut self, now: u64) {
        while let Some(&(expires_at, _)) = self.buf.front() {
            if expires_at > 0 && expires_at <= now {
                self.buf.pop_front();
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_pop_basic() {
        let mut q = TtlQueue::new(8);
        q.push(100, 200, "a");
        q.push(100, 200, "b");
        assert_eq!(q.pop(100), Some("a"));
        assert_eq!(q.pop(100), Some("b"));
        assert_eq!(q.pop(100), None);
    }

    #[test]
    fn expired_items_evicted() {
        let mut q = TtlQueue::new(8);
        q.push(100, 150, "old");
        q.push(100, 300, "fresh");
        // At t=200, "old" (expires_at=150) should be evicted
        assert_eq!(q.pop(200), Some("fresh"));
        assert!(q.is_empty());
    }

    #[test]
    fn zero_ttl_never_expires() {
        let mut q = TtlQueue::new(4);
        q.push(100, 0, "forever");
        // Even far in the future, expires_at=0 means no expiry
        assert_eq!(q.pop(u64::MAX), Some("forever"));
    }

    #[test]
    fn capacity_drops_oldest() {
        let mut q = TtlQueue::new(2);
        q.push(100, 0, "a");
        q.push(100, 0, "b");
        q.push(100, 0, "c"); // "a" should be dropped
        assert_eq!(q.len(), 2);
        assert_eq!(q.pop(100), Some("b"));
        assert_eq!(q.pop(100), Some("c"));
    }

    #[test]
    fn drain_returns_all_non_expired() {
        let mut q = TtlQueue::new(8);
        q.push(100, 150, "expired");
        q.push(100, 300, "ok1");
        q.push(100, 0, "ok2");
        let items = q.drain(200);
        assert_eq!(items, vec!["ok1", "ok2"]);
        assert!(q.is_empty());
    }

    #[test]
    fn peek_does_not_remove() {
        let mut q = TtlQueue::new(4);
        q.push(100, 0, "x");
        assert_eq!(q.peek(100), Some(&"x"));
        assert_eq!(q.len(), 1);
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn zero_capacity_panics() {
        TtlQueue::<u8>::new(0);
    }
}
