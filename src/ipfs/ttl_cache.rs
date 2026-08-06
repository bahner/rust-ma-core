//! Generic TTL cache with positive/negative entries and per-key in-flight locks.
//!
//! Pure policy: no I/O, no knowledge of DIDs or gateways.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use web_time::{Duration, Instant};

/// A cached outcome: a successful value or a remembered failure detail.
#[derive(Clone)]
pub enum Cached<T> {
    Hit(T),
    Miss(String),
}

#[derive(Clone)]
struct Entry<T> {
    expires_at: Instant,
    value: Cached<T>,
}

/// String-keyed cache where hits and misses expire on independent TTLs.
///
/// A TTL of zero disables caching for that outcome kind. `lock_for` hands out
/// a per-key async mutex so concurrent fetchers of the same key collapse into
/// one upstream request.
pub struct TtlCache<T> {
    positive_ttl: Mutex<Duration>,
    negative_ttl: Mutex<Duration>,
    entries: Mutex<HashMap<String, Entry<T>>>,
    in_flight: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl<T: Clone> TtlCache<T> {
    #[must_use]
    pub fn new(positive_ttl: Duration, negative_ttl: Duration) -> Self {
        Self {
            positive_ttl: Mutex::new(positive_ttl),
            negative_ttl: Mutex::new(negative_ttl),
            entries: Mutex::new(HashMap::new()),
            in_flight: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_ttls(&self, positive_ttl: Duration, negative_ttl: Duration) {
        if let Ok(mut ttl) = self.positive_ttl.lock() {
            *ttl = positive_ttl;
        }
        if let Ok(mut ttl) = self.negative_ttl.lock() {
            *ttl = negative_ttl;
        }
    }

    #[must_use]
    pub fn positive_ttl(&self) -> Duration {
        self.positive_ttl
            .lock()
            .map_or(Duration::from_secs(0), |ttl| *ttl)
    }

    #[must_use]
    pub fn negative_ttl(&self) -> Duration {
        self.negative_ttl
            .lock()
            .map_or(Duration::from_secs(0), |ttl| *ttl)
    }

    /// Read a live entry, honouring the current TTL configuration.
    ///
    /// Expired entries are evicted. Hits are returned only when the positive
    /// TTL is non-zero; misses only when the negative TTL is non-zero.
    #[must_use]
    pub fn read(&self, key: &str) -> Option<Cached<T>> {
        let hit_enabled = !self.positive_ttl().is_zero();
        let miss_enabled = !self.negative_ttl().is_zero();
        if !hit_enabled && !miss_enabled {
            return None;
        }

        let mut entries = self.entries.lock().ok()?;
        let entry = entries.get(key).cloned()?;
        if entry.expires_at <= Instant::now() {
            entries.remove(key);
            return None;
        }

        match entry.value {
            Cached::Hit(value) if hit_enabled => Some(Cached::Hit(value)),
            Cached::Miss(value) if miss_enabled => Some(Cached::Miss(value)),
            _ => None,
        }
    }

    /// Store a hit under the positive TTL. No-op when the TTL is zero.
    pub fn write_hit(&self, key: String, value: T) {
        let ttl = self.positive_ttl();
        if !ttl.is_zero() {
            self.write(key, Cached::Hit(value), Instant::now() + ttl);
        }
    }

    /// Store a miss under the negative TTL. No-op when the TTL is zero.
    pub fn write_miss(&self, key: String, detail: String) {
        let ttl = self.negative_ttl();
        if !ttl.is_zero() {
            self.write(key, Cached::Miss(detail), Instant::now() + ttl);
        }
    }

    fn write(&self, key: String, value: Cached<T>, expires_at: Instant) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(key, Entry { expires_at, value });
        }
    }

    /// Get (or create) the in-flight lock for `key`.
    #[must_use]
    pub fn lock_for(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(
            in_flight
                .entry(key.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }

    /// Drop the in-flight lock for `key` once no other fetcher holds it.
    pub fn release_lock(&self, key: &str, lock: &Arc<tokio::sync::Mutex<()>>) {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if in_flight
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, lock))
            && Arc::strong_count(lock) == 2
        {
            in_flight.remove(key);
        }
    }

    #[cfg(test)]
    pub(crate) fn has_in_flight(&self, key: &str) -> bool {
        self.in_flight
            .lock()
            .is_ok_and(|in_flight| in_flight.contains_key(key))
    }
}

#[cfg(test)]
mod tests {
    use super::{Cached, TtlCache};
    use std::sync::Arc;
    use web_time::{Duration, Instant};

    fn cache() -> TtlCache<Vec<u8>> {
        TtlCache::new(Duration::from_mins(1), Duration::from_secs(10))
    }

    #[test]
    fn write_and_read_hit() {
        let cache = cache();
        cache.write_hit("did:ma:test".to_string(), vec![1, 2, 3]);
        let cached = cache.read("did:ma:test");
        assert!(matches!(cached, Some(Cached::Hit(ref b)) if *b == vec![1, 2, 3]));
    }

    #[test]
    fn miss_not_returned_when_negative_ttl_zero() {
        let cache = cache();
        cache.write_miss("did:ma:test".to_string(), "some error".to_string());
        cache.set_ttls(Duration::from_mins(1), Duration::ZERO);
        assert!(
            cache.read("did:ma:test").is_none(),
            "miss should not be returned when miss-cache is disabled"
        );
    }

    #[test]
    fn expired_entry_is_evicted() {
        let cache = cache();
        // Bypass write_hit to plant an already-expired entry.
        let already_expired = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        cache.write("k".to_string(), Cached::Hit(vec![9]), already_expired);
        assert!(
            cache.read("k").is_none(),
            "expired entry must not be returned"
        );
    }

    #[test]
    fn lock_is_shared_per_key_and_released_when_idle() {
        let cache = cache();
        let first = cache.lock_for("did:ma:one");
        let second = cache.lock_for("did:ma:one");
        let other = cache.lock_for("did:ma:two");

        assert!(Arc::ptr_eq(&first, &second));
        assert!(!Arc::ptr_eq(&first, &other));

        drop(second);
        cache.release_lock("did:ma:one", &first);
        assert!(!cache.has_in_flight("did:ma:one"));
    }
}
