#[cfg(not(target_arch = "wasm32"))]
use moka::sync::Cache as PresenceCache;
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
struct CacheEntry<V> {
    value: V,
    epoch_ms: u64,
    seq_no: u64,
}

#[derive(Clone, Debug)]
pub struct TtlCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
{
    // Native builds use moka for thread-safe eviction behavior.
    #[cfg(not(target_arch = "wasm32"))]
    presence: PresenceCache<K, ()>,
    // WASM intentionally uses only local in-memory structures below.
    // We avoid moka in wasm to keep runtime dependencies and behavior simple.
    entries: HashMap<K, CacheEntry<V>>,
    order: BTreeMap<(u64, u64), K>,
    order_key_by_entry: HashMap<K, (u64, u64)>,
    default_max_cache: Duration,
    next_seq_no: u64,
}

impl<K, V> TtlCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
{
    #[cfg(not(target_arch = "wasm32"))]
    fn build_presence_cache(default_max_cache: Duration, capacity: Option<usize>) -> PresenceCache<K, ()> {
        let mut builder = PresenceCache::builder()
            .time_to_live(default_max_cache)
            .time_to_idle(default_max_cache);
        if let Some(cap) = capacity {
            builder = builder.max_capacity(cap as u64);
        }
        builder.build()
    }

    fn now_epoch_ms() -> u64 {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_millis();
        u64::try_from(millis).unwrap_or(u64::MAX)
    }

    fn max_cache_ms(max_cache: Duration) -> u64 {
        let millis = max_cache.as_millis();
        u64::try_from(millis).unwrap_or(u64::MAX)
    }

    fn is_fresh_epoch(epoch_ms: u64, now_ms: u64, max_cache: Duration) -> bool {
        now_ms.saturating_sub(epoch_ms) <= Self::max_cache_ms(max_cache)
    }

    fn alloc_seq_no(&mut self) -> u64 {
        self.next_seq_no = self.next_seq_no.saturating_add(1);
        self.next_seq_no
    }

    fn is_visible_any(&self, entry: &CacheEntry<V>) -> bool {
        let now_ms = Self::now_epoch_ms();
        Self::is_fresh_epoch(entry.epoch_ms, now_ms, self.default_max_cache)
    }

    fn remove_by_order_key_no_compact(&mut self, order_key: (u64, u64)) -> Option<(K, V)> {
        let key = self.order.remove(&order_key)?;
        self.order_key_by_entry.remove(&key);
        #[cfg(not(target_arch = "wasm32"))]
        self.presence.invalidate(&key);
        let entry = self.entries.remove(&key)?;
        Some((key, entry.value))
    }

    fn compact_evicted(&mut self) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.presence.run_pending_tasks();
            let stale = self
                .entries
                .keys()
                .filter(|key| self.presence.get(*key).is_none())
                .cloned()
                .collect::<Vec<_>>();
            for key in stale {
                if let Some(entry) = self.entries.remove(&key) {
                    self.order.remove(&(entry.epoch_ms, entry.seq_no));
                }
                self.order_key_by_entry.remove(&key);
            }
        }

        #[cfg(target_arch = "wasm32")]
        {
            // WASM path: explicit in-memory TTL compaction.
            // This is deliberately simple and does not depend on moka internals.
            let now_ms = Self::now_epoch_ms();
            let cutoff = now_ms.saturating_sub(Self::max_cache_ms(self.default_max_cache));
            let stale_order_keys = self
                .order
                .keys()
                .take_while(|(epoch_ms, _)| *epoch_ms < cutoff)
                .copied()
                .collect::<Vec<_>>();
            for order_key in stale_order_keys {
                let _ = self.remove_by_order_key_no_compact(order_key);
            }
        }
    }

    pub fn new(default_max_cache: Duration) -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            presence: Self::build_presence_cache(default_max_cache, None),
            entries: HashMap::new(),
            order: BTreeMap::new(),
            order_key_by_entry: HashMap::new(),
            default_max_cache,
            next_seq_no: 0,
        }
    }

    pub fn with_capacity(default_max_cache: Duration, capacity: usize) -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            presence: Self::build_presence_cache(default_max_cache, Some(capacity)),
            entries: HashMap::with_capacity(capacity),
            order: BTreeMap::new(),
            order_key_by_entry: HashMap::with_capacity(capacity),
            default_max_cache,
            next_seq_no: 0,
        }
    }

    pub fn default_max_cache(&self) -> Duration {
        self.default_max_cache
    }

    pub fn set_default_max_cache(&mut self, max_cache: Duration) {
        self.compact_evicted();
        self.default_max_cache = max_cache;

        #[cfg(not(target_arch = "wasm32"))]
        {
            self.presence = Self::build_presence_cache(max_cache, Some(self.entries.len().max(1)));
            for key in self.entries.keys() {
                self.presence.insert(key.clone(), ());
            }
        }
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.compact_evicted();
        let now_ms = Self::now_epoch_ms();
        self.insert_with_epoch_ms(key, value, now_ms)
    }

    pub fn insert_with_epoch_ms(&mut self, key: K, value: V, epoch_ms: u64) -> Option<V> {
        self.compact_evicted();
        let mut replaced = None;

        if let Some(previous_order_key) = self.order_key_by_entry.remove(&key) {
            self.order.remove(&previous_order_key);
        }

        if let Some(previous) = self.entries.remove(&key) {
            replaced = Some(previous.value);
        }

        let seq_no = self.alloc_seq_no();
        let order_key = (epoch_ms, seq_no);
        self.order.insert(order_key, key.clone());
        self.order_key_by_entry.insert(key.clone(), order_key);
        #[cfg(not(target_arch = "wasm32"))]
        self.presence.insert(key.clone(), ());
        self.entries.insert(
            key,
            CacheEntry {
                value,
                epoch_ms,
                seq_no,
            },
        );

        replaced
    }

    pub fn touch(&mut self, key: &K) -> bool {
        self.compact_evicted();
        let Some(old_entry) = self.entries.remove(key) else {
            return false;
        };

        self.order_key_by_entry.remove(key);
        self.order.remove(&(old_entry.epoch_ms, old_entry.seq_no));
        let seq_no = self.alloc_seq_no();
        let epoch_ms = Self::now_epoch_ms();
        let order_key = (epoch_ms, seq_no);
        self.order.insert(order_key, key.clone());
        self.order_key_by_entry.insert(key.clone(), order_key);
        #[cfg(not(target_arch = "wasm32"))]
        self.presence.insert(key.clone(), ());
        self.entries.insert(
            key.clone(),
            CacheEntry {
                value: old_entry.value,
                epoch_ms,
                seq_no,
            },
        );
        true
    }

    pub fn epoch_ms_of(&self, key: &K) -> Option<u64> {
        self.entries.get(key).and_then(|entry| {
            if self.is_visible_any(entry) {
                Some(entry.epoch_ms)
            } else {
                None
            }
        })
    }

    pub fn seq_no_of(&self, key: &K) -> Option<u64> {
        self.entries.get(key).and_then(|entry| {
            if self.is_visible_any(entry) {
                Some(entry.seq_no)
            } else {
                None
            }
        })
    }

    pub fn latest_seq_no(&self) -> u64 {
        self.next_seq_no
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.get_with_max_cache(key, self.default_max_cache)
    }

    pub fn get_with_max_cache(&self, key: &K, max_cache: Duration) -> Option<&V> {
        let now_ms = Self::now_epoch_ms();
        self.entries
            .get(key)
            .filter(|entry| Self::is_fresh_epoch(entry.epoch_ms, now_ms, max_cache))
            .map(|entry| &entry.value)
    }

    pub fn get_any(&self, key: &K) -> Option<&V> {
        self.entries.get(key).and_then(|entry| {
            if self.is_visible_any(entry) {
                Some(&entry.value)
            } else {
                None
            }
        })
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.get_mut_with_max_cache(key, self.default_max_cache)
    }

    pub fn get_mut_with_max_cache(&mut self, key: &K, max_cache: Duration) -> Option<&mut V> {
        self.compact_evicted();
        let now_ms = Self::now_epoch_ms();
        let entry = self.entries.get(key)?;
        if !Self::is_fresh_epoch(entry.epoch_ms, now_ms, max_cache) {
            return None;
        }
        self.entries.get_mut(key).map(|entry| &mut entry.value)
    }

    pub fn get_mut_any(&mut self, key: &K) -> Option<&mut V> {
        self.compact_evicted();
        let entry = self.entries.get(key)?;
        if !self.is_visible_any(entry) {
            return None;
        }
        self.entries.get_mut(key).map(|entry| &mut entry.value)
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    pub fn contains_key_any(&self, key: &K) -> bool {
        self.get_any(key).is_some()
    }

    pub fn min(&self) -> Option<(&K, &V)> {
        self.min_with_max_cache(self.default_max_cache)
    }

    pub fn min_with_max_cache(&self, max_cache: Duration) -> Option<(&K, &V)> {
        let now_ms = Self::now_epoch_ms();
        for (order_key, key) in &self.order {
            let Some(entry) = self.entries.get(key) else {
                continue;
            };
            if entry.epoch_ms != order_key.0 || entry.seq_no != order_key.1 {
                continue;
            }
            if Self::is_fresh_epoch(entry.epoch_ms, now_ms, max_cache) {
                return Some((key, &entry.value));
            }
        }
        None
    }

    pub fn max(&self) -> Option<(&K, &V)> {
        self.max_with_max_cache(self.default_max_cache)
    }

    pub fn max_with_max_cache(&self, max_cache: Duration) -> Option<(&K, &V)> {
        let now_ms = Self::now_epoch_ms();
        for (order_key, key) in self.order.iter().rev() {
            let Some(entry) = self.entries.get(key) else {
                continue;
            };
            if entry.epoch_ms != order_key.0 || entry.seq_no != order_key.1 {
                continue;
            }
            if Self::is_fresh_epoch(entry.epoch_ms, now_ms, max_cache) {
                return Some((key, &entry.value));
            }
        }
        None
    }

    pub fn min_any(&self) -> Option<(&K, &V)> {
        let Some((order_key, key)) = self.order.iter().next() else {
            return None;
        };
        let entry = self.entries.get(key)?;
        if entry.epoch_ms != order_key.0 || entry.seq_no != order_key.1 {
            return None;
        }
        if !self.is_visible_any(entry) {
            return None;
        }
        Some((key, &entry.value))
    }

    pub fn max_any(&self) -> Option<(&K, &V)> {
        let Some((order_key, key)) = self.order.iter().next_back() else {
            return None;
        };
        let entry = self.entries.get(key)?;
        if entry.epoch_ms != order_key.0 || entry.seq_no != order_key.1 {
            return None;
        }
        if !self.is_visible_any(entry) {
            return None;
        }
        Some((key, &entry.value))
    }

    fn remove_by_order_key(&mut self, order_key: (u64, u64)) -> Option<(K, V)> {
        self.compact_evicted();
        self.remove_by_order_key_no_compact(order_key)
    }

    pub fn pop_first(&mut self) -> Option<(K, V)> {
        self.compact_evicted();
        self.pop_first_with_max_cache(self.default_max_cache)
    }

    pub fn pop_first_with_max_cache(&mut self, max_cache: Duration) -> Option<(K, V)> {
        self.compact_evicted();
        let now_ms = Self::now_epoch_ms();
        let candidate = self.order.iter().find_map(|(order_key, key)| {
            let entry = self.entries.get(key)?;
            if entry.epoch_ms != order_key.0 || entry.seq_no != order_key.1 {
                return None;
            }
            if Self::is_fresh_epoch(entry.epoch_ms, now_ms, max_cache) {
                Some(*order_key)
            } else {
                None
            }
        })?;
        self.remove_by_order_key(candidate)
    }

    pub fn pop_latest(&mut self) -> Option<(K, V)> {
        self.compact_evicted();
        self.pop_latest_with_max_cache(self.default_max_cache)
    }

    pub fn pop_latest_with_max_cache(&mut self, max_cache: Duration) -> Option<(K, V)> {
        self.compact_evicted();
        let now_ms = Self::now_epoch_ms();
        let candidate = self.order.iter().rev().find_map(|(order_key, key)| {
            let entry = self.entries.get(key)?;
            if entry.epoch_ms != order_key.0 || entry.seq_no != order_key.1 {
                return None;
            }
            if Self::is_fresh_epoch(entry.epoch_ms, now_ms, max_cache) {
                Some(*order_key)
            } else {
                None
            }
        })?;
        self.remove_by_order_key(candidate)
    }

    pub fn pop_first_any(&mut self) -> Option<(K, V)> {
        self.compact_evicted();
        let key = *self.order.keys().next()?;
        self.remove_by_order_key(key)
    }

    pub fn pop_latest_any(&mut self) -> Option<(K, V)> {
        self.compact_evicted();
        let key = *self.order.keys().next_back()?;
        self.remove_by_order_key(key)
    }

    pub fn items(&self) -> Vec<(&K, &V)> {
        self.items_with_max_cache(self.default_max_cache)
    }

    pub fn items_with_max_cache(&self, max_cache: Duration) -> Vec<(&K, &V)> {
        let now_ms = Self::now_epoch_ms();
        self.order
            .iter()
            .filter_map(|(order_key, key)| {
                let entry = self.entries.get(key)?;
                if entry.epoch_ms != order_key.0 || entry.seq_no != order_key.1 {
                    return None;
                }
                if Self::is_fresh_epoch(entry.epoch_ms, now_ms, max_cache) {
                    Some((key, &entry.value))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn items_any(&self) -> Vec<(&K, &V)> {
        self.order
            .iter()
            .filter_map(|(order_key, key)| {
                let entry = self.entries.get(key)?;
                if entry.epoch_ms != order_key.0 || entry.seq_no != order_key.1 {
                    return None;
                }
                if self.is_visible_any(entry) {
                    Some((key, &entry.value))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.compact_evicted();
        #[cfg(not(target_arch = "wasm32"))]
        self.presence.invalidate(key);
        let entry = self.entries.remove(key)?;
        self.order.remove(&(entry.epoch_ms, entry.seq_no));
        self.order_key_by_entry.remove(key);
        Some(entry.value)
    }

    pub fn clear(&mut self) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.presence.invalidate_all();
            self.presence.run_pending_tasks();
        }
        self.entries.clear();
        self.order.clear();
        self.order_key_by_entry.clear();
    }

    pub fn len_any(&self) -> usize {
        self.items_any().len()
    }

    pub fn len(&self) -> usize {
        self.items().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_empty_any(&self) -> bool {
        self.len_any() == 0
    }

    pub fn flush(&mut self) -> usize {
        self.compact_evicted();
        self.flush_older_than(self.default_max_cache)
    }

    pub fn flush_older_than(&mut self, max_cache: Duration) -> usize {
        self.compact_evicted();
        let now_ms = Self::now_epoch_ms();
        let max_age_ms = Self::max_cache_ms(max_cache);
        let cutoff = now_ms.saturating_sub(max_age_ms);

        let stale_keys = self
            .order
            .keys()
            .take_while(|(epoch_ms, _)| *epoch_ms < cutoff)
            .copied()
            .collect::<Vec<_>>();

        let removed = stale_keys.len();
        for order_key in stale_keys {
            let _ = self.remove_by_order_key(order_key);
        }
        removed
    }

    pub fn flush_before_seq_no(&mut self, max_seq_no: u64) -> usize {
        self.compact_evicted();
        let seq_keys = self
            .order
            .keys()
            .filter(|(_, seq)| *seq <= max_seq_no)
            .copied()
            .collect::<Vec<_>>();
        let removed = seq_keys.len();
        for order_key in seq_keys {
            let _ = self.remove_by_order_key(order_key);
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::TtlCache;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn hidden_by_default_max_cache_but_kept_until_flush() {
        let mut cache = TtlCache::new(Duration::from_millis(5));
        cache.insert("a", 1);
        thread::sleep(Duration::from_millis(10));
        assert_eq!(cache.get(&"a"), None);
        assert_eq!(cache.get_any(&"a"), None);
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.len_any(), 0);
    }

    #[test]
    fn touch_extends_visibility_window() {
        let mut cache = TtlCache::new(Duration::from_millis(20));
        cache.insert("a", 1);
        thread::sleep(Duration::from_millis(10));
        assert!(cache.touch(&"a"));
        thread::sleep(Duration::from_millis(12));
        assert_eq!(cache.get(&"a"), Some(&1));
    }

    #[test]
    fn custom_max_cache_filter_works_without_flush() {
        let mut cache = TtlCache::new(Duration::from_secs(1));
        cache.insert("a", 1);
        thread::sleep(Duration::from_millis(10));
        assert_eq!(cache.get_with_max_cache(&"a", Duration::from_millis(5)), None);
        assert_eq!(cache.get_with_max_cache(&"a", Duration::from_millis(50)), Some(&1));
    }

    #[test]
    fn flush_removes_stale_entries_by_default_max_cache() {
        let mut cache = TtlCache::new(Duration::from_millis(5));
        cache.insert("a", 1);
        cache.insert("b", 2);
        thread::sleep(Duration::from_millis(10));
        assert_eq!(cache.flush(), 0);
        assert_eq!(cache.len_any(), 0);
    }

    #[test]
    fn ordered_min_max_and_pops_work() {
        let mut cache = TtlCache::new(Duration::from_secs(60));
        cache.insert("a", 1);
        cache.insert("b", 2);
        cache.insert("c", 3);

        assert_eq!(cache.min().map(|(k, _)| *k), Some("a"));
        assert_eq!(cache.max().map(|(k, _)| *k), Some("c"));

        assert_eq!(cache.pop_first().map(|(k, v)| (k, v)), Some(("a", 1)));
        assert_eq!(cache.pop_latest().map(|(k, v)| (k, v)), Some(("c", 3)));
        assert_eq!(cache.get(&"b"), Some(&2));
    }

    #[test]
    fn flush_before_seq_no_removes_prefix() {
        let mut cache = TtlCache::new(Duration::from_secs(60));
        cache.insert("a", 1);
        let seq_a = cache.seq_no_of(&"a").unwrap_or(0);
        cache.insert("b", 2);
        cache.insert("c", 3);

        assert_eq!(cache.flush_before_seq_no(seq_a), 1);
        assert_eq!(cache.get_any(&"a"), None);
        assert_eq!(cache.get_any(&"b"), Some(&2));
        assert_eq!(cache.get_any(&"c"), Some(&3));
    }
}
